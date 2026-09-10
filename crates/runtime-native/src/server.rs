//! The native server (issue #19): one axum router on a `TcpListener`,
//! with client-IP sanitization outside everything else, the in-process
//! cron scheduler, and graceful shutdown on SIGTERM/SIGINT (what
//! `docker stop` sends).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use cratefield_core::{Config, Harness};
use thiserror::Error;
use tokio::net::TcpListener;

use crate::config::EnvConfig;
use crate::cron::{CronError, spawn_cron_scheduler};
use crate::ports::{
    client_ip, is_loopback_host, normalize_headers, trusted_hosts, trusted_proxy_headers,
    venture_hosts,
};
use crate::runtime::{Native, clone_ports};
use crate::tracing_setup::install_tracing;

/// Logs the push wiring report once at cold start (issue #191), the twin of
/// the Cloudflare runtime's `check_push_wiring_once`. Names and verdicts
/// only: the report never carries a value, so no secret reaches the logs
/// through it.
///
/// A half-wired transport is `error!` in production and `warn!` below it — a
/// venture that meant to enable FCM and mistyped one variable must not boot
/// into a state where every Android send silently answers `NotConfigured`,
/// while a developer wiring a transport one variable at a time must still be
/// able to boot. `fz doctor` is what refuses a deploy.
///
/// Nothing is logged when the venture passed its own adapter: `push_wiring`
/// answers `None`, so no environment is read and no transport the venture
/// deliberately overrode is reported on.
#[cfg(feature = "push")]
fn log_push_wiring(harness: &Harness, runtime: &Native, config: &dyn Config) {
    use cratefield_push_wiring::WiringSeverity;
    let Some(wiring) = runtime.push_wiring() else {
        return;
    };
    tracing::info!("{}", wiring.summary());
    let deployed = cratefield_core::deployed_env(harness.venture().env, config);
    match wiring.severity(deployed) {
        WiringSeverity::Ok => {}
        WiringSeverity::Warning => {
            for problem in wiring.problems() {
                tracing::warn!("{problem}");
            }
        }
        WiringSeverity::Error => {
            for problem in wiring.problems() {
                tracing::error!("{problem}");
            }
        }
    }
}

/// `LISTEN_ADDR` default: loopback only. A deployment open to the world
/// must say so explicitly (`LISTEN_ADDR=0.0.0.0:8080`, as the compose
/// example does) — the same fail-closed instinct as the empty
/// trusted-proxy list.
pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8080";

#[derive(Debug, Error)]
pub enum ServeError {
    /// `LISTEN_ADDR` is not a socket address.
    #[error("LISTEN_ADDR {addr:?} is not a valid socket address")]
    ListenAddr { addr: String },
    /// The listener could not be bound.
    #[error("failed to bind {addr}: {source}")]
    Bind {
        addr: String,
        #[source]
        source: std::io::Error,
    },
    /// A `CRONS` entry is not a valid cron expression; the process
    /// refuses to start rather than silently skipping scheduled work
    /// (wrangler rejects an invalid cron at deploy time for the same
    /// reason).
    #[error("invalid CRONS entry")]
    Cron(#[from] CronError),
    /// The serving loop failed.
    #[error("server failed: {0}")]
    Serve(#[source] std::io::Error),
}

/// Serves the harness: builds the router once, wraps it in the client-IP
/// middleware, starts the cron scheduler for the `CRONS` config, and
/// serves until SIGTERM or SIGINT.
///
/// # Errors
///
/// [`ServeError`] when `LISTEN_ADDR` cannot be parsed or bound, a cron
/// expression is invalid, or the accept loop fails.
///
/// # Errors: shutdown semantics
///
/// Graceful shutdown waits for in-flight requests only. Deferred work
/// (`Defer`/`tokio::spawn`) is not awaited on shutdown — a task killed
/// mid-flight simply ends, like a Worker that stops getting slices
/// after its 30 s `wait_until` budget. Handlers that must finish commit
/// before responding.
pub async fn serve(harness: Arc<Harness>, runtime: Native) -> Result<(), ServeError> {
    install_tracing();
    let config = Arc::new(EnvConfig);
    let addr = listen_addr(&*config)?;
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| ServeError::Bind {
            addr: addr.to_string(),
            source,
        })?;
    serve_on(harness, runtime, listener).await
}

/// Serves the harness on an already-bound listener: builds the router
/// once, wraps it in the client-IP middleware (trust list and `CRONS`
/// from `std::env`), and serves until SIGTERM or SIGINT. `serve` is this
/// plus `LISTEN_ADDR` resolution and binding; tests and ventures with
/// their own socket management (fd passing, port 0) call this directly.
///
/// # Errors
///
/// [`ServeError`] when a `CRONS` entry is invalid or the accept loop
/// fails. Shutdown semantics as on [`serve`].
pub async fn serve_on(
    harness: Arc<Harness>,
    runtime: Native,
    listener: TcpListener,
) -> Result<(), ServeError> {
    install_tracing();

    let config = Arc::new(EnvConfig);
    let ports = runtime.ports();
    #[cfg(feature = "push")]
    log_push_wiring(&harness, &runtime, &*config);

    // Scheduled work: every expression gets its own task, fanned out to
    // every module's `scheduled(ctx, cron)` — the same fan-out
    // `serve_scheduled` performs per Workers cron trigger.
    let crons = cron_expressions(&*config);
    if !crons.is_empty() {
        spawn_cron_scheduler(&harness, &ports, &crons)?;
    }

    let app = harness
        .router(clone_ports(&ports))
        .layer(from_fn_with_state(
            IpTrust {
                trusted: trusted_proxy_headers(&*config),
            },
            client_ip_layer,
        ))
        // Outside the IP layer: a request for a host this deployment does
        // not answer to is refused before anything reads its headers.
        .layer(from_fn_with_state(
            HostTrust::resolve(harness.venture(), &*config),
            host_layer,
        ));

    let addr = listener
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_default();
    tracing::info!(%addr, "cratefield native runtime listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .map_err(ServeError::Serve)
}

/// `CRONS`: comma-separated cron expressions (UTC, wrangler's `[triggers]
/// crons` moved into config). Default: no scheduled work.
fn cron_expressions(config: &dyn Config) -> Vec<String> {
    config
        .get("CRONS")
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn listen_addr(config: &dyn Config) -> Result<SocketAddr, ServeError> {
    let raw = config
        .get("LISTEN_ADDR")
        .unwrap_or_else(|| DEFAULT_LISTEN_ADDR.to_owned());
    raw.parse::<SocketAddr>()
        .map_err(|_| ServeError::ListenAddr { addr: raw })
}

/// The trusted-proxy header list, resolved once per process and shared
/// by every request (deployment config, not request state).
#[derive(Clone)]
struct IpTrust {
    trusted: Vec<String>,
}

/// The hosts this deployment answers to, resolved once per process
/// (issue #129).
#[derive(Clone)]
struct HostTrust {
    /// Lowercased, port-less hosts. Empty means "answer to anything",
    /// which only happens below production.
    allowed: Arc<Vec<String>>,
    /// Whether an unknown host is refused. Production only: local
    /// development and the test suite reach the server by loopback
    /// address, and refusing those by default would make the safe
    /// deployment the one nobody can run.
    enforce: bool,
}

impl HostTrust {
    fn resolve(venture: &cratefield_core::Venture, config: &dyn Config) -> Self {
        let mut allowed = venture_hosts(venture);
        for host in trusted_hosts(config) {
            if !allowed.contains(&host) {
                allowed.push(host);
            }
        }
        let enforce = cratefield_core::deployed_env(venture.env, config)
            == cratefield_core::VentureEnv::Production;
        if enforce && allowed.is_empty() {
            tracing::warn!(
                "no host to answer to: the venture declares no domain and TRUSTED_HOSTS is \
                 unset, so every request would be refused — serving all hosts instead \
                 (issue #129)"
            );
        }
        Self {
            allowed: Arc::new(allowed),
            enforce,
        }
    }

    fn answers_to(&self, host: &str) -> bool {
        if self.allowed.is_empty() {
            return true;
        }
        let host = crate::ports::host_without_port(host);
        self.allowed.iter().any(|known| known == &host) || is_loopback_host(&host)
    }
}

/// Host middleware (issue #129): a native process answers whatever `Host`
/// a caller sends, and `Host` is what ADR 0008's database-per-tenant
/// resolution will key off once phase three lands. An unvalidated one is a
/// link-forgery and cache-poisoning vector now and the cross-tenant vector
/// then, so a production deployment refuses a host it does not serve.
///
/// `x-forwarded-host` is deliberately not consulted: it is not in the
/// `TRUSTED_PROXY_HEADERS` contract #131 established, and a second,
/// parallel header-trust mechanism is exactly what that contract exists to
/// prevent. A proxy that rewrites the host must rewrite `Host` itself.
async fn host_layer(State(trust): State<HostTrust>, request: Request, next: Next) -> Response {
    if !trust.enforce {
        return next.run(request).await;
    }
    let host = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .or_else(|| {
            request
                .uri()
                .authority()
                .map(|authority| authority.as_str().to_owned())
        });
    let Some(host) = host else {
        // HTTP/1.1 requires it and HTTP/2 supplies `:authority`; a
        // request with neither cannot be resolved to a venture.
        return refuse_host(None);
    };
    if !trust.answers_to(&host) {
        return refuse_host(Some(&host));
    }
    next.run(request).await
}

/// The refusal: `421 Misdirected Request` is precisely this condition —
/// the connection reached a server that does not answer for the host.
fn refuse_host(host: Option<&str>) -> Response {
    if let Some(host) = host {
        tracing::warn!(
            host = crate::ports::host_without_port(host),
            "refused a request for a host this deployment does not serve"
        );
    } else {
        tracing::warn!("refused a request that carried no host");
    }
    let problem = cratefield_core::Problem::new(&cratefield_core::SLUGS.not_found)
        .with_detail("this deployment does not serve that host");
    (axum::http::StatusCode::MISDIRECTED_REQUEST, problem).into_response()
}

/// Client-IP middleware: resolve the address (trusted headers first,
/// else the TCP peer), strip every forwarding header, and set the
/// verdict into the header core's `client_ip` reads first. Runs outside
/// the harness's own layers, so the request scope's `ip_hash` and every
/// module's rate-limit key see the sanitized view.
async fn client_ip_layer(
    State(trust): State<IpTrust>,
    mut request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());
    let resolved = client_ip(request.headers(), &trust.trusted, peer);
    normalize_headers(request.headers_mut(), resolved);
    next.run(request).await
}

/// Resolves when the process should stop: SIGINT (Ctrl-C) or, on Unix,
/// SIGTERM (what `docker stop` and systemd send). Public so a venture
/// that assembles its own serving loop gets the same semantics.
///
/// # Panics
///
/// Only if the signal handlers cannot be installed (the process
/// environment disallows it); serving cannot continue meaningfully
/// without shutdown signals.
pub async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {},
            _ = sigterm.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        if ctrl_c.await.is_err() {
            tracing::error!("ctrl_c handler failed; exiting");
        }
    }
    tracing::info!("shutdown signal received; draining in-flight requests");
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::MapConfig;

    #[test]
    fn crons_default_to_empty_and_split_on_commas() {
        assert!(cron_expressions(&MapConfig::default()).is_empty());
        let cfg = MapConfig::from_pairs([("CRONS", "*/5 * * * * , 0 0 * * *,,")]);
        assert_eq!(cron_expressions(&cfg), ["*/5 * * * *", "0 0 * * *"]);
    }

    #[test]
    fn listen_addr_defaults_to_loopback() {
        let addr = listen_addr(&MapConfig::default()).expect("default parses");
        assert_eq!(addr.to_string(), "127.0.0.1:8080");

        let cfg = MapConfig::from_pairs([("LISTEN_ADDR", "0.0.0.0:9999")]);
        let addr = listen_addr(&cfg).expect("parses");
        assert_eq!(addr.to_string(), "0.0.0.0:9999");
    }

    #[test]
    fn bad_listen_addr_is_an_error() {
        let cfg = MapConfig::from_pairs([("LISTEN_ADDR", "not-an-addr")]);
        assert!(matches!(
            listen_addr(&cfg),
            Err(ServeError::ListenAddr { .. })
        ));
    }

    // ------------------------------------------ host isolation (issue #129)

    use cratefield_core::{Venture, VentureEnv};

    fn tenant_a() -> Venture {
        Venture::new("tenant-a", "tenant-a.example").public_url("https://tenant-a.example")
    }

    fn tenant_b() -> Venture {
        Venture::new("tenant-b", "tenant-b.example").public_url("https://tenant-b.example")
    }

    fn production() -> MapConfig {
        MapConfig::from_pairs([("ENV", "production")])
    }

    #[test]
    fn a_production_deployment_answers_only_for_its_own_venture() {
        let trust = HostTrust::resolve(&tenant_a(), &production());
        assert!(trust.enforce);
        assert!(trust.answers_to("tenant-a.example"));
        assert!(trust.answers_to("api.tenant-a.example"));
        assert!(trust.answers_to("TENANT-A.example:8443"), "case and port");

        // The adversarial half: the other tenant's host, and a host that
        // merely looks like ours, are both refused. `Host` is what ADR
        // 0008's per-tenant resolution will read, so answering for a
        // neighbour's host is the cross-tenant vector this closes.
        for foreign in [
            "tenant-b.example",
            "api.tenant-b.example",
            "tenant-a.example.evil.test",
            "eviltenant-a.example",
            "evil.test",
        ] {
            assert!(
                !trust.answers_to(foreign),
                "{foreign} must not be answered for"
            );
        }

        // And the mirror image holds for the other venture, so neither
        // deployment would serve the other's traffic.
        let other = HostTrust::resolve(&tenant_b(), &production());
        assert!(other.answers_to("tenant-b.example"));
        assert!(!other.answers_to("tenant-a.example"));
    }

    #[test]
    fn extra_hosts_are_additive_and_never_widen_to_a_neighbour() {
        let config = MapConfig::from_pairs([
            ("ENV", "production"),
            ("TRUSTED_HOSTS", "cdn.tenant-a.example"),
        ]);
        let trust = HostTrust::resolve(&tenant_a(), &config);
        assert!(trust.answers_to("cdn.tenant-a.example"));
        assert!(trust.answers_to("tenant-a.example"));
        assert!(!trust.answers_to("tenant-b.example"));
    }

    #[test]
    fn loopback_stays_reachable_so_probes_and_local_work_keep_working() {
        let trust = HostTrust::resolve(&tenant_a(), &production());
        for local in ["127.0.0.1:8080", "localhost:8080", "[::1]:8080"] {
            assert!(trust.answers_to(local), "{local} is how a probe arrives");
        }
    }

    #[test]
    fn enforcement_is_production_only_and_follows_the_deployment() {
        // Below production the server answers anything: local development
        // and the test suite reach it by whatever name is convenient, and
        // refusing those would make the safe deployment unrunnable.
        assert!(!HostTrust::resolve(&tenant_a(), &MapConfig::default()).enforce);

        // The deployment's ENV is what decides, not the compiled default
        // — the same rule #143 established for readiness.
        assert!(HostTrust::resolve(&tenant_a(), &production()).enforce);
        let compiled = Venture::new("tenant-a", "tenant-a.example").env(VentureEnv::Production);
        assert!(HostTrust::resolve(&compiled, &MapConfig::default()).enforce);
    }

    #[test]
    fn a_venture_with_no_domain_serves_rather_than_refusing_everything() {
        // Fail-closed must not mean fail-useless: with nothing to compare
        // against, refusing every request would take the deployment down
        // for a configuration mistake it can report instead.
        let anonymous = Venture::new("anon", "");
        let trust = HostTrust::resolve(&anonymous, &production());
        assert!(trust.allowed.is_empty());
        assert!(trust.answers_to("anything.example"));
    }
}
