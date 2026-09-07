//! The native server (issue #19): one axum router on a `TcpListener`,
//! with client-IP sanitization outside everything else, the in-process
//! cron scheduler, and graceful shutdown on SIGTERM/SIGINT (what
//! `docker stop` sends).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::Response;
use cratefield_core::{Config, Harness};
use thiserror::Error;
use tokio::net::TcpListener;

use crate::config::EnvConfig;
use crate::cron::{CronError, spawn_cron_scheduler};
use crate::ports::{client_ip, normalize_headers, trusted_proxy_headers};
use crate::runtime::{Native, clone_ports};
use crate::tracing_setup::install_tracing;

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
}
