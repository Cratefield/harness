//! The example venture as a **native** binary (issue #19): the same
//! modules as the Worker example — `sample`, `email-signup`,
//! `waitlist` — served by `cratefield-runtime-native` on tokio, with
//! Postgres or SQLite behind the `Database` port and, when `REDIS_URL`
//! is set, Redis behind `RateLimiter` and `KeyValue`.
//!
//! ```sh
//! export HARNESS_SECRET=$(openssl rand -hex 32)
//! export DATABASE_URL=sqlite:///tmp/venture.db   # or postgres://…
//! export REDIS_URL=redis://127.0.0.1:6379        # optional
//! LISTEN_ADDR=127.0.0.1:8080 cargo run -p venture-native --release
//! curl -fsS http://127.0.0.1:8080/__health && curl -fsS http://127.0.0.1:8080/__ready
//! ```
//!
//! `--check-ready` runs the container health check (GET `/__ready`
//! against the configured listen address, exit 0/1) — distroless ships
//! no curl, so the binary checks itself; `docker-compose.example.yml`
//! wires it into the app service's healthcheck.

use std::sync::Arc;

use cratefield_adapter_postgres::Postgres;
use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_core::{
    Clock, Config, Database, Harness, HttpClient, KeyValue, RateLimiter, Venture,
};
use cratefield_module_email_signup::EmailSignup;
use cratefield_module_waitlist::Waitlist;
use cratefield_runtime_native::{
    EnvConfig, Native, ReqwestClient, TokioClock, install_tracing, serve,
};
use venture::sample::SampleRowModule;

/// The database this process booted with — kept concretely typed so
/// migrations can run through the adapter's own runner after the
/// harness (which needs the `Arc<dyn Database>` first) is built.
enum BootDb {
    Postgres(Arc<Postgres>),
    Sqlite(Arc<SqliteDatabase>),
}

impl BootDb {
    fn port(&self) -> Arc<dyn Database> {
        match self {
            Self::Postgres(db) => Arc::clone(db) as Arc<dyn Database>,
            Self::Sqlite(db) => Arc::clone(db) as Arc<dyn Database>,
        }
    }
}

#[tokio::main]
async fn main() {
    if std::env::args().any(|arg| arg == "--check-ready") {
        check_ready().await;
        return;
    }
    install_tracing();
    if let Err(err) = run().await {
        tracing::error!(error = %err, "venture-native failed");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = EnvConfig;

    let Some(db) = open_database(&config).await? else {
        return Err(
            "DATABASE_URL is required (postgres://… or sqlite://path | sqlite::memory:)".into(),
        );
    };

    // The `Push` port assembled from the environment (issue #191): with
    // nothing configured every send answers `NotConfigured`, and `serve`
    // logs which transports were found once at cold start.
    let mut runtime = Native::new().db_arc(db.port()).push_from_env();
    if let Some(redis) = cratefield_runtime_native::redis_from_env(&config).await? {
        let rate_limiter: Arc<dyn RateLimiter> = redis.rate_limiter;
        let kv: Arc<dyn KeyValue> = redis.kv;
        runtime = runtime.rate_limiter_arc(rate_limiter).kv_arc(kv);
        tracing::info!("redis rate limiter and key-value ports configured");
    } else {
        tracing::warn!("REDIS_URL unset: RateLimiter and KeyValue ports not configured");
    }

    let http: Arc<dyn HttpClient> = Arc::new(ReqwestClient::new());
    let clock: Arc<dyn Clock> = Arc::new(TokioClock);
    runtime = runtime.mailer(cratefield_adapter_resend::Resend::new(
        Arc::clone(&http),
        None,
        "example@factory0.dev",
        None,
    ));
    if let Some(turnstile) =
        cratefield_adapter_turnstile::Turnstile::from_env(Arc::clone(&http), Arc::clone(&clock))
    {
        runtime = runtime.captcha(turnstile);
    }

    let mut templates = cratefield_module_email_signup::default_templates();
    templates.extend(cratefield_module_waitlist::default_templates());
    let harness = Arc::new(
        Harness::builder()
            .venture(
                Venture::new("venture-example", "example.factory0.dev")
                    .public_url("https://example.factory0.dev")
                    .cors_origins(["https://example.factory0.dev"]),
            )
            .module(SampleRowModule)
            .module(EmailSignup::new())
            .module(
                Waitlist::new()
                    .products(["kontinuum", "undercover-rockstars"])
                    .confirm_ttl_days(7),
            )
            .templates(templates)
            .runtime(runtime.clone())
            .build()?,
    );

    apply_migrations(&harness, &db).await?;
    serve(harness, runtime).await?;
    Ok(())
}

/// `DATABASE_URL`: `postgres://`/`postgresql://` opens a Postgres pool
/// (fails fast on an unreachable server); `sqlite://<path>` or
/// `sqlite::memory:` opens SQLite — the single-node self-hosting shape.
async fn open_database(config: &EnvConfig) -> Result<Option<BootDb>, Box<dyn std::error::Error>> {
    let Some(url) = config.get("DATABASE_URL") else {
        return Ok(None);
    };
    if url.starts_with("postgres://") || url.starts_with("postgresql://") {
        Ok(Some(BootDb::Postgres(Arc::new(
            Postgres::connect(&url).await?,
        ))))
    } else if let Some(path) = url
        .strip_prefix("sqlite://")
        .map(str::to_owned)
        .or_else(|| (url == "sqlite::memory:").then(|| ":memory:".to_owned()))
    {
        Ok(Some(BootDb::Sqlite(Arc::new(SqliteDatabase::open(&path)?))))
    } else {
        Err(format!(
            "DATABASE_URL must start with postgres://, postgresql:// or sqlite:// (got {url:?})"
        )
        .into())
    }
}

/// Applies every module's migrations on boot, idempotently, through the
/// adapter's own runner — the native counterpart of
/// `wrangler d1 migrations apply`. Opt out with `FZ_APPLY_MIGRATIONS=0`
/// when your deploy pipeline applies them explicitly.
async fn apply_migrations(
    harness: &Harness,
    db: &BootDb,
) -> Result<(), Box<dyn std::error::Error>> {
    let skip = EnvConfig
        .get("FZ_APPLY_MIGRATIONS")
        .is_some_and(|raw| matches!(raw.as_str(), "0" | "false" | "no" | "off"));
    if skip {
        tracing::info!("FZ_APPLY_MIGRATIONS=0: skipping migrations on boot");
        return Ok(());
    }
    match db {
        BootDb::Postgres(db) => db.apply_harness_migrations(harness).await?,
        BootDb::Sqlite(db) => {
            for module in harness.modules() {
                db.apply_migrations(module.name(), module.migrations().sqlite)?;
            }
        }
    }
    tracing::info!("module migrations applied");
    Ok(())
}

/// The container health check: `GET /__ready` on the configured listen
/// address, exit 0 on 200, exit 1 otherwise. Wildcard binds
/// (`0.0.0.0`, `::`) are self-connected over loopback.
async fn check_ready() {
    let raw = EnvConfig
        .get("LISTEN_ADDR")
        .unwrap_or_else(|| "127.0.0.1:8080".to_owned());
    let target = match raw.parse::<std::net::SocketAddr>() {
        Ok(addr) => loopback(addr),
        Err(_) => "127.0.0.1:8080".parse().expect("loopback parses"),
    };

    let request = http::Request::builder()
        .uri(format!("http://{target}/__ready"))
        .body(bytes::Bytes::new())
        .expect("static request builds");
    let outcome = ReqwestClient::new().send(request).await;
    let ready = matches!(outcome, Ok(response) if response.status() == 200);
    if !ready {
        eprintln!("not ready: {target}/__ready did not answer 200");
    }
    std::process::exit(i32::from(!ready));
}

fn loopback(addr: std::net::SocketAddr) -> std::net::SocketAddr {
    let ip = match addr.ip() {
        std::net::IpAddr::V4(ip) if ip.is_unspecified() => {
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        }
        std::net::IpAddr::V6(ip) if ip.is_unspecified() => {
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        }
        ip => ip,
    };
    std::net::SocketAddr::new(ip, addr.port())
}
