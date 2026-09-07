//! The `Native` runtime builder (issue #19): the counterpart of
//! `cratefield_runtime_cloudflare::Cloudflare` for a self-hosted binary.
//!
//! ```ignore
//! # use std::sync::Arc;
//! # fn db() -> Arc<dyn cratefield_core::Database> { unimplemented!() }
//! # fn rate_limiter() -> Arc<dyn cratefield_core::RateLimiter> { unimplemented!() }
//! # fn kv() -> Arc<dyn cratefield_core::KeyValue> { unimplemented!() }
//! # fn mailer() -> Arc<dyn cratefield_core::Mailer> { unimplemented!() }
//! use cratefield_runtime_native::Native;
//!
//! let runtime = Native::new()
//!     .db_arc(db())                       // Postgres (adapter-postgres) or Sqlite
//!     .rate_limiter_arc(rate_limiter())   // RedisRateLimiter, optional
//!     .kv_arc(kv())                       // RedisKv, optional
//!     .mailer_arc(mailer());              // Resend::from_env(..), as on Workers
//! # let _runtime: Native = runtime;
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use cratefield_core::{
    Blob, Captcha, Database, HarnessConfig, KeyValue, Mailer, Payments, Port, Ports, Push,
    RateLimiter, Realtime, Runtime, UlidIdGen,
};

use crate::config::EnvConfig;
use crate::ports::{ReqwestClient, SpawnDefer, TokioClock};

static WARNED_SIGNER: AtomicBool = AtomicBool::new(false);

fn warn_once(flag: &AtomicBool, message: &str) {
    if !flag.load(Ordering::Relaxed) {
        flag.store(true, Ordering::Relaxed);
        tracing::warn!("{message}");
    }
}

/// The native runtime. Adapters are passed in as instances (the same
/// pattern as the Cloudflare runtime's `.mailer(..)`/`.captcha(..)`):
/// a Postgres or SQLite [`Database`](cratefield_core::Database) from the
/// matching adapter crate, a [`RedisRateLimiter`](crate::RedisRateLimiter)
/// and [`RedisKv`](crate::RedisKv) over a shared Redis connection
/// manager, `Resend`/`Turnstile` unchanged from the Workers path.
///
/// Config — including `HARNESS_SECRET` for the `Signer` port — is read
/// from `std::env` through the same [`cratefield_core::Config`] trait
/// ([`EnvConfig`]), so module keys behave identically on both runtimes.
#[derive(Clone, Default)]
pub struct Native {
    db: Option<Arc<dyn Database>>,
    rate_limiter: Option<Arc<dyn RateLimiter>>,
    kv: Option<Arc<dyn KeyValue>>,
    blob: Option<Arc<dyn Blob>>,
    push: Option<Arc<dyn Push>>,
    payments: Option<Arc<dyn Payments>>,
    realtime: Option<Arc<dyn Realtime>>,
    mailer: Option<Arc<dyn Mailer>>,
    captcha: Option<Arc<dyn Captcha>>,
}

impl Native {
    pub fn new() -> Self {
        Self::default()
    }

    /// The `Database` port: `Postgres` (`cratefield-adapter-postgres`) or
    /// `SqliteDatabase` (`cratefield-adapter-sqlite`) — any `Database`
    /// implementation.
    #[must_use]
    pub fn db(mut self, db: impl Database + 'static) -> Self {
        self.db = Some(Arc::new(db));
        self
    }

    /// `db` for an already-shared database.
    #[must_use]
    pub fn db_arc(mut self, db: Arc<dyn Database>) -> Self {
        self.db = Some(db);
        self
    }

    /// The `RateLimiter` port: [`RedisRateLimiter`](crate::RedisRateLimiter) in this crate, or a
    /// test fake.
    #[must_use]
    pub fn rate_limiter(mut self, limiter: impl RateLimiter + 'static) -> Self {
        self.rate_limiter = Some(Arc::new(limiter));
        self
    }

    /// `rate_limiter` for an already-shared limiter.
    #[must_use]
    pub fn rate_limiter_arc(mut self, limiter: Arc<dyn RateLimiter>) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    /// The `KeyValue` port: [`RedisKv`](crate::RedisKv) in this crate, or a test fake.
    #[must_use]
    pub fn kv(mut self, kv: impl KeyValue + 'static) -> Self {
        self.kv = Some(Arc::new(kv));
        self
    }

    /// `kv` for an already-shared store.
    #[must_use]
    pub fn kv_arc(mut self, kv: Arc<dyn KeyValue>) -> Self {
        self.kv = Some(kv);
        self
    }

    /// The `Blob` port: a directory store ([`crate::DirBlob`]) or an
    /// S3-compatible adapter.
    #[must_use]
    pub fn blob_arc(mut self, blob: Arc<dyn Blob>) -> Self {
        self.blob = Some(blob);
        self
    }

    /// The `Push` port: an APNs adapter (`cratefield-adapter-apns`) or a test
    /// fake. Notifications reach a device over the runtime's `HttpClient`.
    #[must_use]
    pub fn push_arc(mut self, push: Arc<dyn Push>) -> Self {
        self.push = Some(push);
        self
    }

    /// The `Payments` port: a Stripe adapter (`cratefield-adapter-stripe`) or a
    /// test fake, over the runtime's `HttpClient`.
    #[must_use]
    pub fn payments_arc(mut self, payments: Arc<dyn Payments>) -> Self {
        self.payments = Some(payments);
        self
    }

    /// The `Realtime` port: the in-process room registry
    /// ([`crate::InProcessRealtime`]) built from the module's `RoomHandler`.
    #[must_use]
    pub fn realtime_arc(mut self, realtime: Arc<dyn Realtime>) -> Self {
        self.realtime = Some(realtime);
        self
    }

    #[must_use]
    pub fn mailer(mut self, mailer: impl Mailer + 'static) -> Self {
        self.mailer = Some(Arc::new(mailer));
        self
    }

    #[must_use]
    pub fn mailer_arc(mut self, mailer: Arc<dyn Mailer>) -> Self {
        self.mailer = Some(mailer);
        self
    }

    #[must_use]
    pub fn captcha(mut self, captcha: impl Captcha + 'static) -> Self {
        self.captcha = Some(Arc::new(captcha));
        self
    }

    #[must_use]
    pub fn captcha_arc(mut self, captcha: Arc<dyn Captcha>) -> Self {
        self.captcha = Some(captcha);
        self
    }

    /// Resolves the port bundle once per process from the builder and
    /// `std::env`: config, `Signer` (from `HARNESS_SECRET` — warn once
    /// and leave unset when missing, exactly like the Cloudflare
    /// runtime), `HttpClient` over reqwest, `Clock` over the system
    /// clock, `IdGen`, and `Defer` over `tokio::spawn`.
    ///
    /// Unlike the Workers runtime — which resolves bindings per event —
    /// a native process builds one bundle and shares it: every adapter
    /// here is an `Arc`, so `clone_ports` snapshots cheaply.
    #[must_use]
    pub fn ports(&self) -> Ports {
        let config: Arc<dyn cratefield_core::Config> = Arc::new(EnvConfig);
        let mut ports = Ports::with_config(Arc::clone(&config));

        ports.db.clone_from(&self.db);
        ports.rate_limiter.clone_from(&self.rate_limiter);
        ports.kv.clone_from(&self.kv);
        ports.blob.clone_from(&self.blob);
        ports.push.clone_from(&self.push);
        ports.payments.clone_from(&self.payments);
        ports.realtime.clone_from(&self.realtime);
        ports.mailer.clone_from(&self.mailer);
        ports.captcha.clone_from(&self.captcha);

        match HarnessConfig::from_config(&*config) {
            Ok(parsed) => {
                // Pseudonymise logged emails with a key derived from the
                // harness secret, not a bare (reversible) hash — issue #135.
                cratefield_core::set_log_pseudonym_key(parsed.harness_secret.as_bytes());
                ports.signer = Some(Arc::new(parsed.signer()));
            }
            Err(_) => warn_once(
                &WARNED_SIGNER,
                "HARNESS_SECRET missing or invalid: Signer port not provided",
            ),
        }

        ports.http = Some(Arc::new(ReqwestClient::new()));
        ports.clock = Some(Arc::new(TokioClock));
        ports.id_gen = Some(Arc::new(UlidIdGen));
        ports.defer = Some(Arc::new(SpawnDefer));
        ports
    }
}

impl Runtime for Native {
    /// The static set used by `Harness::build`. `Signer` is included:
    /// its presence is validated at `ports()` time (and by `fz doctor`),
    /// mirroring the Cloudflare runtime.
    fn provides(&self) -> Vec<Port> {
        let mut provided = vec![
            Port::Signer,
            Port::HttpClient,
            Port::Clock,
            Port::IdGen,
            Port::Defer,
        ];
        if self.db.is_some() {
            provided.push(Port::Db);
        }
        if self.rate_limiter.is_some() {
            provided.push(Port::RateLimiter);
        }
        if self.kv.is_some() {
            provided.push(Port::KeyValue);
        }
        if self.blob.is_some() {
            provided.push(Port::Blob);
        }
        if self.push.is_some() {
            provided.push(Port::Push);
        }
        if self.payments.is_some() {
            provided.push(Port::Payments);
        }
        if self.realtime.is_some() {
            provided.push(Port::Realtime);
        }
        if self.mailer.is_some() {
            provided.push(Port::Mailer);
        }
        if self.captcha.is_some() {
            provided.push(Port::Captcha);
        }
        provided
    }
}

/// Snapshots a [`Ports`] bundle by cloning every `Arc` (core's `Ports`
/// is not `Clone`; every field is a shared handle, so this is the whole
/// job). Used to give the cron scheduler the same adapters the HTTP
/// router serves with.
pub(crate) fn clone_ports(ports: &Ports) -> Ports {
    let mut snapshot = Ports::with_config(Arc::clone(&ports.config));
    snapshot.db.clone_from(&ports.db);
    snapshot.mailer.clone_from(&ports.mailer);
    snapshot.captcha.clone_from(&ports.captcha);
    snapshot.rate_limiter.clone_from(&ports.rate_limiter);
    snapshot.signer.clone_from(&ports.signer);
    snapshot.kv.clone_from(&ports.kv);
    snapshot.blob.clone_from(&ports.blob);
    snapshot.push.clone_from(&ports.push);
    snapshot.payments.clone_from(&ports.payments);
    snapshot.realtime.clone_from(&ports.realtime);
    snapshot.http.clone_from(&ports.http);
    snapshot.clock.clone_from(&ports.clock);
    snapshot.id_gen.clone_from(&ports.id_gen);
    snapshot.defer.clone_from(&ports.defer);
    snapshot
}
