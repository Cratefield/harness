//! The `Cloudflare` runtime builder (issue #5).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use factory0_core::{Captcha, Defer, HarnessConfig, Mailer, Port, Ports, Runtime, UlidIdGen};
use worker::Env;

use crate::config::EnvConfig;
use crate::ports::{D1Database, FetchClient, KvStorePort, RateLimitPort, WorkersClock};

fn warn_once(flag: &AtomicBool, message: &str) {
    if !flag.load(Ordering::Relaxed) {
        flag.store(true, Ordering::Relaxed);
        rt_log!(warn, "{message}");
    }
}

/// Runtime logging: `worker::console_log!` on Workers (no tracing
/// dispatcher can be installed there — see `tracing_setup`), `tracing!`
/// natively.
#[macro_export]
macro_rules! rt_log {
    (warn, $($arg:tt)*) => {{
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[warn] {}", format!($($arg)*));
        #[cfg(not(target_arch = "wasm32"))]
        tracing::warn!($($arg)*);
    }};
    (error, $($arg:tt)*) => {{
        #[cfg(target_arch = "wasm32")]
        worker::console_error!("[error] {}", format!($($arg)*));
        #[cfg(not(target_arch = "wasm32"))]
        tracing::error!($($arg)*);
    }};
}
use rt_log;

static WARNED_DB: AtomicBool = AtomicBool::new(false);
static WARNED_KV: AtomicBool = AtomicBool::new(false);
static WARNED_RATE_LIMIT: AtomicBool = AtomicBool::new(false);
static WARNED_SIGNER: AtomicBool = AtomicBool::new(false);

/// The Workers runtime. Binding names are static; `.mailer()`/`.captcha()`
/// take adapter instances (`factory0-adapter-resend`,
/// `factory0-adapter-turnstile`).
pub struct Cloudflare {
    db_binding: Option<&'static str>,
    kv_binding: Option<&'static str>,
    rate_limiter_binding: Option<&'static str>,
    mailer: Option<Arc<dyn Mailer>>,
    captcha: Option<Arc<dyn Captcha>>,
}

impl Default for Cloudflare {
    fn default() -> Self {
        Self::new()
    }
}

impl Cloudflare {
    pub fn new() -> Self {
        Self {
            db_binding: None,
            kv_binding: None,
            rate_limiter_binding: None,
            mailer: None,
            captcha: None,
        }
    }

    #[must_use]
    pub fn db(mut self, binding: &'static str) -> Self {
        self.db_binding = Some(binding);
        self
    }

    #[must_use]
    pub fn kv(mut self, binding: &'static str) -> Self {
        self.kv_binding = Some(binding);
        self
    }

    #[must_use]
    pub fn rate_limiter(mut self, binding: &'static str) -> Self {
        self.rate_limiter_binding = Some(binding);
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

    /// Resolves the per-request `Ports` from the actual bindings and the
    /// event's `wait_until` context. Absent optional bindings leave the
    /// port `None` (logged once per isolate); a missing `HARNESS_SECRET`
    /// leaves `Signer` unset the same way.
    pub fn ports(&self, env: &Env, defer: Arc<dyn Defer>) -> Ports {
        let mut ports = Ports::with_config(Arc::new(EnvConfig(env.clone())));

        if let Some(name) = self.db_binding {
            match env.d1(name) {
                Ok(db) => ports.db = Some(Arc::new(D1Database(db))),
                Err(err) => warn_once(
                    &WARNED_DB,
                    &format!("D1 binding {name:?} not available: {err}"),
                ),
            }
        }
        if let Some(name) = self.kv_binding {
            match env.kv(name) {
                Ok(kv) => ports.kv = Some(Arc::new(KvStorePort(kv))),
                Err(err) => warn_once(
                    &WARNED_KV,
                    &format!("KV binding {name:?} not available: {err}"),
                ),
            }
        }
        if let Some(name) = self.rate_limiter_binding {
            match env.rate_limiter(name) {
                Ok(limiter) => ports.rate_limiter = Some(Arc::new(RateLimitPort(limiter))),
                Err(err) => warn_once(
                    &WARNED_RATE_LIMIT,
                    &format!("Rate limit binding {name:?} not available: {err}"),
                ),
            }
        }

        match HarnessConfig::from_config(&EnvConfig(env.clone())) {
            Ok(config) => {
                ports.signer = Some(Arc::new(config.signer()));
            }
            Err(_) => warn_once(
                &WARNED_SIGNER,
                "HARNESS_SECRET missing or invalid: Signer port not provided",
            ),
        }

        ports.http = Some(Arc::new(FetchClient));
        ports.clock = Some(Arc::new(WorkersClock));
        ports.id_gen = Some(Arc::new(UlidIdGen));
        ports.defer = Some(defer);
        ports.mailer.clone_from(&self.mailer);
        ports.captcha.clone_from(&self.captcha);
        ports
    }
}

impl Runtime for Cloudflare {
    /// The static set used by `Harness::build`. `Signer` is included: its
    /// presence is validated at `ports()` time (and by `fz doctor`).
    fn provides(&self) -> Vec<Port> {
        let mut provided = vec![
            Port::Signer,
            Port::HttpClient,
            Port::Clock,
            Port::IdGen,
            Port::Defer,
        ];
        if self.db_binding.is_some() {
            provided.push(Port::Db);
        }
        if self.kv_binding.is_some() {
            provided.push(Port::KeyValue);
        }
        if self.rate_limiter_binding.is_some() {
            provided.push(Port::RateLimiter);
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
