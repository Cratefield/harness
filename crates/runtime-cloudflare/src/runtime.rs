//! The `Cloudflare` runtime builder (issue #5).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use cratefield_core::{
    BoundedHttpClient, Captcha, Clock, Defer, HarnessConfig, Mailer, Payments, Port, Ports, Push,
    Runtime, SidecarMounts, UlidIdGen,
};
use worker::Env;

use crate::config::EnvConfig;
use crate::ports::{
    D1Database, FetchClient, KvStorePort, R2Blob, RateLimitPort, ServiceDispatcher, WorkersClock,
};

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
static WARNED_BLOB: AtomicBool = AtomicBool::new(false);
static WARNED_RATE_LIMIT: AtomicBool = AtomicBool::new(false);
static WARNED_SIGNER: AtomicBool = AtomicBool::new(false);
static WARNED_SIDECAR: AtomicBool = AtomicBool::new(false);

/// The Workers runtime. Binding names are static; `.mailer()`/`.captcha()`
/// take adapter instances (`cratefield-adapter-resend`,
/// `cratefield-adapter-turnstile`).
pub struct Cloudflare {
    db_binding: Option<&'static str>,
    kv_binding: Option<&'static str>,
    blob_binding: Option<&'static str>,
    rate_limiter_binding: Option<&'static str>,
    mailer: Option<Arc<dyn Mailer>>,
    push: Option<Arc<dyn Push>>,
    payments: Option<Arc<dyn Payments>>,
    captcha: Option<Arc<dyn Captcha>>,
    /// Whether to assemble the `Push` port from the environment
    /// (issue #191). The `Env` only exists per event, so the assembly is
    /// deferred to `ports()` and memoised for the isolate.
    #[cfg(feature = "push")]
    push_from_env: bool,
    #[cfg(feature = "push")]
    assembled_push: std::sync::OnceLock<(Arc<dyn Push>, cratefield_push_wiring::PushWiring)>,
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
            blob_binding: None,
            rate_limiter_binding: None,
            mailer: None,
            push: None,
            payments: None,
            captcha: None,
            #[cfg(feature = "push")]
            push_from_env: false,
            #[cfg(feature = "push")]
            assembled_push: std::sync::OnceLock::new(),
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

    /// The R2 bucket binding backing the `Blob` port.
    #[must_use]
    pub fn blob(mut self, binding: &'static str) -> Self {
        self.blob_binding = Some(binding);
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

    /// The `Push` port. Like `mailer`, the adapter is built from the
    /// venture's secrets (`cratefield-adapter-apns` from an APNs `.p8`) and
    /// passed in, not resolved from a Worker binding.
    #[must_use]
    pub fn push(mut self, push: impl Push + 'static) -> Self {
        self.push = Some(Arc::new(push));
        self
    }

    #[must_use]
    pub fn push_arc(mut self, push: Arc<dyn Push>) -> Self {
        self.push = Some(push);
        self
    }

    /// Assembles the `Push` port from the venture's environment instead of
    /// taking an adapter (issue #191): one `RoutingPush` over whichever of
    /// APNs, FCM and Web Push the deployment configured, built once per
    /// isolate by `cratefield_push_wiring::build_push` — the same function
    /// `fz push` and `fz doctor` call, so the three cannot drift apart on a
    /// variable name.
    ///
    /// The port is then always provided, even with nothing configured: the
    /// router answers `NotConfigured` for every recipient, exactly as an
    /// unconfigured adapter does. `serve()` logs the resulting
    /// [`PushWiring`](cratefield_push_wiring::PushWiring) report once at cold
    /// start, and an explicit `.push(..)`/`.push_arc(..)` still wins.
    #[cfg(feature = "push")]
    #[must_use]
    pub fn push_from_env(mut self) -> Self {
        self.push_from_env = true;
        self
    }

    /// The environment-assembled `Push` port and its report, built once per
    /// isolate. `None` when the venture did not ask for it.
    #[cfg(feature = "push")]
    fn env_push(&self, env: &Env) -> Option<&(Arc<dyn Push>, cratefield_push_wiring::PushWiring)> {
        if !self.push_from_env {
            return None;
        }
        Some(self.assembled_push.get_or_init(|| {
            let clock: Arc<dyn Clock> = Arc::new(WorkersClock);
            let http: Arc<dyn cratefield_core::HttpClient> = Arc::new(BoundedHttpClient::new(
                Arc::new(FetchClient),
                Arc::clone(&clock),
            ));
            cratefield_push_wiring::build_push(&EnvConfig(env.clone()), &http, &clock)
        }))
    }

    /// Which push transports this deployment configured, once `ports()` has
    /// assembled them. `serve()` logs this at cold start; nothing else needs
    /// it. `None` when the venture did not call
    /// [`push_from_env`](Self::push_from_env).
    #[cfg(feature = "push")]
    #[must_use]
    pub fn push_wiring(&self, env: &Env) -> Option<&cratefield_push_wiring::PushWiring> {
        self.env_push(env).map(|(_, wiring)| wiring)
    }

    /// The `Payments` port. Like `mailer`, the adapter is built from the
    /// venture's secrets (`cratefield-adapter-stripe` from the Stripe keys)
    /// and passed in, not resolved from a Worker binding.
    #[must_use]
    pub fn payments(mut self, payments: impl Payments + 'static) -> Self {
        self.payments = Some(Arc::new(payments));
        self
    }

    #[must_use]
    pub fn payments_arc(mut self, payments: Arc<dyn Payments>) -> Self {
        self.payments = Some(payments);
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
        if let Some(name) = self.blob_binding {
            match env.bucket(name) {
                Ok(bucket) => ports.blob = Some(Arc::new(R2Blob(bucket))),
                Err(err) => warn_once(
                    &WARNED_BLOB,
                    &format!("R2 bucket binding {name:?} not available: {err}"),
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
                // Key logged email pseudonyms from the harness secret (#135).
                cratefield_core::set_log_pseudonym_key(config.harness_secret.as_bytes());
                ports.signer = Some(Arc::new(config.signer()));
            }
            Err(_) => warn_once(
                &WARNED_SIGNER,
                "HARNESS_SECRET missing or invalid: Signer port not provided",
            ),
        }

        // Sidecar bindings come from the mount table in config, not from the
        // composition (ADR 0009), so the same artifact serves ventures with
        // and without sidecars. A binding named by the table but absent from
        // this deployment is left unresolved: `has()` then reports false and
        // that one prefix answers 503, rather than the Worker failing.
        match SidecarMounts::from_config(&EnvConfig(env.clone())) {
            Ok(mounts) if !mounts.is_empty() => {
                let mut bindings = BTreeMap::new();
                for mount in mounts.iter() {
                    match env.service(&mount.binding) {
                        Ok(fetcher) => {
                            bindings.insert(mount.binding.clone(), fetcher);
                        }
                        Err(err) => warn_once(
                            &WARNED_SIDECAR,
                            &format!(
                                "service binding {:?} for sidecar {:?} not available: {err}",
                                mount.binding, mount.name
                            ),
                        ),
                    }
                }
                ports.dispatcher = Some(Arc::new(ServiceDispatcher::new(bindings)));
            }
            Ok(_) => {}
            Err(errors) => {
                for error in errors {
                    warn_once(&WARNED_SIDECAR, &error);
                }
            }
        }

        let clock: Arc<dyn Clock> = Arc::new(WorkersClock);
        ports.clock = Some(Arc::clone(&clock));
        ports.http = Some(Arc::new(BoundedHttpClient::new(
            Arc::new(FetchClient),
            clock,
        )));
        ports.id_gen = Some(Arc::new(UlidIdGen));
        ports.defer = Some(defer);
        ports.mailer.clone_from(&self.mailer);
        ports.push.clone_from(&self.push);
        ports.payments.clone_from(&self.payments);
        ports.captcha.clone_from(&self.captcha);

        // An explicit adapter wins; otherwise assemble one from the
        // environment when the venture asked for it (issue #191).
        #[cfg(feature = "push")]
        if ports.push.is_none()
            && let Some((push, _)) = self.env_push(env)
        {
            ports.push = Some(Arc::clone(push));
        }

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
        if self.blob_binding.is_some() {
            provided.push(Port::Blob);
        }
        if self.rate_limiter_binding.is_some() {
            provided.push(Port::RateLimiter);
        }
        if self.mailer.is_some() {
            provided.push(Port::Mailer);
        }
        // `push_from_env` provides the port whatever the environment holds:
        // with nothing configured the router answers `NotConfigured` for
        // every recipient, which is a provided port that sends nothing, not
        // an absent one (issue #191).
        #[cfg(feature = "push")]
        let push_provided = self.push.is_some() || self.push_from_env;
        #[cfg(not(feature = "push"))]
        let push_provided = self.push.is_some();
        if push_provided {
            provided.push(Port::Push);
        }
        if self.payments.is_some() {
            provided.push(Port::Payments);
        }
        if self.captcha.is_some() {
            provided.push(Port::Captcha);
        }
        provided
    }

    /// `Harness::build` gate (issue #133): a Turnstile adapter that is not
    /// hostname-bound, or left fail-open, cannot verify a production
    /// `HumanForm` route — the port is present but not usable, so report
    /// it as not effectively configured. Adapters that do not report
    /// (`binding() == None`) count as effective when present: presence is
    /// all the runtime can know about them.
    fn effectively_configured(&self, port: Port) -> bool {
        match port {
            // `is_none_or`, not `is_some_and`: the doc above and the
            // `Captcha::binding` contract both say a non-reporting adapter
            // counts as effective when present, and the code said the
            // opposite — so a venture with any Captcha adapter that does
            // not report could not boot in production (issue #143).
            Port::Captcha => self.captcha.as_ref().is_some_and(|captcha| {
                captcha
                    .binding()
                    .is_none_or(|binding| binding.hostname_bound && !binding.fail_open)
            }),
            _ => self.provides().contains(&port),
        }
    }
}
