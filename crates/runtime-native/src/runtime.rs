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
    Auth, Blob, BoundedHttpClient, Captcha, Classifier, Clock, Database, HarnessConfig, KeyValue,
    Mailer, Payments, Port, Ports, Push, RateLimiter, Realtime, Runtime, TextModel, Tracker,
    UlidIdGen,
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
    tracker: Option<Arc<dyn Tracker>>,
    realtime: Option<Arc<dyn Realtime>>,
    /// The `TextModel` port (issue #429): like `mailer`, the adapter is
    /// built from the venture's vendor keys and passed in — there is no
    /// vendor-neutral binding to sniff out of the environment.
    text_model: Option<Arc<dyn TextModel>>,
    /// The `Classifier` port (issue #456), the sibling of `text_model`:
    /// the adapter is passed in the same way. An adapter that reaches a
    /// Workers AI binding still arrives here as an instance, so the two
    /// runtimes wire this port identically.
    classifier: Option<Arc<dyn Classifier>>,
    mailer: Option<Arc<dyn Mailer>>,
    captcha: Option<Arc<dyn Captcha>>,
    auth: Option<Arc<dyn Auth>>,
    /// Whether to assemble the `Auth` port from the environment.
    auth_from_env: bool,
    /// Whether to assemble the `Push` port from `std::env` (issue #191).
    /// Built lazily in `ports()` and memoised for the process, so a venture
    /// may call `push_from_env()` before a tokio runtime exists.
    #[cfg(feature = "push")]
    push_from_env: bool,
    #[cfg(feature = "push")]
    assembled_push: Arc<std::sync::OnceLock<(Arc<dyn Push>, cratefield_push_wiring::PushWiring)>>,
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

    /// Assembles the `Push` port from the process environment instead of
    /// taking an adapter (issue #191): one `RoutingPush` over whichever of
    /// APNs, FCM and Web Push the deployment configured, built by the same
    /// `cratefield_push_wiring::build_push` the Workers runtime, `fz push`
    /// and `fz doctor` call, so the four cannot drift apart on a variable
    /// name.
    ///
    /// The port is then always provided, even with nothing configured: the
    /// router answers `NotConfigured` for every recipient, exactly as an
    /// unconfigured adapter does. `serve_on` logs the resulting
    /// [`PushWiring`](cratefield_push_wiring::PushWiring) report once at cold
    /// start, and an explicit `.push_arc(..)` still wins.
    ///
    /// # This is a declaration, and `fz doctor` is what checks it
    ///
    /// Declaring the port rather than gating it on what `std::env` holds at
    /// build time is deliberate, and it keeps this runtime's answer the same
    /// as the Workers one's: there a Worker's `Env` does not exist when
    /// `Harness::build` runs, so a venture that built here and refused there
    /// (or the reverse) is the divergence issue #143 was about.
    ///
    /// `fz doctor` is the gate that used to be the build's. It runs where
    /// the deployment's environment is known, and refuses a production
    /// venture whose modules require push and whose environment routes no
    /// transport at all (issue #191).
    #[cfg(feature = "push")]
    #[must_use]
    pub fn push_from_env(mut self) -> Self {
        self.push_from_env = true;
        self
    }

    /// The environment-assembled `Push` port and its report, built once per
    /// process.
    ///
    /// `None` when the venture did not ask for it — **and** when it passed
    /// an explicit adapter, which wins: assembling a stack of adapters
    /// nothing will serve with costs a `.p8` parse, an RSA parse and a VAPID
    /// scalar, and then reports on transports the venture deliberately
    /// overrode.
    #[cfg(feature = "push")]
    fn env_push(&self) -> Option<&(Arc<dyn Push>, cratefield_push_wiring::PushWiring)> {
        if !self.push_from_env || self.push.is_some() {
            return None;
        }
        Some(self.assembled_push.get_or_init(|| {
            let clock: Arc<dyn Clock> = Arc::new(TokioClock);
            let http: Arc<dyn cratefield_core::HttpClient> = Arc::new(BoundedHttpClient::new(
                Arc::new(ReqwestClient::new()),
                Arc::clone(&clock),
            ));
            cratefield_push_wiring::build_push(&EnvConfig, &http, &clock)
        }))
    }

    /// Which push transports this deployment configured. `serve_on` logs
    /// this at cold start; nothing else needs it.
    ///
    /// `None` when the venture did not call
    /// [`push_from_env`](Self::push_from_env), or passed an explicit adapter
    /// that wins over it — there is nothing to report about an environment
    /// nothing reads.
    ///
    /// Call it *after* `ports()`, as `serve_on` does: `ports()` has then
    /// already assembled and memoised the adapters, and this is the getter
    /// it looks like.
    #[cfg(feature = "push")]
    #[must_use]
    pub fn push_wiring(&self) -> Option<&cratefield_push_wiring::PushWiring> {
        self.env_push().map(|(_, wiring)| wiring)
    }

    /// The `Payments` port: a Stripe adapter (`cratefield-adapter-stripe`) or a
    /// test fake, over the runtime's `HttpClient`.
    #[must_use]
    pub fn payments_arc(mut self, payments: Arc<dyn Payments>) -> Self {
        self.payments = Some(payments);
        self
    }

    /// The `Tracker` port: a [`cratefield_core::RoutingTracker`] over the
    /// per-tracker adapters the venture configured, or a test fake.
    ///
    /// Unlike every other adapter on this harness, the adapter holds no
    /// credential: which tracker to file into and under whose token are
    /// tenant data, supplied per call by the module that files — see
    /// [`cratefield_core::Tracker`] for why that differs from the
    /// Resend/Stripe shape.
    #[must_use]
    pub fn tracker_arc(mut self, tracker: Arc<dyn Tracker>) -> Self {
        self.tracker = Some(tracker);
        self
    }

    /// The `Realtime` port: the in-process room registry
    /// ([`crate::InProcessRealtime`]) built from the module's `RoomHandler`.
    #[must_use]
    pub fn realtime_arc(mut self, realtime: Arc<dyn Realtime>) -> Self {
        self.realtime = Some(realtime);
        self
    }

    /// The `TextModel` port (issue #429): an adapter over the venture's
    /// vendor of choice for each [`ModelTier`](cratefield_core::ModelTier),
    /// or one `RoutingTextModel` over both tiers. The same pattern as
    /// `mailer`.
    #[must_use]
    pub fn text_model(mut self, text_model: impl TextModel + 'static) -> Self {
        self.text_model = Some(Arc::new(text_model));
        self
    }

    /// `text_model` for an already-shared adapter.
    #[must_use]
    pub fn text_model_arc(mut self, text_model: Arc<dyn TextModel>) -> Self {
        self.text_model = Some(text_model);
        self
    }

    /// The `Classifier` port (issue #456): a typed, calibrated decision —
    /// "which of these is it, and how sure are you" — from a purpose-built
    /// classifier, a Workers AI binding (on the Workers twin) or an LLM
    /// behind the `TextModel` port. The same pattern as `text_model`.
    #[must_use]
    pub fn classifier(mut self, classifier: impl Classifier + 'static) -> Self {
        self.classifier = Some(Arc::new(classifier));
        self
    }

    /// `classifier` for an already-shared adapter.
    #[must_use]
    pub fn classifier_arc(mut self, classifier: Arc<dyn Classifier>) -> Self {
        self.classifier = Some(classifier);
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

    /// Wires who a request's credentials speak for (issue #153).
    ///
    /// Without one the deployment cannot identify a caller, and a module
    /// that declares [`Port::Auth`] is refused composition rather than
    /// mounted and left guessing.
    #[must_use]
    pub fn auth(mut self, auth: impl Auth + 'static) -> Self {
        self.auth = Some(Arc::new(auth));
        self
    }

    #[must_use]
    pub fn auth_arc(mut self, auth: Arc<dyn Auth>) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Assembles the `Auth` port from `AUTH_ISSUER` and `AUTH_CLIENT_ID`.
    ///
    /// The port is provided either way, matching the Cloudflare runtime:
    /// a venture generated by `fz build` wires this whenever one of its
    /// tables is not `public-read`, and the two runtimes answering
    /// differently for the same venture would be a difference between
    /// two deployments of one manifest.
    #[must_use]
    pub fn auth_from_env(mut self) -> Self {
        self.auth_from_env = true;
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
        ports.tracker.clone_from(&self.tracker);
        ports.realtime.clone_from(&self.realtime);
        ports.text_model.clone_from(&self.text_model);
        ports.classifier.clone_from(&self.classifier);
        ports.mailer.clone_from(&self.mailer);
        ports.captcha.clone_from(&self.captcha);
        ports.auth.clone_from(&self.auth);

        // An explicit adapter wins; otherwise assemble one from the
        // environment when the venture asked for it (issue #191).
        #[cfg(feature = "push")]
        if ports.push.is_none()
            && let Some((push, _)) = self.env_push()
        {
            ports.push = Some(Arc::clone(push));
        }

        match HarnessConfig::from_config(&*config) {
            Ok(parsed) => {
                // Pseudonymise logged emails with a key derived from the
                // harness secret, not a bare (reversible) hash — issue #135.
                cratefield_core::set_log_pseudonym_key(parsed.harness_secret.as_bytes());
                ports.signer = Some(Arc::new(parsed.signer()));
            }
            Err(err) => warn_once(&WARNED_SIGNER, &format!("Signer port not provided: {err}")),
        }

        let clock: Arc<dyn Clock> = Arc::new(TokioClock);
        ports.clock = Some(Arc::clone(&clock));
        let http: Arc<dyn cratefield_core::HttpClient> = Arc::new(BoundedHttpClient::new(
            Arc::new(ReqwestClient::new()),
            Arc::clone(&clock),
        ));
        ports.http = Some(Arc::clone(&http));
        // After the clock and the HTTP client, which the verifier needs
        // to fetch the issuer's key set.
        if ports.auth.is_none() && self.auth_from_env {
            ports.auth = Some(cratefield_auth_client::from_config(
                ports.config.as_ref(),
                http,
                clock,
            ));
        }
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
        // Provided whatever the environment holds — see `auth_from_env`.
        if self.auth.is_some() || self.auth_from_env {
            provided.push(Port::Auth);
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
        // `push_from_env` provides the port whatever the environment holds:
        // with nothing configured the router answers `NotConfigured` for
        // every recipient, which is a provided port that sends nothing, not
        // an absent one (issue #191).
        //
        // `std::env` is readable here, unlike on Workers — and consulting it
        // is still the wrong move: `provides()` would then answer one thing
        // in CI and another on the box, and a venture would build here and
        // refuse to build on its Workers twin, which is the divergence
        // issue #143 was about. `fz doctor` carries the refusal instead, on
        // both runtimes, where the deployment's environment is known.
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
        if self.tracker.is_some() {
            provided.push(Port::Tracker);
        }
        if self.realtime.is_some() {
            provided.push(Port::Realtime);
        }
        if self.text_model.is_some() {
            provided.push(Port::TextModel);
        }
        if self.classifier.is_some() {
            provided.push(Port::Classifier);
        }
        if self.mailer.is_some() {
            provided.push(Port::Mailer);
        }
        if self.captcha.is_some() {
            provided.push(Port::Captcha);
        }
        provided
    }

    /// The same production gate the Cloudflare runtime applies
    /// (issue #133), which this runtime never did (issue #143): a
    /// Turnstile adapter that is not hostname-bound, or left fail-open,
    /// cannot protect a production `HumanForm` route, so the port is
    /// present but not usable. Without this a self-hosted venture booted
    /// past a check its Workers twin refuses. Adapters that do not report
    /// (`binding() == None`) count as effective when present: presence is
    /// all the runtime can know about them.
    fn effectively_configured(&self, port: Port) -> bool {
        match port {
            Port::Captcha => self.captcha.as_ref().is_some_and(|captcha| {
                captcha
                    .binding()
                    .is_none_or(|binding| binding.hostname_bound && !binding.fail_open)
            }),
            _ => self.provides().contains(&port),
        }
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
    snapshot.tracker.clone_from(&ports.tracker);
    snapshot.realtime.clone_from(&ports.realtime);
    snapshot.text_model.clone_from(&ports.text_model);
    snapshot.classifier.clone_from(&ports.classifier);
    snapshot.http.clone_from(&ports.http);
    snapshot.clock.clone_from(&ports.clock);
    snapshot.id_gen.clone_from(&ports.id_gen);
    snapshot.defer.clone_from(&ports.defer);
    snapshot
}
