//! The deployable auth Worker (issue #41): composes every merged auth module
//! into one harness venture and exposes the Cloudflare `fetch`/`scheduled`
//! entry points. It is an ordinary harness venture — one Worker, one D1 —
//! the shape `fz build` generates; which login methods ship is simply which
//! modules are mounted here.
//!
//! **Composition over forking (issue #646).** [`AuthWorker`] is the whole
//! venture as a value: a [`config::AuthWorkerConfig`] plus any template
//! overrides. A wrapper crate builds `AuthWorker::builder()`, adds its own
//! templates or modules, and serves it through [`serve_request`]; it depends
//! on this crate with `default-features = false`, so the `entry` feature's
//! `fetch`/`scheduled` exports do not collide with its own.
//!
//! **One branded instance per app (issue #777).** Nothing in this crate
//! names an app: every instance supplies its own origin, id, browser
//! origins and branding through configuration (`instances/<app>/wrangler.toml`
//! in the repository), and a missing one is refused at boot. A test fails if
//! an app's name or domain is ever baked into `src/`.
//!
//! **Owner-only (needs-human), per instance:** `wrangler d1 create`, the
//! `HARNESS_SECRET`/signing material, the custom domain on the Cloudflare
//! account, and the first production tag. The runbook is
//! `docs/auth/MANAGED-INSTANCES.md`.

#![forbid(unsafe_code)]

pub mod config;

pub use config::{AuthWorkerConfig, MailerKind, validate_config};

use std::sync::{Arc, OnceLock};

use auth_core::AuthCore;
use auth_magic_link::MagicLink;
use auth_meta::Meta;
use auth_oidc::Oidc;
use auth_passkeys::Passkeys;
use auth_password::Password;
use cratefield_adapter_turnstile::Turnstile;
use cratefield_core::{Harness, HarnessBuilder, Mailer, Template, Venture};
use cratefield_runtime_cloudflare::{
    Cloudflare, EnvConfig, FetchClient, WorkersClock, serve, serve_scheduled,
};
use worker::{Context, Env, Request, Response};

/// The composed venture as a value: validated configuration plus the
/// template overrides a wrapper registers.
pub struct AuthWorker {
    config: AuthWorkerConfig,
    templates: Vec<(String, Box<dyn Template>)>,
}

impl AuthWorker {
    /// Wraps a validated configuration.
    #[must_use]
    pub fn new(config: AuthWorkerConfig) -> Self {
        Self {
            config,
            templates: Vec::new(),
        }
    }

    /// Registers template overrides. They are added **after** the module
    /// defaults in [`AuthWorker::builder`], so an override with the same id
    /// (a locale variant like `<id>@de` included) wins.
    #[must_use]
    pub fn templates(
        mut self,
        templates: impl IntoIterator<Item = (String, Box<dyn Template>)>,
    ) -> Self {
        self.templates.extend(templates);
        self
    }

    /// The configuration this venture was built from.
    #[must_use]
    pub fn config(&self) -> &AuthWorkerConfig {
        &self.config
    }

    /// The venture descriptor derived from the configuration.
    #[must_use]
    pub fn venture(&self) -> Venture {
        self.config.venture()
    }

    /// The composition: the venture, the magic-link and password default
    /// templates, any overrides, and the six auth modules — no runtime, so the caller (a
    /// wrapper venture, or this crate's boot path) chooses one.
    #[must_use]
    pub fn builder(self) -> HarnessBuilder {
        let mut builder = Harness::builder()
            .venture(self.config.venture())
            // Magic-link and password render their mail through the
            // shared registry.
            .templates(auth_magic_link::default_templates())
            .templates(auth_password::default_templates())
            .module(AuthCore::new())
            .module(Oidc::new())
            .module(Passkeys::new())
            .module(MagicLink::new())
            .module(Password::new())
            .module(Meta::new());
        for (id, template) in self.templates {
            builder = builder.template(id, template);
        }
        builder
    }
}

/// Turnstile when `TURNSTILE_SECRET` is present on the Worker `Env` (read
/// from the binding, since `std::env` is empty on Workers), else no `Captcha`
/// port at all.
///
/// The hostname comes from `AUTH_TURNSTILE_HOSTNAME`, defaulting to the host
/// of `AUTH_PUBLIC_URL`. Binding it keeps the adapter effectively configured
/// for the readiness check (issue #133); fail-open stays off, since the
/// captcha is the only backstop behind the limiter on some flows.
fn build_captcha(env: &Env, expected_hostname: &str) -> Option<Turnstile> {
    let secret = env
        .secret("TURNSTILE_SECRET")
        .ok()
        .map(|secret| secret.to_string())
        .filter(|secret| !secret.is_empty())?;
    Some(
        Turnstile::new(Arc::new(FetchClient), Arc::new(WorkersClock), secret)
            .expected_hostname(expected_hostname),
    )
}

/// The Cloudflare runtime, built twice over: once for `Harness::build`'s
/// composition check, once for `serve` to resolve per-request ports from.
/// Both carry the same bindings, so `provides()` tells the truth about what
/// requests will actually see.
fn runtime_for(env: &Env, mailer: Arc<dyn Mailer>, hostname: &str) -> Cloudflare {
    let mut runtime = Cloudflare::new()
        .db("DB")
        .mailer_arc(mailer)
        // Workers Rate Limiting (the `[[ratelimits]]` stanza in
        // wrangler.toml): readiness refuses a venture with public writes or
        // admin routes unless a limiter resolves (issue #437).
        .rate_limiter("RATE_LIMITER");
    if let Some(captcha) = build_captcha(env, hostname) {
        runtime = runtime.captcha(captcha);
    }
    runtime
}

type Instance = (Harness, Cloudflare);

/// The built isolate, or `None` when the deployment's configuration is
/// invalid. The `Option` is cached so a misconfigured deployment answers 500
/// from the first request on: it is built — and its reason logged — once
/// (ADR 0007: no ambient request state; the isolate is built once).
static INSTANCE: OnceLock<Option<Instance>> = OnceLock::new();

/// The isolate, built once from the deployment `Env` with the caller's
/// customiser applied to the [`AuthWorker`] before it is composed.
fn instance(
    env: &Env,
    customize: impl FnOnce(AuthWorker) -> AuthWorker,
) -> Option<&'static Instance> {
    INSTANCE.get_or_init(|| build(env, customize)).as_ref()
}

/// Reads the configuration, customises the venture, and composes the harness
/// and runtime. An invalid value is logged here — once, since the result is
/// cached — and yields `None` rather than a serving instance.
fn build(env: &Env, customize: impl FnOnce(AuthWorker) -> AuthWorker) -> Option<Instance> {
    let failed = |reason: String| {
        worker::console_error!("auth worker configuration invalid: {reason}");
        None
    };
    let parsed = match AuthWorkerConfig::from_config(&EnvConfig(env.clone())) {
        Ok(parsed) => parsed,
        Err(err) => return failed(err.to_string()),
    };
    let worker = customize(AuthWorker::new(parsed));
    let mailer = worker
        .config()
        .mailer(Arc::new(FetchClient), Arc::new(WorkersClock));
    let hostname = worker.config().turnstile_hostname.clone();
    let harness = match worker
        .builder()
        .runtime(runtime_for(env, Arc::clone(&mailer), &hostname))
        .build()
    {
        Ok(harness) => harness,
        Err(err) => return failed(err.to_string()),
    };
    // The runtime `serve` resolves ports from must carry the mailer too.
    Some((harness, runtime_for(env, mailer, &hostname)))
}

/// Serves one request for a venture built from the deployment `Env`.
///
/// A wrapper crate calls this from its own `#[event(fetch)]`, passing a
/// customiser that overrides templates or mounts extra modules. An invalid
/// configuration answers a generic 500 rather than panicking the isolate in a
/// loop; the reason was logged once, when the isolate was first built.
///
/// # Errors
///
/// `Err` when the router or the response conversion fails, or the
/// deployment's configuration is invalid.
pub async fn serve_request(
    req: Request,
    env: Env,
    ctx: Context,
    customize: impl FnOnce(AuthWorker) -> AuthWorker,
) -> worker::Result<Response> {
    let Some((harness, runtime)) = instance(&env, customize) else {
        return Err(worker::Error::RustError(
            "auth worker configuration invalid".to_owned(),
        ));
    };
    serve(harness, runtime, req, env, ctx).await
}

/// Serves one scheduled event for a venture built the same way
/// [`serve_request`] builds it. A cron has no response to fail.
pub async fn serve_scheduled_request(
    event: worker::ScheduledEvent,
    env: Env,
    ctx: worker::ScheduleContext,
    customize: impl FnOnce(AuthWorker) -> AuthWorker,
) {
    if let Some((harness, runtime)) = instance(&env, customize) {
        serve_scheduled(harness, runtime, event, env, ctx).await;
    }
}

/// Worker fetch entry point. Behind the default-on `entry` feature so a
/// wrapper crate depends on this one with `default-features = false` and
/// exports its own.
///
/// # Errors
///
/// Propagates `worker::Error` from the harness router or boot configuration.
#[cfg(feature = "entry")]
#[worker::event(fetch)]
pub async fn fetch(req: Request, env: Env, ctx: Context) -> worker::Result<Response> {
    serve_request(req, env, ctx, |worker| worker).await
}

/// Worker scheduled entry point. Behind the `entry` feature, like `fetch`.
#[cfg(feature = "entry")]
#[worker::event(scheduled)]
pub async fn scheduled(event: worker::ScheduledEvent, env: Env, ctx: worker::ScheduleContext) {
    serve_scheduled_request(event, env, ctx, |worker| worker).await;
}
