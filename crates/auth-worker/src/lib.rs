//! The deployable auth Worker (issue #41): composes every merged auth module
//! into one harness venture and exposes the Cloudflare `fetch`/`scheduled`
//! entry points. Before this, the repository was library crates with no
//! artifact to deploy, so `auth.factory0.ventures` did not exist and every
//! consumer (Yoginini, the Cratefield control plane) was blocked.
//!
//! It is an ordinary harness venture — one Worker, one D1 — the shape `fz
//! build` generates (`examples/tables-canary` is one, committed). Which
//! login methods ship is simply which modules are mounted here; the rest
//! mount later without redeploying consumers.
//!
//! **Owner-only (needs-human):** `wrangler d1 create` for each environment, the
//! `HARNESS_SECRET`/signing material, the `auth.factory0.ventures` route on the
//! Kontinuum Cloudflare account, and the first production tag (auth#41).

#![forbid(unsafe_code)]

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use cratefield_adapter_resend::Resend;
use cratefield_adapter_turnstile::Turnstile;
use cratefield_core::{Harness, MailError, Mailer, Message, SendOutcome, Venture};
use cratefield_runtime_cloudflare::{
    Cloudflare, FetchClient, WorkersClock, serve, serve_scheduled,
};
use worker::{Context, Env, Request, Response, event};

/// The verified sending address (a `send.` subdomain verified in Resend).
const MAIL_FROM: &str = "no-reply@auth.factory0.ventures";

/// Reports a send as done without sending — used until `RESEND_API_KEY` is set,
/// so magic-link/verification requests still create their rows rather than
/// failing the whole flow. Real delivery begins the moment the key is present.
struct NoopMailer;

#[async_trait]
impl Mailer for NoopMailer {
    async fn send(&self, _message: Message) -> Result<SendOutcome, MailError> {
        Ok(SendOutcome::Sent {
            id: "noop".to_owned(),
        })
    }
}

/// Resend when `RESEND_API_KEY` is present on the Worker `Env` (read from the
/// binding, since `std::env` is empty on Workers), else the capture-only no-op.
fn build_mailer(env: &Env) -> Arc<dyn Mailer> {
    let key = env
        .secret("RESEND_API_KEY")
        .ok()
        .map(|secret| secret.to_string())
        .filter(|key| !key.is_empty());
    match key {
        Some(key) => Arc::new(Resend::new(
            Arc::new(FetchClient),
            Arc::new(WorkersClock),
            Some(key),
            MAIL_FROM,
            None,
        )),
        None => Arc::new(NoopMailer),
    }
}

/// Turnstile when `TURNSTILE_SECRET` is present on the Worker `Env`, else
/// no `Captcha` port at all.
///
/// Read from the binding rather than `std::env`, which is empty on Workers.
///
/// The hostname is bound deliberately: an unbound adapter reports itself
/// not effectively configured, so `production_readiness` would still
/// refuse the composition (issue #133). `auth.factory0.ventures` is the
/// route this Worker is served on, and the login methods guard their
/// forms there — one expected hostname is right. Fail-open stays off:
/// the captcha is the only backstop behind the limiter on some flows,
/// and a down Turnstile must not become an open gate.
fn build_captcha(env: &Env) -> Option<Turnstile> {
    let secret = env
        .secret("TURNSTILE_SECRET")
        .ok()
        .map(|secret| secret.to_string())
        .filter(|secret| !secret.is_empty())?;
    Some(
        Turnstile::new(Arc::new(FetchClient), Arc::new(WorkersClock), secret)
            .expected_hostname("auth.factory0.ventures"),
    )
}

/// The Cloudflare runtime, built twice over: once for `Harness::build`'s
/// composition check, once for `serve` to resolve per-request ports from.
/// Both carry the same bindings, so `provides()` tells the truth about
/// what requests will actually see.
fn runtime_for(env: &Env, mailer: Arc<dyn Mailer>) -> Cloudflare {
    let mut runtime = Cloudflare::new()
        .db("DB")
        .mailer_arc(mailer)
        // Workers Rate Limiting (the `[[ratelimits]]` stanza in
        // wrangler.toml): the harness consults it for the admin floor and
        // every guarded public write, and readiness refuses a venture
        // with public writes or admin routes unless a limiter resolves
        // (issue #437).
        .rate_limiter("RATE_LIMITER");
    if let Some(captcha) = build_captcha(env) {
        runtime = runtime.captcha(captcha);
    }
    runtime
}

static INSTANCE: OnceLock<(Harness, Cloudflare)> = OnceLock::new();

/// The composed auth venture: `auth-core` plus every merged login method, over
/// the Cloudflare runtime. Built once per isolate (ADR 0007: no ambient
/// request state).
///
/// The isolate is built from the `Env` of the first request it serves —
/// the same trade the mailer already makes. Bindings are per-deployment
/// configuration in practice: a Worker's `Env` is identical on every
/// request of a deployment, so reading the secrets once is reading them
/// always. `cratefield-waitlist` composes the same way.
fn instance(env: &Env) -> &'static (Harness, Cloudflare) {
    INSTANCE.get_or_init(|| {
        let mailer = build_mailer(env);
        let harness = Harness::builder()
            .venture(
                Venture::new("factory0-auth", "auth.factory0.ventures")
                    .public_url("https://auth.factory0.ventures")
                    // Deliberately no `.env(..)`: one artifact serves both
                    // staging and production here, so the environment is the
                    // deployment's to declare through `ENV` (issue #143), and
                    // hardcoding production would hold the staging Worker to
                    // rules it does not run under. `ventures/cratefield-waitlist`
                    // is the opposite case and does set it.
                    // Consumers call the discovery/JWKS documents (public GETs);
                    // the browser-facing authorize flow is a top-level redirect,
                    // not CORS. These are the first-party app origins.
                    .cors_origins([
                        "https://app.cratefield.com",
                        "https://cratefield.com",
                        "https://yoginini.us",
                    ]),
            )
            // Magic-link renders its mail through the shared registry.
            .templates(factory0_auth_magic_link::default_templates())
            .module(factory0_auth_core::AuthCore::new())
            .module(factory0_auth_oidc::Oidc::new())
            .module(factory0_auth_passkeys::Passkeys::new())
            .module(factory0_auth_magic_link::MagicLink::new())
            .module(factory0_auth_password::Password::new())
            .module(factory0_auth_meta::Meta::new())
            .runtime(runtime_for(env, Arc::clone(&mailer)))
            .build()
            .expect("the auth venture is a valid harness");
        // The runtime `serve` resolves ports from must carry the mailer too.
        let runtime = runtime_for(env, mailer);
        (harness, runtime)
    })
}

#[event(fetch)]
/// Worker fetch entry point.
///
/// # Errors
///
/// Propagates `worker::Error` from the harness router.
pub async fn fetch(req: Request, env: Env, ctx: Context) -> worker::Result<Response> {
    let (harness, runtime) = instance(&env);
    serve(harness, runtime, req, env, ctx).await
}

#[event(scheduled)]
pub async fn scheduled(event: worker::ScheduledEvent, env: Env, ctx: worker::ScheduleContext) {
    let (harness, runtime) = instance(&env);
    serve_scheduled(harness, runtime, event, env, ctx).await;
}
