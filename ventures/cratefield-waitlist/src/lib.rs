//! Cratefield's own early-access waitlist, standing on the Factory Zero
//! harness `waitlist` module. Cratefield dogfooding the thing it ships.
//!
//! The site's form posts to `POST /v1/waitlist` with `product: "cratefield"`,
//! and the entry lands in this worker's own D1 database. Retrieve the list
//! with `GET /v1/waitlist/admin/export.csv` under the admin token.
//!
//! **Mail.** The `waitlist` module records a join only after the mailer
//! reports success, and it sends its confirmation `from` `no-reply@send.
//! cratefield.com`. When the `RESEND_API_KEY` secret is set, this worker uses
//! the Resend adapter and double opt-in comes to life; until then it falls
//! back to `NoopMailer`, which reports success without sending so the
//! address is still captured as a pending entry. The key is read from the
//! Worker `Env` at init — not `std::env`, which is empty on Workers.

#![forbid(unsafe_code)]

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use cratefield_adapter_resend::Resend;
use cratefield_core::{Harness, MailError, Mailer, Message, SendOutcome, Venture};
use cratefield_module_waitlist::Waitlist;
use cratefield_runtime_cloudflare::{Cloudflare, FetchClient, serve, serve_scheduled};
use worker::{Context, Env, Request, Response, event};

/// The address the confirmation mail is sent from; the sending subdomain
/// verified in Resend. The module also defaults to this, so it is belt and
/// braces.
const MAIL_FROM: &str = "no-reply@send.cratefield.com";

/// Reports a send as done without sending: used until a Resend key is set, so
/// a join is still captured (as a pending entry) rather than failing.
struct NoopMailer;

#[async_trait]
impl Mailer for NoopMailer {
    async fn send(&self, _message: Message) -> Result<SendOutcome, MailError> {
        Ok(SendOutcome::Sent {
            id: "noop".to_owned(),
        })
    }
}

/// Resend when `RESEND_API_KEY` is present on the Worker `Env`, else the
/// capture-only no-op. Read from the binding, since `std::env` is empty on
/// Workers.
fn build_mailer(env: &Env) -> Arc<dyn Mailer> {
    let key = env
        .secret("RESEND_API_KEY")
        .ok()
        .map(|secret| secret.to_string())
        .filter(|key| !key.is_empty());
    match key {
        Some(key) => Arc::new(Resend::new(
            Arc::new(FetchClient),
            Some(key),
            MAIL_FROM,
            None,
        )),
        None => Arc::new(NoopMailer),
    }
}

static INSTANCE: OnceLock<(Harness, Cloudflare)> = OnceLock::new();

fn instance(env: &Env) -> &'static (Harness, Cloudflare) {
    INSTANCE.get_or_init(|| {
        let mailer = build_mailer(env);
        let harness = Harness::builder()
            .venture(
                Venture::new("cratefield-waitlist", "cratefield.com")
                    .public_url("https://cratefield.com")
                    // The environment is the deployment's to declare, through
                    // `ENV` in wrangler.toml, which this Worker has always set to
                    // production (issue #143). Deliberately not hardcoded here:
                    // `HarnessBuilder::build` takes no config, so it cannot see
                    // the operator's recorded acceptance and would refuse to build
                    // at all — a panic at boot instead of a serving Worker that
                    // says loudly what it is missing.
                    .cors_origins(["https://cratefield.com", "https://www.cratefield.com"]),
            )
            .templates(cratefield_module_waitlist::default_templates())
            .module(
                Waitlist::new()
                    .products(["cratefield"])
                    .referrals(false)
                    // No /ui is mounted, so send the post-confirm landing to
                    // the site rather than the module's default status page,
                    // which this venture does not serve.
                    .status_redirect("https://cratefield.com/"),
            )
            .runtime(Cloudflare::new().db("DB").mailer_arc(Arc::clone(&mailer)))
            .build()
            .expect("cratefield waitlist harness is valid");
        // The runtime `serve` resolves ports from must carry the mailer too.
        let runtime = Cloudflare::new().db("DB").mailer_arc(mailer);
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
