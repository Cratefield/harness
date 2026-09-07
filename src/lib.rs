//! Cratefield's own early-access waitlist, standing on the Factory Zero
//! harness `waitlist` module. Cratefield dogfooding the thing it ships.
//!
//! The site's form posts to `POST /v1/waitlist` with `product: "cratefield"`,
//! and the entry lands in this worker's own D1 database. Retrieve the list
//! with `GET /v1/waitlist/admin/export.csv` under the admin token.
//!
//! **The mailer is a no-op until a sending domain is verified.** The
//! `waitlist` module records a join only after the mailer reports success, so
//! [`NoopMailer`] reports success without sending: the address is captured as
//! a pending entry, and the site shows an honest "you're on the list" message
//! that promises no confirmation email. Swap [`NoopMailer`] for the Resend
//! adapter once `cratefield.com` has a verified sending domain, and the
//! double opt-in comes to life with no other change.

#![forbid(unsafe_code)]

use std::sync::OnceLock;

use async_trait::async_trait;
use factory0_core::{Harness, MailError, Mailer, Message, SendOutcome, Venture};
use factory0_module_waitlist::Waitlist;
use factory0_runtime_cloudflare::{Cloudflare, serve, serve_scheduled};
use worker::{Context, Env, Request, Response, event};

/// Reports a send as done without sending. See the crate docs for why: the
/// module records the join only on a successful send, and Cratefield has no
/// verified sending domain yet, so this captures the address as a pending
/// entry rather than failing the join.
struct NoopMailer;

#[async_trait]
impl Mailer for NoopMailer {
    async fn send(&self, _message: Message) -> Result<SendOutcome, MailError> {
        Ok(SendOutcome::Sent {
            id: "noop".to_owned(),
        })
    }
}

static INSTANCE: OnceLock<(Harness, Cloudflare)> = OnceLock::new();

fn instance() -> &'static (Harness, Cloudflare) {
    INSTANCE.get_or_init(|| {
        let harness = Harness::builder()
            .venture(
                Venture::new("cratefield-waitlist", "cratefield.com")
                    .public_url("https://cratefield.com")
                    .cors_origins(["https://cratefield.com", "https://www.cratefield.com"]),
            )
            .templates(factory0_module_waitlist::default_templates())
            .module(Waitlist::new().products(["cratefield"]).referrals(false))
            .runtime(Cloudflare::new().db("DB").mailer(NoopMailer))
            .build()
            .expect("cratefield waitlist harness is valid");
        // The mailer must live on the runtime `serve` resolves ports from, so
        // it is set here too (a no-op both times); the builder copy above is
        // what satisfies the Waitlist module's required Mailer port at build.
        let runtime = Cloudflare::new().db("DB").mailer(NoopMailer);
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
    let (harness, runtime) = instance();
    serve(harness, runtime, req, env, ctx).await
}

#[event(scheduled)]
pub async fn scheduled(event: worker::ScheduledEvent, env: Env, ctx: worker::ScheduleContext) {
    let (harness, runtime) = instance();
    serve_scheduled(harness, runtime, event, env, ctx).await;
}
