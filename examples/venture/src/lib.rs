//! The smallest complete Factory Zero venture: `factory0-core` +
//! `factory0-runtime-cloudflare` with one sample module that writes and
//! reads a row through sea-query and D1 (issue #5 acceptance).
//!
//! CI boots this under `wrangler dev --local` and curls `/__health`,
//! `/__ready` and the sample module's round-trip.

#![forbid(unsafe_code)]

mod sample;

use factory0_core::Harness;
use factory0_module_email_signup::EmailSignup;
use factory0_module_waitlist::Waitlist;
use factory0_runtime_cloudflare::{Cloudflare, serve, serve_scheduled};
use std::sync::OnceLock;
use worker::{Context, Env, Request, Response, event};

static INSTANCE: OnceLock<(Harness, Cloudflare)> = OnceLock::new();

fn instance() -> &'static (Harness, Cloudflare) {
    INSTANCE.get_or_init(|| {
        let runtime = Cloudflare::new().db("DB");
        let mut templates = factory0_module_email_signup::default_templates();
        templates.extend(factory0_module_waitlist::default_templates());
        let harness = Harness::builder()
            .venture(
                factory0_core::Venture::new("venture-example", "example.factory0.dev")
                    .public_url("https://example.factory0.dev")
                    .cors_origins(["https://example.factory0.dev"]),
            )
            .module(sample::SampleRowModule)
            .module(EmailSignup::new())
            .module(
                Waitlist::new()
                    .products(["kontinuum", "undercover-rockstars"])
                    .confirm_ttl_days(7),
            )
            .templates(templates)
            .runtime(Cloudflare::new().db("DB"))
            .build()
            .expect("example venture harness is valid");
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
