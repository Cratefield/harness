//! The smallest complete Factory Zero venture: the `cratefield` facade
//! with the `cloudflare` feature, and one sample module that writes and
//! reads a row through sea-query and D1 (issue #5 acceptance).
//!
//! It depends on one crate rather than six, which is the point of the
//! facade — and building this canary through it is how CI knows the
//! facade works on Workers.
//!
//! CI boots this under `wrangler dev --local` and curls `/__health`,
//! `/__ready` and the sample module's round-trip.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

// `pub` + the `rlib` crate type in `Cargo.toml` so the native example
// (`examples/venture-native`) reuses this exact module — one source of
// truth for the wasm and native canaries.
pub mod sample;

use cratefield::Harness;
use cratefield::cloudflare::{Cloudflare, serve, serve_scheduled};
use cratefield::email_signup::EmailSignup;
use cratefield::waitlist::Waitlist;
use std::sync::OnceLock;
use worker::{Context, Env, Request, Response, event};

static INSTANCE: OnceLock<(Harness, Cloudflare)> = OnceLock::new();

fn instance() -> &'static (Harness, Cloudflare) {
    INSTANCE.get_or_init(|| {
        let runtime = Cloudflare::new().db("DB");
        let mut templates = cratefield::email_signup::default_templates();
        templates.extend(cratefield::waitlist::default_templates());
        let harness = Harness::builder()
            .venture(
                cratefield::Venture::new("venture-example", "example.factory0.dev")
                    .public_url("https://example.factory0.dev")
                    // The second origin is the example static site served
                    // next to the API in the CI smoke (`site/`); a real
                    // venture lists only its own sites.
                    .cors_origins(["https://example.factory0.dev", "http://127.0.0.1:8788"]),
            )
            .module(sample::SampleRowModule)
            .module(EmailSignup::new())
            .module(
                Waitlist::new()
                    .products(["kontinuum", "undercover-rockstars"])
                    .confirm_ttl_days(7),
            )
            .templates(templates)
            // The UI renderer (ADR 0010): pages at /ui/<module>/<action>,
            // copy and theme from ui.json (validated by build()).
            .ui(cratefield::ui::Ui::from_spec(include_str!("../ui.json")).expect("ui.json parses"))
            .runtime(
                Cloudflare::new()
                    .db("DB")
                    // Both modules require the Mailer port. With no API key
                    // the adapter is NotConfigured: the port is provided and
                    // no mail is ever sent, which is what an example wants.
                    .mailer(cratefield::resend::Resend::new(
                        std::sync::Arc::new(cratefield::cloudflare::FetchClient),
                        None,
                        "example@factory0.dev",
                        None,
                    )),
            )
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
