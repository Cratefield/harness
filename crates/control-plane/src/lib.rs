//! The Cratefield control plane, as a harness venture.
//!
//! "The same Rust backend as we do now" (the ADR, `docs/ARCHITECTURE.md`)
//! is meant literally: the control plane is one more Worker + D1 built on
//! `Cratefield/harness`, and it dogfoods the same runtime, secrets layer
//! and UI surface it provisions for customers.
//!
//! This crate is the wasm entry point and the composition root. The
//! control-plane logic lives in its module crates (`accounts`, `catalog`,
//! `connections`, `provisioning`, `cms`), added as the epic's children
//! land; today it is the smallest thing that answers `/__health`.

#![forbid(unsafe_code)]

use std::sync::OnceLock;

use cratefield_core::{Harness, Venture};
use cratefield_runtime_cloudflare::{Cloudflare, serve, serve_scheduled};
use worker::{Context, Env, Request, Response, event};

static INSTANCE: OnceLock<(Harness, Cloudflare)> = OnceLock::new();

/// The composed control plane. One instance per isolate; the harness is
/// built once and reused (ADR 0007: no ambient request state, the scope
/// travels with the request).
fn instance() -> &'static (Harness, Cloudflare) {
    INSTANCE.get_or_init(|| {
        let harness = Harness::builder()
            .venture(
                Venture::new("cratefield-control-plane", "cratefield.com")
                    .public_url("https://app.cratefield.com")
                    .cors_origins(["https://app.cratefield.com"]),
            )
            // The console (#3): session guard, login skeleton, operator
            // allowlist. More modules land with the wizard (#8) and dashboard
            // (#11).
            // The shared page chrome (the stylesheet every screen links).
            // Mounted first so it is obvious that it is the frame, not a
            // feature.
            .module(cratefield_chrome::Chrome)
            .module(cratefield_console::Console)
            // The account dashboard (#11): ventures, health verdicts,
            // connections, archiving. Read-only except archiving; see
            // docs/DASHBOARD.md for the half that is not built.
            .module(cratefield_dashboard::Dashboard)
            .runtime(Cloudflare::new().db("DB"))
            .build()
            .expect("the control-plane harness is valid");
        (harness, Cloudflare::new().db("DB"))
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
