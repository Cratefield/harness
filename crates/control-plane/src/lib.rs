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
            //
            // No KMS is wired here on purpose: the Workers runtime has no
            // filesystem for `LocalFileKms` and no managed KMS adapter
            // exists yet (its own issue, deliberately not invented in the
            // pass that added the secrets screen). The dashboard carries
            // `None` and the secrets screen renders that state honestly
            // rather than failing — `Some(kms)` arrives with the adapter.
            .module(cratefield_dashboard::Dashboard::default())
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

#[cfg(test)]
mod tests {
    /// The secrets screen tells an operator the date of the next
    /// automatic key rotation. `serve_scheduled` is the only thing that
    /// runs that pass, and a cron trigger is the only thing that calls
    /// `serve_scheduled` on a Worker — so if this Worker's config loses
    /// its trigger, the screen keeps naming a date and nothing ever acts
    /// on it. A promise a deployment cannot keep is worse than a screen
    /// that admits it does nothing, so the trigger is pinned here rather
    /// than left to a reviewer to notice.
    #[test]
    fn the_worker_registers_the_cron_its_scheduled_work_depends_on() {
        let config = include_str!("../wrangler.toml");
        assert!(
            config.contains("[triggers]"),
            "the control plane declares scheduled work and must register a trigger for it"
        );
        let crons = config
            .split("crons = [")
            .nth(1)
            .and_then(|rest| rest.split(']').next())
            .expect("a triggers section names its cron expressions");
        assert!(
            crons.contains('*'),
            "a cron expression, not an empty list: {crons}"
        );
    }
}
