//! One module, served as its own Worker — the sidecar template (issue
//! #63).
//!
//! The split is the point:
//!
//! - `src/module.rs` is the module, and the part you edit. It knows
//!   nothing about Cloudflare.
//! - `src/lib.rs` (this file) and `src/harness.rs` are the thinnest
//!   Worker that serves it: the harness wiring, the fetch and cron entry
//!   points, nothing else.
//!
//! The Worker is reached by the host over a service binding and mounted
//! at `/v1/<module name>` (ADR 0009). It is **not** publicly routable:
//! `wrangler.toml` sets `workers_dev = false` and declares no routes,
//! and the comment there explains what would break if you lifted that.
//!
//! A sidecar carries its own copy of core and the runtime, so it has its
//! own secrets, its own cron and its own migration stream — all shared
//! with the host only through the database. The README walks each one;
//! getting any of them wrong is silent, which is why the template pins
//! them rather than leaving them to the reader.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

pub mod harness;
pub mod module;

use cratefield_runtime_cloudflare::{Cloudflare, serve, serve_scheduled};
use std::sync::OnceLock;
use worker::{Context, Env, Request, Response, event};

static INSTANCE: OnceLock<(cratefield_core::Harness, Cloudflare)> = OnceLock::new();

fn instance() -> &'static (cratefield_core::Harness, Cloudflare) {
    INSTANCE.get_or_init(|| {
        // One runtime, built once, and the same instance handed to
        // `Harness::build` and to `serve`. `build()` validated the module
        // against the ports of the instance it was given; serving with a
        // second, separately-built instance would mean that check pointed
        // at something other than what runs — a bug class the venture
        // example had already met once.
        let runtime = Cloudflare::new().db("DB");
        let harness = harness::build(&runtime);
        (harness, runtime)
    })
}

#[event(fetch)]
/// Worker fetch entry point: every request goes to the harness router,
/// which serves the module at `/v1/notes` and the probes (`/__health`,
/// `/__ready`, `/__surface`) the host's mount expects to find.
///
/// # Errors
///
/// Propagates `worker::Error` from the harness router.
pub async fn fetch(req: Request, env: Env, ctx: Context) -> worker::Result<Response> {
    let (harness, runtime) = instance();
    serve(harness, runtime, req, env, ctx).await
}

#[event(scheduled)]
/// The cron entry point. **The host's cron never reaches this Worker**:
/// `serve_scheduled` fans an event out over the modules of the Worker
/// that received it, and each Worker's triggers are its own Cloudflare
/// configuration. Without the `[triggers]` block in `wrangler.toml` —
/// and without this handler to receive what it fires — the module's
/// retention purge is dead code that still passes every test.
pub async fn scheduled(event: worker::ScheduledEvent, env: Env, ctx: worker::ScheduleContext) {
    let (harness, runtime) = instance();
    serve_scheduled(harness, runtime, event, env, ctx).await;
}
