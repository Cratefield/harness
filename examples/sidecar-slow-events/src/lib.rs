//! The Worker half of the double (issue #258). The module (see
//! `module.rs`) is ordinary; what makes this sidecar "slow" lives here:
//!
//! `POST /__events` is deliberately delayed before the harness router
//! answers it. That delay is the stand-in for a slow subscriber: from the
//! host's side of the service binding, a subscriber that takes seconds to
//! accept the forward is indistinguishable from this, and it is exactly
//! what the host must survive inside its own `wait_until` without letting
//! it drag the emitting request's response. If the forward ever moved out
//! of `wait_until` into the request path, the CI check's timing assertion
//! fails here first — the delivery assertion alone would not notice.
//!
//! The delay is a constant, not configuration: a double whose slowness can
//! be tuned away by an environment variable is a double the check cannot
//! trust.

pub mod module;

use std::time::Duration;

use cratefield_runtime_cloudflare::{Cloudflare, serve};
use std::sync::OnceLock;
use worker::{Context, Delay, Env, Request, Response, console_log, event};

/// How long `/__events` stalls before answering. It must sit well beyond
/// the CI job's timing assertion (4s) and comfortably inside workerd's
/// `wait_until` budget, so the delayed forward still completes and the
/// delivery evidence appears.
const EVENTS_DELAY: Duration = Duration::from_secs(8);

static INSTANCE: OnceLock<(cratefield_core::Harness, Cloudflare)> = OnceLock::new();

fn instance() -> &'static (cratefield_core::Harness, Cloudflare) {
    INSTANCE.get_or_init(|| {
        // No bindings at all: the probe module declares no ports, and a
        // delivery check has nothing durable to keep.
        let runtime = Cloudflare::new();
        let harness = harness::build(&runtime);
        (harness, runtime)
    })
}

mod harness {
    use crate::module::Probe;
    use cratefield_core::{Harness, Venture};
    use cratefield_runtime_cloudflare::Cloudflare;

    /// The venture identity the host's contract checks read. These values
    /// match `examples/venture`'s harness for the same reason the template's
    /// must: a mismatch is never an error, only a silently different venture.
    pub fn build(runtime: &Cloudflare) -> Harness {
        Harness::builder()
            .venture(
                Venture::new("venture-example", "example.factory0.dev")
                    .public_url("https://example.factory0.dev")
                    .cors_origins(["https://example.factory0.dev", "http://127.0.0.1:8788"]),
            )
            .module(Probe::new())
            .runtime(runtime.clone())
            .build()
            .expect("sidecar slow-events harness is valid")
    }
}

#[event(fetch)]
/// Worker fetch entry point. Serves the module at `/v1/probe` plus the
/// `/__*` probes the host's mount expects, with one deliberate wrinkle:
/// the `/__events` route stalls for the constant delay in this module
/// before answering.
///
/// # Errors
///
/// Propagates `worker::Error` from the harness router.
pub async fn fetch(req: Request, env: Env, ctx: Context) -> worker::Result<Response> {
    // The delay goes *before* the router, so it sits in front of the
    // gateway check and the 202: the caller — the host's forward, inside
    // its `wait_until` — waits the full stretch either way. That is the
    // whole point. A receipt line here also gives the CI job a second,
    // human-readable trail in the sidecar's own log.
    if req.path() == "/__events" {
        console_log!("[sidecar-slow-events] event forward received; stalling {EVENTS_DELAY:?}");
        Delay::from(EVENTS_DELAY).await;
    }
    let (harness, runtime) = instance();
    serve(harness, runtime, req, env, ctx).await
}
