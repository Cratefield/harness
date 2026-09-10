//! `cratefield-runtime-cloudflare` runs a Factory Zero [`Harness`] on
//! Cloudflare Workers (ADR 0001, 0002). It maps bindings to ports:
//! D1 -> `Database`, KV -> `KeyValue`, the Rate Limiting binding ->
//! `RateLimiter`, `HARNESS_SECRET` -> `Signer`, `Context::wait_until` ->
//! `Defer`, `worker::Fetch` -> `HttpClient`.
//!
//! A venture's Worker is three lines:
//!
//! ```ignore
//! #[event(fetch)]
//! pub async fn fetch(req: HttpRequest, env: Env, ctx: Context)
//!     -> Result<http::Response<axum::body::Body>> {
//!     let (harness, runtime) = INSTANCE.get_or_init(build);
//!     serve(harness, runtime, req, env, ctx).await
//! }
//! ```
//!
//! Every port adapter here holds JS handles that workers-rs already marks
//! `Send + Sync` (`unsafe impl` inside the `worker` crate, sound because a
//! Workers isolate is single-threaded — ADR 0002). This crate itself
//! contains no `unsafe`.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod config;
mod ports;
mod runtime;
mod tracing_setup;

pub use config::EnvConfig;
pub use ports::{
    ContextDefer, D1Database, FetchClient, KvStorePort, RateLimitPort, ScheduleDefer, WorkersClock,
    client_ip,
};
pub use runtime::Cloudflare;
pub use tracing_setup::install_tracing;

use cratefield_core::Harness;
use std::sync::Arc;
use tower::ServiceExt;
use worker::{Context, Env, Request as WorkerRequest, Response as WorkerResponse};

/// Runs every module's [`Module::validate_config`] against the live config
/// once per isolate and logs any failure to `console_error!`. `validate_config`
/// cannot run at build or in `fz doctor` (neither has the deploy config; it
/// lives on the `Env`), so cold start is the first place it can, and this
/// makes a misconfigured deployment loud in Workers Logs (issue #101). It only
/// logs — a bad module still degrades per request rather than failing the whole
/// Worker's boot; that harder behaviour is a decision for an ADR.
fn check_module_config_once(harness: &Harness, config: &dyn cratefield_core::Config) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static CHECKED: AtomicBool = AtomicBool::new(false);
    if CHECKED.swap(true, Ordering::Relaxed) {
        return;
    }
    for module in harness.modules() {
        if let Err(err) = module.validate_config(config) {
            worker::console_error!(
                "[config] module `{}` has invalid configuration: {err}",
                module.name()
            );
        }
    }
}

/// Logs the push wiring report once per isolate, next to
/// [`check_module_config_once`] (issue #191). Names and verdicts only —
/// [`PushWiring::summary`](cratefield_push_wiring::PushWiring::summary) never
/// carries a value, so no secret can reach Workers Logs through it.
///
/// A half-wired transport is `console_error!` in production and
/// `console_log!` below it: a venture that meant to enable FCM and mistyped
/// one variable must not boot into a state where every Android send silently
/// answers `NotConfigured`, while a developer wiring a transport one variable
/// at a time must still be able to boot. Like the module-config check this
/// only logs; refusing to serve is a decision for an ADR.
#[cfg(feature = "push")]
fn check_push_wiring_once(
    harness: &Harness,
    runtime: &Cloudflare,
    env: &Env,
    config: &dyn cratefield_core::Config,
) {
    use cratefield_push_wiring::WiringSeverity;
    use std::sync::atomic::{AtomicBool, Ordering};
    static CHECKED: AtomicBool = AtomicBool::new(false);
    if CHECKED.swap(true, Ordering::Relaxed) {
        return;
    }
    let Some(wiring) = runtime.push_wiring(env) else {
        return;
    };
    worker::console_log!("[push] {}", wiring.summary());
    let deployed = cratefield_core::deployed_env(harness.venture().env, config);
    match wiring.severity(deployed) {
        WiringSeverity::Ok => {}
        WiringSeverity::Warning => {
            for problem in wiring.problems() {
                worker::console_log!("[push] warning: {problem}");
            }
        }
        WiringSeverity::Error => {
            for problem in wiring.problems() {
                worker::console_error!("[push] {problem}");
            }
        }
    }
}

/// Serves one fetch event: resolves ports from the bindings, builds the
/// router, hands a fully-buffered request over, and converts the response.
///
/// Takes the native `worker::Request` (the fetch macro's `FromRequest`
/// accepts it): `Request::bytes()` is the only body read that reliably
/// resolves under workerd/miniflare — streaming a `worker::Body` through
/// the axum bridge or re-wrapping it into `web_sys::Request` hangs the
/// isolate (verified empirically). Bodies are bounded by the harness's
/// 64 KiB `/v1/*` limit either way.
///
/// # Errors
///
/// `worker::Error` on conversion/transport failures; problem+json
/// responses are ordinary 4xx/5xx Worker responses.
pub async fn serve(
    harness: &Harness,
    runtime: &Cloudflare,
    mut req: WorkerRequest,
    env: Env,
    ctx: Context,
) -> worker::Result<WorkerResponse> {
    install_tracing();
    let ports = runtime.ports(&env, Arc::new(ContextDefer(ctx)));
    check_module_config_once(harness, ports.config.as_ref());
    #[cfg(feature = "push")]
    check_push_wiring_once(harness, runtime, &env, ports.config.as_ref());
    let router = harness.router(ports);

    let bytes = req.bytes().await?;
    let method = http::Method::from_bytes(req.method().to_string().as_bytes())
        .map_err(|err| worker::Error::RustError(err.to_string()))?;
    let mut builder = http::Request::builder()
        .method(method)
        .uri(req.url()?.to_string());
    {
        let headers = req.headers();
        for (name, value) in headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
    }
    let buffered = builder
        .body(axum::body::Body::from(bytes))
        .map_err(|err| worker::Error::RustError(err.to_string()))?;

    let response = router
        .oneshot(buffered)
        .await
        .map_err(|err| worker::Error::RustError(err.to_string()))?;
    response_to_worker(response).await
}

async fn response_to_worker(
    response: http::Response<axum::body::Body>,
) -> worker::Result<WorkerResponse> {
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, MAX_RESPONSE_BUFFER)
        .await
        .map_err(|err| worker::Error::RustError(err.to_string()))?;
    let mut out =
        WorkerResponse::from_bytes(bytes.as_ref().to_vec())?.with_status(parts.status.as_u16());
    {
        let worker_headers = out.headers_mut();
        // Per name: drop what `from_bytes` pre-set (a default
        // `content-type: application/octet-stream`), then `append` every
        // value. `set` kept only the last value of a multi-valued header
        // (`Vary` from the CORS layer plus the handler's own, later
        // `Set-Cookie`; found by `GET /__surface` losing
        // `Vary: Authorization`, issue #70), and a bare `append` stacked
        // onto the pre-set default (found by `/ui` pages answering
        // `content-type: application/octet-stream, text/html`, issue #72).
        for name in parts.headers.keys() {
            let _ = worker_headers.delete(name.as_str());
            for value in parts.headers.get_all(name) {
                let _ = worker_headers.append(name.as_str(), value.to_str().unwrap_or_default());
            }
        }
    }
    Ok(out)
}

/// Responses are JSON (small); 1 MiB is a generous ceiling.
const MAX_RESPONSE_BUFFER: usize = 1024 * 1024;

/// Fans a scheduled event out to every module's `scheduled(ctx, cron)`.
/// Handler errors are logged and never fail the cron.
pub async fn serve_scheduled(
    harness: &Harness,
    runtime: &Cloudflare,
    event: worker::ScheduledEvent,
    env: Env,
    ctx: worker::ScheduleContext,
) {
    install_tracing();
    let cron = event.cron();
    let ports = runtime.ports(&env, Arc::new(ScheduleDefer(ctx)));
    check_module_config_once(harness, ports.config.as_ref());
    #[cfg(feature = "push")]
    check_push_wiring_once(harness, runtime, &env, ports.config.as_ref());
    for module in harness.modules() {
        let module_ctx = harness.module_context(module.as_ref(), &ports);
        if let Err(err) = module.scheduled(&module_ctx, &cron).await {
            tracing::error!(
                module = module.name(),
                cron = %cron,
                error = %err,
                "scheduled module work failed",
            );
        }
    }
}
