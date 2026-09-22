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

mod body_limit;
mod config;
mod ports;
mod runtime;
mod tracing_setup;

pub use config::EnvConfig;
pub use ports::{
    ContextDefer, D1Database, FetchClient, KvStorePort, RateLimitPort, RoomDriver, ScheduleDefer,
    WorkersClock, client_ip,
};
pub use runtime::Cloudflare;
pub use tracing_setup::install_tracing;

use crate::body_limit::{BodyPlan, Capped, body_plan, read_capped};
use axum::response::IntoResponse;
use cratefield_core::{Harness, Problem, RequestSummary};
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
/// only logs; refusing to serve is a decision for an ADR, and `fz doctor` is
/// what refuses a deploy.
///
/// Nothing is logged when the venture passed its own adapter: `push_wiring`
/// answers `None`, so no environment is read and no transport the venture
/// deliberately overrode is reported on. It runs after `ports()`, which has
/// already assembled and memoised the adapters, so this reads a report
/// rather than building one.
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
/// router, refuses an oversize body before it is resident, hands the
/// request over, and converts the response (issue #440).
///
/// Takes the native `worker::Request` (the fetch macro's `FromRequest`
/// accepts it): `Request::bytes()` is the only body read that reliably
/// resolves under workerd/miniflare — streaming a `worker::Body` through
/// the axum bridge or re-wrapping it into `web_sys::Request` hangs the
/// isolate (verified empirically). `bytes()` therefore remains the read for
/// every body that declares a `content-length` within the ceiling.
///
/// Before any byte is read, the request's per-module body ceiling is looked
/// up from the path ([`Harness::max_body_bytes`]) — the coarse value a
/// module may raise (LinkedIn's image upload), never lower. A declared
/// `content-length` above it is answered `413` (`request-too-large`)
/// without reading the body: an isolate has a fixed memory ceiling, and the
/// router's `DefaultBodyLimit` only fires once the body is already
/// resident, which is too late for a Worker that has already died. A body
/// with no usable `content-length` — chunked, streamed, or a header that
/// does not parse — is read through `Request::stream()` (a worker-native
/// stream, not the hanging axum bridge) and aborted the moment it passes
/// the ceiling, so nothing larger than the ceiling is ever held. A request
/// with no body at all — most GETs, HEAD, OPTIONS — reaches the router as
/// an empty buffer without any read: worker 0.8.5's `Request::stream()`
/// sets `body_used` before discovering there is no body, so the bodyless
/// case is detected through `inner()` first (issue #440). Inside the
/// router, `DefaultBodyLimit` stays the precise per-route enforcer.
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
    // `ports` moves into `router()` below, and the ceiling lookup reads the
    // same config the module contexts were built with — clone the `Arc`
    // out first.
    let config = Arc::clone(&ports.config);
    let router = harness.router(ports);
    let url = req.url()?;
    let limit = harness.max_body_bytes(url.path(), config.as_ref());

    // Copied out so the header borrow ends before the body is read mutably.
    // `worker::Headers::get` already yields `Option<String>`; a lookup
    // failure is treated as no declaration at all, which earns the capped
    // stream rather than trust.
    let declared = req.headers().get("content-length").ok().flatten();

    let bytes = match body_plan(declared.as_deref(), limit) {
        BodyPlan::Refuse => {
            // The tail left unread here trips `wrangler dev`'s drain
            // middleware — a dev-only artefact, recorded in this README's
            // wasm notes.
            return response_to_worker(Problem::request_too_large().into_response()).await;
        }
        BodyPlan::Buffer => req.bytes().await?,
        BodyPlan::Stream => {
            // A bodyless request (most GETs, HEAD, OPTIONS) must reach the
            // router as an empty body, and worker 0.8.5 makes that a
            // non-obvious requirement: `Request::stream()` sets
            // `body_used = true` *before* it looks for a body
            // (request.rs:199-204), so a null-body request answers
            // `Err("no body for request")` having already poisoned the
            // request — and `bytes()` afterwards can only answer
            // `Error::BodyUsed` (request.rs:158-173). The old
            // `Err(_) => req.bytes()` fallback therefore failed every
            // bodyless request out of `serve()` — `/__health`, `/__ready`,
            // `/ui/*`, `/.well-known/jwks.json` (issue #440). Probe
            // non-destructively through `inner()`, the raw
            // `web_sys::Request`, whose `body()` answers `None` exactly
            // where `stream()` would fail: with no body, hand the router
            // the empty buffer the Fetch spec gives a null body and never
            // touch `stream()` at all.
            match req.inner().body() {
                None => Vec::new(),
                Some(_) => match req.stream() {
                    Ok(stream) => match read_capped(stream, limit).await {
                        Ok(Capped::Within(bytes)) => bytes,
                        Ok(Capped::TooLarge) => {
                            return response_to_worker(
                                Problem::request_too_large().into_response(),
                            )
                            .await;
                        }
                        Err(err) => return Err(err),
                    },
                    // Belt and braces: past the probe, `stream()`'s only
                    // remaining failure mode is the `body_used` poison, and
                    // `bytes()` reads that same flag — so no read can
                    // succeed here. The arm answers empty, not silently:
                    // it is unreachable while the probe and `stream()` read
                    // the same `body()` getter (a body the probe saw cannot
                    // disappear), so a genuine transport error is not being
                    // swallowed, and a 500 on a body the getter had just
                    // reported would be strictly worse.
                    Err(_) => Vec::new(),
                },
            }
        }
    };

    let method = http::Method::from_bytes(req.method().to_string().as_bytes())
        .map_err(|err| worker::Error::RustError(err.to_string()))?;
    let mut builder = http::Request::builder().method(method).uri(url.to_string());
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
    if let Some(line) = response.extensions().get().and_then(summary_line) {
        // The request span is inert on Workers (no dispatcher, see
        // `tracing_setup`), so its fields reach Workers Logs as one JSON
        // line instead — indexed as fields, and matched by
        // `wrangler tail --search <request-id>`.
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("{line}");
        #[cfg(not(target_arch = "wasm32"))]
        tracing::info!("{line}");
    }
    response_to_worker(response).await
}

/// The Workers Logs line for one request: the core [`RequestSummary`]
/// serialized as JSON.
fn summary_line(summary: &RequestSummary) -> Option<String> {
    serde_json::to_string(summary).ok()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_line_is_one_json_object_carrying_the_request_id() {
        let summary = RequestSummary {
            request_id: "01J9ZQ4V6X8Y2K3M5N7P9R1T3W".to_owned(),
            method: "GET".to_owned(),
            route: "/v1/sample/hello".to_owned(),
            module: "sample".to_owned(),
            status: 200,
            ip_hash: "0123456789ab".to_owned(),
            ua_family: "mozilla".to_owned(),
        };
        let line = summary_line(&summary).expect("serializes");
        assert!(!line.contains('\n'), "one line: {line}");
        let parsed: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
        assert_eq!(parsed["request_id"], "01J9ZQ4V6X8Y2K3M5N7P9R1T3W");
        assert_eq!(parsed["route"], "/v1/sample/hello");
        assert_eq!(parsed["status"], 200);
    }
}
