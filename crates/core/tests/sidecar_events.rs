//! Events crossing the sidecar boundary (issue #62, ADR 0017): the host
//! forwards every emission to `POST /__events` on each mounted sidecar,
//! inside the emitting request's `wait_until`; the sidecar answers `202`
//! immediately and runs its own handlers in its own `wait_until`. At-most-
//! once, no retry, failures logged and never surfaced to the caller.

// Test fixtures recording what crossed the boundary are not request state
// (ADR 0007); the scoped allow follows the workspace clippy.toml policy, as
// the fakes in `cratefield-testing` do.
#![allow(clippy::disallowed_types)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use bytes::Bytes;
use common::*;
use futures_channel::oneshot;
use futures_core::future::BoxFuture as CoreBoxFuture;
use cratefield_core::{
    AnyError, BoxFuture, Config, ConfigError, DispatchError, Dispatcher, EventBus, GATEWAY_PURPOSE,
    HARNESS_SIDECARS, HmacSigner, KeyRing, Kid, MapConfig, Module, ModuleContext, Payload, Ports,
    Runtime, SIDECAR_GATEWAY_SECRET, Scope, Signer, TokenPolicy, X_HARNESS_GATEWAY, X_REQUEST_ID,
    slash as _unused_marker_do_not_use,
};

const SECRET: &str = "sidecar-events-test-secret-0123456789abcdef";

// ------------------------------------------------------------------ fixtures

/// A defer that parks futures until the test releases them, so a test can
/// observe that a response returns *before* the deferred work runs — the
/// difference between "answered 202" and "ran the handler".
#[derive(Default)]
struct CollectDefer(std::sync::Mutex<Vec<CoreBoxFuture<'static, ()>>>);

impl cratefield_core::Defer for CollectDefer {
    fn wait_until(&self, fut: CoreBoxFuture<'static, ()>) {
        self.0.lock().expect("defer lock").push(fut);
    }
}

impl CollectDefer {
    fn len(&self) -> usize {
        self.0.lock().expect("defer lock").len()
    }

    fn run_all(&self) {
        for fut in self.0.lock().expect("defer lock").drain(..) {
            pollster::block_on(fut);
        }
    }
}

/// Answers `200` for everything except `POST /__events`, where the test
/// chooses the outcome; records every request it was given.
struct EventDispatcher {
    events_status: StatusCode,
    events_fails: bool,
    seen: std::sync::Mutex<Vec<http::Request<Bytes>>>,
}

impl EventDispatcher {
    fn answering(status: StatusCode) -> Self {
        Self {
            events_status: status,
            events_fails: false,
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn broken() -> Self {
        Self {
            events_status: StatusCode::OK,
            events_fails: true,
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn events_requests(&self) -> Vec<http::Request<Bytes>> {
        self.seen
            .lock()
            .expect("seen lock")
            .iter()
            .filter(|r| r.uri().path() == "/__events")
            .cloned()
            .collect()
    }
}

#[async_trait]
impl Dispatcher for EventDispatcher {
    fn has(&self, _binding: &str) -> bool {
        true
    }

    async fn dispatch(
        &self,
        _binding: &str,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, DispatchError> {
        let is_events = request.uri().path() == "/__events";
        self.seen.lock().expect("seen lock").push(request);
        if is_events && self.events_fails {
            return Err(DispatchError::Unavailable {
                binding: "ACME".to_owned(),
                reason: "sidecar unreachable".to_owned(),
            });
        }
        let status = if is_events {
            self.events_status
        } else {
            StatusCode::OK
        };
        Ok(http::Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Bytes::from_static(b"{}"))
            .expect("static response"))
    }
}

/// A module that emits `waitlist.confirmed` from `POST /emit` and answers
/// its own normal response regardless of what the bus did.
struct EmitRouteModule;

impl Module for EmitRouteModule {
    fn name(&self) -> &'static str {
        "waitlist"
    }
    fn version(&self) -> &'static str {
        "0.0.0"
    }
    fn requires(&self) -> &'static [cratefield_core::Port] {
        &[]
    }
    fn migrations(&self) -> cratefield_core::Migrations {
        cratefield_core::Migrations::default()
    }
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let events = ctx.events.clone();
        axum::Router::new().route(
            "/emit",
            axum::routing::post(move |scope: Scope, body: String| {
                let events = events.clone();
                async move {
                    let payload: serde_json::Value = serde_json::from_str(&body)
                        .unwrap_or(serde_json::json!({}));
                    events.emit_in(&scope, "waitlist.confirmed", payload);
                    axum::Json(serde_json::json!({ "ok": true }))
                }
            }),
        )
    }
}

/// A module whose subscriber parks on a channel, so a test can prove the
/// `202` beats the handler.
struct SlowSubscriberModule {
    gate: oneshot::Sender<()>,
    ran: Arc<AtomicBool>,
    payload: Arc<std::sync::Mutex<Option<serde_json::Value>>>,
}

impl Module for SlowSubscriberModule {
    fn name(&self) -> &'static str {
        "email-signup"
    }
    fn version(&self) -> &'static str {
        "0.0.0"
    }
    fn requires(&self) -> &'static [cratefield_core::Port] {
        &[]
    }
    fn migrations(&self) -> cratefield_core::Migrations {
        cratefield_core::Migrations::default()
    }
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        axum::Router::new()
    }
    fn events(
        &self,
    ) -> Vec<(cratefield_core::EventName, cratefield_core::EventHandler)> {
        let gate = self.gate.clone();
        let ran = Arc::clone(&self.ran);
        let payload = Arc::clone(&self.payload);
        vec![(
            "waitlist.confirmed".to_owned(),
            Arc::new(
                move |_scope: &Scope,
                      value: serde_json::Value|
                      -> BoxFuture<'static, Result<(), AnyError>> {
                    let mut gate = Some(gate.clone());
                    let ran = Arc::clone(&ran);
                    let payload = Arc::clone(&payload);
                    Box::pin(async move {
                        // The parked half lives in the test; awaiting it
                        // here is what a slow handler does.
                        if let Some(gate) = gate.take() {
                            let _ = gate.send(());
                        }
                        Ok(())
                        .map(|_: ()| {
                            payload.lock().expect("payload lock").replace(value);
                            ran.store(true, Ordering::SeqCst);
                        })
                    })
                },
            ),
        )]
    }
}

struct AllPorts;

impl Runtime for AllPorts {
    fn provides(&self) -> Vec<cratefield_core::Port> {
        cratefield_core::Port::ALL.to_vec()
    }
}

fn harness(modules: Vec<Arc<dyn Module>>, config: &[(&str, &str)]) -> (cratefield_core::Harness, Ports) {
    let mut builder = cratefield_core::Harness::builder()
        .venture(
            cratefield_core::Venture::new("test-venture", "test.example")
                .cors_origins(["https://test.example"]),
        )
        .runtime(AllPorts);
    for module in modules {
        builder = builder.module_arc(module);
    }
    (builder.build().expect("harness builds"), ports_with(config))
}

fn ports_with(config: &[(&str, &str)]) -> Ports {
    Ports::with_config(Arc::new(MapConfig::from_pairs(
        config.iter().map(|(k, v)| (*k, *v)),
    )))
}

/// The same construction `gateway_signer` uses, for minting the stamp a
/// test presents to `/__events` or asserts on a forwarded request.
fn test_signer() -> Arc<HmacSigner> {
    let mut ring = KeyRing::new();
    ring.rotate_signing(Kid::Cur, SECRET.as_bytes().to_vec())
        .expect("test secret is long enough");
    Arc::new(HmacSigner::from_ring(ring).with_policy(TokenPolicy::default()))
}

fn gateway_stamp() -> String {
    test_signer().sign(&Payload {
        purpose: GATEWAY_PURPOSE.to_owned(),
        subject: "email-signup".to_owned(),
        exp: None,
        kid: Kid::Cur,
    })
}

async fn post_json(router: &axum::Router, uri: &str, headers: &[(&str, &str)], body: &str) -> axum::response::Response {
    let mut builder = Request::builder().method(Method::POST).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_owned()))
        .expect("request builds");
    use tower::ServiceExt;
    router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers")
}

// -------------------------------------------------- the capturing subscriber

struct CapturingSubscriber {
    lines: std::sync::Mutex<Vec<String>>,
}

impl tracing::Subscriber for CapturingSubscriber {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _attributes: &tracing::span::Attributes<'_>) -> tracing::Id {
        tracing::Id::from_u64(1)
    }
    fn record(&self, _id: &tracing::Id, _values: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _from: &tracing::Id, _to: &tracing::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Line(std::sync::Mutex<Vec<String>>);
        impl tracing::field::Visit for Line {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0
                    .lock()
                    .expect("line lock")
                    .push(format!("{field}={value:?}"));
            }
        }
        let visitor = Line(std::sync::Mutex::new(Vec::new()));
        event.record(&mut visitor);
        self.lines
            .lock()
            .expect("log lock")
            .push(visitor.0.into_inner().expect("line lock").join(" "));
    }
    fn enter(&self, _id: &tracing::Id) {}
    fn exit(&self, _id: &tracing::Id) {}
}

/// Runs `f` under the capturing subscriber and returns the collected lines.
fn capture_logs<T>(f: impl FnOnce() -> T) -> Vec<String> {
    let subscriber = Arc::new(CapturingSubscriber {
        lines: std::sync::Mutex::new(Vec::new()),
    });
    let _guard = tracing::subscriber::with_default(
        tracing::subscriber::Interest::new;
        |_| (),
    );
    unreachable!()
}

// ------------------------------------------------------------------- tests
