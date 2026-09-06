//! The ADR 0007 regression test: two requests handled concurrently by the
//! same router, each parked on a channel inside its handler, resumed in
//! the order B then A. Each must log and return its own request id.
//!
//! The discarded TypeScript v1 swapped request ids between concurrent
//! requests because "the current request" lived in shared mutable state.
//! Rust reproduces the bug only if someone reintroduces ambient state
//! (`thread_local!`, a `static RefCell`, a swapped extension); this test
//! fails the moment the scope leaks between requests.

// Test-fixture synchronization (handing a one-shot receiver to the parked
// handler) is not request state; allowed per the clippy.toml policy.
#![allow(clippy::disallowed_types)]

mod common;

use std::sync::Arc;

use axum::http::{Method, StatusCode, header};
use common::*;
use factory0_core::Harness;
use futures_channel::oneshot;
use tower::ServiceExt;

fn parked_harness(park: SharedParkGate) -> factory0_core::Harness {
    Harness::builder()
        .venture(
            factory0_core::Venture::new("test-venture", "test.example")
                .cors_origins(["https://test.example"]),
        )
        .module(SampleModule::parking(park))
        .runtime(FakeRuntime(all_ports()))
        .build()
        .expect("parked harness builds")
}

#[test]
fn concurrent_requests_keep_their_own_scope() {
    let (gate_a_tx, gate_a_rx) = oneshot::channel::<&'static str>();
    let (gate_b_tx, gate_b_rx) = oneshot::channel::<&'static str>();

    let park_a: SharedParkGate = Arc::new(std::sync::Mutex::new(Some(gate_a_rx)));
    let park_b: SharedParkGate = Arc::new(std::sync::Mutex::new(Some(gate_b_rx)));

    let harness_a = parked_harness(park_a);
    let harness_b = parked_harness(park_b);

    let router_a = harness_a.router(factory0_core::Ports::empty());
    let router_b = harness_b.router(factory0_core::Ports::empty());

    let id_a = "request-AAAAAAAA";
    let id_b = "request-BBBBBBBB";

    let request_a = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/v1/sample/park")
        .header("x-request-id", id_a)
        .body(axum::body::Body::empty())
        .expect("request a builds");
    let request_b = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/v1/sample/park")
        .header("x-request-id", id_b)
        .body(axum::body::Body::empty())
        .expect("request b builds");

    let future_a = router_a.oneshot(request_a);
    let future_b = router_b.oneshot(request_b);

    let thread_a =
        std::thread::spawn(move || pollster::block_on(future_a).expect("router answers"));
    let thread_b =
        std::thread::spawn(move || pollster::block_on(future_b).expect("router answers"));

    // Resume in the order B then A.
    gate_b_tx.send("b-first").expect("gate b open");
    gate_a_tx.send("a-second").expect("gate a open");

    let response_a = thread_a.join().expect("request a completes");
    let response_b = thread_b.join().expect("request b completes");

    assert_eq!(response_a.status(), StatusCode::OK);
    assert_eq!(response_b.status(), StatusCode::OK);

    assert_eq!(response_a.headers().get("x-request-id").unwrap(), id_a);
    assert_eq!(response_b.headers().get("x-request-id").unwrap(), id_b);

    let body_a = pollster::block_on(body_json(response_a));
    let body_b = pollster::block_on(body_json(response_b));
    assert_eq!(body_a["request_id"], id_a);
    assert_eq!(body_b["request_id"], id_b);
    assert_eq!(body_a["gate"], "a-second");
    assert_eq!(body_b["gate"], "b-first");
}

/// Same regression, but both requests through ONE router instance (the
/// middleware and extensions are shared; the scopes must not be).
#[test]
fn concurrent_requests_through_one_router_keep_their_own_scope() {
    let (gate_a_tx, gate_a_rx) = oneshot::channel::<&'static str>();
    let (gate_b_tx, gate_b_rx) = oneshot::channel::<&'static str>();

    let park_a: SharedParkGate = Arc::new(std::sync::Mutex::new(Some(gate_a_rx)));
    let park_b: SharedParkGate = Arc::new(std::sync::Mutex::new(Some(gate_b_rx)));

    // A module that parks on either channel depending on the query param.
    let module = EitherParkModule {
        a: park_a,
        b: park_b,
    };
    let harness = Harness::builder()
        .venture(
            factory0_core::Venture::new("test-venture", "test.example")
                .cors_origins(["https://test.example"]),
        )
        .module(module)
        .runtime(FakeRuntime(all_ports()))
        .build()
        .expect("harness builds");

    let router = harness.router(factory0_core::Ports::empty());
    let router_a = router.clone();
    let router_b = router;

    let request_a = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/v1/sample/park?ch=a")
        .header("x-request-id", "request-AAAAAAAA")
        .body(axum::body::Body::empty())
        .expect("request a builds");
    let request_b = axum::http::Request::builder()
        .method(Method::GET)
        .uri("/v1/sample/park?ch=b")
        .header("x-request-id", "request-BBBBBBBB")
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::empty())
        .expect("request b builds");

    let thread_a = std::thread::spawn(move || {
        pollster::block_on(router_a.oneshot(request_a)).expect("router answers")
    });
    let thread_b = std::thread::spawn(move || {
        pollster::block_on(router_b.oneshot(request_b)).expect("router answers")
    });

    gate_b_tx.send("b-first").expect("gate b open");
    gate_a_tx.send("a-second").expect("gate a open");

    let response_a = thread_a.join().expect("a completes");
    let response_b = thread_b.join().expect("b completes");

    assert_eq!(
        response_a.headers().get("x-request-id").unwrap(),
        "request-AAAAAAAA"
    );
    assert_eq!(
        response_b.headers().get("x-request-id").unwrap(),
        "request-BBBBBBBB"
    );

    // The header alone is not the proof: the discarded TypeScript harness
    // set the header correctly and still handed request A request B's scope
    // inside the handler. Assert what each handler actually observed.
    let body_a = pollster::block_on(body_json(response_a));
    let body_b = pollster::block_on(body_json(response_b));
    assert_eq!(body_a["request_id"], "request-AAAAAAAA");
    assert_eq!(body_b["request_id"], "request-BBBBBBBB");
    assert_eq!(body_a["gate"], "a-second");
    assert_eq!(body_b["gate"], "b-first");
}

struct EitherParkModule {
    a: SharedParkGate,
    b: SharedParkGate,
}

impl factory0_core::Module for EitherParkModule {
    fn name(&self) -> &'static str {
        "sample"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [factory0_core::Port] {
        &[]
    }

    fn migrations(&self) -> factory0_core::Migrations {
        factory0_core::Migrations::default()
    }

    fn validate_config(
        &self,
        _cfg: &dyn factory0_core::Config,
    ) -> Result<(), factory0_core::ConfigError> {
        Ok(())
    }

    fn router(&self, _ctx: factory0_core::ModuleContext) -> axum::Router {
        let a = Arc::clone(&self.a);
        let b = Arc::clone(&self.b);
        axum::Router::new().route(
            "/park",
            axum::routing::get(
                move |scope: factory0_core::Scope,
                      axum::extract::RawQuery(query): axum::extract::RawQuery| async move {
                    let park = match query.as_deref() {
                        Some("ch=a") => &a,
                        Some("ch=b") => &b,
                        _ => panic!("test must send ch=a or ch=b"),
                    };
                    let receiver = park
                        .lock()
                        .expect("park lock uncontended")
                        .take()
                        .expect("park gate used once");
                    let gate: &'static str = receiver.await.expect("gate open");
                    factory0_core::Json(serde_json::json!({
                        "gate": gate,
                        "request_id": scope.request_id,
                    }))
                },
            ),
        )
    }
}
