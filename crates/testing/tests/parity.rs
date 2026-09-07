//! What the sidecar hop must preserve, and proof the parity axis fails
//! when it does not (issue #64, ADR 0009).
//!
//! The generic axis in [`cratefield_testing::conformance`] probes a real
//! module with requests the kit can build without knowing its routes.
//! These cases need shapes a real module will not produce on demand — a
//! `303`, a chosen problem body, an echo of what the far end received —
//! so they use a probe module built for it.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use cratefield_core::{
    Config, ConfigError, HARNESS_SIDECARS, MapConfig, Migrations, Module, ModuleContext, Port,
    Problem, Scope, X_REQUEST_ID,
};
use cratefield_testing::{FakeSidecar, Fault, TestHarness, shared_sidecar};
use tower::ServiceExt;

/// Answers one of every shape the hop could mangle.
struct Shapes;

impl Module for Shapes {
    fn name(&self) -> &'static str {
        "shapes"
    }
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    fn requires(&self) -> &'static [Port] {
        &[]
    }
    fn migrations(&self) -> Migrations {
        Migrations::default()
    }
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let state = Arc::new(ctx);
        axum::Router::new()
            .route("/redirect", get(redirect))
            .route("/problem", get(problem))
            .route("/echo", get(echo))
            .with_state(state)
    }
}

async fn redirect() -> Response {
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, "https://example.test/after")],
    )
        .into_response()
}

/// A problem whose `instance` is the request id: the field most likely
/// to differ across a hop, and the one an operator uses to find the log.
async fn problem(scope: Scope) -> Response {
    Problem::validation_failed("email: email must contain exactly one @")
        .instance(&scope.request_id)
        .into_response()
}

/// Echoes what the far end actually received, so header forwarding can
/// be asserted from the caller's side.
async fn echo(State(_state): State<Arc<ModuleContext>>, headers: HeaderMap) -> Response {
    let seen: Vec<String> = ["cf-connecting-ip", "authorization", X_REQUEST_ID]
        .iter()
        .map(|name| {
            format!(
                "{name}={}",
                headers
                    .get(*name)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("<absent>")
            )
        })
        .collect();
    seen.join("\n").into_response()
}

const REQUEST_ID: &str = "parity-case-0123456789";

/// The two mounts under comparison. `_remote` is the harness the fake
/// binding serves; it is held here so it outlives the host.
struct Mounts {
    direct: TestHarness,
    host: TestHarness,
    sidecar: Arc<FakeSidecar>,
    _remote: TestHarness,
}

fn mounts() -> Mounts {
    mounts_with(None)
}

/// An in-process harness and a host harness whose only `shapes` is a
/// sidecar, optionally with the hop deliberately broken.
fn mounts_with(fault: Option<Fault>) -> Mounts {
    let in_process = TestHarness::new(vec![Box::new(Shapes)]);
    let remote = TestHarness::new(vec![Box::new(Shapes)]);
    let fake = match fault {
        Some(fault) => FakeSidecar::faulty("SHAPES", remote.router.clone(), fault),
        None => FakeSidecar::new("SHAPES", remote.router.clone()),
    };
    let (sidecar, dispatcher) = shared_sidecar(fake);
    let host = TestHarness::with_builder(
        Vec::new(),
        |builder| builder,
        move |ports| {
            ports.config = Arc::new(MapConfig::from_pairs([
                ("HARNESS_SECRET", cratefield_testing::TEST_HARNESS_SECRET),
                (HARNESS_SIDECARS, r#"{"shapes":"SHAPES"}"#),
            ]));
            ports.dispatcher = Some(dispatcher);
        },
    );
    Mounts {
        direct: in_process,
        host,
        sidecar,
        _remote: remote,
    }
}

async fn send(
    router: &axum::Router,
    path: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, String) {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(X_REQUEST_ID, REQUEST_ID);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = router
        .clone()
        .oneshot(builder.body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
    (
        parts.status,
        parts.headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

#[pollster::test]
async fn a_redirect_is_not_remapped() {
    let m = mounts();
    let a = send(&m.direct.router, "/v1/shapes/redirect", &[]).await;
    let b = send(&m.host.router, "/v1/shapes/redirect", &[]).await;
    assert_eq!(a.0, StatusCode::SEE_OTHER);
    assert_eq!(b.0, StatusCode::SEE_OTHER, "the hop remapped a 303");
    assert_eq!(
        a.1.get(header::LOCATION),
        b.1.get(header::LOCATION),
        "the hop changed where the browser goes"
    );
    assert_eq!(m.sidecar.calls(), 1);
}

#[pollster::test]
async fn a_problem_body_survives_byte_for_byte() {
    let m = mounts();
    let a = send(&m.direct.router, "/v1/shapes/problem", &[]).await;
    let b = send(&m.host.router, "/v1/shapes/problem", &[]).await;
    assert_eq!(a.0, b.0);
    assert_eq!(a.2, b.2, "problem body differs across the hop");
    assert_eq!(
        a.1.get(header::CONTENT_TYPE).unwrap(),
        "application/problem+json"
    );
    assert_eq!(a.1.get(header::CONTENT_TYPE), b.1.get(header::CONTENT_TYPE));
    let parsed: serde_json::Value = serde_json::from_str(&b.2).unwrap();
    assert_eq!(
        parsed["instance"], REQUEST_ID,
        "instance must be the caller's request id, or an operator cannot find the log"
    );
    assert_eq!(
        parsed["type"], "https://factory0.ventures/problems/validation-failed",
        "the problem type is the stable contract"
    );
}

#[pollster::test]
async fn the_request_id_crosses_once_and_the_caller_is_forwarded() {
    let m = mounts();
    let headers = [("cf-connecting-ip", "203.0.113.5")];
    let a = send(&m.direct.router, "/v1/shapes/echo", &headers).await;
    let b = send(&m.host.router, "/v1/shapes/echo", &headers).await;
    // What the far end saw is identical: the caller's ip and id, not the
    // host's.
    assert_eq!(
        a.2, b.2,
        "the sidecar saw different headers than the module did"
    );
    assert!(b.2.contains("cf-connecting-ip=203.0.113.5"), "{}", b.2);
    assert!(
        b.2.contains(&format!("{X_REQUEST_ID}={REQUEST_ID}")),
        "{}",
        b.2
    );
    // And on the way back, exactly one id, the caller's.
    let ids: Vec<_> = b.1.get_all(X_REQUEST_ID).iter().collect();
    assert_eq!(ids.len(), 1, "one request id, not one per harness");
    assert_eq!(ids[0], REQUEST_ID);
}

#[pollster::test]
async fn an_unavailable_sidecar_is_a_503_problem_not_a_500() {
    for fault in [Fault::Unavailable, Fault::NotBound] {
        let m = mounts_with(Some(fault));
        let (status, headers, body) = send(&m.host.router, "/v1/shapes/echo", &[]).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{fault:?} must degrade the prefix, not crash it"
        );
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "application/problem+json"
        );
        assert!(
            body.contains("sidecar-unavailable"),
            "{fault:?} answered {body}"
        );
        // Everything else keeps serving.
        let (health, _, _) = send(&m.host.router, "/__health", &[]).await;
        assert_eq!(health, StatusCode::OK);
    }
}

/// The host owns the response's request id: a sidecar that drops it or
/// adds a second one cannot change what the caller sees. Both are
/// survivable rather than defects, which is why neither appears in the
/// teeth below. Asserted so the property is not lost by "simplifying"
/// the scope layer to forward whatever came back.
#[pollster::test]
async fn the_host_owns_the_response_request_id() {
    for fault in [Fault::DropRequestId, Fault::DuplicateRequestId] {
        let m = mounts_with(Some(fault));
        let (status, headers, _) = send(&m.host.router, "/v1/shapes/echo", &[]).await;
        assert_eq!(status, StatusCode::OK, "{fault:?}");
        let ids: Vec<_> = headers.get_all(X_REQUEST_ID).iter().collect();
        assert_eq!(ids.len(), 1, "{fault:?}: exactly one id reaches the caller");
        assert_eq!(ids[0], REQUEST_ID, "{fault:?}: and it is the caller's");
    }
}

/// The axis has teeth: break the hop and the comparisons fail, naming
/// what diverged. Without this the suite could be asserting nothing.
#[test]
fn a_broken_hop_fails_the_comparisons() {
    for (fault, expected) in [
        (Fault::RemapStatus, "status differs"),
        (Fault::MangleBody, "body differs"),
        // A request whose headers were dropped reaches the sidecar with
        // no caller id, so the sidecar mints its own and the problem's
        // `instance` diverges. That field is how a lost request id
        // shows up from the outside.
        (Fault::StripRequestHeaders, "body differs"),
    ] {
        let panicked = std::panic::catch_unwind(|| {
            let m = mounts_with(Some(fault));
            let a = pollster::block_on(send(&m.direct.router, "/v1/shapes/problem", &[]));
            let b = pollster::block_on(send(&m.host.router, "/v1/shapes/problem", &[]));
            assert_eq!(a.0, b.0, "status differs");
            assert_eq!(a.2, b.2, "body differs");
            assert_eq!(
                b.1.get_all(X_REQUEST_ID).iter().count(),
                1,
                "request id count differs"
            );
            let echo_a = pollster::block_on(send(&m.direct.router, "/v1/shapes/echo", &[]));
            let echo_b = pollster::block_on(send(&m.host.router, "/v1/shapes/echo", &[]));
            assert_eq!(echo_a.2, echo_b.2, "the sidecar saw different headers");
        });
        let err = panicked.expect_err(&format!("{fault:?} must fail the comparisons"));
        let message = err
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| err.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            .unwrap_or_default();
        assert!(
            message.contains(expected),
            "{fault:?} failed for the wrong reason: {message}"
        );
    }
}
