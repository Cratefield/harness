//! Problem `type` URIs are named under the serving venture's own base
//! (issue #557): `<public_url>/problems/<slug>`, the venture's explicit
//! `problem_base` override when it set one, and `about:blank` when it has
//! no public URL — never another venture's domain.

mod common;

use axum::http::{Method, StatusCode, header};
use common::*;
use cratefield_core::{Harness, Ports, Problem, Venture};
use std::sync::Arc;

/// A harness whose venture publishes `https://api.example.test`.
fn api_venture() -> Venture {
    Venture::new("acme", "acme.test")
        .public_url("https://api.example.test")
        .cors_origins(["https://api.example.test"])
}

async fn ready_problem_type(venture: Venture) -> String {
    let harness = Harness::builder()
        .venture(venture)
        .module(SampleModule::default())
        .runtime(FakeRuntime(all_ports()))
        .build()
        .expect("harness builds");
    let router = harness.router(Ports::empty());
    let response = request(&router, Method::GET, "/__ready", &[], None).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = body_json(response).await;
    body["type"].as_str().expect("type is a string").to_owned()
}

/// (a) A venture with a public URL names its problems under it.
#[pollster::test]
async fn a_venture_with_a_public_url_names_problems_under_it() {
    assert_eq!(
        ready_problem_type(api_venture()).await,
        "https://api.example.test/problems/not-ready"
    );
}

/// (b) A venture with no public URL falls back to the RFC 9457 §4.2.1
/// default — never to some other venture's domain.
#[pollster::test]
async fn a_venture_without_a_public_url_answers_about_blank() {
    let venture = Venture::new("acme", "acme.test")
        .public_url("  ")
        .cors_origins(["https://acme.test"]);
    assert_eq!(ready_problem_type(venture).await, "about:blank");
}

/// (c) An explicit `problem_base` override wins over the public URL.
#[pollster::test]
async fn an_explicit_problem_base_overrides_the_public_url() {
    let venture = api_venture().problem_base("https://errors.acme.test/types/");
    assert_eq!(
        ready_problem_type(venture).await,
        "https://errors.acme.test/types/not-ready"
    );
}

/// (c) An override without a trailing slash is normalized to exactly one,
/// so the slug is appended rather than glued on.
#[test]
fn an_override_is_normalized_to_one_trailing_slash() {
    let v = api_venture().problem_base("https://errors.acme.test/types");
    assert_eq!(v.problem_type_base(), "https://errors.acme.test/types/");
    let v = v.problem_base("https://errors.acme.test/types/");
    assert_eq!(v.problem_type_base(), "https://errors.acme.test/types/");
    // `about:blank` itself is a complete URI, never a base to append to.
    let v = api_venture().problem_base("about:blank");
    assert_eq!(v.problem_type_base(), "about:blank");
}

/// (d) The acceptance: no problem body the harness serves names a
/// hard-coded venture. Driven from several of the paths that produce
/// problems — the fallback 404, a `Json` rejection with no module state,
/// the readiness probe, and the harness's own admin rate-limit floor —
/// every body is grepped for the old base.
#[pollster::test]
async fn no_problem_body_names_another_ventures_domain() {
    let harness = harness_with_sample();
    let mut ports = Ports::empty();
    ports.rate_limiter = Some(Arc::new(RecordingLimiter::new(LimiterVerdict::Deny)));
    let router = harness.router(ports);

    // The paths: an unknown route (fallback), a body that fails to
    // deserialize (extractor rejection), the readiness probe (503), and an
    // admin route through the harness limiter (429).
    let paths = [
        (Method::GET, "/v1/no-such-module/route", None),
        (
            Method::POST,
            "/v1/sample/echo",
            Some(br#"{"wrong": "field"}"#.to_vec()),
        ),
        (Method::GET, "/__ready", None),
        (Method::GET, "/v1/sample/admin/whoami", Some(b"{}".to_vec())),
    ];
    let mut bodies = Vec::new();
    for (method, path, body) in paths {
        let response = request(&router, method, path, &[], body).await;
        assert!(
            response.status().is_client_error() || response.status().is_server_error(),
            "{path}: {}",
            response.status()
        );
        bodies.push((path, body_string(response).await));
    }

    for (path, body) in &bodies {
        assert!(
            !body.contains("factory0.ventures"),
            "{path} names factory0.ventures: {body}"
        );
    }
    // The slugs themselves are unchanged under the venture's own base.
    let types: Vec<String> = bodies
        .iter()
        .filter_map(|(_, body)| serde_json::from_str::<serde_json::Value>(body).ok())
        .filter_map(|body| body["type"].as_str().map(str::to_owned))
        .collect();
    assert!(
        types.contains(&"https://test.example/problems/validation-failed".to_owned()),
        "{types:?}"
    );
    assert!(
        types.contains(&"https://test.example/problems/not-ready".to_owned()),
        "{types:?}"
    );
    assert!(
        types.contains(&"https://test.example/problems/rate-limited".to_owned()),
        "{types:?}"
    );
    // The 404 fallback has no problem body today (axum's default), which is
    // its own empty kind of neutral; the assertion above covers it.
}

/// The re-render keeps what the producing layer put on the response: the
/// status, the problem content type, and the other headers (`retry-after`
/// from the limiter, `x-request-id` from the scope layer), and the body
/// keeps `detail` and `instance`.
#[pollster::test]
async fn the_rerender_keeps_status_headers_and_problem_fields() {
    let harness = harness_with_sample();
    let mut ports = Ports::empty();
    ports.rate_limiter = Some(Arc::new(RecordingLimiter::new(LimiterVerdict::Deny)));
    let router = harness.router(ports);

    let response = request(
        &router,
        Method::GET,
        "/v1/sample/admin/whoami",
        &[("x-request-id", "client-id-12345678")],
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response.headers().get("retry-after").unwrap(),
        "11",
        "the limiter's header survives the re-render"
    );
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/problem+json"
    );
    assert_eq!(
        response.headers().get("x-request-id").unwrap(),
        "client-id-12345678"
    );
    let body = body_json(response).await;
    assert_eq!(body["type"], "https://test.example/problems/rate-limited");
}

/// A trimmed trailing slash on `public_url` still yields one slash.
#[test]
fn the_base_normalizes_one_trailing_slash() {
    let v = Venture::new("acme", "acme.test").public_url("https://acme.test/");
    assert_eq!(v.problem_type_base(), "https://acme.test/problems/");
}

/// Without a harness there is no venture to name: the context-free
/// rendering is `about:blank`, and the problem rides in the extensions for
/// a serving venture to re-render.
#[pollster::test]
async fn a_problem_without_a_harness_is_about_blank() {
    use axum::response::IntoResponse;
    let response = Problem::not_found().into_response();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/problem+json"
    );
    let problem = response
        .extensions()
        .get::<Problem>()
        .cloned()
        .expect("the problem rides in the extensions");
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body reads");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("problem body");
    assert_eq!(body["type"], "about:blank");
    assert_eq!(body["title"], "Not found");
    // And the venture's resolver is what turns it back into a URI.
    let v = api_venture();
    assert_eq!(
        problem.type_uri(&v.problem_type_base()),
        "https://api.example.test/problems/not-found"
    );
}
