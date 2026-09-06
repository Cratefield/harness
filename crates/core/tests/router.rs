//! Router behaviors (issue #2 acceptance): health, ready, problem+json
//! shape, CORS, request id, security headers, body limit, sample module
//! route.

mod common;

use std::sync::Arc;

use axum::http::{Method, StatusCode, header};
use common::*;
use factory0_core::Ports;

/// `GET /__health` lists modules and versions without touching the db.
#[pollster::test]
async fn health_lists_modules_and_versions() {
    let harness = harness_with_sample();
    let router = harness.router(Ports::empty());
    let response = request(&router, Method::GET, "/__health", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["venture"], "test-venture");
    assert_eq!(body["env"], "development");
    assert_eq!(body["modules"][0]["name"], "sample");
    assert_eq!(body["modules"][0]["version"], env!("CARGO_PKG_VERSION"));
}

/// `GET /__ready` runs `SELECT 1` through the Database port.
#[pollster::test]
async fn ready_ok_with_database() {
    let harness = harness_with_sample();
    let router = harness.router(ports_with(Some(Arc::new(SelectOneDb))));
    let response = request(&router, Method::GET, "/__ready", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["ok"], true);
}

#[pollster::test]
async fn ready_503_without_database() {
    let harness = harness_with_sample();
    let router = harness.router(Ports::empty());
    let response = request(&router, Method::GET, "/__ready", &[], None).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/problem+json"
    );
    let body = body_json(response).await;
    assert_eq!(body["type"], "https://factory0.ventures/problems/not-ready");
}

#[pollster::test]
async fn ready_503_when_database_fails() {
    let harness = harness_with_sample();
    let router = harness.router(ports_with(Some(Arc::new(FailingDb))));
    let response = request(&router, Method::GET, "/__ready", &[], None).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = body_json(response).await;
    assert_eq!(body["type"], "https://factory0.ventures/problems/not-ready");
}

#[pollster::test]
async fn ready_503_when_database_is_too_slow() {
    let harness = harness_with_sample();
    let mut ports = ports_with(Some(Arc::new(SelectOneDb)));
    ports.clock = Some(Arc::new(InstantTimeoutClock));
    let router = harness.router(ports);
    let response = request(&router, Method::GET, "/__ready", &[], None).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = body_string(response).await;
    assert!(body.contains("did not answer within 2 s"), "body: {body}");
}

/// The sample module from the acceptance list is reachable at
/// `/v1/sample`, and its handler sees the request's own scope.
#[pollster::test]
async fn sample_module_mounts_under_v1_sample() {
    let harness = harness_with_sample();
    let router = harness.router(Ports::empty());
    let response = request(&router, Method::GET, "/v1/sample/hello", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let echoed_id = response
        .headers()
        .get("x-request-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let body = body_json(response).await;
    assert_eq!(body["venture"], "test-venture");
    assert_eq!(body["request_id"], echoed_id);
}

/// A valid incoming request id is accepted and echoed.
#[pollster::test]
async fn request_id_accepted_when_valid() {
    let harness = harness_with_sample();
    let router = harness.router(Ports::empty());
    let response = request(
        &router,
        Method::GET,
        "/v1/sample/hello",
        &[("x-request-id", "client-id-12345678")],
        None,
    )
    .await;
    assert_eq!(
        response.headers().get("x-request-id").unwrap(),
        "client-id-12345678"
    );
}

/// An invalid incoming request id is replaced with a fresh ULID (26 chars,
/// Crockford base 32) and still echoed.
#[pollster::test]
async fn request_id_generated_when_invalid() {
    let harness = harness_with_sample();
    let router = harness.router(Ports::empty());

    for bad in ["short", &"x".repeat(129), "bad chars!"] {
        let response = request(
            &router,
            Method::GET,
            "/v1/sample/hello",
            &[("x-request-id", bad)],
            None,
        )
        .await;
        let id = response
            .headers()
            .get("x-request-id")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(id.len(), 26, "ULID length for input {bad:?}");
        assert!(
            id.bytes().all(|b| b.is_ascii_alphanumeric()),
            "ULID charset for input {bad:?}: {id}"
        );
        assert_ne!(id, bad);
    }
}

#[pollster::test]
async fn request_id_always_set_on_response() {
    let harness = harness_with_sample();
    let router = harness.router(Ports::empty());
    let response = request(&router, Method::GET, "/__health", &[], None).await;
    assert!(response.headers().get("x-request-id").is_some());
}

/// CORS: allowed origins are echoed; other origins get no CORS headers.
#[pollster::test]
async fn cors_allows_listed_origin_only() {
    let harness = harness_with_sample();
    let router = harness.router(Ports::empty());

    let allowed = request(
        &router,
        Method::GET,
        "/v1/sample/hello",
        &[("origin", "https://test.example")],
        None,
    )
    .await;
    assert_eq!(
        allowed
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "https://test.example"
    );

    let denied = request(
        &router,
        Method::GET,
        "/v1/sample/hello",
        &[("origin", "https://evil.example")],
        None,
    )
    .await;
    assert!(
        denied
            .headers()
            .get("access-control-allow-origin")
            .is_none()
    );
}

/// `/v1/*` responses carry the security headers; `/__health` does not.
#[pollster::test]
async fn security_headers_on_v1_only() {
    let harness = harness_with_sample();
    let router = harness.router(Ports::empty());

    let api = request(&router, Method::GET, "/v1/sample/hello", &[], None).await;
    let (api_parts, api_body) = api.into_parts();
    drop(api_body);
    let headers = api_parts.headers;
    assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(
        headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
        "nosniff"
    );
    assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");

    let health = request(&router, Method::GET, "/__health", &[], None).await;
    let headers = health.headers();
    assert!(headers.get(header::CACHE_CONTROL).is_none());
    assert!(headers.get(header::X_CONTENT_TYPE_OPTIONS).is_none());
    assert!(headers.get("referrer-policy").is_none());
}

/// Deserialization failures become a 400 `validation-failed` problem
/// naming the field, with `instance` set to the request id.
#[pollster::test]
async fn invalid_json_is_a_validation_problem() {
    let harness = harness_with_sample();
    let router = harness.router(Ports::empty());

    let missing_field = request(
        &router,
        Method::POST,
        "/v1/sample/echo",
        &[],
        Some(br#"{"wrong": "field"}"#.to_vec()),
    )
    .await;
    assert_eq!(missing_field.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        missing_field.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/problem+json"
    );
    let body = body_json(missing_field).await;
    assert_eq!(
        body["type"],
        "https://factory0.ventures/problems/validation-failed"
    );
    assert_eq!(body["title"], "Request validation failed");
    assert_eq!(body["status"], 400);
    let detail = body["detail"].as_str().unwrap();
    assert!(detail.contains("email"), "detail names the field: {detail}");
    let instance = body["instance"].as_str().unwrap();
    assert_eq!(instance.len(), 26, "instance is the generated request id");

    let garbage = request(
        &router,
        Method::POST,
        "/v1/sample/echo",
        &[],
        Some(b"not json".to_vec()),
    )
    .await;
    assert_eq!(garbage.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(garbage).await["type"],
        "https://factory0.ventures/problems/validation-failed"
    );
}

/// The 64 KiB body limit applies to `/v1/*` JSON bodies.
#[pollster::test]
async fn oversized_body_rejected() {
    let harness = harness_with_sample();
    let router = harness.router(Ports::empty());
    let big = format!("{{\"email\":\"{}\"}}", "a".repeat(70_000));
    let response = request(
        &router,
        Method::POST,
        "/v1/sample/echo",
        &[],
        Some(big.into_bytes()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// Valid JSON passes through the core extractor unchanged.
#[pollster::test]
async fn valid_json_echoes() {
    let harness = harness_with_sample();
    let router = harness.router(Ports::empty());
    let response = request(
        &router,
        Method::POST,
        "/v1/sample/echo",
        &[],
        Some(br#"{"email":"nick@example.com"}"#.to_vec()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["email"], "nick@example.com");
}

/// Every core slug definition has a unique slug and a stable type URI.
#[test]
fn problem_slugs_are_unique() {
    let registry = factory0_core::problem_registry();
    let mut seen = std::collections::HashSet::new();
    for def in registry {
        assert!(seen.insert(def.slug), "duplicate slug {}", def.slug);
        let problem = factory0_core::Problem::new(def);
        assert!(
            problem
                .type_uri()
                .starts_with("https://factory0.ventures/problems/")
        );
        assert_eq!(problem.status, def.status);
    }
}

/// `/__health` carries the observability detail from issue #14:
/// `harness_api`, `HARNESS_BUILD` from config, mailer/captcha presence.
struct NeverMailer;
#[async_trait::async_trait]
impl factory0_core::Mailer for NeverMailer {
    async fn send(
        &self,
        _message: factory0_core::Message,
    ) -> Result<factory0_core::SendOutcome, factory0_core::MailError> {
        Ok(factory0_core::SendOutcome::NotConfigured)
    }
}

#[pollster::test]
async fn health_lists_contract_and_port_detail() {
    let harness = harness_with_sample();
    let mut ports = Ports::with_config(Arc::new(factory0_core::MapConfig::from_pairs([(
        "HARNESS_BUILD",
        "c8ecd06",
    )])));
    ports.mailer = Some(Arc::new(NeverMailer));
    let router = harness.router(ports);
    let response = request(&router, Method::GET, "/__health", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["harness_api"], factory0_core::HARNESS_API);
    assert_eq!(body["harness_build"], "c8ecd06");
    assert_eq!(body["mailer"], "configured");
    assert_eq!(body["captcha"], "absent");

    // Without config or ports: null build, mailer not configured.
    let bare = harness.router(Ports::empty());
    let response = request(&bare, Method::GET, "/__health", &[], None).await;
    let body = body_json(response).await;
    assert_eq!(body["harness_build"], serde_json::Value::Null);
    assert_eq!(body["mailer"], "not_configured");
}
