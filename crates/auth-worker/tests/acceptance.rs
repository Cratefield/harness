//! Acceptance for one branded instance (issues #646, #777): its own
//! origin, an Owlpost mailer, a two-origin CORS allowlist and its own
//! branding, driven end to end through `AuthWorker::builder()` with fake
//! ports — a magic-link request really sends under the instance's display
//! name, CORS answers only the configured origins, pages and problem types
//! name the instance and nobody else, and a template override wins.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_auth_worker::{AuthWorker, AuthWorkerConfig};
use cratefield_core::{
    MapConfig, Port, Ports, Rendered, Runtime, SystemClock, Template, TemplateError, UlidIdGen,
};
use cratefield_testing::{FakeCaptcha, FakeHttpClient, FakeRateLimiter};
use tower::ServiceExt;

/// A runtime that can provide every port, so `Harness::build` composes the
/// venture. The ports actually handed to a request are the fakes built below.
struct AllPorts;

impl Runtime for AllPorts {
    fn provides(&self) -> Vec<Port> {
        Port::ALL.to_vec()
    }
}

/// The deployment's variables: the Worker keys plus the module keys the
/// magic-link flow needs (`auth-magic-link` reads its own public base and
/// From — they do not default from `AUTH_PUBLIC_URL` / `MAIL_FROM`).
fn pairs() -> Vec<(&'static str, &'static str)> {
    vec![
        ("AUTH_PUBLIC_URL", "https://auth.example.test"),
        ("AUTH_VENTURE_NAME", "example-auth"),
        ("AUTH_BRAND_NAME", "Example"),
        ("AUTH_BRAND_ACCENT", "#123abc"),
        ("AUTH_BRAND_PRIVACY_URL", "https://example.test/privacy"),
        ("AUTH_MAILER", "owlpost"),
        ("OWLPOST_API_KEY", "test-key"),
        ("OWLPOST_BASE_URL", "https://owlpost.example.test"),
        (
            "AUTH_CORS_ORIGINS",
            "https://one.example.test, https://two.example.test",
        ),
        // Deliberately different from the magic-link From below: the module
        // sets `Message.from`, which overrides this adapter-level default,
        // so the assertion below shows which one wins on the wire.
        ("MAIL_FROM", "postmaster@auth.example.test"),
        ("AUTH_MAGIC_LINK_PUBLIC_BASE", "https://auth.example.test"),
        ("AUTH_MAGIC_LINK_MAIL_FROM", "no-reply@auth.example.test"),
        ("AUTH_MAGIC_LINK_ALLOW_REGISTRATION", "true"),
    ]
}

/// Builds the venture through the same path the Worker boots, with fake
/// ports and a migrated in-memory database.
fn build(customize: impl FnOnce(AuthWorker) -> AuthWorker) -> (axum::Router, FakeHttpClient) {
    let config = AuthWorkerConfig::from_config(&MapConfig::from_pairs(pairs())).expect("config");

    let http = FakeHttpClient::ok_json(r#"{"id":"msg_1"}"#);
    let harness = customize(AuthWorker::new(config.clone()))
        .builder()
        .runtime(AllPorts)
        .build()
        .expect("the venture composes");

    let db = Arc::new(SqliteDatabase::in_memory().expect("in-memory sqlite"));
    for module in harness.modules() {
        db.apply_migrations(module.name(), module.migrations().sqlite)
            .expect("migrations apply");
    }

    let mut ports = Ports::with_config(Arc::new(MapConfig::from_pairs(pairs())));
    ports.db = Some(db);
    ports.mailer = Some(config.mailer(Arc::new(http.clone()), Arc::new(SystemClock)));
    ports.captcha = Some(Arc::new(FakeCaptcha::allow_all()));
    ports.rate_limiter = Some(Arc::new(FakeRateLimiter::always_allow()));
    ports.clock = Some(Arc::new(SystemClock));
    ports.id_gen = Some(Arc::new(UlidIdGen));

    (harness.router(ports), http)
}

async fn send(router: &axum::Router, request: Request<Body>) -> (StatusCode, HeaderMap) {
    let (status, headers, _) = send_full(router, request).await;
    (status, headers)
}

async fn send_full(
    router: &axum::Router,
    request: Request<Body>,
) -> (StatusCode, HeaderMap, String) {
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .expect("a readable body");
    (
        parts.status,
        parts.headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

/// Nothing a person or a client sees names another app, or the umbrella
/// the service used to run under.
fn assert_neutral(body: &str) {
    let lower = body.to_ascii_lowercase();
    // Spelt in halves so this file does not match a search for them.
    for marker in [
        concat!("factory", "0"),
        concat!("factory", " zero"),
        concat!("fz", "_session"),
    ] {
        assert!(!lower.contains(marker), "{marker} leaked: {body}");
    }
}

fn request_link() -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/auth-magic-link/request")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"email":"ada@example.com"}"#))
        .expect("request")
}

fn preflight(origin: &str) -> Request<Body> {
    Request::builder()
        .method(Method::OPTIONS)
        .uri("/v1/auth-magic-link/request")
        .header(header::ORIGIN, origin)
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .body(Body::empty())
        .expect("request")
}

fn allow_origin(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .and_then(|value| value.to_str().ok())
}

#[test]
fn a_magic_link_request_sends_through_owlpost() {
    pollster::block_on(async {
        let (router, http) = build(|worker| worker);

        let (status, _) = send(&router, request_link()).await;
        assert_eq!(status, StatusCode::ACCEPTED);

        let captured = http.captured();
        assert_eq!(captured.len(), 1, "one mail was sent: {captured:?}");
        let (method, uri, body) = &captured[0];
        assert_eq!(method, "POST");
        assert_eq!(uri, "https://owlpost.example.test/v1/emails");
        assert!(
            body.contains(r#""from":"no-reply@auth.example.test""#),
            "the magic-link module's from, not the adapter's MAIL_FROM, reached the wire: {body}"
        );
        assert!(body.contains(r#""to":"ada@example.com""#), "{body}");
        // The subject names the instance's display name, not its id.
        assert!(body.contains("Sign in to Example"), "{body}");
        assert!(!body.contains("example-auth"), "{body}");
        assert_neutral(body);
    });
}

#[test]
fn the_pages_carry_the_instance_s_branding() {
    pollster::block_on(async {
        let (router, _) = build(|worker| worker);
        let request = Request::builder()
            .uri("/v1/auth-core/authorize?client_id=nobody&redirect_uri=https://x.test/cb&response_type=code")
            .body(Body::empty())
            .expect("request");
        let (status, _, page) = send_full(&router, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            page.contains("<title>Sign-in error · Example</title>"),
            "{page}"
        );
        assert!(
            page.contains("#123abc"),
            "the accent is not applied: {page}"
        );
        assert!(page.contains("https://example.test/privacy"), "{page}");
        assert!(page.contains("auth.example.test · Example"), "{page}");
        assert_neutral(&page);
    });
}

#[test]
fn problem_types_are_named_under_the_instance_s_origin() {
    pollster::block_on(async {
        let (router, _) = build(|worker| worker);
        let request = Request::builder()
            .method(Method::POST)
            .uri("/v1/auth-core/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("grant_type=authorization_code&client_id=nobody"))
            .expect("request");
        // No signing keys in this kit, so the answer is the stable
        // "not configured" problem; what matters is whose name it carries.
        let (status, _, body) = send_full(&router, request).await;
        assert!(!status.is_success(), "{status}: {body}");
        assert!(
            body.contains(r#""type":"https://auth.example.test/problems/"#),
            "the problem type is not under the instance's origin: {body}"
        );
        assert_neutral(&body);
    });
}

#[test]
fn cors_answers_only_the_configured_origins() {
    pollster::block_on(async {
        let (router, _) = build(|worker| worker);

        for origin in ["https://one.example.test", "https://two.example.test"] {
            let (status, headers) = send(&router, preflight(origin)).await;
            assert!(status.is_success(), "{origin}: {status}");
            assert_eq!(allow_origin(&headers), Some(origin));
        }

        // An origin that is not on the allowlist — including one this
        // venture used to serve — gets no `Access-Control-Allow-Origin`.
        for origin in ["https://app.cratefield.com", "https://evil.example.test"] {
            let (_, headers) = send(&router, preflight(origin)).await;
            assert_eq!(allow_origin(&headers), None, "{origin} was allowed");
        }
    });
}

/// A template that renders a marker a default would never produce.
struct Marker;

impl Template for Marker {
    fn render(&self, _data: &serde_json::Value, _locale: &str) -> Result<Rendered, TemplateError> {
        Ok(Rendered {
            subject: "override subject".to_owned(),
            html: "<p>override</p>".to_owned(),
            text: "override body".to_owned(),
        })
    }
}

#[test]
fn a_template_override_wins_over_the_module_default() {
    pollster::block_on(async {
        let (router, http) = build(|worker| {
            worker.templates([(
                auth_magic_link::TEMPLATE_MAGIC_LINK.to_owned(),
                Box::new(Marker) as Box<dyn Template>,
            )])
        });

        let (status, _) = send(&router, request_link()).await;
        assert_eq!(status, StatusCode::ACCEPTED);

        let captured = http.captured();
        let body = &captured[0].2;
        assert!(
            body.contains("override subject"),
            "the override did not win: {body}"
        );
    });
}
