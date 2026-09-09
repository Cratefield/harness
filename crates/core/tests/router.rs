//! Router behaviors (issue #2 acceptance): health, ready, problem+json
//! shape, CORS, request id, security headers, body limit, sample module
//! route.

mod common;

use std::sync::Arc;

use axum::Router;
use axum::http::{Method, StatusCode, header};
use common::*;
use cratefield_core::{Config, Harness, MapConfig, Module, Port, Ports};

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

/// A `token` query parameter is a credential in the URL (issue #135):
/// `/ui/waitlist/status?token=…` authenticates with the URL itself and is
/// outside `/v1/*`, so the root-level middleware must give any
/// token-bearing request the no-store headers — whatever the path.
#[pollster::test]
async fn token_bearing_requests_get_no_store_even_off_v1() {
    let harness = harness_with_sample();
    let router = harness.router(Ports::empty());

    let response = request(&router, Method::GET, "/__health?token=abc", &[], None).await;
    let headers = response.headers();
    assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(
        headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
        "nosniff"
    );
    assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");

    // The token may sit behind other parameters…
    let response = request(
        &router,
        Method::GET,
        "/__health?page=2&token=abc",
        &[],
        None,
    )
    .await;
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );

    // …and a look-alike parameter must not be mistaken for one.
    let response = request(
        &router,
        Method::GET,
        "/__health?access_token=abc&tokenizer=1",
        &[],
        None,
    )
    .await;
    assert!(response.headers().get(header::CACHE_CONTROL).is_none());
    assert!(response.headers().get("referrer-policy").is_none());
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
    let registry = cratefield_core::problem_registry();
    let mut seen = std::collections::HashSet::new();
    for def in registry {
        assert!(seen.insert(def.slug), "duplicate slug {}", def.slug);
        let problem = cratefield_core::Problem::new(def);
        assert!(
            problem
                .type_uri()
                .starts_with("https://factory0.ventures/problems/")
        );
        assert_eq!(problem.status, def.status);
    }
}

/// Issue #46: a module's well-known router is served at the root under
/// `/.well-known` (never under `/v1`), while the module keeps its `/v1`
/// mount and its `/__health` entry.
#[pollster::test]
async fn well_known_served_at_root_and_not_under_v1() {
    let harness = Harness::builder()
        .venture(base_venture())
        .module(SampleModule::default().with_well_known())
        .runtime(FakeRuntime(all_ports()))
        .build()
        .expect("single well-known provider builds");
    let router = harness.router(Ports::empty());

    let root = request(&router, Method::GET, "/.well-known/test", &[], None).await;
    assert_eq!(root.status(), StatusCode::OK);
    assert_eq!(body_json(root).await["served"], "well-known");

    let under_v1 = request(
        &router,
        Method::GET,
        "/v1/sample/.well-known/test",
        &[],
        None,
    )
    .await;
    assert_eq!(under_v1.status(), StatusCode::NOT_FOUND);

    let module_route = request(&router, Method::GET, "/v1/sample/hello", &[], None).await;
    assert_eq!(module_route.status(), StatusCode::OK);

    let health = request(&router, Method::GET, "/__health", &[], None).await;
    let body = body_json(health).await;
    assert_eq!(body["modules"][0]["name"], "sample");
}

/// Issue #46: two modules providing a well-known router fail the build
/// with an error naming both.
#[test]
fn two_well_known_routers_fail_build_naming_both() {
    let error = Harness::builder()
        .venture(base_venture())
        .module(SampleModule::default().with_well_known())
        .module(SampleModule::named("other").with_well_known())
        .runtime(FakeRuntime(all_ports()))
        .build()
        .expect_err("two well-known providers must not build");
    let message = error.to_string();
    assert!(message.contains("`sample`"), "names sample: {message}");
    assert!(message.contains("`other`"), "names other: {message}");
    assert!(
        message.contains(".well-known"),
        "names the mount: {message}"
    );
}

/// Issue #46: a form_post-shaped body (Sign in with Apple) parses through
/// the `Form` extractor.
#[pollster::test]
async fn form_post_body_parses() {
    let harness = harness_with_sample();
    let router = harness.router(Ports::empty());
    let response = form_request(
        &router,
        Method::POST,
        "/v1/sample/callback",
        "code=abc.def&state=xyz0123456".to_owned(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["code"], "abc.def");
    assert_eq!(body["state"], "xyz0123456");
}

/// Malformed forms (missing field, wrong content type) become 400
/// `validation-failed` problems with `instance` set, like invalid JSON.
#[pollster::test]
async fn malformed_form_is_a_validation_problem() {
    let harness = harness_with_sample();
    let router = harness.router(Ports::empty());

    let missing_field = form_request(
        &router,
        Method::POST,
        "/v1/sample/callback",
        "code=abc.def".to_owned(),
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
    let detail = body["detail"].as_str().unwrap();
    assert!(detail.contains("state"), "detail names the field: {detail}");
    assert_eq!(
        body["instance"].as_str().unwrap().len(),
        26,
        "instance is the generated request id"
    );

    let wrong_type = request(
        &router,
        Method::POST,
        "/v1/sample/callback",
        &[],
        Some(br#"{"code": "c", "state": "s"}"#.to_vec()),
    )
    .await;
    assert_eq!(wrong_type.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(wrong_type).await["type"],
        "https://factory0.ventures/problems/validation-failed"
    );
}

/// The 64 KiB body limit applies to form bodies exactly as to JSON.
#[pollster::test]
async fn oversized_form_body_rejected() {
    let harness = harness_with_sample();
    let router = harness.router(Ports::empty());
    let big = format!("code={}&state=x", "a".repeat(70_000));
    let response = form_request(&router, Method::POST, "/v1/sample/callback", big).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body = body_json(response).await;
    assert_eq!(
        body["type"],
        "https://factory0.ventures/problems/request-too-large"
    );
}

/// `/__health` carries the observability detail from issue #14:
/// `harness_api`, `HARNESS_BUILD` from config, mailer/captcha presence.
struct NeverMailer;
#[async_trait::async_trait]
impl cratefield_core::Mailer for NeverMailer {
    async fn send(
        &self,
        _message: cratefield_core::Message,
    ) -> Result<cratefield_core::SendOutcome, cratefield_core::MailError> {
        Ok(cratefield_core::SendOutcome::NotConfigured)
    }
}

#[pollster::test]
async fn health_lists_contract_and_port_detail() {
    let harness = harness_with_sample();
    let mut ports = Ports::with_config(Arc::new(cratefield_core::MapConfig::from_pairs([(
        "HARNESS_BUILD",
        "c8ecd06",
    )])));
    ports.mailer = Some(Arc::new(NeverMailer));
    let router = harness.router(ports);
    let response = request(&router, Method::GET, "/__health", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["harness_api"], cratefield_core::HARNESS_API);
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

// ------------------------------------------ deployed readiness (issue #143)

/// A runtime that provides everything but can back none of it usefully —
/// the shape of a venture whose Captcha binding is absent or fail-open.
struct UnusableCaptcha;

impl cratefield_core::Runtime for UnusableCaptcha {
    fn provides(&self) -> Vec<Port> {
        Port::ALL.to_vec()
    }
    fn effectively_configured(&self, port: Port) -> bool {
        port != Port::Captcha
    }
}

/// A public writer with no surface — the shape of the auth login methods.
struct PublicWriter;

impl Module for PublicWriter {
    fn name(&self) -> &'static str {
        "writer"
    }
    fn version(&self) -> &'static str {
        "0.0.0-test"
    }
    fn requires(&self) -> &'static [Port] {
        &[]
    }
    fn public_writes(&self) -> bool {
        true
    }
    fn migrations(&self) -> cratefield_core::Migrations {
        cratefield_core::Migrations::default()
    }
    fn validate_config(&self, _: &dyn Config) -> Result<(), cratefield_core::ConfigError> {
        Ok(())
    }
    fn router(&self, _: cratefield_core::ModuleContext) -> Router {
        Router::new().route("/join", axum::routing::post(|| async { "ok" }))
    }
}

/// Issue #143. The production gate keyed off the **compiled**
/// `Venture::env`, which defaults to `Development` and which
/// `ventures/cratefield-waitlist` never sets — while its wrangler.toml
/// ships `ENV = "production"`. So the one venture actually in production
/// ran with every production-only rule switched off. The deployment's
/// answer now counts, and a deployment that cannot back its own declared
/// abuse controls refuses the guarded routes instead of serving them.
#[pollster::test]
async fn a_deployment_that_declares_production_is_held_to_it() {
    let harness = Harness::builder()
        .venture(base_venture())
        .module(PublicWriter)
        .runtime(UnusableCaptcha)
        .build()
        .expect("a development venture builds: the compiled env says development");

    // Deployed as production, exactly as the waitlist Worker is.
    let ports = Ports::with_config(Arc::new(MapConfig::from_pairs([("ENV", "production")])));
    let router = harness.router(ports);

    let refused = request(
        &router,
        Method::POST,
        "/v1/writer/join",
        &[],
        Some(b"{}".to_vec()),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body_json(refused).await["type"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap(),
        "not-production-ready"
    );

    // The probes stay up: an operator has to be able to see why.
    let health = request(&router, Method::GET, "/__health", &[], None).await;
    assert_eq!(health.status(), StatusCode::OK);
}

#[pollster::test]
async fn the_same_venture_serves_normally_when_the_deployment_is_not_production() {
    let harness = Harness::builder()
        .venture(base_venture())
        .module(PublicWriter)
        .runtime(UnusableCaptcha)
        .build()
        .expect("builds");
    let router = harness.router(Ports::with_config(Arc::new(MapConfig::default())));
    let ok = request(
        &router,
        Method::POST,
        "/v1/writer/join",
        &[],
        Some(b"{}".to_vec()),
    )
    .await;
    assert_ne!(ok.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[pollster::test]
async fn an_operator_can_accept_the_gap_explicitly_and_it_is_recorded() {
    let harness = Harness::builder()
        .venture(base_venture())
        .module(PublicWriter)
        .runtime(UnusableCaptcha)
        .build()
        .expect("builds");

    // An empty reason is not an acceptance: an override nobody has to
    // answer for is the silent default this gate exists to remove.
    let blank = harness.router(Ports::with_config(Arc::new(MapConfig::from_pairs([
        ("ENV", "production"),
        (cratefield_core::ALLOW_UNPROTECTED_WRITES, "   "),
    ]))));
    let refused = request(
        &blank,
        Method::POST,
        "/v1/writer/join",
        &[],
        Some(b"{}".to_vec()),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);

    // A stated reason serves, and the reason is what someone answers for.
    let accepted = harness.router(Ports::with_config(Arc::new(MapConfig::from_pairs([
        ("ENV", "production"),
        (
            cratefield_core::ALLOW_UNPROTECTED_WRITES,
            "issue #143: Turnstile pending on the Cloudflare account",
        ),
    ]))));
    let served = request(
        &accepted,
        Method::POST,
        "/v1/writer/join",
        &[],
        Some(b"{}".to_vec()),
    )
    .await;
    assert_ne!(served.status(), StatusCode::SERVICE_UNAVAILABLE);
}

// --------------------------------------- module dependency order (#26)

/// The names the harness holds, in the order it holds them.
fn order(harness: &Harness) -> Vec<&str> {
    harness.modules().iter().map(|m| m.name()).collect()
}

fn build_with(modules: Vec<SampleModule>) -> Result<Harness, cratefield_core::ConfigError> {
    let mut builder = Harness::builder()
        .venture(base_venture())
        .runtime(FakeRuntime(all_ports()));
    for module in modules {
        builder = builder.module(module);
    }
    builder.build()
}

/// Issue #26 / RECONCILIATION.md §2. `depends_on` is a partial order for
/// migrations, and the sort that realises it is stable — so a venture
/// that declares nothing, which is every venture today, keeps exactly the
/// order it composed.
#[test]
fn with_nothing_declared_the_order_is_the_one_composed() {
    let harness = build_with(vec![
        SampleModule::named("charlie"),
        SampleModule::named("alpha"),
        SampleModule::named("bravo"),
    ])
    .expect("builds");
    assert_eq!(order(&harness), ["charlie", "alpha", "bravo"]);
}

#[test]
fn a_module_follows_what_it_sits_on_top_of() {
    // Composed in an order that violates the declaration, so passing
    // cannot be an accident of the input.
    let harness = build_with(vec![
        SampleModule::named("orders").depending_on(&["accounts"]),
        SampleModule::named("accounts"),
    ])
    .expect("builds");
    assert_eq!(order(&harness), ["accounts", "orders"]);

    // A chain, and an unrelated module that keeps its composed position
    // relative to the others it does not constrain.
    let harness = build_with(vec![
        SampleModule::named("shipping").depending_on(&["orders"]),
        SampleModule::named("audit"),
        SampleModule::named("orders").depending_on(&["accounts"]),
        SampleModule::named("accounts"),
    ])
    .expect("builds");
    let names = order(&harness);
    let at = |needle: &str| names.iter().position(|n| *n == needle).expect("present");
    assert!(at("accounts") < at("orders"), "{names:?}");
    assert!(at("orders") < at("shipping"), "{names:?}");
    assert!(names.contains(&"audit"), "{names:?}");
}

#[test]
fn depending_on_a_module_the_venture_did_not_compose_fails_the_build() {
    let errors = build_with(vec![
        SampleModule::named("orders").depending_on(&["accounts"]),
    ])
    .expect_err("a dependency on nothing is a build error");
    assert!(
        errors
            .problems
            .iter()
            .any(|e| e.contains("orders") && e.contains("accounts")),
        "{:?}",
        errors.problems
    );
}

#[test]
fn a_cycle_is_a_build_error_not_a_boot_error() {
    // The whole reason this is checked in `build`: a boot error is one a
    // deployment discovers in production.
    let errors = build_with(vec![
        SampleModule::named("alpha").depending_on(&["bravo"]),
        SampleModule::named("bravo").depending_on(&["alpha"]),
    ])
    .expect_err("a cycle cannot be ordered");
    assert!(
        errors.problems.iter().any(|e| e.contains("cycle")),
        "{:?}",
        errors.problems
    );

    // A module outside the cycle does not rescue it.
    let errors = build_with(vec![
        SampleModule::named("solo"),
        SampleModule::named("alpha").depending_on(&["bravo"]),
        SampleModule::named("bravo").depending_on(&["charlie"]),
        SampleModule::named("charlie").depending_on(&["alpha"]),
    ])
    .expect_err("a longer cycle is still a cycle");
    let cycle = errors
        .problems
        .iter()
        .find(|e| e.contains("cycle"))
        .expect("named");
    assert!(!cycle.contains("solo"), "only the stuck modules: {cycle}");
}

#[test]
fn a_module_may_depend_on_itself_only_by_being_a_cycle() {
    let errors = build_with(vec![SampleModule::named("alpha").depending_on(&["alpha"])])
        .expect_err("self-dependency cannot be ordered");
    assert!(
        errors.problems.iter().any(|e| e.contains("cycle")),
        "{:?}",
        errors.problems
    );
}
