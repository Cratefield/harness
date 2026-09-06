//! The shared conformance suite (issue #9): every module must pass it.

use factory0_core::{
    AnyError, BoxFuture, Config, ConfigError, EventHandler, EventName, HmacSigner, Migrations,
    Module, ModuleContext, Port, Ports, UlidIdGen,
};
use std::sync::Arc;

use crate::{TestHarness, request};

/// Wraps a module so its `well_known` router (when present) carries a
/// probe route the kit can request, proving where `Harness::router`
/// mounted it (issue #46). Everything else delegates unchanged.
struct WellKnownProbe {
    inner: Arc<dyn Module>,
}

impl Module for WellKnownProbe {
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    fn version(&self) -> &'static str {
        self.inner.version()
    }
    fn harness_api(&self) -> u32 {
        self.inner.harness_api()
    }
    fn requires(&self) -> &'static [Port] {
        self.inner.requires()
    }
    fn optional(&self) -> &'static [Port] {
        self.inner.optional()
    }
    fn tables(&self) -> &'static [&'static str] {
        self.inner.tables()
    }
    fn emits(&self) -> &'static [&'static str] {
        self.inner.emits()
    }
    fn public_writes(&self) -> bool {
        self.inner.public_writes()
    }
    fn migrations(&self) -> Migrations {
        self.inner.migrations()
    }
    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        self.inner.validate_config(cfg)
    }
    fn router(&self, ctx: ModuleContext) -> axum::Router {
        self.inner.router(ctx)
    }
    fn well_known(&self) -> Option<axum::Router> {
        self.inner.well_known().map(|router| {
            router.route(
                WELL_KNOWN_PROBE_PATH,
                axum::routing::get(|| async { "well-known" }),
            )
        })
    }
    fn events(&self) -> Vec<(EventName, EventHandler)> {
        self.inner.events()
    }
    fn scheduled<'a>(
        &'a self,
        ctx: &'a ModuleContext,
        cron: &'a str,
    ) -> BoxFuture<'a, Result<(), AnyError>> {
        self.inner.scheduled(ctx, cron)
    }
}

/// Route the probe wrapper registers inside the module's well-known
/// router; reachable at `/.well-known{WELL_KNOWN_PROBE_PATH}`.
const WELL_KNOWN_PROBE_PATH: &str = "/conformance-probe";

/// A `Ports` with every port faked, for the visibility check: declared
/// ports must survive `view_for`, undeclared ones must be hidden.
fn full_fake_ports() -> Ports {
    let mut ports = Ports::empty();
    ports.db = Some(Arc::new(crate::fakes::EmptyDatabase));
    ports.mailer = Some(Arc::new(crate::fakes::FakeMailer::new(
        crate::fakes::MailerMode::SendOk,
    )));
    ports.captcha = Some(Arc::new(crate::fakes::FakeCaptcha::allow_all()));
    ports.rate_limiter = Some(Arc::new(crate::fakes::FakeRateLimiter::always_allow()));
    ports.signer = Some(Arc::new(
        HmacSigner::new(crate::TEST_HARNESS_SECRET, None).expect("test secret is long enough"),
    ));
    ports.kv = Some(Arc::new(crate::fakes::MemoryKeyValue::new()));
    ports.http = Some(Arc::new(crate::fakes::FakeHttpClient::ok_json("{}")));
    ports.clock = Some(Arc::new(crate::fakes::FixedClock(
        time::OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("fixed epoch"),
    )));
    ports.id_gen = Some(Arc::new(UlidIdGen));
    ports.defer = Some(Arc::new(crate::fakes::FakeDefer::new()));
    ports
}

/// Runs the shared conformance suite against one module:
///
/// 1. mounts under `/v1/<name>` and `/__health` lists it with its version;
/// 2. a request under the module prefix is answered (no harness-level
///    crash — module-specific routes are covered by the module's own
///    tests via [`crate::request`]);
/// 3. migrations apply from scratch **twice** on fresh databases
///    (idempotence);
/// 4. no undeclared port access: `Ports::view_for` hides every port the
///    module did not declare;
/// 5. two concurrent requests keep their own request ids (ADR 0007);
/// 6. a well-known router, when provided, serves at the root under
///    `/.well-known` and never under `/v1` (issue #46).
///
/// # Panics
///
/// Panics with a message naming the failed check.
pub fn conformance(module: Box<dyn Module>) {
    let name = module.name().to_owned();
    let version = module.version().to_owned();
    let has_well_known = module.well_known().is_some();

    let kit = TestHarness::new(vec![Box::new(WellKnownProbe {
        inner: Arc::from(module),
    })]);
    let module = kit
        .modules
        .iter()
        .find(|m| m.name() == name)
        .unwrap_or_else(|| panic!("module {name} missing from kit"))
        .clone();

    // 1. health lists it.
    let health = pollster::block_on(request(
        &kit.router,
        axum::http::Method::GET,
        "/__health",
        None,
    ));
    let body = health.json();
    let listed = body["modules"]
        .as_array()
        .unwrap_or_else(|| panic!("health modules array missing: {body}"));
    let entry = listed
        .iter()
        .find(|entry| entry["name"] == name.as_str())
        .unwrap_or_else(|| panic!("health does not list {name}: {body}"));
    assert_eq!(entry["version"], version, "health lists the module version");

    // 2. a request under the prefix is answered without panicking.
    let probe = pollster::block_on(request(
        &kit.router,
        axum::http::Method::GET,
        &format!("/v1/{name}/"),
        None,
    ));
    // Any status is the module's business; the point is no crash.
    let _ = probe.status;

    // 3. migrations apply twice on fresh databases.
    for round in 1..=2 {
        let fresh = factory0_adapter_sqlite::SqliteDatabase::in_memory()
            .unwrap_or_else(|err| panic!("fresh db {round}: {err}"));
        for module in &kit.modules {
            fresh
                .apply_migrations(module.name(), module.migrations().sqlite)
                .unwrap_or_else(|err| panic!("round {round}, {}: {err}", module.name()));
        }
    }

    // 4. undeclared ports are hidden (declared ones stay visible).
    let view = full_fake_ports().view_for(module.as_ref());
    for (port, provided) in [
        (Port::Db, view.db.is_some()),
        (Port::Mailer, view.mailer.is_some()),
        (Port::Captcha, view.captcha.is_some()),
        (Port::RateLimiter, view.rate_limiter.is_some()),
        (Port::Signer, view.signer.is_some()),
        (Port::KeyValue, view.kv.is_some()),
        (Port::HttpClient, view.http.is_some()),
        (Port::Clock, view.clock.is_some()),
        (Port::IdGen, view.id_gen.is_some()),
        (Port::Defer, view.defer.is_some()),
    ] {
        let declared = module.requires().contains(&port) || module.optional().contains(&port);
        assert_eq!(
            provided,
            declared,
            "{name}: port {} must be visible only when declared",
            port.name()
        );
    }

    // 5. two concurrent requests keep their own request ids (ADR 0007).
    let router_a = kit.router.clone();
    let router_b = kit.router.clone();
    let id_a = "conformance-AAAAAAAA";
    let id_b = "conformance-BBBBBBBB";
    let make = |router: axum::Router, id: &'static str| {
        std::thread::spawn(move || {
            use tower::ServiceExt;
            let request = axum::http::Request::builder()
                .uri("/__health")
                .header("x-request-id", id)
                .body(axum::body::Body::empty())
                .expect("request builds");
            let response = pollster::block_on(router.oneshot(request)).expect("router answers");
            response
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok())
                .expect("request id echoed")
                .to_string()
        })
    };
    let handle_a = make(router_a, id_a);
    let handle_b = make(router_b, id_b);
    assert_eq!(handle_a.join().expect("a completes"), id_a);
    assert_eq!(handle_b.join().expect("b completes"), id_b);

    check_well_known_mount(&kit, &name, has_well_known);
}

/// Conformance check 6 (issue #46): the module's well-known router, when
/// present, serves at the root under `/.well-known` and never under
/// `/v1`; when absent, nothing mounts at `/.well-known`.
fn check_well_known_mount(kit: &TestHarness, name: &str, has_well_known: bool) {
    let probe = pollster::block_on(request(
        &kit.router,
        axum::http::Method::GET,
        &format!("/.well-known{WELL_KNOWN_PROBE_PATH}"),
        None,
    ));
    if has_well_known {
        assert_eq!(
            probe.status,
            axum::http::StatusCode::OK,
            "{name}: well-known router must serve at the root"
        );
        let under_v1 = pollster::block_on(request(
            &kit.router,
            axum::http::Method::GET,
            &format!("/v1/{name}/.well-known{WELL_KNOWN_PROBE_PATH}"),
            None,
        ));
        assert_eq!(
            under_v1.status,
            axum::http::StatusCode::NOT_FOUND,
            "{name}: well-known routes must not be nested under /v1"
        );
    } else {
        assert_eq!(
            probe.status,
            axum::http::StatusCode::NOT_FOUND,
            "{name}: nothing must mount at /.well-known without a well-known router"
        );
    }
}

/// Asserts the named crate's normal dependency tree is wasm-safe: no
/// `worker`, `wasm-bindgen`, `tokio`, `reqwest` (ADR 0001). Runs `cargo
/// tree -p <crate> --edges normal` in the caller's workspace — call it
/// with `env!("CARGO_PKG_NAME")` from a module test.
///
/// # Panics
///
/// Panics when a forbidden dependency is found or cargo fails.
pub fn assert_wasm_safe_deps(module_crate: &str) {
    let output =
        std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args(["tree", "-p", module_crate, "--edges", "normal"])
            .output()
            .unwrap_or_else(|err| panic!("cargo tree failed: {err}"));
    assert!(
        output.status.success(),
        "cargo tree failed for {module_crate}"
    );
    let tree = String::from_utf8_lossy(&output.stdout);
    for forbidden in ["worker v", "wasm-bindgen v", "tokio v", "reqwest v"] {
        assert!(
            !tree.contains(forbidden),
            "{module_crate} pulls forbidden dependency `{}`:\n{tree}",
            forbidden.trim_end_matches(" v")
        );
    }
}
