//! The shared conformance suite (issue #9): every module must pass it.

use cratefield_core::{
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
    ports.blob = Some(Arc::new(crate::fakes::MemoryBlob::new()));
    ports.push = Some(Arc::new(crate::fakes::FakePush::new(crate::fakes::PushMode::DeliverOk)));
    ports.http = Some(Arc::new(crate::fakes::FakeHttpClient::ok_json("{}")));
    ports.clock = Some(Arc::new(crate::fakes::FixedClock(
        time::OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("fixed epoch"),
    )));
    ports.id_gen = Some(Arc::new(UlidIdGen));
    ports.defer = Some(Arc::new(crate::fakes::FakeDefer::new()));
    ports
}

/// Runs the shared conformance suite against one module, once per
/// dialect available in the environment (issue #20 — SQLite always,
/// Postgres when `FZ_TEST_POSTGRES_URL` names a server):
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
/// Panics with a message naming the failed check and the dialect.
pub fn conformance(module: Box<dyn Module>) {
    let inner: Arc<dyn Module> = Arc::from(module);
    conformance_inner(&inner, true);
}

/// [`conformance`] without the sidecar parity axis (issue #64). `reason`
/// is recorded in code and printed by the run, so a module that opts out
/// says why in the same place it opts out. Use it only for a module that
/// genuinely cannot be sidecar-mounted; "it fails" is not a reason.
///
/// # Panics
///
/// Panics when `reason` is empty, and on any conformance failure.
pub fn conformance_in_process_only(module: Box<dyn Module>, reason: &str) {
    assert!(
        !reason.trim().is_empty(),
        "conformance_in_process_only needs a reason: it is the only record of why \
         `{}` is not checked for sidecar parity",
        module.name()
    );
    eprintln!("[{}] sidecar parity axis skipped: {reason}", module.name());
    let inner: Arc<dyn Module> = Arc::from(module);
    conformance_inner(&inner, false);
}

fn conformance_inner(inner: &Arc<dyn Module>, parity: bool) {
    let name = inner.name().to_owned();
    let version = inner.version().to_owned();
    let has_well_known = inner.well_known().is_some();
    let module: Arc<dyn Module> = Arc::new(WellKnownProbe {
        inner: inner.clone(),
    });

    for dialect in crate::dialect::Dialect::available() {
        conformance_on_dialect(&dialect, module.clone(), &name, &version, has_well_known);
    }

    if parity {
        // One instance across both mounts, as the dialect axis above
        // already does: the probes never reach a module's parked context.
        parity_on(inner, &name);
    }
}

fn conformance_on_dialect(
    dialect: &crate::dialect::Dialect,
    module: Arc<dyn Module>,
    name: &str,
    version: &str,
    has_well_known: bool,
) {
    let kit = TestHarness::from_arcs(vec![module], dialect.clone(), |_| {});
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
        .find(|entry| entry["name"] == *name)
        .unwrap_or_else(|| panic!("health does not list {name}: {body}"));
    assert_eq!(
        entry["version"],
        version,
        "[{}] health lists the module version",
        dialect.name()
    );

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
    #[cfg(feature = "postgres")]
    if let crate::dialect::Dialect::Postgres { .. } = &dialect {
        crate::pg::migrations_apply_twice(&kit.modules)
            .unwrap_or_else(|message| panic!("[postgres] {message}"));
        check_visibility_and_scope(&kit, module.as_ref(), name, has_well_known);
        return;
    }
    for round in 1..=2 {
        let fresh = cratefield_adapter_sqlite::SqliteDatabase::in_memory()
            .unwrap_or_else(|err| panic!("[sqlite] fresh db {round}: {err}"));
        for module in &kit.modules {
            fresh
                .apply_migrations(module.name(), module.migrations().sqlite)
                .unwrap_or_else(|err| panic!("[sqlite] round {round}, {}: {err}", module.name()));
        }
    }
    check_visibility_and_scope(&kit, module.as_ref(), name, has_well_known);
}

/// Conformance checks 4-6: undeclared ports stay hidden, concurrent
/// requests keep their request ids, and a well-known router mounts at
/// the root only.
fn check_visibility_and_scope(
    kit: &TestHarness,
    module: &dyn Module,
    name: &str,
    has_well_known: bool,
) {
    // 4. undeclared ports are hidden (declared ones stay visible).
    let view = full_fake_ports().view_for(module);
    for (port, provided) in [
        (Port::Db, view.db.is_some()),
        (Port::Mailer, view.mailer.is_some()),
        (Port::Captcha, view.captcha.is_some()),
        (Port::RateLimiter, view.rate_limiter.is_some()),
        (Port::Signer, view.signer.is_some()),
        (Port::KeyValue, view.kv.is_some()),
        (Port::Blob, view.blob.is_some()),
        (Port::Push, view.push.is_some()),
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

    check_well_known_mount(kit, name, has_well_known);
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

/// One probe of the [`sidecar_parity`] battery: a request whose answer
/// must be identical whether the module is linked in or reached over a
/// service binding.
struct Probe {
    what: &'static str,
    method: axum::http::Method,
    /// Appended to `/v1/<module>`.
    path: &'static str,
    body: Option<&'static str>,
}

/// The request id both mounts are given, so `instance` in a problem body
/// and the `x-request-id` header can be compared byte for byte. The
/// harness accepts a client-supplied id that matches its pattern.
const PARITY_REQUEST_ID: &str = "parity-0123456789abcdef";

/// Sends one probe through `router`, with the fixed request id.
async fn probe_once(router: &axum::Router, name: &str, probe: &Probe) -> crate::TestResponse {
    use axum::http::{HeaderValue, Request, header};
    use tower::ServiceExt;

    let uri = format!("/v1/{name}{}", probe.path);
    let mut builder = Request::builder()
        .method(probe.method.clone())
        .uri(uri)
        .header(
            cratefield_core::X_REQUEST_ID,
            HeaderValue::from_static(PARITY_REQUEST_ID),
        )
        .header("cf-connecting-ip", HeaderValue::from_static("203.0.113.9"));
    let body = match probe.body {
        Some(json) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            axum::body::Body::from(json)
        }
        None => axum::body::Body::empty(),
    };
    let response = router
        .clone()
        .oneshot(builder.body(body).expect("probe request builds"))
        .await
        .expect("router is infallible");
    crate::TestResponse::of(response).await
}

/// Asserts that a module answers identically in-process and behind a
/// sidecar mount (issue #64, ADR 0009: a caller cannot tell which).
///
/// Both mounts are given the same client-supplied request id, so the
/// `instance` of a problem body and the `x-request-id` header are
/// comparable byte for byte. Probes are deliberately module-agnostic —
/// unknown paths, a malformed body, a wrong method — because the kit
/// does not know the module's routes and because those are exactly the
/// paths where the hop could quietly rewrite something.
///
/// Also asserted: a body over the harness's 64 KiB cap is refused by the
/// **host** and never forwarded.
///
/// # Panics
///
/// Panics naming the probe and the field that diverged.
pub fn sidecar_parity(module: Box<dyn Module>) {
    let name = module.name().to_owned();
    parity_on(&Arc::from(module), &name);
}

fn parity_on(shared: &Arc<dyn Module>, name: &str) {
    // In-process: the module is linked into the harness under test.
    let in_process = TestHarness::from_arcs(
        vec![shared.clone()],
        crate::dialect::Dialect::Sqlite,
        |_| {},
    );

    // Sidecar: a second harness holds the module, and the host holds a
    // mount table pointing at it over a fake service binding.
    let remote = TestHarness::from_arcs(
        vec![shared.clone()],
        crate::dialect::Dialect::Sqlite,
        |_| {},
    );
    let (sidecar, dispatcher) = crate::sidecar::shared(crate::sidecar::FakeSidecar::new(
        "PARITY",
        remote.router.clone(),
    ));
    let table = format!("{{\"{name}\":\"PARITY\"}}");
    let host = TestHarness::with_builder(
        Vec::new(),
        |builder| builder,
        |ports| {
            ports.config = Arc::new(cratefield_core::MapConfig::from_pairs([
                ("HARNESS_SECRET", crate::TEST_HARNESS_SECRET),
                (cratefield_core::HARNESS_SIDECARS, table.as_str()),
            ]));
            ports.dispatcher = Some(dispatcher);
        },
    );

    let probes = [
        Probe {
            what: "an unknown path under the module prefix",
            method: axum::http::Method::GET,
            path: "/__parity_no_such_route",
            body: None,
        },
        Probe {
            what: "a POST to an unknown path",
            method: axum::http::Method::POST,
            path: "/__parity_no_such_route",
            body: Some(r#"{"parity":true}"#),
        },
        Probe {
            what: "the module root",
            method: axum::http::Method::GET,
            path: "",
            body: None,
        },
        Probe {
            what: "a malformed JSON body at the module root",
            method: axum::http::Method::POST,
            path: "",
            body: Some("{not json"),
        },
    ];

    for (sent, probe) in probes.iter().enumerate() {
        let direct = pollster::block_on(probe_once(&in_process.router, name, probe));
        let hopped = pollster::block_on(probe_once(&host.router, name, probe));
        // Without this the axis could pass vacuously: if the mount stopped
        // forwarding, the host would answer its own 404 and a module that
        // also answers 404 would compare equal. Every probe must have
        // crossed the hop.
        assert_eq!(
            sidecar.calls(),
            sent + 1,
            "[{name}] {} never reached the sidecar: the mount is not forwarding, \
             so this comparison proves nothing",
            probe.what
        );
        compare(name, probe.what, &direct, &hopped);
    }

    check_oversized_body_stops_at_the_host(&host, &sidecar, name);
}

/// A body over the harness cap is refused by the **host** and never
/// forwarded: the forwarder buffers, so a body it accepted would be held
/// in the isolate twice (issue #64, amended).
fn check_oversized_body_stops_at_the_host(
    host: &TestHarness,
    sidecar: &Arc<crate::sidecar::FakeSidecar>,
    name: &str,
) {
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;

    let before = sidecar.calls();
    let big = "x".repeat(cratefield_core::MAX_BODY_BYTES + 1);
    let response = pollster::block_on(async {
        let request = Request::builder()
            .method(axum::http::Method::POST)
            .uri(format!("/v1/{name}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(big))
            .expect("oversized request builds");
        let response = host
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("router is infallible");
        crate::TestResponse::of(response).await
    });
    assert_eq!(
        response.status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "[{name}] a body over {} bytes must be refused by the host",
        cratefield_core::MAX_BODY_BYTES
    );
    assert_eq!(
        sidecar.calls(),
        before,
        "[{name}] an oversized body must never be forwarded to the sidecar"
    );
}

/// Compares one probe's two answers: status, the problem body byte for
/// byte, and the request id (present exactly once, and the one the
/// caller sent).
fn compare(name: &str, what: &str, direct: &crate::TestResponse, hopped: &crate::TestResponse) {
    assert_eq!(
        direct.status, hopped.status,
        "[{name}] status differs over the sidecar hop for {what}"
    );
    assert_eq!(
        direct.body(),
        hopped.body(),
        "[{name}] body differs over the sidecar hop for {what}"
    );
    for header in [
        axum::http::header::CONTENT_TYPE.as_str(),
        axum::http::header::LOCATION.as_str(),
    ] {
        assert_eq!(
            direct.headers.get(header),
            hopped.headers.get(header),
            "[{name}] `{header}` differs over the sidecar hop for {what}"
        );
    }
    for (label, response) in [("in-process", direct), ("sidecar", hopped)] {
        let ids: Vec<_> = response
            .headers
            .get_all(cratefield_core::X_REQUEST_ID)
            .iter()
            .collect();
        assert_eq!(
            ids.len(),
            1,
            "[{name}] {label} answered {} request ids for {what}; exactly one is the contract",
            ids.len()
        );
        assert_eq!(
            ids[0], PARITY_REQUEST_ID,
            "[{name}] {label} did not echo the caller's request id for {what}"
        );
    }
}
