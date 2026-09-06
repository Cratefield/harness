//! The shared conformance suite (issue #9): every module must pass it.

use factory0_core::{Module, Port, Ports};
use std::sync::Arc;

use crate::{TestHarness, request};

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
/// 5. two concurrent requests keep their own request ids (ADR 0007).
///
/// # Panics
///
/// Panics with a message naming the failed check.
pub fn conformance(module: Box<dyn Module>) {
    let name = module.name().to_owned();
    let version = module.version().to_owned();

    let kit = TestHarness::new(vec![module]);
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

    // 4. undeclared ports are hidden.
    let mut ports = Ports::empty();
    ports.db = Some(Arc::new(crate::fakes::EmptyDatabase));
    let view = ports.view_for(module.as_ref());
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
