//! The shared conformance suite (issue #9) plus the wasm dependency
//! boundary (ADR 0001) for `cratefield-module-telemetry`.

use cratefield_module_telemetry::Telemetry;
use cratefield_testing::{assert_wasm_safe_deps, conformance};

fn module() -> Telemetry {
    Telemetry::new().events(["run"]).modules(["telemetry"])
}

#[test]
fn telemetry_conforms() {
    conformance(Box::new(module()));
}

#[test]
fn telemetry_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
