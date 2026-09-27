//! The shared conformance suite (issue #9) plus the wasm dependency
//! boundary (ADR 0001) for `cratefield-module-webhooks`.

use cratefield_module_webhooks::Webhooks;
use cratefield_testing::{assert_wasm_safe_deps, conformance};

fn module() -> Webhooks {
    Webhooks::new()
}

#[test]
fn webhooks_conforms() {
    conformance(Box::new(module()));
}

#[test]
fn webhooks_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
