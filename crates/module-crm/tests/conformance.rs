//! The shared conformance suite (issue #9) plus the wasm dependency
//! boundary (ADR 0001) for `cratefield-module-crm`.

use cratefield_module_crm::Crm;
use cratefield_testing::{assert_wasm_safe_deps, conformance};

#[test]
fn crm_conforms() {
    conformance(Box::new(Crm::new()));
}

#[test]
fn crm_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
