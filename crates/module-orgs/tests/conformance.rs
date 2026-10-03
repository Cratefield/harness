//! The shared conformance suite (issue #9) plus the wasm dependency
//! boundary (ADR 0001) for `cratefield-module-orgs`.

mod support;

use cratefield_testing::{assert_wasm_safe_deps, conformance};

#[test]
fn orgs_conforms() {
    conformance(Box::new(support::module()));
}

#[test]
fn orgs_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
