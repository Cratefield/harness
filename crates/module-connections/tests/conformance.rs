//! The shared conformance suite (issue #9) plus the wasm dependency
//! boundary (ADR 0001) for `cratefield-module-connections`.

mod support;

use cratefield_testing::{assert_wasm_safe_deps, conformance};

#[test]
fn connections_conforms() {
    conformance(Box::new(support::module()));
}

#[test]
fn connections_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
