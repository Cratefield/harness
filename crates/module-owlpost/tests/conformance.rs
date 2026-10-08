//! The shared conformance suite (issue #9) plus the wasm dependency
//! boundary (ADR 0001) for `cratefield-module-owlpost`.

use cratefield_module_owlpost::Owlpost;
use cratefield_testing::{assert_wasm_safe_deps, conformance};

#[test]
fn owlpost_conforms() {
    conformance(Box::new(Owlpost::default()));
}

#[test]
fn owlpost_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
