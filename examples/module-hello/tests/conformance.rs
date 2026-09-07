//! The shared conformance suite (issue #9) plus the wasm dependency
//! boundary (ADR 0001) for `cratefield-module-hello`.

use cratefield_module_hello::Hello;
use cratefield_testing::{assert_wasm_safe_deps, conformance};

#[test]
fn hello_conforms() {
    conformance(Box::new(Hello::new()));
}

#[test]
fn hello_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
