//! The shared conformance suite (issue #9) plus the wasm dependency
//! boundary (ADR 0001) for `factory0-module-waitlist`.

use factory0_module_waitlist::Waitlist;
use factory0_testing::{assert_wasm_safe_deps, conformance};

fn module() -> Waitlist {
    Waitlist::new().products(["kontinuum"])
}

#[test]
fn waitlist_conforms() {
    conformance(Box::new(module()));
}

#[test]
fn waitlist_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
