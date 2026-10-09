//! The shared conformance suite (issue #9) plus the wasm dependency
//! boundary (ADR 0001) for `cratefield-module-sealed`.

mod support;

use cratefield_module_sealed::{NoopNotifier, Sealed};
use cratefield_testing::{assert_wasm_safe_deps, conformance};
use std::sync::Arc;

fn module() -> Sealed {
    Sealed::new(Arc::new(support::FakeKms::new()), Arc::new(NoopNotifier))
}

#[test]
fn sealed_conforms() {
    conformance(Box::new(module()));
}

#[test]
fn sealed_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
