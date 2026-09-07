//! The shared conformance suite (issue #9) plus the wasm dependency
//! boundary (ADR 0001) for `cratefield-module-cms`.

use cratefield_module_cms::Cms;
use cratefield_testing::{assert_wasm_safe_deps, conformance};

fn module() -> Cms {
    Cms::new().collections(["pages"])
}

#[test]
fn cms_conforms() {
    conformance(Box::new(module()));
}

#[test]
fn cms_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
