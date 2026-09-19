//! The shared conformance suite (issue #9) plus the wasm dependency
//! boundary (ADR 0001) for `cratefield-module-changelog`.

use cratefield_module_changelog::Changelog;
use cratefield_testing::{assert_wasm_safe_deps, conformance};

fn module() -> Changelog {
    Changelog::new().repo("owner/name")
}

#[test]
fn changelog_conforms() {
    conformance(Box::new(module()));
}

#[test]
fn changelog_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
