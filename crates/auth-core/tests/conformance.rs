//! The shared conformance suite plus the wasm dependency boundary, as for
//! every Factory Zero module.

use cratefield_testing::{assert_wasm_safe_deps, conformance};
use factory0_auth_core::AuthCore;

#[test]
fn auth_core_conforms() {
    conformance(Box::new(AuthCore::new()));
}

#[test]
fn auth_core_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
