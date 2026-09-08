//! The shared conformance suite plus the wasm dependency boundary.

use cratefield_testing::{assert_wasm_safe_deps, conformance};
use factory0_auth_magic_link::MagicLink;

#[test]
fn auth_magic_link_conforms() {
    conformance(Box::new(MagicLink::new()));
}

#[test]
fn auth_magic_link_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
