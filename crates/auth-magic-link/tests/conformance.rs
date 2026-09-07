//! The shared conformance suite plus the wasm dependency boundary.

use factory0_auth_magic_link::MagicLink;
use factory0_testing::{assert_wasm_safe_deps, conformance};

#[test]
fn auth_magic_link_conforms() {
    conformance(Box::new(MagicLink::new()));
}

#[test]
fn auth_magic_link_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
