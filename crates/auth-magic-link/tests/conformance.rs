//! The shared conformance suite plus the wasm dependency boundary.

use cratefield_auth_magic_link::MagicLink;
use cratefield_testing::{assert_wasm_safe_deps, conformance};

#[test]
fn auth_magic_link_conforms() {
    conformance(Box::new(MagicLink::new()));
}

#[test]
fn auth_magic_link_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
