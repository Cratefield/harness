//! The shared conformance suite plus the wasm dependency boundary, as for
//! every Factory Zero module.

use cratefield_testing::{assert_wasm_safe_deps, conformance};
use factory0_auth_oidc::Oidc;

#[test]
fn auth_oidc_conforms() {
    conformance(Box::new(Oidc::new()));
}

#[test]
fn auth_oidc_deps_are_wasm_safe() {
    // ADR 0100 Q3: openidconnect and oauth2 reach wasm32 with default
    // features off. This is the check that keeps them there.
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
