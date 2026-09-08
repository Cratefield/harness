//! The shared conformance suite plus the wasm dependency boundary, as for
//! every Factory Zero module.

use cratefield_testing::{assert_wasm_safe_deps, conformance};
use factory0_auth_passkeys::Passkeys;

#[test]
fn auth_passkeys_conforms() {
    conformance(Box::new(Passkeys::new()));
}

#[test]
fn auth_passkeys_deps_are_wasm_safe() {
    // The whole reason relying-party verification is hand-written (ADR
    // 0100): upstream webauthn-rs pulls OpenSSL and cannot reach wasm32.
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
