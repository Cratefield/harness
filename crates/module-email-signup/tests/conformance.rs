//! The shared conformance suite (issue #9) plus the wasm dependency
//! boundary (ADR 0001) for `factory0-module-email-signup`.

use factory0_module_email_signup::EmailSignup;
use factory0_testing::{assert_wasm_safe_deps, conformance};

#[test]
fn email_signup_conforms() {
    conformance(Box::new(EmailSignup::new()));
}

#[test]
fn email_signup_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
