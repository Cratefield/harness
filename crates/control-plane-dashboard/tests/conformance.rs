//! The shared conformance suite (issues #244, #272, #280) for
//! `cratefield-dashboard`: it owns exactly one table, and until this file
//! existed even that one was outside export, erasure and the
//! migrations-versus-`tables()` check.

use cratefield_dashboard::Dashboard;
use cratefield_testing::{assert_wasm_safe_deps, conformance};

#[test]
fn dashboard_conforms() {
    // No KMS wired: the secrets screen then takes its honest no-KMS
    // state, which is also a composition the conformance kit must
    // accept without a store ever being opened.
    conformance(Box::new(Dashboard::default()));
}

#[test]
fn dashboard_deps_are_wasm_safe() {
    // The control plane is itself a harness venture, so its modules are
    // held to the same dependency boundary as any other (ADR 0001).
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
