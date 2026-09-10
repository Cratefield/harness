//! `Native::push_from_env()` and the report it does — and does not — make
//! (issue #191).
//!
//! The `push` feature is off by default; `examples/venture-native` turns it
//! on, so a workspace build has it. These tests are compiled out without it
//! rather than failing to build.

#![cfg(feature = "push")]

use std::sync::Arc;

use cratefield_core::{Port, Push, RoutingPush, Runtime};
use cratefield_runtime_native::Native;

/// Stands in for an adapter the venture passed itself.
fn mine() -> Arc<dyn Push> {
    Arc::new(RoutingPush::new())
}

#[test]
fn an_explicit_adapter_wins_and_the_environment_is_not_even_read() {
    // `push_wiring()` used to build the whole env stack anyway — parsing a
    // `.p8`, an RSA key and a VAPID scalar for three adapters nothing will
    // serve with — and then report `apns=configured` although the venture's
    // own adapter serves. In production a half-wired environment then
    // failed the deploy for transports it had deliberately overridden.
    let runtime = Native::new().push_arc(mine()).push_from_env();
    assert!(
        runtime.push_wiring().is_none(),
        "an environment nothing reads has nothing to report"
    );
    assert!(runtime.provides().contains(&Port::Push));
}

#[test]
fn without_an_explicit_adapter_the_environment_is_what_serves() {
    let runtime = Native::new().push_from_env();
    let wiring = runtime
        .push_wiring()
        .expect("push_from_env reports what it found");
    // Whatever this machine's environment holds, the report covers all
    // three transports and the port is provided either way.
    assert_eq!(wiring.iter().count(), 3, "{}", wiring.summary());
    assert!(runtime.provides().contains(&Port::Push));
}

#[test]
fn a_venture_that_never_asked_reports_nothing() {
    let runtime = Native::new();
    assert!(runtime.push_wiring().is_none());
    assert!(!runtime.provides().contains(&Port::Push));
}
