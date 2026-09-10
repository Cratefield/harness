//! The shared conformance suite (issue #9) and the wasm-safety check every
//! module runs.

use cratefield_module_notifications::Notifications;
use cratefield_testing::{assert_wasm_safe_deps, conformance};

#[test]
fn notifications_conforms() {
    conformance(Box::new(
        Notifications::new().categories(["booking", "room_starting"]),
    ));
}

/// The module ships to `wasm32-unknown-unknown` inside a venture's Worker,
/// so nothing in its normal dependency tree may be native-only.
#[test]
fn notifications_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
