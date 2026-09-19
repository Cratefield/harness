//! `Native` reports the `TextModel` port it is handed (issue #429).
//!
//! The runtime's `provides()` is hand-written `if`s — the shape that once
//! lost `Port::Auth` out of `Ports::provides` — so the wired direction gets
//! its own assertion, the way `push_wiring.rs` buys it for `Port::Push`:
//! a runtime that holds an adapter must say it provides the port, or a
//! module requiring `TextModel` is refused a build it could have served.

use std::sync::Arc;

use cratefield_core::{Port, RoutingTextModel, Runtime, TextModel};
use cratefield_runtime_native::Native;

/// Stands in for an adapter the venture passed itself.
fn mine() -> Arc<dyn TextModel> {
    Arc::new(RoutingTextModel::new())
}

#[test]
fn a_runtime_with_an_adapter_provides_the_port() {
    let runtime = Native::new().text_model_arc(mine());
    assert!(runtime.provides().contains(&Port::TextModel));
}

#[test]
fn a_runtime_without_one_does_not() {
    let runtime = Native::new();
    assert!(!runtime.provides().contains(&Port::TextModel));
}
