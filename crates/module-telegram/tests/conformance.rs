//! The shared conformance suite (issue #9) plus the wasm dependency
//! boundary (ADR 0001) for `cratefield-module-telegram`.

use cratefield_module_telegram::{Telegram, TelegramEvents};
use cratefield_testing::{assert_wasm_safe_deps, conformance};

#[test]
fn telegram_conforms() {
    conformance(Box::new(Telegram::new(TelegramEvents::new())));
}

/// The module ships to `wasm32-unknown-unknown` inside a venture's Worker,
/// so nothing in its normal dependency tree may be native-only.
#[test]
fn telegram_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
