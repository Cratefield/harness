//! The wasm dependency boundary, as for every adapter. There is no module
//! conformance suite for an adapter: `TextModel` is a trait module, not yet
//! a `Port` with a shared fake, so the adapter's own acceptance tests carry
//! the behaviour (issue #430).

use cratefield_testing::assert_wasm_safe_deps;

#[test]
fn anthropic_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
