//! The shared conformance suite for `cratefield-chrome`.
//!
//! It is composed into the control plane at `crates/control-plane/src/lib.rs`
//! beside `Console` and `Dashboard`, both of which run this suite. This
//! crate had no `tests/` directory at all — the only `impl Module` in the
//! workspace that ran none of the shared checks.

use cratefield_chrome::Chrome;
use cratefield_testing::{assert_wasm_safe_deps, conformance};

#[test]
fn chrome_conforms() {
    conformance(Box::new(Chrome));
}

#[test]
fn chrome_deps_are_wasm_safe() {
    // The control plane is itself a harness venture, so its modules are
    // held to the same dependency boundary as any other (ADR 0001).
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
