//! The shared conformance suite (issues #244, #272, #280) for
//! `cratefield-console`: until this file existed the module owned five
//! tables and was checked by nothing.

use cratefield_console::Console;
use cratefield_testing::{assert_wasm_safe_deps, conformance};

#[test]
fn console_conforms() {
    conformance(Box::new(Console));
}

#[test]
fn console_deps_are_wasm_safe() {
    // The control plane is itself a harness venture, so its modules are
    // held to the same dependency boundary as any other (ADR 0001).
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
