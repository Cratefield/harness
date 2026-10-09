//! The shared conformance suite (issue #9) plus the wasm dependency
//! boundary (ADR 0001) for `cratefield-module-guardrails`.
//!
//! The engine is ports over in-memory fakes, so the module mounts with no
//! adapter at all — the same trick the conformance suite runs elsewhere.

mod support;

use cratefield_module_guardrails::GuardrailsModule;
use cratefield_testing::{assert_wasm_safe_deps, conformance};

use support::{Rig, rig};

fn module() -> GuardrailsModule {
    let Rig { engine, .. } = rig();
    GuardrailsModule::new(std::sync::Arc::new(engine))
}

#[test]
fn guardrails_conforms() {
    conformance(Box::new(module()));
}

#[test]
fn guardrails_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
