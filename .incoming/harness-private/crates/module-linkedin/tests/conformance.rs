//! The public conformance kit, run against the private module (issue #2, #6).

use fz_module_linkedin::Linkedin;

#[test]
fn passes_the_public_conformance_suite() {
    factory0_testing::conformance(Box::new(Linkedin::new()));
}

#[test]
fn stays_wasm_safe() {
    factory0_testing::assert_wasm_safe_deps("fz-module-linkedin");
}
