//! The public conformance kit, run against the private module (issue #2, #6).

use fz_module_linkedin::Linkedin;

#[test]
fn passes_the_public_conformance_suite() {
    cratefield_testing::conformance(Box::new(Linkedin::new()));
}

#[test]
fn stays_wasm_safe() {
    cratefield_testing::assert_wasm_safe_deps("fz-module-linkedin");
}
