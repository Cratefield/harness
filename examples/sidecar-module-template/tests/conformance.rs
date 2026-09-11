//! The conformance kit (issue #9), run against the module exactly as the
//! Worker serves it.
//!
//! Note the boundary this suite does *not* check:
//! `assert_wasm_safe_deps` is for module crates, whose dependency tree
//! must stay free of `worker`/`tokio`. This crate is a *Worker*, so it
//! legitimately links the `worker` runtime — the wasm boundary is proven
//! by the CI leg that runs `worker-build --release`, the same way the
//! example venture's is.

use cratefield_testing::conformance;
use sidecar_module_template::module::Notes;

#[test]
fn notes_conforms() {
    conformance(Box::new(Notes::new()));
}
