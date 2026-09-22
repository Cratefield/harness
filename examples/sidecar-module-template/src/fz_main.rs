//! The venture-side `fz` bin, per the `cratefield-cli` docs pattern: the
//! CLI must see the compiled-in harness, so it is linked into this crate
//! rather than installed. This is what makes `fz migrations collect`
//! (which writes `migrations/`) and `fz doctor` work in the template.
//!
//! The bin is named `sidecar-fz`, not `fz`: the generated
//! `examples/tables-canary` already owns `fz` in this workspace, and two
//! bins with one name collide at `target/debug/fz` (issue #447).

fn main() {
    cratefield_cli::main_for(sidecar_module_template::harness::harness);
}
