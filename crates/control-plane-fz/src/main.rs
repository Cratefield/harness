//! The control-plane venture's `fz` (epic #1): `fz migrations collect`/`doctor`
//! need to link this venture's own harness to see its modules. Composes the
//! venture's modules over an `AllPorts` runtime (fz reads module metadata,
//! not live bindings) and hands it to the CLI.
//!
//! **The module list here must match `crates/control-plane/src/lib.rs`.** It
//! did not: the dashboard was mounted in the Worker and in neither of the two
//! binaries that operate it, so `collect` never wrote the `connection` table's
//! migration and the deployed screen would have read a table nothing created.

use cratefield_core::{Harness, Port, Runtime, Venture};

struct AllPorts;

impl Runtime for AllPorts {
    fn provides(&self) -> Vec<Port> {
        Port::ALL.to_vec()
    }
}

fn harness() -> Harness {
    Harness::builder()
        .venture(
            Venture::new("cratefield-control-plane", "cratefield.com")
                .public_url("https://app.cratefield.com")
                .cors_origins(["https://app.cratefield.com"]),
        )
        .module(cratefield_console::Console)
        .module(cratefield_dashboard::Dashboard)
        .runtime(AllPorts)
        .build()
        .expect("the control-plane venture is a valid harness")
}

fn main() {
    cratefield_cli::main_for(harness);
}
