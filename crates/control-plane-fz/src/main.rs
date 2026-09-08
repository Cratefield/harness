//! The control-plane venture's `fz` (epic #1): `fz migrations collect`/`doctor`
//! need to link this venture's own harness to see its modules. Composes the
//! console module over an `AllPorts` runtime (fz reads module metadata, not
//! live bindings) and hands it to the CLI.

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
        .runtime(AllPorts)
        .build()
        .expect("the control-plane venture is a valid harness")
}

fn main() {
    cratefield_cli::main_for(harness);
}
