//! `fz` standalone binary. Most `fz` commands run inside a venture repo
//! where the binary links the venture's compiled-in harness (see the
//! library docs). The one exception is `fz build <manifest>`, which
//! *generates* a venture from a manifest and so needs no harness — that is
//! what this standalone binary (and the Docker image) exists to run.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    cratefield_cli::run_standalone(std::env::args().skip(1))
}
