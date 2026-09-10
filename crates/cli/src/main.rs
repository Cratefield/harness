//! `fz` standalone binary. Most `fz` commands run inside a venture repo
//! where the binary links the venture's compiled-in harness (see the
//! library docs). The exceptions are the commands that need no harness,
//! and this binary (with the Docker image) is what runs them:
//! `fz build <manifest>`, which *generates* a venture from a manifest; the
//! manifest workflow — `fz plan` / `deploy` / `add` / `init` / `verify`
//! (harness #140) — which works on the manifest and its on-disk records;
//! and `fz push` (issue #184), which reads the venture's environment.
//! `cratefield_cli::harness_free` is the single seam that decides, and the
//! refusal this binary prints is written from the same list.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    cratefield_cli::run_standalone(std::env::args().skip(1))
}
