//! What more than one acceptance test needs, in one place.
//!
//! `tests/` is one binary per file, so a helper copied into three of them
//! is three copies that drift — `repo_root`'s `.nth(2)` was already written
//! out three times, and it is exactly the kind of constant that is wrong
//! everywhere at once when this crate moves.

use std::path::{Path, PathBuf};

/// The repository root: two levels above `crates/cli-acceptance`.
///
/// The guards walk the whole working tree from here, so a wrong answer is a
/// guard that quietly checks nothing.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repo root is two levels above this crate")
        .to_path_buf()
}
