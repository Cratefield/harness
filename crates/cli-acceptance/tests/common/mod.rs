//! What more than one acceptance test needs, in one place.
//!
//! `tests/` is one binary per file, so a helper copied into three of them
//! is three copies that drift — `repo_root`'s `.nth(2)` was already written
//! out three times, and it is exactly the kind of constant that is wrong
//! everywhere at once when this crate moves.
//!
//! That same one-binary-per-file rule compiles this module into every test
//! that includes it, so a helper only two of them need is "never used" in
//! the rest. Hence the allow: it is about how `tests/` is built, not about
//! anything here being unused.
#![allow(dead_code)]

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

/// Every `.rs` file under `dir`, tracked or not — an untracked new file is
/// exactly the one a guard must still see.
///
/// Symlinks are never followed. `Path::is_dir` follows them, and a working
/// tree that holds a symlink to one of its own ancestors — a `docs/` link
/// back to the root, a `target` link into a shared cache — then recurses
/// until the stack runs out, which is a crashed test binary and not a
/// guard result. `DirEntry::file_type` reads the entry itself.
///
/// Shared, because there is more than one guard walking the workspace now
/// and a copied walker is a walker that stops matching the one that is
/// tested.
pub fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            // Build output and VCS internals are not sources.
            if matches!(name.as_ref(), "target" | ".git" | "node_modules" | "build") {
                continue;
            }
            rust_sources(&path, out);
        } else if file_type.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// A workspace-relative, forward-slashed path, for a guard's own messages
/// and for the prefix tests that decide what is exempt.
pub fn relative_to(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}
