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
// A test-support module, included with `mod support;` (or `mod common;`)
// into each test binary in this crate. `pub` is how a helper reads here,
// and the lint is right that nothing outside can reach it — the module is
// private to every binary that includes it. Saying so once beats
// `pub(crate)` on forty helpers.
#![allow(unreachable_pub)]

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

/// Every `Cargo.toml` under `dir`, tracked or not — same walker rules as
/// [`rust_sources`], same reason: an untracked new crate is exactly the one
/// a manifest guard must still see.
pub fn workspace_manifests(dir: &Path, out: &mut Vec<PathBuf>) {
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
            if matches!(name.as_ref(), "target" | ".git" | "node_modules" | "build") {
                continue;
            }
            workspace_manifests(&path, out);
        } else if file_type.is_file() && name.as_ref() == "Cargo.toml" {
            out.push(path);
        }
    }
}

/// The text of one dependency's entry in a manifest, from the key at
/// `key_offset` to the line that starts the next key or section header.
///
/// Deliberately line-based rather than a TOML parse: what a feature guard
/// reads — `workspace = true`, `default-features = false`, `"wasm_js"` —
/// is plain text inside the entry. An entry formatted across a key-looking
/// line gets a loud failure, not a guard that is wrong quietly.
pub fn dependency_entry(source: &str, key_offset: usize) -> &str {
    let rest = &source[key_offset..];
    let mut cursor = 0;
    while let Some(at) = rest[cursor..].find('\n') {
        let line = &rest[cursor..cursor + at];
        if cursor > 0 {
            let trimmed = line.trim();
            if trimmed.starts_with('[') || (trimmed.contains('=') && !trimmed.starts_with('#')) {
                return &rest[..cursor];
            }
        }
        cursor += at + 1;
    }
    rest
}

/// The most recent section header above `key_offset`, e.g.
/// `[target.'cfg(not(target_arch = "wasm32"))'.dependencies]`.
pub fn enclosing_section(source: &str, key_offset: usize) -> Option<&str> {
    source[..key_offset]
        .rmatch_indices('\n')
        .find_map(|(at, _)| {
            let line_start = source[..at].rfind('\n').map_or(0, |prev| prev + 1);
            let line = source[line_start..at].trim();
            line.starts_with('[').then_some(line)
        })
}
