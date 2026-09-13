//! A path a document points at is a path that exists.
//!
//! Documentation goes stale in two ways. One is a claim that is no longer
//! true, which no tool can check. The other is a pointer that no longer
//! lands — `crates/venture` after the crate was renamed, `docs/PRICING.md`
//! for a file that sits under `docs/control-plane/` — and that one is
//! mechanical, so it should not be anybody's job to notice.
//!
//! It is worth checking because a pointer is load-bearing. The
//! control-plane architecture ADR described a layout from before the
//! repositories were folded together (#166), and the first sign was that
//! the paths in it did not resolve. `docs/control-plane/ROADMAP.md` cited
//! `docs/PRICING.md` three times as the authority for what the free tier
//! includes, and there is no such file.
//!
//! Only paths that begin with a known top-level directory are checked,
//! and only inside backticks. A bare word in prose is prose.

mod common;

use std::path::{Path, PathBuf};

use common::repo_root;

/// The top-level directories a citation can start with. Anything else in
/// backticks is a crate name, a command or a fragment of prose.
const ROOTS: &[&str] = &[
    "crates/",
    "docs/",
    "examples/",
    "ventures/",
    "tools/",
    "bench/",
    "spikes/",
    ".github/",
];
// `migrations/` is deliberately absent: it is a path *inside* a generated
// venture, never one at this repository's root, so checking it here would
// report every correct citation as broken. That is not a hypothetical —
// this guard's first run said exactly that about nine of them.

/// Every markdown file worth checking: the design docs and the ADRs, plus
/// each crate's README, which is also its docs.rs front page.
fn documents(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    collect_markdown(&root.join("docs"), &mut found);
    if let Ok(crates) = std::fs::read_dir(root.join("crates")) {
        for entry in crates.flatten() {
            let readme = entry.path().join("README.md");
            if readme.is_file() {
                found.push(readme);
            }
        }
    }
    let readme = root.join("README.md");
    if readme.is_file() {
        found.push(readme);
    }
    found.sort();
    found
}

fn collect_markdown(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            collect_markdown(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "md") {
            out.push(path);
        }
    }
}

/// Every backticked path citation in `text`, with the line it is on.
fn citations(text: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let mut rest = line;
        while let Some(open) = rest.find('`') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('`') else {
                break;
            };
            let inner = &after[..close];
            if ROOTS.iter().any(|root| inner.starts_with(root))
                // A glob is a shape, not a file.
                && !inner.contains('*')
                // A path with a suffix the prose added, like `docs/X.md §4`.
                && !inner.contains(' ')
                // `ventures/<venture>/` names a shape a reader fills in.
                && !inner.contains('<')
            {
                found.push((number + 1, inner.to_owned()));
            }
            rest = &after[close + 1..];
        }
    }
    found
}

#[test]
fn the_scan_finds_the_citations_that_exist() {
    // "Every citation resolves" is satisfied by there being none, and a
    // changed markdown convention would produce exactly that.
    let root = repo_root();
    let total: usize = documents(&root)
        .iter()
        .filter_map(|doc| std::fs::read_to_string(doc).ok())
        .map(|text| citations(&text).len())
        .sum();
    assert!(
        total >= 100,
        "only {total} path citations found across the documentation — the scan is reading nothing"
    );
}

#[test]
fn every_path_a_document_points_at_exists() {
    let root = repo_root();
    let mut broken = Vec::new();
    for doc in documents(&root) {
        let Ok(text) = std::fs::read_to_string(&doc) else {
            continue;
        };
        for (line, cited) in citations(&text) {
            // A trailing slash means a directory, which `exists` handles;
            // both forms are checked the same way.
            if !root.join(&cited).exists() {
                let shown = doc
                    .strip_prefix(&root)
                    .unwrap_or(&doc)
                    .display()
                    .to_string();
                broken.push(format!("{shown}:{line} points at `{cited}`"));
            }
        }
    }
    assert!(
        broken.is_empty(),
        "documentation points at paths that do not exist:\n  {}",
        broken.join("\n  ")
    );
}

#[test]
fn the_check_fires_on_a_path_that_is_gone() {
    // The test above passes on a clean tree and would also pass on a
    // scan that extracts nothing or a predicate that always says yes.
    let root = repo_root();
    let found = citations("see `crates/core/src/lib.rs` and `crates/gone/src/lib.rs`");
    assert_eq!(found.len(), 2, "the extractor missed a citation: {found:?}");
    assert!(root.join(&found[0].1).exists(), "a real path reads as gone");
    assert!(
        !root.join(&found[1].1).exists(),
        "an invented path reads as present"
    );

    // And the things that are deliberately not citations stay out.
    assert!(
        citations("a `cratefield-core` crate, a `cargo test` command").is_empty(),
        "a crate name or a command was taken for a path"
    );
    assert!(
        citations("every `crates/*/README.md`").is_empty(),
        "a glob was taken for a path"
    );
}
