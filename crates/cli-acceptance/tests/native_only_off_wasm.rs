//! No wasm artefact depends on a native-only crate — checked where the
//! check can actually run.
//!
//! `cratefield-runtime-native` and `cratefield-adapter-postgres` each carry
//! a `#[cfg(target_arch = "wasm32")] compile_error!` saying so, and **neither
//! has ever fired.** Cargo builds a crate's dependencies before the crate
//! itself, so a wasm build of either dies inside a dependency first:
//!
//! ```text
//! $ cargo check -p cratefield-runtime-native --target wasm32-unknown-unknown
//! error: This wasm target is unsupported by mio. If using Tokio, disable the net feature.
//!
//! $ cargo check -p cratefield-adapter-postgres --target wasm32-unknown-unknown
//! error: The wasm32/64-unknown-unknown are not supported by default; you may
//!        need to enable the "wasm_js" crate feature.
//! ```
//!
//! Those are exactly the confusing failures the guards were written to
//! replace, and the carefully worded message never reaches anybody. A
//! `build.rs` does not rescue it either — cargo aborts on the dependency
//! before the build script's failure is reported; that was tried.
//!
//! So the rule lives here instead, where it runs on the host in
//! milliseconds and can say what is wrong. `cargo tree --target
//! wasm32-unknown-unknown` resolves the graph without compiling anything,
//! which is the whole point: the question is "is this crate reachable",
//! and reachability is answerable without asking whether it builds.
//!
//! Same shape as `getrandom_wasm_js_guard.rs` and `wasm_dispatcher_guard.rs`:
//! the rule is a test, and the test proves its own detector fires.

mod common;

use common::{repo_root, workspace_manifests};
use std::path::PathBuf;

/// Every workspace manifest, collected. `common::workspace_manifests`
/// pushes into a caller's vector; these three scans each want the whole
/// list.
fn manifests() -> Vec<PathBuf> {
    let mut out = Vec::new();
    workspace_manifests(&repo_root(), &mut out);
    out
}

/// The crates that declare themselves native-only, read from the guards
/// rather than listed here — a third crate that adds the `compile_error!`
/// is covered the day it is added, and a rename cannot leave this list
/// pointing at a name nothing has.
fn native_only_crates() -> Vec<String> {
    let mut found = Vec::new();
    for manifest in manifests() {
        let Some(dir) = manifest.parent() else {
            continue;
        };
        let lib = dir.join("src/lib.rs");
        let Ok(source) = std::fs::read_to_string(&lib) else {
            continue;
        };
        // The guard's own shape: a wasm cfg immediately above a
        // `compile_error!`. Matching the text rather than parsing keeps
        // this readable, and the self-check below fails if it stops
        // matching.
        let Some(at) = source.find("compile_error!") else {
            continue;
        };
        if !source[..at].rsplit('\n').take(3).any(|line| {
            line.contains("cfg") && line.contains("target_arch") && line.contains("wasm")
        }) {
            continue;
        }
        let Ok(manifest_text) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        if is_detached(&manifest_text) {
            continue;
        }
        if let Some(name) = package_name(&manifest_text) {
            found.push(name);
        }
    }
    found.sort();
    found
}

/// Whether a manifest detaches itself from this workspace with its own
/// `[workspace]` table. `spikes/` does that on purpose (ADR 0013), and a
/// detached crate is not resolvable with `cargo tree -p` from here — it
/// also ships no artefact, so it is not this guard's business.
fn is_detached(manifest: &str) -> bool {
    manifest
        .lines()
        .any(|line| line.trim_start().starts_with("[workspace]"))
}

/// The `name = "..."` of a manifest's `[package]` section.
fn package_name(manifest: &str) -> Option<String> {
    let package = manifest.find("[package]")?;
    let rest = &manifest[package..];
    let at = rest.find("\nname")?;
    let line = rest[at + 1..].lines().next()?;
    let value = line.split('=').nth(1)?.trim();
    Some(value.trim_matches('"').to_owned())
}

/// Every package that produces a wasm artefact: a `cdylib` is a Worker, a
/// browser bundle or a sidecar, and nothing else in this workspace builds
/// one.
fn wasm_packages() -> Vec<String> {
    let mut found = Vec::new();
    for manifest in manifests() {
        let Ok(text) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        if !text.contains("cdylib") || is_detached(&text) {
            continue;
        }
        if let Some(name) = package_name(&text) {
            found.push(name);
        }
    }
    found.sort();
    found
}

/// `cargo tree` for one package, resolved for wasm. No compilation.
fn wasm_tree(package: &str) -> String {
    let output =
        std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args([
                "tree",
                "-p",
                package,
                "--target",
                "wasm32-unknown-unknown",
                "--edges",
                "normal",
            ])
            .current_dir(repo_root())
            .output()
            .unwrap_or_else(|err| panic!("cargo tree failed for {package}: {err}"));
    assert!(
        output.status.success(),
        "cargo tree failed for {package}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn the_detector_finds_the_crates_that_declare_themselves_native_only() {
    // The assertion below this one is an absence, and an absence over an
    // empty list is free. These two are the crates that carry the guard
    // today; if the scan stops finding them it is finding nothing.
    let native = native_only_crates();
    for expected in ["cratefield-adapter-postgres", "cratefield-runtime-native"] {
        assert!(
            native.iter().any(|name| name == expected),
            "the scan no longer sees {expected}'s wasm guard; it found {native:?}"
        );
    }
}

#[test]
fn every_wasm_package_is_found_and_named() {
    // Same reason: a tree that came back empty, or a package list that
    // came back empty, would satisfy the reachability assertion without
    // looking at anything.
    let packages = wasm_packages();
    assert!(
        packages.len() >= 5,
        "only {} wasm packages found — the scan is looking at nothing: {packages:?}",
        packages.len()
    );
    for package in &packages {
        let tree = wasm_tree(package);
        assert!(
            tree.contains(package.as_str()),
            "the wasm tree for {package} does not name it:\n{tree}"
        );
    }
}

#[test]
fn no_wasm_package_can_reach_a_native_only_crate() {
    let native = native_only_crates();
    let packages = wasm_packages();
    for package in &packages {
        let tree = wasm_tree(package);
        for forbidden in &native {
            // A trailing space so `cratefield-adapter-postgres` cannot be
            // matched by a longer name that starts the same way.
            assert!(
                !tree.contains(&format!("{forbidden} ")),
                "{package} reaches {forbidden}, which cannot be built for wasm. \
                 The compile would fail inside one of that crate's own \
                 dependencies with an unrelated message, which is why this is \
                 checked here.\n{tree}"
            );
        }
    }
}

#[test]
fn the_reachability_check_fires_on_a_tree_that_has_one() {
    // The three tests above pass on a clean workspace and would also pass
    // on a broken detector. This drives the predicate itself over a tree
    // that does contain a native-only crate.
    let native = native_only_crates();
    let forbidden = native.first().expect("at least one native-only crate");
    let clean = "venture v0.1.1\n├── cratefield-core v0.5.0\n";
    let dirty = format!("venture v0.1.1\n├── {forbidden} v0.1.4\n");
    let hit = |tree: &str| tree.contains(&format!("{forbidden} "));
    assert!(!hit(clean), "the predicate fires on a clean tree");
    assert!(hit(&dirty), "the predicate misses a native-only crate");
}
