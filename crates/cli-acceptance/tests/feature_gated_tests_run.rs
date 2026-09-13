//! A test gated on an off-by-default feature runs somewhere, or it runs
//! nowhere.
//!
//! `cargo test --workspace` builds default features, so a test file that
//! opens with `#![cfg(feature = "push")]` compiles to an empty binary and
//! reports `0 passed`. Nothing fails, nothing is skipped, and no output
//! distinguishes "three tests passed" from "three tests were compiled
//! away" — the run just says `ok`.
//!
//! That is how `crates/runtime-native/tests/push_wiring.rs` sat in the
//! tree with three tests that had never executed in CI: `push` is off by
//! default and no job enabled it. Found by reading the gates rather than
//! by anything going red, which is the point of this file.
//!
//! The rule: every feature that gates a whole test target has a CI step
//! that turns it on for that package. Checked against the workflow text,
//! the same way `tools/doc-commands.sh` checks documented commands.

mod common;

use std::path::{Path, PathBuf};

use common::repo_root;

/// One test target that is gated in full, and the feature gating it.
#[derive(Debug, PartialEq, Eq)]
struct GatedTarget {
    package: String,
    file: String,
    feature: String,
}

/// The `name = "..."` of a manifest's `[package]` section.
fn package_name(manifest: &str) -> Option<String> {
    let package = manifest.find("[package]")?;
    let rest = &manifest[package..];
    let at = rest.find("\nname")?;
    let line = rest[at + 1..].lines().next()?;
    Some(line.split('=').nth(1)?.trim().trim_matches('"').to_owned())
}

/// Every `crates/*/tests/*.rs` whose *file-level* attribute gates the
/// whole target — `#![cfg(feature = "x")]`, not a `#[cfg]` on one item.
/// A file-level gate is the one that silently empties a whole binary.
fn gated_targets() -> Vec<GatedTarget> {
    let root = repo_root();
    let mut found = Vec::new();
    let Ok(crates) = std::fs::read_dir(root.join("crates")) else {
        return found;
    };
    for entry in crates.flatten() {
        let dir = entry.path();
        let Ok(manifest) = std::fs::read_to_string(dir.join("Cargo.toml")) else {
            continue;
        };
        let Some(package) = package_name(&manifest) else {
            continue;
        };
        let Ok(tests) = std::fs::read_dir(dir.join("tests")) else {
            continue;
        };
        for test in tests.flatten() {
            let path = test.path();
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let Ok(source) = std::fs::read_to_string(&path) else {
                continue;
            };
            if let Some(feature) = file_level_feature_gate(&source) {
                found.push(GatedTarget {
                    package: package.clone(),
                    file: relative(&root, &path),
                    feature,
                });
            }
        }
    }
    found.sort_by(|a, b| (&a.package, &a.file).cmp(&(&b.package, &b.file)));
    found
}

/// The feature in a `#![cfg(feature = "…")]` inner attribute, if the file
/// has one. Only inner attributes (`#!`) gate the whole target.
fn file_level_feature_gate(source: &str) -> Option<String> {
    source
        .lines()
        .filter(|line| line.trim_start().starts_with("#!["))
        .find_map(|line| {
            let (_, rest) = line.split_once("cfg(feature = \"")?;
            let (feature, _) = rest.split_once('"')?;
            Some(feature.to_owned())
        })
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

fn workflows() -> Vec<PathBuf> {
    let dir = repo_root().join(".github/workflows");
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "yml"))
        .collect();
    found.sort();
    found
}

#[test]
fn the_scan_finds_the_gated_targets_that_exist() {
    // Everything below is "no gated target is unrun", which an empty list
    // satisfies for free. This one says the list is not empty and still
    // holds the target that prompted the whole file.
    let gated = gated_targets();
    assert!(
        gated.iter().any(|target| {
            target.package == "cratefield-runtime-native" && target.feature == "push"
        }),
        "the scan no longer sees runtime-native's push-gated tests; it found {gated:?}"
    );
}

#[test]
fn every_fully_gated_test_target_is_run_by_a_workflow() {
    let gated = gated_targets();
    let workflows: Vec<String> = workflows()
        .iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .collect();

    for target in &gated {
        // The step that would run it: a `cargo test` naming this package
        // and either this feature or `--all-features`.
        let run = workflows.iter().any(|text| {
            text.lines().any(|line| {
                let line = line.trim();
                line.contains("cargo test")
                    && line.contains(&format!("-p {}", target.package))
                    && (line.contains(&format!("--features {}", target.feature))
                        || line.contains(&format!("--features \"{}\"", target.feature))
                        || line.contains("--all-features"))
            })
        });
        assert!(
            run,
            "{} is gated on `{}`, which is off by default, and no workflow step runs \
             `cargo test -p {} --features {}`. The workspace run compiles this file to an \
             empty binary and reports `0 passed`, so nothing tells you the tests never ran.",
            target.file, target.feature, target.package, target.feature
        );
    }
}

#[test]
fn the_coverage_check_fires_on_a_target_nothing_runs() {
    // The test above passes on a clean tree and would also pass on a
    // predicate that always says yes. This drives the predicate over a
    // package no workflow mentions.
    let workflows: Vec<String> = workflows()
        .iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .collect();
    let covered = |package: &str, feature: &str| {
        workflows.iter().any(|text| {
            text.lines().any(|line| {
                let line = line.trim();
                line.contains("cargo test")
                    && line.contains(&format!("-p {package}"))
                    && (line.contains(&format!("--features {feature}"))
                        || line.contains("--all-features"))
            })
        })
    };
    assert!(
        covered("cratefield-runtime-native", "push"),
        "the real case is not detected as covered"
    );
    assert!(
        !covered("cratefield-not-a-crate", "imaginary"),
        "the predicate says yes to a package no workflow names"
    );
}
