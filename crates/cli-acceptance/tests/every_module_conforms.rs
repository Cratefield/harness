//! Every module in the workspace runs the shared conformance suite.
//!
//! `cratefield_testing::conformance` is where a module's cross-cutting
//! rules are checked at all: that its declared tables match its
//! migrations, that every declared table has a `personal_data()` entry,
//! that its routes carry the visibility and scope the harness expects,
//! that a `well_known()` router mounts where it says. None of that is
//! checked anywhere else, so a module without the suite is a module with
//! none of it.
//!
//! `cratefield-console`'s own conformance file records what that costs:
//! *"until this file existed the module owned five tables and was checked
//! by nothing."* It was fixed for that crate, and `cratefield-chrome` —
//! composed into the control plane two lines below it — was missed. It
//! had no `tests/` directory at all.
//!
//! Nothing failed. Nothing could: a missing test file is not a failing
//! one. So the rule is here, where a missing file is the failure.

mod common;

use std::path::Path;

use common::repo_root;

/// The `name = "..."` of a manifest's `[package]` section.
fn package_name(manifest: &str) -> Option<String> {
    let package = manifest.find("[package]")?;
    let rest = &manifest[package..];
    let at = rest.find("\nname")?;
    let line = rest[at + 1..].lines().next()?;
    Some(line.split('=').nth(1)?.trim().trim_matches('"').to_owned())
}

/// Crates that implement [`Module`] for something other than a module a
/// venture composes, and so have nothing for the suite to run over.
///
/// Both are the machinery itself: `cratefield-core` declares the trait and
/// implements it in doc examples and unit-test fixtures, and
/// `cratefield-testing` implements it for the probe the suite drives. A
/// third name here would want a sentence saying why.
const NOT_COMPOSABLE: &[&str] = &["cratefield-core", "cratefield-testing"];

/// Every workspace crate whose `src/` implements `Module` outside a test
/// module, paired with whether its `tests/` call the suite.
fn modules() -> Vec<(String, bool)> {
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
        if NOT_COMPOSABLE.contains(&package.as_str()) {
            continue;
        }
        if !implements_module(&dir.join("src")) {
            continue;
        }
        found.push((package, runs_conformance(&dir.join("tests"))));
    }
    found.sort();
    found
}

/// Whether any `.rs` under `dir` has a top-level `impl Module for`.
///
/// Top-level: the line is not indented. Every fixture in this workspace
/// lives inside a `mod tests`, so it is indented, and every real module
/// implements the trait at column zero. Crude, and the self-check below
/// is what notices when it stops being true.
fn implements_module(dir: &Path) -> bool {
    sources(dir).iter().any(|source| {
        source
            .lines()
            .any(|line| line.starts_with("impl Module for"))
    })
}

/// Whether any `.rs` under `dir` calls the shared suite.
fn runs_conformance(dir: &Path) -> bool {
    sources(dir).iter().any(|source| {
        source.contains("conformance(Box::new(") || source.contains("conformance_in_process_only(")
    })
}

/// Every `.rs` file under `dir`, read. Missing directory reads as empty,
/// which is the case this whole file is about.
fn sources(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            out.extend(sources(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs")
            && let Ok(text) = std::fs::read_to_string(&path)
        {
            out.push(text);
        }
    }
    out
}

#[test]
fn the_scan_finds_the_modules_that_exist() {
    // "No module is unchecked" is an absence, and an empty list satisfies
    // it. These are modules the workspace certainly has; if the scan stops
    // seeing them it is seeing nothing.
    let modules = modules();
    let names: Vec<&str> = modules.iter().map(|(name, _)| name.as_str()).collect();
    for expected in [
        "cratefield-chrome",
        "cratefield-console",
        "cratefield-module-waitlist",
        "factory0-auth-core",
    ] {
        assert!(
            names.contains(&expected),
            "the scan no longer sees {expected} as a module; it found {names:?}"
        );
    }
    assert!(
        modules.len() >= 12,
        "only {} modules found — the scan is reading nothing: {names:?}",
        modules.len()
    );
}

#[test]
fn every_module_runs_the_shared_conformance_suite() {
    let unchecked: Vec<String> = modules()
        .into_iter()
        .filter(|(_, runs)| !runs)
        .map(|(name, _)| name)
        .collect();
    assert!(
        unchecked.is_empty(),
        "these crates implement `Module` and run none of the shared conformance checks: \
         {unchecked:?}. Add `tests/conformance.rs` calling \
         `cratefield_testing::conformance(Box::new(<Module>))` — a module without it has its \
         table declarations, personal-data entries, route visibility and well-known mount \
         checked by nothing, and a missing test file never fails."
    );
}

#[test]
fn the_check_fires_on_a_module_with_no_suite() {
    // The test above passes on a clean tree and would also pass on a
    // predicate that always says yes. `runs_conformance` over a directory
    // that does not exist is the exact case `cratefield-chrome` was in.
    let root = repo_root();
    assert!(
        !runs_conformance(&root.join("crates/control-plane-chrome/no-such-directory")),
        "a directory that does not exist reads as running the suite"
    );
    assert!(
        runs_conformance(&root.join("crates/control-plane-chrome/tests")),
        "chrome's own conformance test is not detected"
    );
    assert!(
        implements_module(&root.join("crates/control-plane-chrome/src")),
        "chrome is not detected as implementing Module"
    );
}
