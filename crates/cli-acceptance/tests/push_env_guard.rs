//! One reader for the push environment, enforced rather than asserted
//! (issue #191).
//!
//! `serve()`, `fz push send` and `fz doctor` all have to answer the same
//! question — which push transports did this venture configure — and if each
//! reads the environment itself they drift on a variable name. The drift is
//! invisible: the doctor reports a healthy deployment while every Android
//! send answers `NotConfigured`.
//!
//! So `cratefield-push-wiring` owns the names, and this guard fails the build
//! if any other Rust source in the workspace names one of them in a string
//! literal. It is the same shape as `card_data_guard.rs`: the rule is a test,
//! and the test proves the detector fires.
//!
//! The names come from `PUSH_ENV` rather than being written out here, so this
//! file names none of them itself and a new variable is guarded the moment it
//! joins the table.

use std::path::{Path, PathBuf};

use cratefield_push_wiring::PUSH_ENV;

/// The crate that is allowed to name them: the one reader.
const READER: &str = "crates/push-wiring";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repo root is two levels above this crate")
        .to_path_buf()
}

/// The push environment variables a source names in a **string literal** —
/// which is what reading one looks like (`config.get("…")`,
/// `env.secret("…")`).
///
/// A backticked mention in a doc comment is prose about the wiring, not a
/// second reader, and is deliberately not flagged: the adapters document
/// their own variables and should keep doing so.
fn offenders_in(source: &str) -> Vec<&'static str> {
    PUSH_ENV
        .iter()
        .map(|var| var.name)
        .filter(|name| source.contains(&format!("\"{name}\"")))
        .collect()
}

/// Every `.rs` file in the working tree, tracked or not — an untracked new
/// file is exactly the one a guard must still see.
fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            // Build output and VCS internals are not sources.
            if matches!(name.as_ref(), "target" | ".git" | "node_modules" | "build") {
                continue;
            }
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn only_the_wiring_crate_names_a_push_environment_variable() {
    let root = repo_root();
    let mut sources = Vec::new();
    rust_sources(&root, &mut sources);
    assert!(
        sources.len() > 100,
        "the walk found only {} Rust sources, so it is not walking the workspace",
        sources.len()
    );

    let mut violations = Vec::new();
    for path in sources {
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if relative.starts_with(READER) {
            continue;
        }
        let source = std::fs::read_to_string(&path).unwrap_or_default();
        for name in offenders_in(&source) {
            violations.push(format!("{relative} reads {name} directly"));
        }
    }

    assert!(
        violations.is_empty(),
        "the push environment has one reader, `{READER}`. These call \
         `cratefield_push_wiring::build_push` (or `inspect_push`) instead:\n  - {}",
        violations.join("\n  - ")
    );
}

#[test]
fn the_guard_fires_on_a_source_that_reads_one() {
    // A guard nobody tests is a guard nobody knows is wired (issue #44's
    // lesson). This is what `serve()` reading the environment itself would
    // look like.
    let var = PUSH_ENV.first().expect("the table is not empty");
    let source = format!("let key = config.get(\"{}\").unwrap();\n", var.name);
    assert_eq!(offenders_in(&source), vec![var.name]);
}

#[test]
fn the_guard_does_not_fire_on_prose() {
    // The adapters document their own variables in doc comments, and must
    // keep being able to.
    let var = PUSH_ENV.first().expect("the table is not empty");
    let source = format!("//! Reads the `{}` secret at construction.\n", var.name);
    assert!(offenders_in(&source).is_empty(), "{source}");
}

#[test]
fn every_variable_in_the_table_is_guarded() {
    // Not one name is exempt: adding a variable to the table extends the
    // guard, with nothing to remember.
    for var in PUSH_ENV {
        let source = format!("config.get(\"{}\")", var.name);
        assert_eq!(offenders_in(&source), vec![var.name], "{}", var.name);
    }
}
