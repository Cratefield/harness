//! `fz push send` is a **build option**, and the docs make promises about
//! it that only a build flag can keep (issue #184).
//!
//! `push-send` pulls the native runtime's HTTP client, so an `fz` compiled
//! without it refuses the send in one line. That is fine — a loud absence
//! is a build option — but it is not fine for the image the `needs-human`
//! live proofs (issue #186) are run with to be the one that refuses, while
//! the README says the standalone binary and the image serve it. Nothing
//! in a Rust test can observe how the image was built, so the promise is
//! checked against the Dockerfile itself.
//!
//! The second half is the mirror image: the way to get a send-capable `fz`
//! must never be documented as a feature on the venture's own
//! `cratefield-cli` dependency. A generated venture builds a wasm
//! `cdylib` beside that dependency, and `cratefield-runtime-native`
//! `compile_error!`s on wasm32 — so following that advice would break the
//! build of the thing the venture actually deploys.

mod common;

use common::repo_root;

/// The feature the send needs. Named once here; both halves read it.
const FEATURE: &str = "push-send";

fn read(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

/// A Dockerfile/shell line continued with `\` is one logical line.
fn logical_lines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        let trimmed = line.trim_end();
        if let Some(head) = trimmed.strip_suffix('\\') {
            current.push_str(head);
            current.push(' ');
        } else {
            current.push_str(trimmed);
            lines.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

#[test]
fn the_image_builds_the_cli_with_the_feature_its_send_needs() {
    let dockerfile = read("docker/Dockerfile");
    let builds: Vec<String> = logical_lines(&dockerfile)
        .into_iter()
        .filter(|line| line.contains("cargo build") && line.contains("cratefield-cli"))
        .collect();
    assert_eq!(
        builds.len(),
        1,
        "expected exactly one `fz` build line in docker/Dockerfile, found {builds:?}"
    );
    assert!(
        builds[0].contains(&format!("--features {FEATURE}")),
        "the image's `fz` is built without `{FEATURE}`, so `fz push send` refuses in the very \
         image the live proofs are run with:\n  {}",
        builds[0]
    );
}

#[test]
fn the_readme_installs_a_binary_rather_than_flipping_a_venture_dependency() {
    let readme = read("crates/cli/README.md");
    assert!(
        readme.contains(&format!(
            "cargo install cratefield-cli --features {FEATURE}"
        )),
        "the README must give the install that produces a send-capable `fz`"
    );
    let dependency_recipes: Vec<&str> = readme
        .lines()
        .filter(|line| line.contains("cratefield-cli = {") && line.contains(FEATURE))
        .collect();
    assert!(
        dependency_recipes.is_empty(),
        "this tells an operator to add `{FEATURE}` to a dependency, which pulls \
         cratefield-runtime-native into the venture's wasm build and breaks it:\n  - {}",
        dependency_recipes.join("\n  - ")
    );
}

#[test]
fn the_guard_reads_a_continued_line_as_one_line() {
    // The build line is continued with `\`; a guard that read it line by
    // line would find no `--features` on the line carrying `cargo build`
    // and fire on a Dockerfile that is perfectly correct — or, worse,
    // pass on one that is not.
    let lines =
        logical_lines("RUN cargo build \\\n --features push-send \\\n && cp a b\nWORKDIR /w\n");
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines[0].contains("cargo build"), "{lines:?}");
    assert!(lines[0].contains("--features push-send"), "{lines:?}");
}
