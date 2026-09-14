//! `examples/tables-canary` is what the generator produces, byte for
//! byte.
//!
//! The canary exists because nothing compiled a generated venture:
//! `examples/venture` is hand-written, so the generator could emit source
//! that does not build — and did emit source that builds and then panics.
//! Being a workspace member is what compiles it; its own `tests/boots.rs`
//! is what composes it.
//!
//! This is the third leg. A committed copy that has drifted from the
//! generator is a canary for a generator nobody runs any more: it would
//! keep compiling and keep booting while the real output did neither.
//!
//! # Why the comparison formats first
//!
//! The committed copy is a workspace member, so `cargo fmt --all`
//! formats it — and rustfmt rewraps what the generator emitted. Comparing
//! raw text then fails on a difference nobody made, and chasing it means
//! hand-matching rustfmt's wrapping inside the generator's string
//! literals, which is fragile and was wrong three times in a row.
//!
//! So the generator's output goes through the same `rustfmt` first. The
//! comparison is then exactly the question worth asking: is the committed
//! canary what this generator produces?

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root")
}

#[test]
fn the_committed_canary_is_what_the_generator_writes() {
    let root = repo_root();
    let dir = root.join("examples/tables-canary");
    let json = std::fs::read_to_string(dir.join("venture.json")).expect("the canary's manifest");
    let manifest = cratefield_manifest::VentureManifest::from_json_str(&json).expect("it parses");
    let set = manifest
        .resolve(&cratefield_manifest::catalog::builtin())
        .expect("it resolves");
    let venture = cratefield_manifest::generate(
        &manifest,
        &set,
        // The same source the canary was written with, or every path
        // dependency in its `Cargo.toml` differs and the comparison is
        // about that rather than about the generator.
        &cratefield_manifest::generate::HarnessSource::Path("../..".into()),
    )
    .expect("it generates");

    assert!(!venture.files.is_empty(), "the generator wrote nothing");
    for file in &venture.files {
        let path = dir.join(&file.path);
        let is_rust = std::path::Path::new(&file.path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"));
        let generated = if is_rust {
            formatted(&file.contents)
        } else {
            file.contents.clone()
        };
        let committed = std::fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!(
                "{} is missing from the canary ({err}); regenerate with \
                 `cargo run -p cratefield-manifest --example write-venture -- \
                 examples/tables-canary/venture.json examples/tables-canary`",
                file.path
            )
        });
        assert_eq!(
            committed, generated,
            "{} has drifted from the generator; regenerate with \
             `cargo run -p cratefield-manifest --example write-venture -- \
             examples/tables-canary/venture.json examples/tables-canary`",
            file.path
        );
    }
}

#[test]
fn the_canary_declares_a_table_that_is_not_public() {
    // Otherwise it compiles and boots without ever exercising the
    // verifier wiring, which is the part that was broken.
    let root = repo_root();
    let json = std::fs::read_to_string(root.join("examples/tables-canary/venture.json"))
        .expect("the canary's manifest");
    let manifest = cratefield_manifest::VentureManifest::from_json_str(&json).expect("it parses");
    assert!(
        manifest
            .table_access
            .values()
            .any(|access| *access != cratefield_manifest::Access::PublicRead),
        "the canary's tables are all public, so it proves nothing about auth"
    );
    assert!(
        manifest
            .table_access
            .values()
            .any(|access| *access == cratefield_manifest::Access::PublicRead),
        "and none are public, so it proves nothing about the other side"
    );
}

/// `source` through the toolchain's rustfmt, for the edition the
/// generated crate declares.
///
/// A missing rustfmt is a failure, not a skip. A comparison that quietly
/// stops comparing is worse than one that is not there: it reports
/// success for a canary nobody checked.
fn formatted(source: &str) -> String {
    use std::io::Write as _;

    let mut child = Command::new("rustfmt")
        .args(["--edition", "2021", "--emit", "stdout", "--quiet"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("rustfmt is on PATH (it ships with the toolchain `cargo fmt` uses)");
    child
        .stdin
        .as_mut()
        .expect("a stdin pipe")
        .write_all(source.as_bytes())
        .expect("rustfmt takes the source");
    let out = child.wait_with_output().expect("rustfmt finishes");
    assert!(
        out.status.success(),
        "rustfmt refused the generated source: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("rustfmt writes utf-8")
}
