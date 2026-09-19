//! `fz client-ts` acceptance tests (issue #155): a `/__surface` contract
//! document in, the files of a typed `@cratefield/client` package out.
//! Proves the command runs harness-free through the ordinary argv entry
//! (`cratefield_cli::run`, whose harness closure a harness-free command
//! never calls), from a file and from stdin, pins the `--json` payload
//! shape the way `doctor_json.rs` pins the doctor's, refuses a document
//! that is not a contract with a stable code and a non-zero exit, and
//! generates byte-identical files on a second run.

mod common;

use cratefield_cli::client_ts::{Generated, client_ts};
use cratefield_cli::run;
use cratefield_testing::TempDir;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use venture_fixture::harness_v1;

/// The package-relative files a generated client is made of, sorted.
const FILES: [&str; 6] = [
    "README.md",
    "package.json",
    "src/index.ts",
    "src/runtime.ts",
    "src/types.ts",
    "tsconfig.json",
];

/// A small `/__surface` document, spelled the way the venture serves it:
/// a read-only `note` table (the wire spells `method` upper-case,
/// `audience` kebab-case, `outcome` tagged with `kind`, `captcha` always
/// present).
fn surface_document() -> String {
    serde_json::json!({
        "surface_api": cratefield_core::SURFACE_API,
        "harness_api": 1,
        "venture": {
            "name": "waitlist",
            "public_url": "https://waitlist.example.com",
        },
        "modules": [
            {
                "name": "tables",
                "version": "0.1.0",
                "actions": [
                    {
                        "name": "list-note",
                        "method": "GET",
                        "path": "/note",
                        "audience": "public",
                        "outcome": { "kind": "json" },
                        "captcha": false,
                    },
                    {
                        "name": "read-note",
                        "method": "GET",
                        "path": "/note/{key}",
                        "audience": "public",
                        "outcome": { "kind": "json" },
                        "captcha": false,
                    },
                ],
                "views": [],
            }
        ],
    })
    .to_string()
}

fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(ToString::to_string).collect()
}

fn write_document(dir: &Path, body: &str) -> String {
    let surface = dir.join("surface.json");
    fs::write(&surface, body).expect("write the document");
    surface.to_str().expect("utf-8 temp path").to_owned()
}

fn landed_files(out: &Path) -> Vec<(String, Vec<u8>)> {
    FILES
        .iter()
        .map(|relative| {
            (
                (*relative).to_owned(),
                fs::read(out.join(relative))
                    .unwrap_or_else(|err| panic!("{relative} must be written: {err}")),
            )
        })
        .collect()
}

/// The ordinary path: a document on disk, the package on disk, nothing
/// else touched.
#[test]
fn generates_the_package_from_a_file() {
    let tmp = TempDir::new("client-ts-file");
    let surface = write_document(tmp.path(), &surface_document());
    let out = tmp.path().join("client");

    let code = run(
        harness_v1,
        args(&[
            "client-ts",
            "--surface",
            &surface,
            "--out",
            out.to_str().unwrap(),
        ]),
    );
    assert_eq!(code, ExitCode::SUCCESS, "client-ts must succeed");

    let landed = landed_files(&out);
    assert_eq!(landed.len(), FILES.len(), "the whole package lands");
    let package = String::from_utf8(
        landed
            .iter()
            .find(|(path, _)| path == "package.json")
            .expect("package.json")
            .1
            .clone(),
    )
    .expect("utf-8");
    assert!(
        package.contains("@cratefield/client"),
        "the package is the published name, got: {package}"
    );
}

/// The pipe in the README works: `curl … | fz client-ts --surface -`.
/// The standalone binary is the only way to hand a test real stdin, so
/// this spawns it through cargo, the way `native_only_off_wasm.rs`
/// spawns cargo.
#[test]
fn generates_the_package_from_stdin() {
    let tmp = TempDir::new("client-ts-stdin");
    let out = tmp.path().join("client");

    let mut child = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args([
            "run",
            "--quiet",
            "-p",
            "cratefield-cli",
            "--bin",
            "cratefield-cli",
            "--",
            "client-ts",
            "--surface",
            "-",
            "--out",
            out.to_str().expect("utf-8 temp path"),
        ])
        .current_dir(common::repo_root())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the standalone fz");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(surface_document().as_bytes())
        .expect("pipe the document");
    let output = child.wait_with_output().expect("run fz");
    assert!(
        output.status.success(),
        "fz client-ts --surface - must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        landed_files(&out).len(),
        FILES.len(),
        "the whole package lands"
    );
}

/// The exact stdout payload `fz client-ts --json` emits for a clean run:
/// one object, one line, empty failures, the package's identity and the
/// files it wrote — the wire contract pinned.
#[test]
fn json_payload_is_pinned() {
    let tmp = TempDir::new("client-ts-json");
    let surface = write_document(tmp.path(), &surface_document());
    let out = tmp.path().join("client");

    let generated: Generated = client_ts(&surface, &out).expect("generates");
    let payload = generated.render_json().expect("serializes");
    assert!(!payload.contains('\n'), "one line, no embedded newlines");

    let parsed: serde_json::Value = serde_json::from_str(&payload).expect("parses");
    assert_eq!(parsed["schema"], serde_json::json!(1), "schema present");
    assert_eq!(parsed["ok"], serde_json::json!(true));
    assert_eq!(
        parsed["failures"],
        serde_json::json!([]),
        "clean run: empty failure list"
    );
    assert_eq!(parsed["package"], serde_json::json!("@cratefield/client"));
    assert_eq!(parsed["venture"], serde_json::json!("waitlist"));
    assert_eq!(
        parsed["out"],
        serde_json::json!(out.to_str().expect("utf-8 temp path"))
    );
    let hash = parsed["composition_hash"]
        .as_str()
        .expect("the hash is a string");
    assert_eq!(hash.len(), 64, "a sha256 as hex, got {hash}");
    assert_eq!(
        parsed["files_written"],
        serde_json::json!(FILES.len()),
        "one entry per file"
    );
    let mut files: Vec<&str> = parsed["files"]
        .as_array()
        .expect("the file list")
        .iter()
        .map(|path| path.as_str().expect("paths are strings"))
        .collect();
    files.sort_unstable();
    assert_eq!(files, FILES, "the payload lists what landed on disk");
}

/// A document that is not JSON, and a document that is JSON but not a
/// `/__surface` contract, are different mistakes with different stable
/// codes — and the prose path exits non-zero either way.
#[test]
fn a_document_that_is_not_a_contract_refuses_with_a_stable_code() {
    let tmp = TempDir::new("client-ts-refusal");
    let out = tmp.path().join("client");

    // Not JSON at all.
    let surface = write_document(tmp.path(), "not json");
    let refusal = client_ts(&surface, &out).expect_err("must refuse");
    assert_eq!(refusal.code.code, "surface-unreadable");
    assert!(
        refusal.message.contains("is not valid JSON"),
        "the message names the mistake: {}",
        refusal.message
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&refusal.render_json().expect("serializes")).expect("parses");
    assert_eq!(parsed["schema"], serde_json::json!(1));
    assert_eq!(parsed["ok"], serde_json::json!(false));
    assert_eq!(
        parsed["failures"][0]["code"],
        serde_json::json!("surface-unreadable")
    );

    // JSON, but not a surface document: the message names the fix.
    let surface = write_document(tmp.path(), r#"{"hello":true}"#);
    let refusal = client_ts(&surface, &out).expect_err("must refuse");
    assert_eq!(refusal.code.code, "surface-invalid");
    assert!(
        refusal.message.contains("point --surface at the JSON"),
        "the message names the fix: {}",
        refusal.message
    );

    // Both refusals are failures on the prose path too, and neither
    // wrote anything under `out`.
    for surface in [
        write_document(tmp.path(), "not json"),
        write_document(tmp.path(), r#"{"hello":true}"#),
    ] {
        assert_eq!(
            run(
                harness_v1,
                args(&[
                    "client-ts",
                    "--surface",
                    &surface,
                    "--out",
                    out.to_str().unwrap()
                ])
            ),
            ExitCode::FAILURE,
            "a refused document must exit non-zero"
        );
    }
    assert!(!out.exists(), "a refused run writes nothing under --out");
}

/// Determinism, end to end: two runs over the same document land
/// byte-identical files under different directories.
#[test]
fn two_runs_generate_identical_bytes() {
    let tmp = TempDir::new("client-ts-determinism");
    let surface = write_document(tmp.path(), &surface_document());
    let first = tmp.path().join("first");
    let second = tmp.path().join("second");

    for out in [&first, &second] {
        assert_eq!(
            run(
                harness_v1,
                args(&[
                    "client-ts",
                    "--surface",
                    &surface,
                    "--out",
                    out.to_str().unwrap()
                ])
            ),
            ExitCode::SUCCESS,
            "both runs must succeed"
        );
    }
    assert_eq!(
        landed_files(&first),
        landed_files(&second),
        "the same document generates the same bytes"
    );

    let rehash = client_ts(&surface, &tmp.path().join("third")).expect("generates");
    let one = client_ts(&surface, &tmp.path().join("fourth")).expect("generates");
    assert_eq!(
        rehash.composition_hash, one.composition_hash,
        "the reported hash is a function of the document, not the run"
    );
}
