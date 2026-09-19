//! The output side: what [`generate`] emits for a whole venture's Tables
//! contract, and whether the TypeScript it emits actually type-checks.
//!
//! The compile check runs the real `tsc` when one is reachable (`npx`
//! with the `typescript` package, or a binary named by `$TSC`) and skips
//! cleanly otherwise: a CI host without Node has no verdict to give, and
//! the generated source is still covered by the structural assertions
//! below.

use std::path::Path;
use std::process::Command;

use cratefield_client_ts::{GeneratedPackage, generate};
use cratefield_core::{SURFACE_API, SurfaceDocument};
use cratefield_testing::TempDir;
use serde_json::{Value, json};

/// The document a harness serves at `/__surface` for a venture with four
/// tables, spelled exactly the way `cratefield_tables_api::surface` and
/// `cratefield_tables::json_schema` publish them: `method` upper-case,
/// `audience` kebab-case, `outcome` tagged with `kind`, and a schema on
/// the write actions alone.
fn document() -> SurfaceDocument {
    let document = json!({
        "surface_api": SURFACE_API,
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
                    // `note`: public, every verb, every column kind.
                    action("list-note", "GET", "/note", "public", None),
                    action("read-note", "GET", "/note/{key}", "public", None),
                    action("create-note", "POST", "/note", "public", Some(note_schema())),
                    action("replace-note", "PUT", "/note/{key}", "public", Some(note_schema())),
                    action("delete-note", "DELETE", "/note/{key}", "public", None),
                    // `visit`: a `subject` table with an integer key.
                    action("list-visit", "GET", "/visit", "subject", None),
                    action("read-visit", "GET", "/visit/{key}", "subject", None),
                    action("create-visit", "POST", "/visit", "subject", Some(visit_schema())),
                    action("replace-visit", "PUT", "/visit/{key}", "subject", Some(visit_schema())),
                    action("delete-visit", "DELETE", "/visit/{key}", "subject", None),
                    // `pair`: a composite key, so only the page and the create.
                    action("list-pair", "GET", "/pair", "subject", None),
                    action("create-pair", "POST", "/pair", "subject", Some(pair_schema())),
                    // `audit`: the known gap — a read-only table whose entry
                    // carries no schema anywhere.
                    action("list-audit", "GET", "/audit", "admin", None),
                    action("read-audit", "GET", "/audit/{key}", "admin", None),
                ],
                "views": [],
            }
        ],
    });
    serde_json::from_value(document)
        .expect("a document in the published shape must deserialize as a SurfaceDocument")
}

/// One action, as the Tables module publishes it.
fn action(name: &str, method: &str, path: &str, audience: &str, input: Option<Value>) -> Value {
    let mut action = json!({
        "name": name,
        "method": method,
        "path": path,
        "audience": audience,
        "outcome": { "kind": "json" },
        "captcha": false,
    });
    if let Some(input) = input {
        action["input"] = input;
    }
    action
}

/// A row schema as `cratefield_tables::json_schema` renders it: optional
/// columns carry `"null"` in their `type` (or `enum`), a `json` column
/// names no `type` at all, text bans U+0000, and the key is marked by its
/// `description`.
fn note_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "note",
        "type": "object",
        "properties": {
            "id": {
                "type": "string",
                "description": "Primary key of `note`.",
            },
            "title": {
                "type": "string",
                "minLength": 1,
                "not": { "pattern": "\u{0}" },
            },
            "body": {
                "type": ["string", "null"],
                "not": { "pattern": "\u{0}" },
            },
            "priority": { "type": "string", "enum": ["low", "high"] },
            "status": { "type": "string", "enum": ["todo", "done", null] },
            "visits": { "type": ["integer", "null"], "minimum": 0 },
            "score": { "type": "number", "minimum": 0 },
            "pinned": { "type": "boolean" },
            "due": { "type": ["string", "null"], "format": "date-time" },
            "meta": {},
        },
        "required": ["id", "title", "score", "pinned"],
        "additionalProperties": false,
    })
}

/// A table keyed on an integer: the generated `get` takes a number.
fn visit_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "visit",
        "type": "object",
        "properties": {
            "id": {
                "type": "integer",
                "description": "Primary key of `visit`.",
            },
            "note_id": { "type": "string" },
            "count": { "type": ["integer", "null"] },
        },
        "required": ["id", "note_id"],
        "additionalProperties": false,
    })
}

/// A composite key: two columns marked, so no single-row routes exist.
fn pair_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "pair",
        "type": "object",
        "properties": {
            "left": {
                "type": "string",
                "description": "Primary key of `pair`.",
            },
            "right": {
                "type": "string",
                "description": "Primary key of `pair`.",
            },
            "note": { "type": ["string", "null"] },
        },
        "required": ["left", "right"],
        "additionalProperties": false,
    })
}

/// Writes every generated file under `root`, creating parents.
fn write_package(package: &GeneratedPackage, root: &Path) {
    for file in &package.files {
        let path = root.join(&file.path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("a parent directory");
        }
        std::fs::write(&path, &file.contents).expect("a generated file");
    }
}

/// The `tsc` invocation to run, as an argv. `Err` carries the printed
/// reason the toolchain is unreachable and the check must skip.
fn tsc_command() -> Result<Vec<String>, String> {
    if let Ok(tsc) = std::env::var("TSC") {
        return Ok(vec![tsc]);
    }
    // Reachable means usable: the probe both proves `npx` exists and
    // settles the `typescript` package into the npm cache, so the real
    // run below is a local compile, not a download.
    let probe = Command::new("npx")
        .args(["--yes", "--package", "typescript@5", "tsc", "--version"])
        .output();
    match probe {
        Ok(output) if output.status.success() => Ok(vec![
            "npx".to_owned(),
            "--yes".to_owned(),
            "--package".to_owned(),
            "typescript@5".to_owned(),
            "tsc".to_owned(),
        ]),
        Ok(output) => Err(format!(
            "`npx typescript tsc --version` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )),
        Err(reason) => Err(format!("`npx` is not runnable here: {reason}")),
    }
}

#[test]
fn the_generated_package_type_checks_under_strict_tsc() {
    let package = generate(&document()).expect("the four-table document must generate");

    // The generator's contract with the publish pipeline: pure and
    // deterministic. The second run must be byte-identical, hash included.
    let again = generate(&document()).expect("generation is total over a valid document");
    assert_eq!(
        package, again,
        "the same document generates the same package"
    );
    assert_eq!(package.composition_hash.len(), 64, "a sha256, as hex");
    assert_eq!(package.package_name, "@cratefield/client");
    let paths: Vec<&str> = package
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    assert_eq!(
        paths,
        [
            "package.json",
            "tsconfig.json",
            "README.md",
            "src/index.ts",
            "src/runtime.ts",
            "src/types.ts",
        ],
        "every file, in write order"
    );

    // The defects the first real compile run exposed, pinned here so they
    // stay fixed: the page query is imported as the value `list()`
    // constructs, the factory's option types are imported where its
    // signatures name them, and a table's async iterator yields rows, not
    // queries.
    let index = &package
        .files
        .iter()
        .find(|file| file.path == "src/index.ts")
        .expect("an index")
        .contents;
    assert!(
        index.contains("import { TableQuery } from \"./runtime.js\";"),
        "a typed table's `list()` constructs TableQuery"
    );
    assert!(
        index.contains("import type { ClientOptions, TokenSource } from \"./runtime.js\";"),
        "createClient's signatures name its option types"
    );
    assert!(
        index.contains("[Symbol.asyncIterator](): AsyncGenerator<NoteRow, void, void>"),
        "walking a table yields its rows"
    );

    // The verdict itself, over the real files. Skipped — never failed —
    // when no toolchain is reachable: a CI host without Node has nothing
    // to say here.
    let tsc = match tsc_command() {
        Ok(argv) => argv,
        Err(reason) => {
            println!("skipping the TypeScript compile check: {reason}");
            return;
        }
    };
    let package_dir = TempDir::new("client-ts-check");
    write_package(&package, package_dir.path());
    // A debugging aid: leave the generated package somewhere permanent
    // when a failure needs inspecting by hand.
    if let Ok(mirror) = std::env::var("CF_CLIENT_TS_EMIT_DIR") {
        write_package(&package, Path::new(&mirror));
    }
    let checked = Command::new(&tsc[0])
        .args(&tsc[1..])
        .args(["--noEmit", "-p", "tsconfig.json"])
        .current_dir(package_dir.path())
        .output()
        .expect("tsc spawns once the probe succeeded");
    assert!(
        checked.status.success(),
        "the generated package must type-check under strict tsc\n--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
}
