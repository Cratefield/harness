//! Generates `docs/COMPATIBILITY.md` (issue #17): the contract-version
//! rule, the 1.0 rule, and the per-crate table of supported
//! `factory0-core` ranges, read from `cargo metadata`. Run without
//! arguments to write the file, or with `--check` to verify the
//! checked-in copy has no drift (CI fails the run on drift).
//!
//! ```text
//! cargo run -p factory0-cli --example compatibility-doc          # write
//! cargo run -p factory0-cli --example compatibility-doc -- --check
//! ```
//!
//! Host-only tooling: like the CLI's `doctor`, this shells out to cargo;
//! it never runs inside a Worker.

use factory0_core::HARNESS_API;
use serde_json::Value;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// One row: a workspace crate that depends on `factory0-core`.
struct Consumer {
    name: String,
    version: String,
    /// The `factory0-core` requirement as declared (e.g. `0.1`).
    core_req: String,
    /// False for `publish = false` crates (examples, test-only).
    published: bool,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn consumers(root: &Path) -> Vec<Consumer> {
    let output =
        std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args(["metadata", "--no-deps", "--format-version", "1"])
            .current_dir(root)
            .output()
            .expect("cargo metadata runs");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata emits JSON");

    let mut out = Vec::new();
    let empty: Vec<Value> = Vec::new();
    for package in metadata["packages"].as_array().unwrap_or(&empty) {
        let name = package["name"].as_str().unwrap_or_default().to_string();
        if name == "factory0-core" {
            continue;
        }
        let Some(req) = package["dependencies"]
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .filter(|dep| dep["name"].as_str() == Some("factory0-core"))
            // `kind` is null for a normal dependency; dev/build
            // requirements are irrelevant to consumers of the crate.
            .find(|dep| dep["kind"].is_null())
            .and_then(|dep| dep["req"].as_str())
        else {
            continue;
        };
        out.push(Consumer {
            version: package["version"].as_str().unwrap_or_default().to_string(),
            published: package["publish"] != Value::Bool(false),
            core_req: req.to_string(),
            name,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Human form of a requirement: `0.1` covers `>=0.1.0, <0.2.0`; `1.2`
/// covers `>=1.2.0, <2.0.0` (caret semantics, the only form the
/// workspace uses).
fn range(req: &str) -> String {
    let nums: Vec<u32> = req
        .trim_start_matches('^')
        .split('.')
        .map(|part| part.parse().unwrap_or(0))
        .collect();
    let (major, minor) = (
        nums.first().copied().unwrap_or(0),
        nums.get(1).copied().unwrap_or(0),
    );
    if major == 0 {
        format!(">=0.{minor}.0, <0.{}.0", minor + 1)
    } else {
        format!(">={major}.{minor}.0, <{}.0.0", major + 1)
    }
}

fn markdown(rows: &[Consumer]) -> String {
    let mut out = String::new();
    out.push_str("# Compatibility\n\n");
    out.push_str(
        "Generated from the workspace manifests by `cargo run -p factory0-cli --example\n\
         compatibility-doc` and checked in CI for drift. Do not edit by hand.\n\n",
    );

    out.push_str("## The contract version\n\n");
    let _ = write!(
        out,
        "- `HARNESS_API` is {HARNESS_API}. Every module and adapter is compiled\n\
         \x20 against a `factory0-core` whose `HARNESS_API` matches; `Harness::build`\n\
         \x20 and `fz doctor` refuse a mismatch, naming the module, its version and\n\
         \x20 the core crate.\n\
         - **The 1.0 rule:** `HARNESS_API` is bumped only for breaking changes to\n\
         \x20 the module contract (the `Module` trait, `ModuleContext`, ports).\n\
         \x20 `factory0-core`'s major version follows `HARNESS_API`: a core 2.x is\n\
         \x20 the first that accepts API 2, a core 1.x never does. Anything else —\n\
         \x20 new optional trait methods, new ports, new error slugs — ships in a\n\
         \x20 minor bump with the API unchanged.\n\
         - **Dependency ranges:** while pre-1.0, modules and adapters depend on\n\
         \x20 `factory0-core` with a caret on the current minor (`\"0.1\"` accepts\n\
         \x20 0.1.x only), so a new core minor can never silently mix with older\n\
         \x20 modules. From 1.0 the range is `\"^1\"`-style: compatible within the\n\
         \x20 major. Ventures pin exact versions; the supported range per release\n\
         \x20 is the table below.\n\n"
    );

    out.push_str("## Supported core ranges\n\n");
    out.push_str("| Crate | Version | HARNESS_API | `factory0-core` range |\n");
    out.push_str("|---|---|---|---|\n");
    for row in rows {
        let name = if row.published {
            row.name.clone()
        } else {
            format!("{} *(not published)*", row.name)
        };
        let _ = writeln!(
            out,
            "| `{name}` | {} | {HARNESS_API} | `{}` — `{}` |",
            row.version,
            row.core_req,
            range(&row.core_req),
        );
    }
    out.push_str(
        "\nA module row means: that module version was built and conformance-tested\n\
         against every `factory0-core` its range accepts at the time of release\n\
         (the caret keeps it to one pre-1.0 minor). The conformance suite runs\n\
         per module crate via `.github/workflows/conformance.yml`, which is also\n\
         exported as a reusable workflow for `harness-private`.\n",
    );
    out
}

fn main() {
    let root = workspace_root();
    let path = root.join("docs/COMPATIBILITY.md");
    let rows = consumers(&root);
    assert!(!rows.is_empty(), "no factory0-core consumers in workspace");
    let generated = markdown(&rows);
    let check = std::env::args().any(|arg| arg == "--check");

    if check {
        let current = std::fs::read_to_string(&path).unwrap_or_default();
        if current != generated {
            eprintln!(
                "docs/COMPATIBILITY.md is stale; regenerate with `cargo run -p factory0-cli \
                 --example compatibility-doc` and commit it"
            );
            std::process::exit(1);
        }
        println!(
            "docs/COMPATIBILITY.md is up to date ({} crates)",
            rows.len()
        );
        return;
    }

    std::fs::write(&path, generated).expect("write docs/COMPATIBILITY.md");
    println!("wrote {} ({} crates)", path.display(), rows.len());
}
