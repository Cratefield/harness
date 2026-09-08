//! `fz build <manifest>` — the headless compile engine's front door.
//!
//! Parse and validate a venture manifest, resolve its module set against
//! the built-in catalog, and generate a deterministic Cloudflare venture
//! crate (issue #138). This is standalone: it needs no compiled-in harness,
//! because it *produces* one. It stops at source — turning the generated
//! crate into a deployable wasm is `worker-build` and `wrangler deploy`,
//! which the printed plan names as the next (toolchain / needs-human) steps.

use std::path::Path;

use cratefield_manifest::{HarnessSource, VentureManifest, builtin, generate};

/// Runs `fz build`.
///
/// # Errors
///
/// A human-readable message if the manifest cannot be read, parsed,
/// resolved, generated, or written.
pub fn run(manifest_path: &Path, out: &Path, harness_path: Option<&str>) -> Result<(), String> {
    let raw = std::fs::read_to_string(manifest_path)
        .map_err(|err| format!("cannot read {}: {err}", manifest_path.display()))?;
    let manifest = parse(manifest_path, &raw)?;

    let module_set = manifest
        .resolve(&builtin())
        .map_err(|err| err.to_string())?;

    let source = match harness_path {
        Some(path) => HarnessSource::Path(path.to_owned()),
        None => HarnessSource::default(),
    };
    let venture = generate(&manifest, &module_set, &source).map_err(|err| err.to_string())?;

    for file in &venture.files {
        let dest = out.join(&file.path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|err| format!("cannot create {}: {err}", parent.display()))?;
        }
        std::fs::write(&dest, &file.contents)
            .map_err(|err| format!("cannot write {}: {err}", dest.display()))?;
    }

    println!("fz build: {}", venture.name);
    println!("  module set:  {}", venture.content_key);
    println!("  modules:     {}", venture.modules.join(" -> "));
    println!("  composition: sha256:{}", venture.composition_hash);
    println!(
        "  wrote {} files to {}:",
        venture.files.len(),
        out.display()
    );
    for file in &venture.files {
        println!("    {}", file.path);
    }
    println!();
    println!("next:");
    println!(
        "  1. cd {} && cargo run --bin fz -- migrations collect   # collect D1 migrations",
        out.display()
    );
    println!("  2. worker-build --release   # compile the venture to wasm (needs the toolchain)");
    println!(
        "  3. wrangler deploy          # stand up the Worker + D1 (needs Cloudflare creds — needs-human)"
    );
    Ok(())
}

/// Parse a manifest from JSON or TOML, chosen by file extension. The
/// manifest crate itself is JSON/serde-only (so it compiles to wasm for the
/// compose engine); TOML is decoded here into the same struct.
fn parse(path: &Path, raw: &str) -> Result<VentureManifest, String> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("toml") => toml::from_str(raw).map_err(|err| format!("invalid TOML manifest: {err}")),
        _ => VentureManifest::from_json_str(raw).map_err(|err| err.to_string()),
    }
}
