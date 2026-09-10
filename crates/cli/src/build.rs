//! `fz build <manifest>` — the headless compile engine's front door.
//!
//! Parse and validate a venture manifest, resolve its module set against
//! the catalog (the built-in one, or a release-stamped one via
//! `--catalog`), and generate a deterministic Cloudflare venture crate
//! (issue #138). This is standalone: it needs no compiled-in harness,
//! because it *produces* one. It stops at source — turning the generated
//! crate into a deployable wasm is `worker-build` and `wrangler deploy`,
//! which the printed plan names as the next (toolchain / needs-human)
//! steps.
//!
//! ## Construct, never deploy (issue #142)
//!
//! Construction and deployment are separate operations with separate
//! credentials, and this command only ever constructs. It writes sources
//! plus a `provenance.json` ([`Provenance`]) binding the artifact to the
//! exact reviewed release pins resolution chose; it never runs wrangler,
//! never contacts a deployment target, and refuses to *attest* a
//! sanctioned build when the environment shows a deploy credential or
//! any other contract gap. Wrangler remains the only holder of the path
//! to production credentials.
//!
//! `sandbox_attestation_from_env` is honest about what it is: a probe
//! of this process's environment. On the build service — whose
//! environment the platform, not the tenant, controls — it is the
//! machine-checkable form of the
//! [`BuildEnvironmentAttestation`] contract, and every shortfall is a
//! hard refusal with itemized reasons. On any other machine it proves
//! nothing about isolation, which is exactly why a local build without
//! the markers records `attestation: null` rather than a pass: an
//! explicit gap beats a fake green check.

use std::path::Path;

use cratefield_manifest::{
    BuildEnvViolation, BuildEnvironmentAttestation, Catalog, HarnessSource, Provenance,
    ResourceLimits, VentureManifest, builtin, generate,
};

/// Runs `fz build`.
///
/// `catalog_path` selects a release-stamped catalog (issue #142); `None`
/// uses the built-in catalog whose seed pins carry the visible
/// placeholder digest — fine for local development, refused by any
/// attested build. `built_at` and `builder` are recorded verbatim in
/// provenance; the CLI owns no clock and invents nothing.
///
/// # Errors
///
/// A human-readable message if the manifest or catalog cannot be read,
/// parsed, resolved, or written; or if an environment that claims
/// sanctioned-build status fails the contract.
pub fn run(
    manifest_path: &Path,
    out: &Path,
    harness_path: Option<&str>,
    catalog_path: Option<&Path>,
    built_at: Option<&str>,
    builder: Option<&str>,
) -> Result<(), String> {
    let raw = std::fs::read_to_string(manifest_path)
        .map_err(|err| format!("cannot read {}: {err}", manifest_path.display()))?;
    let manifest = parse(manifest_path, &raw)?;

    let catalog = load_catalog(catalog_path)?;
    let module_set = manifest.resolve(&catalog).map_err(|err| err.to_string())?;

    // An environment that claims sanctioned status must pass its own
    // contract before a single byte is written (issue #142); an
    // unattested local build proceeds, visibly labelled.
    let attestation = sandbox_attestation_from_env();
    if let Some(env) = &attestation {
        let violations = env.check();
        if !violations.is_empty() {
            return Err(BuildEnvViolation(violations).to_string());
        }
    }

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

    let builder_identity = builder
        .map(str::to_owned)
        .or_else(|| std::env::var("FZ_BUILDER").ok())
        .unwrap_or_else(|| "local".to_owned());
    let built_at_record = built_at
        .map(str::to_owned)
        .or_else(|| std::env::var("FZ_BUILD_TIMESTAMP").ok());
    let provenance = Provenance::record(
        &venture,
        &module_set,
        &builder_identity,
        built_at_record.as_deref(),
        attestation.clone(),
    )
    .map_err(|err| err.to_string())?;
    std::fs::write(out.join("provenance.json"), provenance.to_json().as_bytes())
        .map_err(|err| format!("cannot write provenance.json: {err}"))?;

    println!("fz build: {}", venture.name);
    println!("  module set:  {}", venture.content_key);
    println!("  modules:     {}", venture.modules.join(" -> "));
    println!("  composition: sha256:{}", venture.composition_hash);
    println!("  pins:");
    for release in module_set.releases() {
        println!(
            "    {} @ {} {}",
            release.slug, release.version, release.digest
        );
    }
    match &provenance.attestation {
        Some(env) => println!(
            "  provenance:  provenance.json — attested build (environment digest {})",
            env.attestation_digest()
        ),
        None => println!(
            "  provenance:  provenance.json — local build, unattested (no \
             FZ_BUILD_SANDBOX_DIGEST). A sanctioned build must satisfy the \
             BuildEnvironmentAttestation contract and pin stamped digests."
        ),
    }
    println!(
        "  wrote {} files to {}:",
        venture.files.len(),
        out.display()
    );
    for file in &venture.files {
        println!("    {}", file.path);
    }
    println!("    provenance.json");
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

/// The catalog to resolve against. `--catalog` points at a JSON the
/// release process stamped with real digests (issue #142); without it
/// the built-in catalog serves development. A supplied catalog must be
/// coherent — resolution would validate anyway, and failing here gives
/// the operator the data bug before the compile.
fn load_catalog(path: Option<&Path>) -> Result<Catalog, String> {
    let Some(path) = path else {
        return Ok(builtin());
    };
    let raw = std::fs::read_to_string(path)
        .map_err(|err| format!("cannot read {}: {err}", path.display()))?;
    let catalog: Catalog = serde_json::from_str(&raw)
        .map_err(|err| format!("invalid catalog {}: {err}", path.display()))?;
    catalog.validate().map_err(|err| err.to_string())?;
    Ok(catalog)
}

/// The build-service environment probe (issue #142). Absent
/// `FZ_BUILD_SANDBOX_DIGEST` this is an unattested local build and
/// provenance records that honestly (`attestation: null`). Present
/// means "this is the service": `FZ_BUILD_SANDBOX=disposable`,
/// `FZ_BUILD_ISOLATION=workspace-scoped`, `FZ_BUILD_NETWORK` one of
/// `deny-all`/`registry-allowlist`, `FZ_BUILD_SECRETS=production-absent`,
/// `FZ_BUILD_LIMITS="600s,4Gi,10Gi"`, and no deploy credential visible
/// to the process — each checked by
/// [`BuildEnvironmentAttestation::check`], every gap an itemized
/// refusal.
fn sandbox_attestation_from_env() -> Option<BuildEnvironmentAttestation> {
    let sandbox_digest = std::env::var("FZ_BUILD_SANDBOX_DIGEST").ok()?;
    Some(BuildEnvironmentAttestation {
        sandbox_digest,
        disposable: env_is("FZ_BUILD_SANDBOX", "disposable"),
        workspace_scoped: env_is("FZ_BUILD_ISOLATION", "workspace-scoped"),
        network_egress: std::env::var("FZ_BUILD_NETWORK").unwrap_or_default(),
        deploy_credentials_withheld: !deploy_credentials_present(),
        production_key_absent: env_is("FZ_BUILD_SECRETS", "production-absent"),
        limits: parse_limits(&std::env::var("FZ_BUILD_LIMITS").unwrap_or_default()),
    })
}

fn env_is(key: &str, expected: &str) -> bool {
    std::env::var(key).is_ok_and(|value| value == expected)
}

/// A build that can see a deploy credential must not attest one was
/// withheld (issue #142). `FZ_BUILD_HAS_DEPLOY_CREDENTIALS=1` is the
/// explicit override for substrates that inject credentials under names
/// this list does not know.
fn deploy_credentials_present() -> bool {
    std::env::var_os("CLOUDFLARE_API_TOKEN").is_some()
        || std::env::var_os("CF_API_TOKEN").is_some()
        || std::env::var_os("WRANGLER_API_TOKEN").is_some()
        || std::env::var("FZ_BUILD_HAS_DEPLOY_CREDENTIALS").is_ok_and(|v| v == "1")
}

/// `FZ_BUILD_LIMITS` is positional: `"wall-clock,memory,disk"`, in
/// whatever units the enforcing substrate uses. Missing parts parse to
/// empty and fail [`BuildEnvironmentAttestation::check`] as missing
/// limits (issue #142).
fn parse_limits(raw: &str) -> ResourceLimits {
    let mut parts = raw.split(',').map(str::trim);
    ResourceLimits {
        wall_clock: parts.next().unwrap_or("").to_owned(),
        memory: parts.next().unwrap_or("").to_owned(),
        disk: parts.next().unwrap_or("").to_owned(),
    }
}

/// Parse a manifest from JSON or TOML, chosen by file extension. The
/// manifest crate itself is JSON/serde-only (so it compiles to wasm for the
/// compose engine); TOML is decoded here into the same struct.
pub(crate) fn parse(path: &Path, raw: &str) -> Result<VentureManifest, String> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("toml") => toml::from_str(raw).map_err(|err| format!("invalid TOML manifest: {err}")),
        _ => VentureManifest::from_json_str(raw).map_err(|err| err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_positional_with_room_for_gaps() {
        let limits = parse_limits("600s, 4Gi ,10Gi");
        assert_eq!(limits.wall_clock, "600s");
        assert_eq!(limits.memory, "4Gi");
        assert_eq!(limits.disk, "10Gi");
        let sparse = parse_limits("");
        assert!(sparse.wall_clock.is_empty());
        let partial = parse_limits("600s");
        assert_eq!(partial.wall_clock, "600s");
        assert!(partial.memory.is_empty());
    }

    #[test]
    fn sparse_limits_fail_the_contract() {
        let env = BuildEnvironmentAttestation {
            sandbox_digest: format!("sha256:{}", "b".repeat(64)),
            disposable: true,
            workspace_scoped: true,
            network_egress: "deny-all".to_owned(),
            deploy_credentials_withheld: true,
            production_key_absent: true,
            limits: parse_limits("600s"),
        };
        let violations = env.check();
        assert_eq!(violations.len(), 2, "{violations:?}");
        assert!(violations.contains(&"no memory limit declared"));
        assert!(violations.contains(&"no disk limit declared"));
    }
}
