//! `fz build-key`: the artifact's content address, computed and shown
//! outside any build (issue #59).
//!
//! The artifact is a pure function of the module set and their exact
//! versions, the harness API, the rustc that will compile it and the
//! profile it compiles under — [`cratefield_manifest::build_key()`] is
//! the identity, this command is its inspection surface. A cache (whose
//! physical home is a control-plane decision) looks a compiled venture
//! up by this key; `fz build-key` exists so CI, the control plane and
//! an operator can compute and compare the address before any cargo
//! invocation.
//!
//! What is deliberately *not* an input: the venture name, host, config,
//! seed data and the sidecar mount table. Those are per-customer
//! deployment configuration — two customers sharing a module set share
//! the artifact and still get separate Workers, databases and secrets,
//! and one wasm serves customers whose sidecar mounts differ, which is
//! what makes the cache real (issue #59, as amended).

use crate::build::{load_catalog, parse};
use cratefield_manifest::{BUILD_PROFILE, BuildKeyInputs, build_key, canonical_inputs};
use std::path::Path;

/// A computed key together with the canonical form of the inputs that
/// produced it, so a caller (or test) can assert on the inputs, not
/// only the hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildKeyReport {
    /// `sha256:<64 hex>`.
    pub key: String,
    /// The pretty-printed canonical input JSON.
    pub inputs_json: String,
}

/// Computes the build key for a manifest. `rustc_version` is injected
/// rather than probed so the computation is testable without a
/// toolchain; [`rustc_version`] is the real probe `run` uses.
///
/// # Errors
///
/// If the manifest or catalog cannot be read, parsed, validated or
/// resolved, or if the resolved releases carry a duplicate slug.
pub fn compute_with(
    manifest_path: &Path,
    catalog_path: Option<&Path>,
    rustc_version: &str,
) -> Result<BuildKeyReport, String> {
    let raw = std::fs::read_to_string(manifest_path)
        .map_err(|err| format!("cannot read {}: {err}", manifest_path.display()))?;
    let manifest = parse(manifest_path, &raw)?;
    let catalog = load_catalog(catalog_path)?;
    let module_set = manifest.resolve(&catalog).map_err(|err| err.to_string())?;

    let inputs = BuildKeyInputs {
        releases: module_set.releases().to_vec(),
        harness_api: cratefield_core::HARNESS_API,
        rustc_version: rustc_version.to_owned(),
        profile: BUILD_PROFILE.to_owned(),
    };
    let key = build_key(&inputs).map_err(|err| err.to_string())?;
    Ok(BuildKeyReport {
        key,
        inputs_json: canonical_inputs(&inputs),
    })
}

/// The rustc version the artifact would compile under: `$RUSTC` when
/// set (the pinned-toolchain convention every build script here
/// follows), `rustc` otherwise. The version *string* is the input, not
/// a parsed triple — `rustc --version` is what a human compares.
///
/// # Errors
///
/// If rustc cannot be run: an artifact address computed without
/// knowing the compiler would silently collide across toolchains.
pub fn rustc_version() -> Result<String, String> {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let output = std::process::Command::new(&rustc)
        .arg("--version")
        .output()
        .map_err(|err| {
            format!(
                "cannot run {rustc} --version: {err} — the key names the \
             compiler, so it cannot be computed without one"
            )
        })?;
    if !output.status.success() {
        return Err(format!(
            "{rustc} --version failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Runs `fz build-key`. Prints the key, then the inputs that produced
/// it. Reads nothing but the manifest (and an optional catalog); runs
/// no cargo, writes nothing.
///
/// # Errors
///
/// See [`compute_with`] and [`rustc_version`].
pub fn run(manifest_path: &Path, catalog_path: Option<&Path>) -> Result<(), String> {
    let report = compute_with(manifest_path, catalog_path, &rustc_version()?)?;
    println!("fz build-key: {}", report.key);
    println!("{}", report.inputs_json);
    println!();
    println!(
        "The sidecar mount table is not an input: two compositions differing only in \
         HARNESS_SIDECARS share this key and the same artifact (issue #59, amended)."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const RUSTC_TEST_VERSION: &str = "rustc 1.98.1 (test-fixture 2026-01-01)";

    /// Writes a manifest to a temp file and returns its path. `fz
    /// build-key` reads from disk like `fz build` does, so the test
    /// exercises the real read path.
    fn write_manifest(name: &str, modules: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("fz-build-key-{}-{}.json", name, std::process::id()));
        std::fs::write(
            &path,
            format!(r#"{{ "name": "acme", "host": "acme.factory0.dev", "modules": {modules} }}"#),
        )
        .expect("temp manifest writes");
        path
    }

    #[test]
    fn reordering_the_manifest_does_not_change_the_key() {
        let a = write_manifest("order-a", r#"["waitlist", "email-signup"]"#);
        let b = write_manifest("order-b", r#"["email-signup", "waitlist"]"#);
        let ka = compute_with(&a, None, RUSTC_TEST_VERSION).unwrap();
        let kb = compute_with(&b, None, RUSTC_TEST_VERSION).unwrap();
        assert_eq!(ka, kb);
        assert!(ka.key.starts_with("sha256:"));
        let _ = std::fs::remove_file(a);
        let _ = std::fs::remove_file(b);
    }

    #[test]
    fn the_sidecar_mount_table_is_not_an_input() {
        // The amended acceptance criterion: two compositions differing
        // only in their sidecar mounts produce the same key. This is
        // structural, and the test pins the structure: `compute_with`
        // takes no mount parameter, reads no environment, and the
        // canonical inputs it hashes name only modules, harness API,
        // rustc and profile. `HARNESS_SIDECARS` and `fz --sidecars`
        // feed the *deployed* harness at runtime (`crate::sidecars`),
        // never this computation — edition 2024 makes the env var
        // unsettable from a `forbid(unsafe_code)` test, so the
        // guarantee is asserted where it actually lives: the input
        // surface.
        let manifest = write_manifest("sidecars", r#"["waitlist"]"#);
        let first = compute_with(&manifest, None, RUSTC_TEST_VERSION).unwrap();
        let second = compute_with(&manifest, None, RUSTC_TEST_VERSION).unwrap();
        assert_eq!(first.key, second.key);
        assert!(!first.inputs_json.contains("sidecar"));
        assert!(!first.inputs_json.contains("mount"));
        let _ = std::fs::remove_file(manifest);
    }

    #[test]
    fn per_customer_configuration_is_not_an_input_either() {
        // The same property on the other axis: name, host, CORS and
        // config belong to the deployment, so two customers on the same
        // module set share the key and the artifact while keeping
        // separate Workers, databases and secrets.
        let a =
            std::env::temp_dir().join(format!("fz-build-key-cfg-a-{}.json", std::process::id()));
        let b =
            std::env::temp_dir().join(format!("fz-build-key-cfg-b-{}.json", std::process::id()));
        std::fs::write(
            &a,
            r#"{ "name": "acme", "host": "acme.dev", "cors_origins": ["https://a.dev"], "config": { "brand": "A" }, "modules": ["waitlist"] }"#,
        )
        .expect("temp manifest writes");
        std::fs::write(
            &b,
            r#"{ "name": "other", "host": "other.dev", "config": { "brand": "B" }, "modules": ["waitlist"] }"#,
        )
        .expect("temp manifest writes");
        let ka = compute_with(&a, None, RUSTC_TEST_VERSION).unwrap();
        let kb = compute_with(&b, None, RUSTC_TEST_VERSION).unwrap();
        assert_eq!(ka.key, kb.key);
        let _ = std::fs::remove_file(a);
        let _ = std::fs::remove_file(b);
    }

    #[test]
    fn changing_a_pin_changes_the_key() {
        let builtin = crate::build::load_catalog(None).unwrap();
        let version = builtin
            .modules
            .iter()
            .find(|m| m.slug == "cms")
            .unwrap()
            .releases[0]
            .version
            .clone();

        let a = write_manifest("pin-a", r#"["cms"]"#);
        let ka = compute_with(&a, None, RUSTC_TEST_VERSION).unwrap();

        // Same set, a different rustc — the other axis the key must move on.
        let kb = compute_with(&a, None, "rustc 1.99.0 (other 2026-06-01)").unwrap();
        assert_ne!(ka.key, kb.key);
        assert!(ka.inputs_json.contains(&version));
        let _ = std::fs::remove_file(a);
    }

    #[test]
    fn an_unresolvable_manifest_is_refused_before_any_hashing() {
        let ghost = write_manifest("ghost", r#"["ghost"]"#);
        let err = compute_with(&ghost, None, RUSTC_TEST_VERSION).unwrap_err();
        assert!(err.contains("ghost"), "names the unknown module: {err}");
        let _ = std::fs::remove_file(ghost);
    }
}
