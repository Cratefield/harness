//! The Factory Zero venture manifest and deterministic composition
//! generator (issue #138).
//!
//! A [`VentureManifest`] is the small declarative document that says what a
//! backend *is* — which modules, on which host, with what config and seed
//! data. It is the SHARED contract of "Build Anywhere": the native compile
//! engine (`fz build`) generates a venture crate from it and compiles it;
//! the wasm compose engine (later) mounts the same module set in the
//! browser. The same manifest promotes to Cloudflare unchanged.
//!
//! Three concerns, three modules:
//! - [`catalog`] — the module catalog and dependency resolution (the
//!   wasm-clean canonical home of control-plane's `cratefield_catalog`
//!   logic; see that module's docs).
//! - [`manifest`] — the [`VentureManifest`] format and parsing.
//! - [`generate`](mod@generate) — the deterministic Rust composition generator.

#![forbid(unsafe_code)]

pub mod build_key;
pub mod catalog;
pub mod generate;
pub mod manifest;
pub mod provenance;

pub use build_key::{BUILD_PROFILE, BuildKeyError, BuildKeyInputs, build_key, canonical_inputs};
pub use catalog::{
    Catalog, CatalogError, CatalogModule, ModuleRelease, ModuleSet, PinnedRelease, ReleaseReview,
    ResolveError, Tier, builtin, is_exact_version, is_sha256_digest,
};
pub use generate::{GeneratedFile, GeneratedVenture, HarnessSource, generate};
pub use manifest::{ManifestError, ModuleRef, VentureManifest};
pub use provenance::{
    BuildEnvViolation, BuildEnvironmentAttestation, PROVENANCE_SCHEMA, Provenance, ProvenanceError,
    ProvenanceFile, ResourceLimits, file_digest, is_placeholder_digest,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> &'static str {
        r#"{
            "name": "acme-signups",
            "host": "acme.factory0.dev",
            "cors_origins": ["https://acme.example"],
            "modules": ["waitlist", { "slug": "email-signup" }],
            "config": { "brand": "Acme" },
            "seed_sql": "INSERT INTO waitlist_product (slug) VALUES ('launch');"
        }"#
    }

    #[test]
    fn a_manifest_parses_both_module_ref_forms() {
        let manifest = VentureManifest::from_json_str(sample_json()).expect("parses");
        assert_eq!(manifest.name, "acme-signups");
        assert_eq!(manifest.module_slugs(), vec!["waitlist", "email-signup"]);
    }

    #[test]
    fn a_manifest_round_trips_through_json() {
        let manifest = VentureManifest::from_json_str(sample_json()).expect("parses");
        let json = manifest.to_json_string().expect("serializes");
        let back = VentureManifest::from_json_str(&json).expect("re-parses");
        assert_eq!(manifest, back);
    }

    #[test]
    fn resolution_pulls_the_closure_and_keys_order_independently() {
        let manifest = VentureManifest::from_json_str(sample_json()).expect("parses");
        let set = manifest.resolve(&builtin()).expect("resolves");
        assert!(set.contains("waitlist"));
        assert!(set.contains("email-signup"));
        // built-in modules have no deps today, so the key is the two slugs
        // sorted — and independent of listed order.
        assert_eq!(set.content_key(), "email-signup+waitlist");
    }

    #[test]
    fn an_unknown_module_is_refused_with_a_clear_error() {
        let json = r#"{ "name": "x", "host": "x.dev", "modules": ["ghost"] }"#;
        let manifest = VentureManifest::from_json_str(json).expect("parses");
        let err = manifest.resolve(&builtin()).expect_err("unknown module");
        assert!(matches!(
            err,
            ManifestError::Resolve(ResolveError::UnknownModule(ref s)) if s == "ghost"
        ));
    }

    #[test]
    fn an_empty_name_is_refused() {
        let json = r#"{ "name": "", "host": "x.dev", "modules": [] }"#;
        let manifest = VentureManifest::from_json_str(json).expect("parses");
        assert_eq!(
            manifest.validate(),
            Err(ManifestError::MissingField("name"))
        );
    }

    #[test]
    fn a_duplicate_module_is_refused() {
        let json = r#"{ "name": "x", "host": "x.dev", "modules": ["cms", "cms"] }"#;
        let manifest = VentureManifest::from_json_str(json).expect("parses");
        assert_eq!(
            manifest.validate(),
            Err(ManifestError::DuplicateModule("cms".to_owned()))
        );
    }

    #[test]
    fn generation_is_deterministic() {
        let manifest = VentureManifest::from_json_str(sample_json()).expect("parses");
        let set = manifest.resolve(&builtin()).expect("resolves");
        let a = generate(&manifest, &set, &HarnessSource::default()).expect("generates");
        let b = generate(&manifest, &set, &HarnessSource::default()).expect("generates");
        assert_eq!(a, b, "the same manifest must generate byte-identical files");
        assert_eq!(a.composition_hash, b.composition_hash);
    }

    #[test]
    fn generation_emits_the_expected_files_and_wiring() {
        let manifest = VentureManifest::from_json_str(sample_json()).expect("parses");
        let set = manifest.resolve(&builtin()).expect("resolves");
        let venture = generate(&manifest, &set, &HarnessSource::default()).expect("generates");

        let paths: Vec<&str> = venture.files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.contains(&"Cargo.toml"));
        assert!(paths.contains(&"src/lib.rs"));
        assert!(paths.contains(&"src/fz_main.rs"));
        assert!(paths.contains(&"wrangler.toml"));
        assert!(paths.contains(&"seed.sql"), "seed_sql present -> seed.sql");

        let file = |name: &str| {
            venture
                .files
                .iter()
                .find(|f| f.path == name)
                .map(|f| f.contents.as_str())
                .unwrap_or_default()
        };

        let cargo = file("Cargo.toml");
        // both modules need a mailer -> resend feature is wired
        assert!(cargo.contains("\"resend\""), "{cargo}");
        assert!(cargo.contains("\"email-signup\""));
        assert!(cargo.contains("\"waitlist\""));
        assert!(cargo.contains("crate-type = [\"cdylib\", \"rlib\"]"));

        let lib = file("src/lib.rs");
        assert!(lib.contains("use cratefield::waitlist::Waitlist;"));
        assert!(lib.contains("use cratefield::email_signup::EmailSignup;"));
        assert!(lib.contains(".module(Waitlist::new())"));
        assert!(lib.contains(".module(EmailSignup::new())"));
        assert!(lib.contains("default_templates()"));
        assert!(lib.contains("cratefield::Venture::new(\"acme-signups\", \"acme.factory0.dev\")"));

        let fz = file("src/fz_main.rs");
        assert!(fz.contains("cratefield_cli::main_for(acme_signups::harness);"));

        let wrangler = file("wrangler.toml");
        assert!(wrangler.contains("binding = \"DB\""));
        assert!(wrangler.contains("[vars]"));
        assert!(wrangler.contains("brand = \"Acme\""));
    }

    #[test]
    fn a_cms_only_venture_needs_no_mailer() {
        let json = r#"{ "name": "docs-site", "host": "docs.dev", "modules": ["cms"] }"#;
        let manifest = VentureManifest::from_json_str(json).expect("parses");
        let set = manifest.resolve(&builtin()).expect("resolves");
        let venture = generate(&manifest, &set, &HarnessSource::default()).expect("generates");
        let cargo = &venture.files[0].contents;
        assert!(
            !cargo.contains("\"resend\""),
            "cms needs no mailer: {cargo}"
        );
    }

    #[test]
    fn a_path_source_emits_path_deps_for_offline_builds() {
        let manifest = VentureManifest::from_json_str(sample_json()).expect("parses");
        let set = manifest.resolve(&builtin()).expect("resolves");
        let venture = generate(
            &manifest,
            &set,
            &HarnessSource::Path("/opt/harness".to_owned()),
        )
        .expect("generates");
        let cargo = &venture.files[0].contents;
        assert!(
            cargo.contains("path = \"/opt/harness/crates/facade\""),
            "{cargo}"
        );
    }

    #[test]
    fn the_builtin_catalog_is_coherent() {
        builtin()
            .validate()
            .expect("the built-in catalog must be valid");
    }

    // -- release gating (issue #142) ------------------------------------

    fn single_entry(slug: &str, releases: Vec<ModuleRelease>) -> Catalog {
        Catalog {
            modules: vec![CatalogModule {
                slug: slug.to_owned(),
                name: slug.to_owned(),
                summary: String::new(),
                tier: Tier::Optional,
                depends_on: vec![],
                releases,
            }],
        }
    }

    fn approved_pin(version: &str) -> ModuleRelease {
        ModuleRelease {
            version: version.to_owned(),
            digest: format!("sha256:{}", "a".repeat(64)),
            review: ReleaseReview::Approved {
                reviewer: "test-reviewer".to_owned(),
                reviewed_at: "2026-01-01T00:00:00Z".to_owned(),
            },
        }
    }

    #[test]
    fn the_builtin_catalog_resolves_with_reviewed_pins() {
        let set = builtin()
            .resolve(&["waitlist"])
            .expect("the shipped catalog resolves");
        assert_eq!(set.releases().len(), set.slugs().len());
        let pin = set.release("waitlist").expect("waitlist is pinned");
        assert_eq!(pin.version, "0.1.1");
        // The honesty marker: seed digests are the visible placeholder
        // until CI stamps releases; a sanctioned build refuses them.
        assert!(is_placeholder_digest(&pin.digest));
    }

    #[test]
    fn an_entry_with_no_pinned_release_is_refused() {
        let catalog = single_entry("blog", vec![]);
        assert_eq!(
            catalog.resolve(&["blog"]),
            Err(ResolveError::Unpinned("blog".to_owned()))
        );
    }

    #[test]
    fn revocation_refuses_a_selection_that_resolved_minutes_earlier() {
        let mut catalog = single_entry("blog", vec![approved_pin("1.0.0")]);
        catalog
            .resolve(&["blog"])
            .expect("approved before the advisory");
        catalog.modules[0].releases = vec![ModuleRelease {
            version: "1.0.0".to_owned(),
            digest: format!("sha256:{}", "a".repeat(64)),
            review: ReleaseReview::Revoked {
                by: "sec-oncall".to_owned(),
                revoked_at: "2026-09-08T00:00:00Z".to_owned(),
                reason: "dependency poisoned".to_owned(),
            },
        }];
        let err = catalog
            .resolve(&["blog"])
            .expect_err("revoked after the advisory");
        assert!(matches!(
            &err,
            ResolveError::Revoked { slug, version, .. }
                if slug == "blog" && version == "1.0.0"
        ));
        assert!(err.to_string().contains("dependency poisoned"));
    }

    #[test]
    fn the_manifest_propagates_a_release_refusal() {
        let json = r#"{ "name": "x", "host": "x.dev", "modules": ["blog"] }"#;
        let manifest = VentureManifest::from_json_str(json).expect("parses");
        let catalog = single_entry(
            "blog",
            vec![ModuleRelease {
                version: "2.0.0".to_owned(),
                digest: format!("sha256:{}", "a".repeat(64)),
                review: ReleaseReview::Pending,
            }],
        );
        let err = manifest
            .resolve(&catalog)
            .expect_err("pending is not approved");
        assert!(matches!(
            err,
            ManifestError::Resolve(ResolveError::Unreviewed { ref slug, ref version })
                if slug == "blog" && version == "2.0.0"
        ));
    }

    // -- provenance (issue #142) ----------------------------------------

    fn artifact() -> GeneratedVenture {
        let files = vec![
            GeneratedFile {
                path: "Cargo.toml".to_owned(),
                contents: "[package]\nname = \"acme\"\n".to_owned(),
            },
            GeneratedFile {
                path: "src/lib.rs".to_owned(),
                contents: "// venture\n".to_owned(),
            },
        ];
        let composition_hash = generate::composition_hash_of(&files);
        GeneratedVenture {
            name: "acme-signups".to_owned(),
            modules: vec!["waitlist".to_owned()],
            content_key: "waitlist".to_owned(),
            composition_hash,
            files,
        }
    }

    fn reviewed_set() -> ModuleSet {
        single_entry("waitlist", vec![approved_pin("1.0.0")])
            .resolve(&["waitlist"])
            .expect("resolves")
    }

    fn good_env() -> BuildEnvironmentAttestation {
        BuildEnvironmentAttestation {
            sandbox_digest: format!("sha256:{}", "b".repeat(64)),
            disposable: true,
            workspace_scoped: true,
            network_egress: "registry-allowlist".to_owned(),
            deploy_credentials_withheld: true,
            production_key_absent: true,
            limits: ResourceLimits {
                wall_clock: "600s".to_owned(),
                memory: "4Gi".to_owned(),
                disk: "10Gi".to_owned(),
            },
        }
    }

    #[test]
    fn provenance_round_trips_and_verifies_its_artifact() {
        let artifact = artifact();
        let record = Provenance::record(
            &artifact,
            &reviewed_set(),
            "test-builder",
            Some("2026-09-09T00:00:00Z"),
            None,
        )
        .expect("a local record always writes");
        assert_eq!(record.attestation, None);
        assert_eq!(record.releases.len(), 1);
        let back = Provenance::from_json(&record.to_json()).expect("round-trips");
        assert_eq!(back, record);
        back.verify_against(&artifact)
            .expect("the artifact verifies");
    }

    #[test]
    fn a_tampered_file_fails_verification() {
        let artifact = artifact();
        let record =
            Provenance::record(&artifact, &reviewed_set(), "b", None, None).expect("records");
        let mut tampered = artifact.clone();
        tampered.files[1].contents = "// evil\n".to_owned();
        let err = record
            .verify_against(&tampered)
            .expect_err("digest must catch the edit");
        assert!(matches!(
            err,
            ProvenanceError::FileDigestMismatch { ref path, .. } if path == "src/lib.rs"
        ));
    }

    #[test]
    fn files_swapped_in_or_out_fail_verification() {
        let artifact = artifact();
        let record =
            Provenance::record(&artifact, &reviewed_set(), "b", None, None).expect("records");
        let mut extra = artifact.clone();
        extra.files.push(GeneratedFile {
            path: "src/backdoor.rs".to_owned(),
            contents: String::new(),
        });
        assert!(matches!(
            record.verify_against(&extra),
            Err(ProvenanceError::FileListMismatch { .. })
        ));
    }

    #[test]
    fn a_fabricated_composition_hash_fails_verification() {
        let artifact = artifact();
        let record =
            Provenance::record(&artifact, &reviewed_set(), "b", None, None).expect("records");
        let mut drifted = artifact.clone();
        drifted.composition_hash = "deadbeef".to_owned();
        assert!(matches!(
            record.verify_against(&drifted),
            Err(ProvenanceError::CompositionMismatch { .. })
        ));
    }

    #[test]
    fn provenance_never_claims_a_different_venture_or_set() {
        let artifact = artifact();
        let record =
            Provenance::record(&artifact, &reviewed_set(), "b", None, None).expect("records");
        let other = GeneratedVenture {
            name: "someone-else".to_owned(),
            ..artifact.clone()
        };
        assert!(matches!(
            record.verify_against(&other),
            Err(ProvenanceError::VentureMismatch { .. })
        ));
        let other = GeneratedVenture {
            content_key: "cms+waitlist".to_owned(),
            ..artifact
        };
        assert!(matches!(
            record.verify_against(&other),
            Err(ProvenanceError::ModuleSetMismatch { .. })
        ));
    }

    #[test]
    fn a_record_with_an_unknown_schema_is_rejected() {
        let artifact = artifact();
        let json = Provenance::record(&artifact, &reviewed_set(), "b", None, None)
            .expect("records")
            .to_json()
            .replace(PROVENANCE_SCHEMA, "fz-provenance/99");
        assert!(matches!(
            Provenance::from_json(&json),
            Err(ProvenanceError::BadRecord(_))
        ));
    }

    #[test]
    fn an_attestation_that_fails_the_contract_is_refused_at_record_time() {
        let mut env = good_env();
        env.network_egress = "open".to_owned();
        env.deploy_credentials_withheld = false;
        let violations = env.check();
        assert_eq!(violations.len(), 2, "{violations:?}");
        assert!(matches!(
            Provenance::record(&artifact(), &reviewed_set(), "b", None, Some(env)),
            Err(ProvenanceError::Environment(BuildEnvViolation(ref v))) if v.len() == 2
        ));
        assert!(good_env().check().is_empty(), "the fixture is sound");
    }

    #[test]
    fn a_sanctioned_build_refuses_placeholder_pins() {
        // The shipped pins are stamped placeholders; resolution accepts
        // their *shape* (local dev builds must keep working) but an
        // attested, sanctioned record refuses them (issue #142).
        let set = builtin().resolve(&["waitlist"]).expect("resolves");
        assert!(matches!(
            Provenance::record(&artifact(), &set, "fleet-a", None, Some(good_env())),
            Err(ProvenanceError::UnstampedPin(ref slug)) if slug == "waitlist"
        ));
    }

    #[test]
    fn a_sanctioned_record_carries_a_stable_attestation_digest() {
        let artifact = artifact();
        let record = Provenance::record(
            &artifact,
            &reviewed_set(),
            "fleet-a",
            None,
            Some(good_env()),
        )
        .expect("a clean attestation records");
        record.verify_against(&artifact).expect("verifies");
        let env = record.attestation.as_ref().expect("attested");
        assert_eq!(env.attestation_digest(), good_env().attestation_digest());
        let back = BuildEnvironmentAttestation::from_json(&env.to_json()).expect("round-trips");
        assert_eq!(back.attestation_digest(), env.attestation_digest());
        let json = record.to_json();
        assert!(json.contains("\"built-at\": null"), "no clock, no lie");
        assert_eq!(Provenance::from_json(&json).expect("parses"), record);
    }

    #[test]
    fn file_digests_are_content_bound_sha256_addresses() {
        let a = file_digest("hello");
        assert!(is_sha256_digest(&a));
        assert_ne!(a, file_digest("hellp"));
        assert!(!is_placeholder_digest(&a));
        assert!(is_placeholder_digest(&format!("sha256:{}", "0".repeat(64))));
    }
}
