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

pub mod catalog;
pub mod generate;
pub mod manifest;

pub use catalog::{Catalog, CatalogModule, ModuleSet, ResolveError, Tier, builtin};
pub use generate::{GeneratedFile, GeneratedVenture, HarnessSource, generate};
pub use manifest::{ManifestError, ModuleRef, VentureManifest};

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
}
