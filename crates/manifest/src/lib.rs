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

pub mod access;
pub mod build_key;
pub mod catalog;
pub mod diff;
pub mod generate;
mod generate_tables;
pub mod manifest;
pub mod privacy;
pub mod provenance;

pub use build_key::{BUILD_PROFILE, BuildKeyError, BuildKeyInputs, build_key, canonical_inputs};
pub use catalog::{
    Catalog, CatalogError, CatalogModule, ModuleRelease, ModuleSet, PinnedRelease, ReleaseReview,
    ResolveError, Tier, builtin, is_exact_version, is_sha256_digest,
};
pub use generate::{GeneratedFile, GeneratedVenture, HarnessSource, generate};
pub use manifest::{ManifestError, ModuleRef, VentureManifest};
// Re-exported so a caller building a `VentureManifest` can name the type
// of its `tables` field without adding a dependency of its own.
pub use access::{Access, AccessMap, LEVELS};
pub use cratefield_tables::Schema;
pub use diff::{Change as DeclarationChange, Move, diff as declaration_diff};
pub use privacy::{Disposition, KINDS, TablePrivacy, TablePrivacyMap};
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

    /// A manifest declaring tables of its own (issue #153).
    fn with_tables() -> &'static str {
        r#"{
            "name": "acme-signups",
            "host": "acme.factory0.dev",
            "cors_origins": ["https://acme.example"],
            "modules": ["waitlist"],
            "tables": {
                "note": {
                    "primary_key": "id",
                    "fields": [
                        { "name": "id", "kind": "uuid", "required": true },
                        { "name": "author", "kind": "text" },
                        { "name": "body", "kind": "text", "max_len": 400 }
                    ]
                }
            },
            "table_privacy": {
                "note": {
                    "holds": "personal",
                    "subject": "author",
                    "kind": "content",
                    "disposition": "erase",
                    "description": "The notes you wrote, and when."
                }
            },
            "table_access": { "note": "owner" }
        }"#
    }

    #[test]
    fn a_manifest_without_tables_still_reads_and_writes_unchanged() {
        // The common case, and the one a new field breaks first: nothing
        // in the document mentions tables, and nothing in the output does
        // either.
        let manifest = VentureManifest::from_json_str(sample_json()).expect("parses");
        assert!(manifest.tables.is_empty());
        manifest.validate().expect("valid");
        let written = serde_json::to_string(&manifest).expect("writes");
        assert!(!written.contains("tables"), "{written}");
    }

    #[test]
    fn a_declared_table_is_carried_and_checked() {
        let manifest = VentureManifest::from_json_str(with_tables()).expect("parses");
        manifest.validate().expect("valid");
        assert_eq!(manifest.tables.tables.len(), 1);
        assert_eq!(manifest.tables.tables[0].name, "note");
        // And back out again: a manifest a control plane writes has to be
        // one it can read.
        let written = serde_json::to_string(&manifest).expect("writes");
        let again = VentureManifest::from_json_str(&written).expect("reads what it wrote");
        assert_eq!(manifest, again);
    }

    #[test]
    fn a_declaration_that_is_not_legal_fails_the_manifest_not_something_later() {
        // The primary key names no declared field. Reported here, beside
        // the manifest's own problems, rather than by whatever layer
        // would have met it next.
        let broken = with_tables().replace(r#""primary_key": "id""#, r#""primary_key": "nope""#);
        let manifest = VentureManifest::from_json_str(&broken).expect("parses");
        let error = manifest.validate().expect_err("not legal");
        let text = error.to_string();
        assert!(text.contains("[tables]"), "{text}");
        assert!(text.contains("nope"), "{text}");
    }

    #[test]
    fn a_declared_table_becomes_a_module_the_venture_composes() {
        // A declaration that produced no module would be a section that
        // does nothing: the tables would not be created, would not be in
        // `fz data export`, and would not be reachable by erasure.
        let manifest = VentureManifest::from_json_str(with_tables()).expect("parses");
        let set = manifest.resolve(&catalog::builtin()).expect("resolves");
        let venture = generate::generate(&manifest, &set, &generate::HarnessSource::default())
            .expect("generates");

        let file = |name: &str| {
            venture
                .files
                .iter()
                .find(|f| f.path == name)
                .map(|f| f.contents.as_str())
                .unwrap_or_default()
        };

        let tables = file("src/tables.rs");
        assert!(!tables.is_empty(), "no src/tables.rs was emitted");
        assert!(
            tables.contains("CREATE TABLE IF NOT EXISTS note"),
            "{tables}"
        );
        // `tables()` and `personal_data()` both name it, which is the
        // pair `unlisted_tables` and `undeclared_tables` compare.
        assert!(tables.contains("&[\"note\"]"), "{tables}");
        assert!(tables.contains("table: \"note\""), "{tables}");
        assert!(tables.contains("subject: \"author\""), "{tables}");
        assert!(tables.contains("DataKind::Content"), "{tables}");
        assert!(tables.contains("Disposition::Erase"), "{tables}");

        // A table whose access is not `public-read` is a question about
        // who is asking, so the module declares the port that answers it.
        assert!(
            tables.contains("&[Port::Db, Port::Auth]"),
            "an owner table generated a module that needs no verifier: {tables}"
        );

        // The module serves the tables rather than only creating them.
        // `crates/tables-api/tests/routes.rs` hand-writes this same shape
        // and compiles and drives it, so what these assert is that the
        // generator emits that shape — not that the shape works.
        assert!(
            tables.contains("cratefield::tables_api::router(Arc::new("),
            "the generated module creates the tables and serves nothing: {tables}"
        );
        assert!(
            tables.contains("cratefield::tables_api::Tables {"),
            "{tables}"
        );
        assert!(tables.contains("const DECLARED: &str = r#"), "{tables}");
        // And reads it while composing, so a declaration it cannot read
        // refuses the deployment rather than serving no tables.
        //
        // The body of `validate_config` alone, not everything after it:
        // the first version of this sliced to the end of the file, which
        // contains `router`'s own `parse` call, so it passed with
        // `validate_config` returning `Ok(())`.
        let validate = {
            let from = tables
                .find("fn validate_config")
                .expect("the module validates its config");
            let rest = &tables[from..];
            let to = rest.find("fn router").expect("router follows it");
            &rest[..to]
        };
        assert!(
            validate.contains("cratefield::tables_api::parse(DECLARED)"),
            "the declaration is never read while composing: {validate}"
        );

        // And publishes what it serves, or `/__surface` describes a
        // venture smaller than the one running.
        assert!(
            tables.contains("fn surface(&self) -> Surface"),
            "the declared tables are served and unpublished: {tables}"
        );
        assert!(
            tables.contains("cratefield::tables_api::surface(&tables)"),
            "{tables}"
        );

        // And the venture composes it, or it is a file nobody builds.
        // The facade feature that carries the routes, or the generated
        // crate does not compile: `cratefield::tables_api` is behind it.
        let cargo = file("Cargo.toml");
        assert!(cargo.contains("\"tables-api\","), "{cargo}");

        let lib = file("src/lib.rs");
        assert!(lib.contains("pub mod tables;"), "{lib}");
        assert!(
            lib.contains(".module(crate::tables::DeclaredTables::new())"),
            "{lib}"
        );
    }

    #[test]
    fn a_venture_with_a_non_public_table_wires_a_verifier() {
        // The module requires `Port::Auth`, so the runtime has to provide
        // one or the composition is refused at boot — correct, and
        // useless, because nothing would ever wire it.
        let manifest = VentureManifest::from_json_str(with_tables()).expect("parses");
        let set = manifest.resolve(&catalog::builtin()).expect("resolves");
        let venture = generate::generate(&manifest, &set, &generate::HarnessSource::default())
            .expect("generates");
        let lib = venture
            .files
            .iter()
            .find(|f| f.path == "src/lib.rs")
            .map(|f| f.contents.as_str())
            .unwrap_or_default();
        assert!(
            lib.contains(".auth_from_env()"),
            "an owner table generated a venture that cannot boot: {lib}"
        );
    }

    #[test]
    fn a_venture_whose_tables_are_all_public_does_not_wire_a_verifier() {
        // Nothing asks who is calling, so nothing needs an auth service.
        let manifest = VentureManifest::from_json_str(
            &with_tables().replace(r#""note": "owner""#, r#""note": "public-read""#),
        )
        .expect("parses");
        let set = manifest.resolve(&catalog::builtin()).expect("resolves");
        let venture = generate::generate(&manifest, &set, &generate::HarnessSource::default())
            .expect("generates");
        let lib = venture
            .files
            .iter()
            .find(|f| f.path == "src/lib.rs")
            .map(|f| f.contents.as_str())
            .unwrap_or_default();
        assert!(!lib.contains("auth_from_env"), "{lib}");
    }

    #[test]
    fn a_venture_whose_tables_are_all_public_does_not_demand_a_verifier() {
        // The other half, and the one that makes the rule a rule rather
        // than a constant: requiring `Port::Auth` from every venture
        // would make a deployment that serves only public reference data
        // refuse to start until somebody wired an auth service it has no
        // use for.
        let tables = generated_tables_rs(
            &with_tables().replace(r#""note": "owner""#, r#""note": "public-read""#),
        );
        assert!(tables.contains("&[Port::Db]"), "{tables}");
        assert!(!tables.contains("Port::Auth"), "{tables}");
    }

    /// `src/tables.rs` as generated from a manifest's JSON.
    fn generated_tables_rs(json: &str) -> String {
        let manifest = VentureManifest::from_json_str(json).expect("the fixture parses");
        let set = manifest.resolve(&catalog::builtin()).expect("resolves");
        let venture = generate::generate(&manifest, &set, &generate::HarnessSource::default())
            .expect("generates");
        venture
            .files
            .iter()
            .find(|f| f.path == "src/tables.rs")
            .map(|f| f.contents.clone())
            .unwrap_or_default()
    }

    #[test]
    fn one_table_that_is_not_public_is_enough_to_need_a_verifier() {
        // Any, not all: a venture serving nine public tables and one
        // `owner` table still has to be able to say who is asking.
        let two_tables = with_tables()
            .replace(
                r#""note": {
                    "primary_key": "id","#,
                r#""tier": {
                    "primary_key": "id",
                    "fields": [ { "name": "id", "kind": "uuid", "required": true } ]
                },
                "note": {
                    "primary_key": "id","#,
            )
            .replace(
                r#""table_privacy": {"#,
                r#""table_privacy": {
                "tier": { "holds": "nothing", "reason": "Plan tiers; nobody is in them." },"#,
            )
            .replace(
                r#""table_access": { "note": "owner" }"#,
                r#""table_access": { "note": "owner", "tier": "public-read" }"#,
            );
        let tables = generated_tables_rs(&two_tables);
        assert!(
            tables.contains("\"tier\""),
            "the fixture has both: {tables}"
        );
        assert!(tables.contains("Port::Auth"), "{tables}");
    }

    #[test]
    fn a_venture_that_lists_no_cors_origins_still_generates_valid_rust() {
        // `.cors_origins([])` has no inferable element type, so this
        // generated a crate that did not compile. Found by generating a
        // venture and running `cargo check` over it rather than by any
        // test here: every fixture in this file lists an origin, so the
        // empty case had never been rendered.
        //
        // `validate()` now refuses an empty list, so `fz build` cannot
        // reach this — but `generate()` is a library function and this
        // calls it directly, which is the only way the renderer's empty
        // case stays covered. The test's name is about the Rust it
        // renders; whether that venture would *boot* is a different
        // question, and the answer was no.
        // The module set comes from a manifest that is legal; the
        // manifest handed to `generate` is then emptied of its origins,
        // which `validate` would refuse and `generate` does not check.
        let legal = VentureManifest::from_json_str(sample_json()).expect("parses");
        let set = legal.resolve(&catalog::builtin()).expect("resolves");
        let mut without = legal.clone();
        without.cors_origins.clear();
        assert!(
            without.validate().is_err(),
            "an empty origin list has to be a manifest error, or `fz build` \
             emits a venture that panics on its first request"
        );

        let venture = generate::generate(&without, &set, &generate::HarnessSource::default())
            .expect("generates");
        let lib = venture
            .files
            .iter()
            .find(|f| f.path == "src/lib.rs")
            .map(|f| f.contents.as_str())
            .unwrap_or_default();
        assert!(!lib.contains("cors_origins"), "{lib}");

        // And one that does list them still gets the call.
        let manifest = VentureManifest::from_json_str(sample_json()).expect("parses");
        let set = manifest.resolve(&catalog::builtin()).expect("resolves");
        let venture = generate::generate(&manifest, &set, &generate::HarnessSource::default())
            .expect("generates");
        let lib = venture
            .files
            .iter()
            .find(|f| f.path == "src/lib.rs")
            .map(|f| f.contents.as_str())
            .unwrap_or_default();
        assert!(
            lib.contains(".cors_origins([\"https://acme.example\"])"),
            "{lib}"
        );
    }

    #[test]
    fn a_declared_table_must_say_who_may_reach_it() {
        // Same argument as the privacy block: `public-read` by default
        // publishes a venture's tables the day the CRUD layer lands, and
        // `admin` by default makes them useless until somebody notices.
        let base: serde_json::Value =
            serde_json::from_str(with_tables()).expect("the fixture is JSON");
        let mut object = base.as_object().expect("an object").clone();
        object.remove("table_access");
        let error = VentureManifest::from_json_str(&serde_json::Value::Object(object).to_string())
            .expect("parses")
            .validate()
            .expect_err("must say");
        let text = error.to_string();
        assert!(text.contains("does not say who may reach it"), "{text}");
        assert!(text.contains("public-read"), "the four are listed: {text}");
    }

    #[test]
    fn owner_needs_the_table_to_say_whose_each_row_is() {
        // `owner` matches a caller against the column the privacy block
        // names. On a table that holds nothing personal there is no such
        // column, and a route falling back to "everyone" or "nobody"
        // would be deciding that silently.
        let base: serde_json::Value =
            serde_json::from_str(with_tables()).expect("the fixture is JSON");
        let mut object = base.as_object().expect("an object").clone();
        object.insert(
            "table_privacy".to_owned(),
            serde_json::json!({ "note": { "holds": "nothing", "reason": "Reference data." } }),
        );
        let error = VentureManifest::from_json_str(&serde_json::Value::Object(object).to_string())
            .expect("parses")
            .validate()
            .expect_err("nothing to match a caller against");
        let text = error.to_string();
        assert!(
            text.contains("no column to match a caller against"),
            "{text}"
        );

        // The other three do not need one.
        for level in ["public-read", "tenant-members", "admin"] {
            let mut object = base.as_object().expect("an object").clone();
            object.insert(
                "table_privacy".to_owned(),
                serde_json::json!({ "note": { "holds": "nothing", "reason": "Reference data." } }),
            );
            object.insert(
                "table_access".to_owned(),
                serde_json::json!({ "note": level }),
            );
            VentureManifest::from_json_str(&serde_json::Value::Object(object).to_string())
                .expect("parses")
                .validate()
                .unwrap_or_else(|err| panic!("{level} should be legal here: {err}"));
        }
    }

    #[test]
    fn access_for_a_table_that_is_not_declared_is_refused() {
        let base: serde_json::Value =
            serde_json::from_str(with_tables()).expect("the fixture is JSON");
        let mut object = base.as_object().expect("an object").clone();
        object.insert(
            "table_access".to_owned(),
            serde_json::json!({ "note": "owner", "ghost": "admin" }),
        );
        let error = VentureManifest::from_json_str(&serde_json::Value::Object(object).to_string())
            .expect("parses")
            .validate()
            .expect_err("not a declared table");
        assert!(
            error.to_string().contains("not a declared table"),
            "{error}"
        );
    }

    #[test]
    fn a_venture_with_no_declared_tables_gets_no_tables_module() {
        let manifest = VentureManifest::from_json_str(sample_json()).expect("parses");
        let set = manifest.resolve(&catalog::builtin()).expect("resolves");
        let venture = generate::generate(&manifest, &set, &generate::HarnessSource::default())
            .expect("generates");
        let paths: Vec<&str> = venture.files.iter().map(|f| f.path.as_str()).collect();
        assert!(!paths.contains(&"src/tables.rs"), "{paths:?}");
        let lib = venture
            .files
            .iter()
            .find(|f| f.path == "src/lib.rs")
            .map(|f| f.contents.as_str())
            .unwrap_or_default();
        assert!(!lib.contains("mod tables"), "{lib}");
    }

    /// The same manifest with the privacy block removed.
    fn without_privacy() -> String {
        let full: serde_json::Value =
            serde_json::from_str(with_tables()).expect("the fixture is JSON");
        let mut object = full.as_object().expect("an object").clone();
        object.remove("table_privacy");
        serde_json::Value::Object(object).to_string()
    }

    #[test]
    fn a_declared_table_must_say_what_it_holds() {
        // Both available defaults are wrong: "nothing personal unless you
        // say" puts a venture's tables outside export and erasure
        // silently, and "personal unless you say" deletes reference data
        // the first time somebody asks. So there is no default.
        let manifest = VentureManifest::from_json_str(&without_privacy()).expect("parses");
        let error = manifest.validate().expect_err("must say");
        let text = error.to_string();
        assert!(text.contains("does not say what it holds"), "{text}");
        assert!(text.contains("tables.note.privacy"), "{text}");
    }

    #[test]
    fn saying_a_table_holds_nothing_is_one_line_and_needs_the_reason() {
        let base: serde_json::Value =
            serde_json::from_str(&without_privacy()).expect("the fixture is JSON");
        let with = |privacy: serde_json::Value| {
            let mut object = base.as_object().expect("an object").clone();
            object.insert(
                "table_privacy".to_owned(),
                serde_json::json!({ "note": privacy }),
            );
            // This test is about the privacy block, so the access level
            // is one that asks nothing of it — `owner` would need a
            // subject column, which is a different rule's business.
            object.insert(
                "table_access".to_owned(),
                serde_json::json!({ "note": "public-read" }),
            );
            VentureManifest::from_json_str(&serde_json::Value::Object(object).to_string())
                .expect("parses")
        };

        with(serde_json::json!({
            "holds": "nothing",
            "reason": "One row per plan tier; nobody is named in it."
        }))
        .validate()
        .expect("a reason is all it takes");

        // Without the reason it is a silence wearing a decision's
        // clothes, which is the thing this refuses.
        let error = with(serde_json::json!({ "holds": "nothing", "reason": "  " }))
            .validate()
            .expect_err("an empty reason is not a reason");
        assert!(error.to_string().contains("needs a reason"), "{error}");
    }

    #[test]
    fn a_declaration_must_describe_columns_the_table_actually_has() {
        // Each rule is a promise about a column, and a promise about a
        // column that does not exist is not checkable by anything later.
        let base: serde_json::Value =
            serde_json::from_str(&without_privacy()).expect("the fixture is JSON");
        let check = |privacy: serde_json::Value| -> String {
            let mut object = base.as_object().expect("an object").clone();
            object.insert(
                "table_privacy".to_owned(),
                serde_json::json!({ "note": privacy }),
            );
            object.insert(
                "table_access".to_owned(),
                serde_json::json!({ "note": "public-read" }),
            );
            VentureManifest::from_json_str(&serde_json::Value::Object(object).to_string())
                .expect("parses")
                .validate()
                .expect_err("not valid")
                .to_string()
        };

        let text = check(serde_json::json!({
            "holds": "personal", "subject": "nobody", "kind": "content",
            "disposition": "erase", "description": "x"
        }));
        assert!(text.contains("`nobody` is not a field"), "{text}");

        let text = check(serde_json::json!({
            "holds": "personal", "subject": "author", "kind": "invented",
            "disposition": "erase", "description": "x"
        }));
        assert!(text.contains("is not a data kind"), "{text}");

        // An empty description is published to the person asking.
        let text = check(serde_json::json!({
            "holds": "personal", "subject": "author", "kind": "content",
            "disposition": "erase", "description": " "
        }));
        assert!(text.contains("must not be empty"), "{text}");
    }

    #[test]
    fn anonymise_names_columns_a_database_can_actually_overwrite() {
        // The same check `cratefield-module-privacy` makes against the
        // applied schema rather than trusting: a `NOT NULL` column with
        // no default has nothing to be overwritten with, and a primary
        // key cannot move.
        let base: serde_json::Value =
            serde_json::from_str(&without_privacy()).expect("the fixture is JSON");
        let check = |columns: serde_json::Value| -> String {
            let mut object = base.as_object().expect("an object").clone();
            object.insert(
                "table_privacy".to_owned(),
                serde_json::json!({ "note": {
                    "holds": "personal", "subject": "author", "kind": "content",
                    "disposition": { "anonymise": columns },
                    "description": "x"
                }}),
            );
            VentureManifest::from_json_str(&serde_json::Value::Object(object).to_string())
                .expect("parses")
                .validate()
                .map_or_else(|err| err.to_string(), |()| String::new())
        };

        assert!(
            check(serde_json::json!(["body"])).is_empty(),
            "an optional column is fine"
        );
        assert!(
            check(serde_json::json!(["id"])).contains("required and has no default"),
            "a required column with no default was accepted"
        );
        assert!(
            check(serde_json::json!([])).contains("erases nothing"),
            "an empty anonymise list was accepted"
        );
        assert!(
            check(serde_json::json!(["ghost"])).contains("not a field"),
            "a column that does not exist was accepted"
        );
    }

    #[test]
    fn privacy_for_a_table_that_is_not_declared_is_refused() {
        let base: serde_json::Value =
            serde_json::from_str(with_tables()).expect("the fixture is JSON");
        let mut object = base.as_object().expect("an object").clone();
        let mut privacy = object["table_privacy"].as_object().expect("map").clone();
        privacy.insert(
            "ghost".to_owned(),
            serde_json::json!({ "holds": "nothing", "reason": "x" }),
        );
        object.insert(
            "table_privacy".to_owned(),
            serde_json::Value::Object(privacy),
        );
        let error = VentureManifest::from_json_str(&serde_json::Value::Object(object).to_string())
            .expect("parses")
            .validate()
            .expect_err("not a declared table");
        assert!(
            error.to_string().contains("not a declared table"),
            "{error}"
        );
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
        let json = r#"{ "name": "x", "host": "x.dev", "cors_origins": ["https://x.dev"], "modules": ["ghost"] }"#;
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
        let json = r#"{ "name": "x", "host": "x.dev", "cors_origins": ["https://x.dev"], "modules": ["cms", "cms"] }"#;
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
        // The mailer wiring must move with `Resend::new`'s signature; a
        // generated venture that cannot compile is found here, not at deploy.
        assert!(lib.contains("cratefield::resend::Resend::new("));
        assert!(lib.contains("cratefield::cloudflare::WorkersClock"));
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
        let json = r#"{ "name": "docs-site", "host": "docs.dev", "cors_origins": ["https://docs.dev"], "modules": ["cms"] }"#;
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
        let json = r#"{ "name": "x", "host": "x.dev", "cors_origins": ["https://x.dev"], "modules": ["blog"] }"#;
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
