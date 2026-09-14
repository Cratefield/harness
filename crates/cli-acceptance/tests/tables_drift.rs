//! Acceptance for `fz tables drift` (issue #153): the featureless build
//! refuses with a message and never dials; the `postgres`-feature build
//! reads a real catalog and reports against the manifest's declaration.
//!
//! The pair this exercises landed a PR apart and had no way to meet: a
//! manifest can declare `[tables]`, and `cratefield_introspect::drift`
//! can compare a declaration against a catalog. Until this command
//! neither was reachable by a person.

use std::path::{Path, PathBuf};

use cratefield_cli::tables::drift_report;

/// The same throwaway-directory helper the other acceptance files carry;
/// `tests/` is one binary per file, so it is defined where it is used.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "fz-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("after the epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A manifest declaring one table, written to `dir` as `venture.json`.
fn manifest_at(dir: &Path, tables: &str) -> std::path::PathBuf {
    named_manifest_at(dir, "venture.json", tables)
}

/// The same, under a name of the caller's choosing — two manifests in one
/// directory is the whole shape of a diff, and one helper that always
/// wrote `venture.json` silently made them the same file.
fn named_manifest_at(dir: &Path, name: &str, tables: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    // Every declared table has to say what it holds (issue #153), so the
    // fixture says it here too: this file is about drift, and a manifest
    // that would not validate is not a fixture for anything.
    let empty = tables.trim() == "{}";
    let privacy = if empty {
        "{}".to_owned()
    } else {
        r#"{ "note": { "holds": "nothing", "reason": "A fixture table; nobody is in it." } }"#
            .to_owned()
    };
    // And who may reach it, for the same reason: a declared table without
    // an access level is not a manifest the harness will accept.
    let access = if empty {
        "{}".to_owned()
    } else {
        r#"{ "note": "public-read" }"#.to_owned()
    };
    let body = format!(
        r#"{{
            "name": "acme",
            "host": "acme.factory0.dev",
            "modules": [],
            "tables": {tables},
            "table_privacy": {privacy},
            "table_access": {access}
        }}"#
    );
    std::fs::write(&path, body).expect("manifest writes");
    path
}

const ONE_TABLE: &str = r#"{
    "note": {
        "primary_key": "id",
        "fields": [
            { "name": "id", "kind": "uuid", "required": true },
            { "name": "body", "kind": "text", "max_len": 400 }
        ]
    }
}"#;

#[test]
fn an_unreachable_dialect_is_refused_before_anything_dials() {
    let dir = TempDir::new("tables-drift-dialect");
    let manifest = manifest_at(dir.path(), ONE_TABLE);
    // A credential in the URL, to prove the refusal never echoes it.
    let err = drift_report(
        &manifest,
        "sqlite",
        "postgres://leak:supersecret@127.0.0.1:1/none",
    )
    .expect_err("sqlite is not reachable from here");
    assert!(
        !err.contains("supersecret"),
        "the refusal echoed the connection string: {err}"
    );
    assert!(err.to_lowercase().contains("sqlite"), "{err}");
}

#[cfg(not(feature = "postgres"))]
#[test]
fn without_the_feature_the_command_says_which_build_is_needed() {
    let dir = TempDir::new("tables-drift-featureless");
    let manifest = manifest_at(dir.path(), ONE_TABLE);
    let err = drift_report(&manifest, "postgres", "postgres://127.0.0.1:1/none")
        .expect_err("the featureless build cannot dial");
    assert!(err.contains("postgres` feature"), "{err}");
}

#[cfg(feature = "postgres")]
mod on_postgres {
    use super::{ONE_TABLE, TempDir, manifest_at};
    use cratefield_cli::tables::drift_report;

    #[test]
    fn a_manifest_with_no_tables_says_so_without_reading_a_catalog() {
        // Nothing to compare is not "no drift" — it is a different
        // sentence, and the command says which.
        let dir = TempDir::new("tables-drift-empty");
        let manifest = manifest_at(dir.path(), "{}");
        // The URL is unreachable on purpose: an empty declaration must
        // answer before anything dials.
        drift_report(&manifest, "postgres", "postgres://127.0.0.1:1/none")
            .expect("an empty declaration needs no database");
    }

    #[tokio::test]
    async fn a_database_built_from_the_declaration_reports_no_drift() {
        let Some(base) = cratefield_adapter_postgres::testing::base_url() else {
            eprintln!(
                "SKIPPED: {}",
                cratefield_adapter_postgres::testing::skip_reason()
            );
            return;
        };
        let temp = cratefield_adapter_postgres::testing::TempDb::create(&base, "tablesdrift")
            .await
            .expect("throwaway database");

        // Build the database from the declaration's own DDL, so a report
        // of anything at all is a false one.
        let schema: cratefield_tables::Schema =
            serde_json::from_str(ONE_TABLE).expect("the fixture parses");
        let db = cratefield_adapter_postgres::Postgres::connect(&temp.url)
            .await
            .expect("connect");
        let sql = schema
            .ddl(cratefield_tables::SqlDialect::Postgres)
            .expect("renders");
        for statement in sql.split(';').filter(|s| !s.trim().is_empty()) {
            cratefield_core::Database::execute(
                &db,
                &cratefield_core::Statement::new(statement.to_owned()),
            )
            .await
            .expect("ddl applies");
        }
        db.close().await.expect("close");

        let dir = TempDir::new("tables-drift-live");
        let manifest = manifest_at(dir.path(), ONE_TABLE);
        // Runs on a blocking thread: `drift_report` drives its own
        // executor, and starting one inside tokio's would panic.
        let path = manifest.clone();
        let url = temp.url.clone();
        let count = tokio::task::spawn_blocking(move || drift_report(&path, "postgres", &url))
            .await
            .expect("joins")
            .expect("the catalog reads");
        assert_eq!(
            count, 0,
            "false drift against a database built from the declaration"
        );

        // And the same command against a declaration the database does
        // not match. Without this the assertion above passes on a report
        // that found everything as readily as on one that found nothing —
        // which is what it did before the command answered with a count.
        let grown = ONE_TABLE.replace(
            r#"{ "name": "body", "kind": "text", "max_len": 400 }"#,
            r#"{ "name": "body", "kind": "text", "max_len": 400 },
            { "name": "extra", "kind": "text" }"#,
        );
        let moved = manifest_at(dir.path(), &grown);
        let url = temp.url.clone();
        let count = tokio::task::spawn_blocking(move || drift_report(&moved, "postgres", &url))
            .await
            .expect("joins")
            .expect("the catalog reads");
        assert_eq!(
            count, 1,
            "a declared column the database lacks was not seen"
        );

        temp.finish().await;
    }
}

// ---------------------------------------------------------------------------
// `fz tables diff` — the question before a deploy
// ---------------------------------------------------------------------------

/// `ONE_TABLE` with `extra` appended to `note`.
fn grown() -> String {
    ONE_TABLE.replace(
        r#"{ "name": "body", "kind": "text", "max_len": 400 }"#,
        r#"{ "name": "body", "kind": "text", "max_len": 400 },
            { "name": "extra", "kind": "text" }"#,
    )
}

#[test]
fn two_identical_declarations_have_no_changes() {
    // The case every false report would break, and the one that makes
    // the assertions below mean something: a diff that reported
    // everything would satisfy several of them by accident.
    let dir = TempDir::new("tables-diff-same");
    let a = manifest_at(dir.path(), ONE_TABLE);
    let b = dir.path().join("other.json");
    std::fs::copy(&a, &b).expect("copy");
    let count = cratefield_cli::tables::diff_report(&a, &b).expect("both read");
    assert_eq!(count, 0);
}

#[test]
fn a_new_optional_column_is_one_expand() {
    let dir = TempDir::new("tables-diff-grown");
    let before = named_manifest_at(dir.path(), "before.json", ONE_TABLE);
    let after = named_manifest_at(dir.path(), "after.json", &grown());

    let count = cratefield_cli::tables::diff_report(&before, &after).expect("both read");
    assert_eq!(count, 1, "one added column is one change");

    // And the command fails, because the finding is the point: a CI job
    // comparing a branch against `main` needs something to branch on.
    let error = cratefield_cli::tables::diff(&before, &after).expect_err("a change is a finding");
    assert!(error.contains("1 change"), "{error}");
}

#[test]
fn a_manifest_that_is_not_legal_is_refused_rather_than_compared() {
    // Comparing against a declaration that could never be deployed
    // reports differences nobody can act on, and the reason it cannot be
    // deployed is the thing worth saying.
    let dir = TempDir::new("tables-diff-illegal");
    let good = manifest_at(dir.path(), ONE_TABLE);
    let bad = dir.path().join("bad.json");
    std::fs::write(
        &bad,
        std::fs::read_to_string(&good)
            .expect("read")
            .replace(r#""primary_key": "id""#, r#""primary_key": "nope""#),
    )
    .expect("write");

    let error = cratefield_cli::tables::diff_report(&good, &bad).expect_err("not legal");
    assert!(error.contains("nope"), "{error}");
    assert!(
        error.contains("bad.json"),
        "the message names which one: {error}"
    );
}
