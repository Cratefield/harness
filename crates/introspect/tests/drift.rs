//! Drift between a declaration and a live database (issue #153).
//!
//! Every case runs against a real SQLite database built from the
//! declaration's own DDL, because the two traps this module exists for
//! are both facts about what a catalog gives back — and a fake catalog
//! would be a fake of exactly the thing under test.

use cratefield_core::Database;
use cratefield_introspect::{UNSEEN, drift, unseen};
use cratefield_tables::{Change, Schema, SqlDialect, Step};
use serde::Deserialize;

#[derive(Deserialize)]
struct Manifest {
    tables: Schema,
}

fn schema(fragment: &str) -> Schema {
    toml::from_str::<Manifest>(fragment)
        .expect("the fragment parses")
        .tables
}

/// A declaration using every kind whose storage type is lossy, so the
/// round trip through a catalog is what the assertions rest on.
const DECLARED: &str = r#"
[tables.post]
primary_key = "id"

[[tables.post.fields]]
name = "id"
kind = "uuid"
required = true

[[tables.post.fields]]
name = "title"
kind = "text"
max_len = 200
required = true

[[tables.post.fields]]
name = "status"
kind = "enum"
values = ["draft", "published"]
default = "draft"

[[tables.post.fields]]
name = "seen_at"
kind = "timestamp"

[[tables.post.fields]]
name = "payload"
kind = "json"

[[tables.post.fields]]
name = "live"
kind = "boolean"

[[tables.post.fields]]
name = "reads"
kind = "integer"
min = 0
"#;

/// A database holding exactly what `declared` asks for.
async fn built(declared: &Schema) -> cratefield_adapter_sqlite::SqliteDatabase {
    let db = cratefield_adapter_sqlite::SqliteDatabase::in_memory().expect("sqlite");
    // The migration ledger both adapters write; the catalog reader
    // excludes the harness's reserved prefix, the ledger among them, and
    // its presence here is the realistic case.
    db.apply_migrations("probe", &[]).expect("ledger");
    let sql = declared.ddl(SqlDialect::Sqlite).expect("renders");
    for statement in sql.split(';').filter(|s| !s.trim().is_empty()) {
        db.execute(&cratefield_core::Statement::new(statement.to_owned()))
            .await
            .expect("ddl applies");
    }
    db
}

fn lines(changes: &[Change]) -> Vec<String> {
    changes
        .iter()
        .map(|change| format!("{} [{}]", change.line(), change.step))
        .collect()
}

#[pollster::test]
async fn a_database_built_from_the_declaration_has_no_drift() {
    // The case every false report would break. Five of these columns have
    // a storage type that is not their declared kind, and two carry
    // bounds the catalog cannot see; comparing naively reports a rewrite
    // for each one.
    let declared = schema(DECLARED);
    let db = built(&declared).await;
    let changes = drift(&db, &declared).await.expect("catalog reads");
    assert!(changes.is_empty(), "false drift: {:#?}", lines(&changes));
}

#[pollster::test]
async fn a_table_the_declaration_does_not_name_is_not_its_to_remove() {
    // The module crates own tables in the same database. Diffing the two
    // whole catalogs reports every one of them as gone.
    let declared = schema(DECLARED);
    let db = built(&declared).await;
    db.execute(&cratefield_core::Statement::new(
        "CREATE TABLE waitlist_entries (id TEXT PRIMARY KEY, email TEXT)".to_owned(),
    ))
    .await
    .expect("a module's table");

    let changes = drift(&db, &declared).await.expect("catalog reads");
    assert!(
        changes.is_empty(),
        "a table nobody declared was reported: {:#?}",
        lines(&changes)
    );
}

#[pollster::test]
async fn a_column_the_declaration_added_expands() {
    let declared = schema(DECLARED);
    let db = built(&declared).await;
    let grown = schema(&format!(
        "{DECLARED}\n[[tables.post.fields]]\nname = \"subtitle\"\nkind = \"text\"\n"
    ));

    let changes = drift(&db, &grown).await.expect("catalog reads");
    assert_eq!(changes.len(), 1, "{:#?}", lines(&changes));
    assert_eq!(changes[0].step, Step::Expand);
    assert_eq!(changes[0].field.as_deref(), Some("subtitle"));
}

#[pollster::test]
async fn a_column_the_database_still_has_contracts() {
    // The declaration dropped `payload`; the column is still there, and
    // the values in it are still there with it.
    let declared = schema(DECLARED);
    let db = built(&declared).await;
    let shrunk = schema(&DECLARED.replace(
        "[[tables.post.fields]]\nname = \"payload\"\nkind = \"json\"\n",
        "",
    ));

    let changes = drift(&db, &shrunk).await.expect("catalog reads");
    assert_eq!(changes.len(), 1, "{:#?}", lines(&changes));
    assert_eq!(changes[0].step, Step::Contract);
    assert_eq!(changes[0].field.as_deref(), Some("payload"));
}

#[pollster::test]
async fn a_table_the_database_does_not_have_yet_expands() {
    let declared = schema(DECLARED);
    let db = built(&declared).await;
    let grown = schema(&format!(
        "{DECLARED}\n[tables.comment]\nprimary_key = \"id\"\n\
         [[tables.comment.fields]]\nname = \"id\"\nkind = \"uuid\"\nrequired = true\n"
    ));

    let changes = drift(&db, &grown).await.expect("catalog reads");
    assert_eq!(changes.len(), 1, "{:#?}", lines(&changes));
    assert_eq!(changes[0].step, Step::Expand);
    assert_eq!(changes[0].table, "comment");
    assert!(changes[0].field.is_none());
}

#[pollster::test]
async fn a_change_a_catalog_cannot_see_reports_nothing_and_says_so() {
    // `uuid` and `text` are both TEXT. The database genuinely does not
    // know which was declared, so "no drift" is the honest answer to the
    // question asked — and `unseen()` is how a report says that out loud
    // rather than letting a reader believe more was checked.
    let declared = schema(DECLARED);
    let db = built(&declared).await;
    let retyped = schema(&DECLARED.replace(
        "name = \"id\"\nkind = \"uuid\"",
        "name = \"id\"\nkind = \"text\"",
    ));

    let changes = drift(&db, &retyped).await.expect("catalog reads");
    assert!(changes.is_empty(), "{:#?}", lines(&changes));

    let footer = unseen();
    assert!(footer.contains("uuid"), "{footer}");
    assert!(footer.contains("bounds"), "{footer}");
    assert!(!UNSEEN.is_empty());
}

#[pollster::test]
async fn the_report_still_sees_what_the_catalog_does_record() {
    // The projection drops a lot, and a projection that dropped
    // everything would pass every test above. These are the properties a
    // catalog does record, and drift has to keep reporting them.
    let declared = schema(DECLARED);
    let db = built(&declared).await;

    // Required, and unique, both flipped on a column that has neither.
    let tightened = schema(&DECLARED.replace(
        "name = \"seen_at\"\nkind = \"timestamp\"",
        "name = \"seen_at\"\nkind = \"timestamp\"\nrequired = true\nunique = true",
    ));
    let changes = drift(&db, &tightened).await.expect("catalog reads");
    let steps: Vec<Step> = changes.iter().map(|change| change.step).collect();
    assert_eq!(changes.len(), 2, "{:#?}", lines(&changes));
    assert!(
        steps.iter().all(|step| *step == Step::Rewrite),
        "{:#?}",
        lines(&changes)
    );

    // And a real type change the catalog *can* see: text to integer.
    let retyped = schema(&DECLARED.replace(
        "name = \"seen_at\"\nkind = \"timestamp\"",
        "name = \"seen_at\"\nkind = \"integer\"",
    ));
    let changes = drift(&db, &retyped).await.expect("catalog reads");
    assert_eq!(changes.len(), 1, "{:#?}", lines(&changes));
    assert_eq!(changes[0].step, Step::Rewrite);
    assert!(
        changes[0].detail.contains("type changes"),
        "{:#?}",
        lines(&changes)
    );
}
