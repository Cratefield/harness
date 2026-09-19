//! Writing a declared table, against a real database.
//!
//! The rules that matter are about ownership: a caller cannot write a row
//! into somebody else's name, and cannot change or delete one that is not
//! theirs. Both are decided in `access` and both have to reach the SQL,
//! which is what these check.

use std::sync::Arc;

use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_core::{
    Caller, Config, Database, ModuleContext, Ports, Problem, Statement, Subject, Tenancy,
};
use cratefield_manifest::Access;
use cratefield_tables::{Schema, TableDef};
use cratefield_tables_api::{
    Reach, TableApi, Tables, create, may_write, one, remove, replace, settle_subject,
};
use cratefield_testing::{AuthMode, FakeAuth};
use http::HeaderMap;
use serde_json::{Value, json};

#[derive(serde::Deserialize)]
struct Fragment {
    tables: Schema,
}

const NOTE: &str = r#"
[tables.note]
primary_key = "id"

[[tables.note.fields]]
name = "id"
kind = "text"
required = true

[[tables.note.fields]]
name = "author"
kind = "text"
required = true

[[tables.note.fields]]
name = "body"
kind = "text"
"#;

fn note() -> TableDef {
    toml::from_str::<Fragment>(NOTE)
        .expect("parses")
        .tables
        .table("note")
        .expect("declared")
        .clone()
}

fn seeded() -> SqliteDatabase {
    let db = SqliteDatabase::in_memory().expect("in-memory sqlite");
    pollster::block_on(async {
        db.execute(&Statement::new(
            "CREATE TABLE note (id TEXT PRIMARY KEY NOT NULL, author TEXT NOT NULL, body TEXT)",
        ))
        .await
        .expect("created");
        for (id, author) in [("n1", "ada"), ("n2", "grace")] {
            db.execute(&Statement::with_values(
                "INSERT INTO note (id, author, body) VALUES (?, ?, ?)".to_owned(),
                vec![id.into(), author.into(), "seed".into()],
            ))
            .await
            .expect("seeded");
        }
    });
    db
}

fn tables(access: Access) -> Tables {
    let mut ports = Ports::empty();
    ports.auth = Some(Arc::new(FakeAuth::new(AuthMode::TokenIsTheSubject)));
    let config: Arc<dyn Config> = Arc::clone(&ports.config);
    Tables {
        tables: vec![TableApi {
            table: note(),
            access,
            subject: Some("author".to_owned()),
        }],
        ctx: Arc::new(ModuleContext {
            ports,
            config,
            events: cratefield_core::EventBus::default(),
            templates: Arc::new(cratefield_core::TemplateRegistry::default()),
            venture: Arc::new(cratefield_core::Venture::new("acme", "acme.test")),
            unprotected_writes_accepted: false,
            personal_data: Arc::new(cratefield_core::PersonalDataCatalog::default()),
            ui_mounted: false,
        }),
    }
}

fn scope() -> cratefield_core::Scope {
    cratefield_core::Scope {
        request_id: "test".to_owned(),
        defer: Arc::new(cratefield_core::NoopDefer),
        span: tracing::Span::none(),
    }
}

fn as_caller(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().expect("a header value"),
    );
    headers
}

fn ada() -> Caller {
    Caller::Subject(Subject::new("ada"))
}

fn api(access: Access, subject: Option<&str>) -> TableApi {
    TableApi {
        table: note(),
        access,
        subject: subject.map(str::to_owned),
    }
}

#[test]
fn a_public_table_is_served_and_never_written() {
    // `public-read` is exactly that. A venture that wants public rows
    // written has not declared this level.
    let refusal = may_write(
        &api(Access::PublicRead, None),
        Tenancy::Sole,
        &ada(),
        Ok(()),
    )
    .expect_err("public-read is read");
    assert_eq!(refusal.slug, "table-read-only");
    assert_eq!(refusal.status.as_u16(), 403);
}

#[test]
fn a_row_written_to_an_owner_table_is_the_writers_own() {
    // The subject column is settled by the harness, not taken from the
    // body, so a caller cannot write a row into somebody else's name.
    let reach = Reach::OwnedBy {
        column: "author".to_owned(),
        subject: "ada".to_owned(),
    };
    let mut absent = json!({ "id": "n9", "body": "mine" });
    settle_subject(&reach, &mut absent).expect("filled in");
    assert_eq!(absent["author"], json!("ada"));

    let mut null = json!({ "id": "n9", "author": Value::Null });
    settle_subject(&reach, &mut null).expect("filled in");
    assert_eq!(null["author"], json!("ada"));

    let mut already = json!({ "id": "n9", "author": "ada" });
    settle_subject(&reach, &mut already).expect("left alone");
    assert_eq!(already["author"], json!("ada"));
}

#[test]
fn a_row_naming_somebody_else_is_refused_rather_than_quietly_corrected() {
    // Overwriting would be safe — the row would still be the caller's —
    // but the client asked for something and got something else without
    // being told, which is how a bug in a client becomes data nobody can
    // explain.
    let reach = Reach::OwnedBy {
        column: "author".to_owned(),
        subject: "ada".to_owned(),
    };
    let mut theirs = json!({ "id": "n9", "author": "grace" });
    let refusal = settle_subject(&reach, &mut theirs).expect_err("not hers to give");
    assert_eq!(refusal.slug, "not-yours-to-give");
    assert_eq!(theirs["author"], json!("grace"), "it was not rewritten");
}

#[test]
fn nothing_is_settled_when_the_reach_is_everything() {
    let mut row = json!({ "id": "n9", "author": "grace" });
    settle_subject(&Reach::Everything, &mut row).expect("no scope, no change");
    assert_eq!(row["author"], json!("grace"));
}

#[test]
fn a_created_row_is_stored_under_the_callers_own_name() {
    let db = seeded();
    let tables = tables(Access::Owner);
    let written = pollster::block_on(create(
        &tables,
        &db,
        Tenancy::Sole,
        &as_caller("ada"),
        &scope(),
        "note",
        json!({ "id": "n9", "body": "mine" }),
    ))
    .expect("ada writes her own");
    assert_eq!(written["author"], json!("ada"));

    // And she can read it back; the row is hers.
    let read = pollster::block_on(one(
        &tables,
        &db,
        Tenancy::Sole,
        &as_caller("ada"),
        &scope(),
        "note",
        &json!({ "id": "n9" }),
    ))
    .expect("hers");
    assert_eq!(read["body"], json!("mine"));
}

#[test]
fn a_key_that_is_taken_is_a_conflict_and_not_a_500() {
    let db = seeded();
    let tables = tables(Access::Owner);
    let refusal = pollster::block_on(create(
        &tables,
        &db,
        Tenancy::Sole,
        &as_caller("ada"),
        &scope(),
        "note",
        json!({ "id": "n1", "body": "again" }),
    ))
    .expect_err("n1 exists");
    assert_eq!(refusal.status.as_u16(), 409, "{}", refusal.slug);
}

/// A declared table whose *name* contains the word the conflict check
/// used to look for, and which is missing from the database.
const UNIQUE_CODES: &str = r#"
[tables.unique_codes]
primary_key = "id"

[[tables.unique_codes.fields]]
name = "id"
kind = "text"
required = true

[[tables.unique_codes.fields]]
name = "author"
kind = "text"
required = true
"#;

#[test]
fn a_failure_that_is_not_a_conflict_is_not_one_because_the_table_is_named_unique() {
    // `no such table: unique_codes` — the shape of a half-applied
    // migration — matched a bare `unique` and came back as `409
    // already-exists`. The caller is told the key is taken, picks
    // another, and is told the same; the real failure never surfaces,
    // because the conflict branch does not log.
    let table = toml::from_str::<Fragment>(UNIQUE_CODES)
        .expect("parses")
        .tables
        .table("unique_codes")
        .expect("declared")
        .clone();
    let base = tables(Access::TenantMembers);
    let tables = Tables {
        tables: vec![TableApi {
            table,
            access: Access::TenantMembers,
            subject: Some("author".to_owned()),
        }],
        ctx: base.ctx,
    };
    // An empty database: the declared table was never created.
    let db = SqliteDatabase::in_memory().expect("in-memory sqlite");
    let refusal = pollster::block_on(create(
        &tables,
        &db,
        Tenancy::Sole,
        &as_caller("ada"),
        &scope(),
        "unique_codes",
        json!({ "id": "c1", "author": "ada" }),
    ))
    .expect_err("there is no such table");
    assert_ne!(
        refusal.status.as_u16(),
        409,
        "a conflict that did not happen: {}",
        refusal.slug
    );
    assert_eq!(refusal.status.as_u16(), 500, "{}", refusal.slug);
}

#[test]
fn changing_somebody_elses_row_reports_no_such_row() {
    // Not a 403: that is an answer about a row the caller was never in a
    // position to learn exists.
    let db = seeded();
    let tables = tables(Access::Owner);
    let refusal = pollster::block_on(replace(
        &tables,
        &db,
        Tenancy::Sole,
        &as_caller("ada"),
        &scope(),
        "note",
        &json!({ "id": "n2" }),
        json!({ "id": "n2", "body": "taken over" }),
    ))
    .expect_err("grace's row");
    assert_eq!(refusal.status.as_u16(), 404, "{}", refusal.slug);

    // And grace's row is untouched, which is the part that matters.
    let hers = pollster::block_on(one(
        &tables,
        &db,
        Tenancy::Sole,
        &as_caller("grace"),
        &scope(),
        "note",
        &json!({ "id": "n2" }),
    ))
    .expect("still hers");
    assert_eq!(hers["body"], json!("seed"));
}

#[test]
fn deleting_somebody_elses_row_reports_no_such_row_and_leaves_it() {
    let db = seeded();
    let tables = tables(Access::Owner);
    let refusal = pollster::block_on(remove(
        &tables,
        &db,
        Tenancy::Sole,
        &as_caller("ada"),
        &scope(),
        "note",
        &json!({ "id": "n2" }),
    ))
    .expect_err("grace's row");
    assert_eq!(refusal.status.as_u16(), 404);

    assert!(
        pollster::block_on(one(
            &tables,
            &db,
            Tenancy::Sole,
            &as_caller("grace"),
            &scope(),
            "note",
            &json!({ "id": "n2" }),
        ))
        .is_ok(),
        "a refused delete removed the row anyway"
    );
}

#[test]
fn a_caller_changes_and_deletes_their_own_row() {
    let db = seeded();
    let tables = tables(Access::Owner);
    pollster::block_on(replace(
        &tables,
        &db,
        Tenancy::Sole,
        &as_caller("ada"),
        &scope(),
        "note",
        &json!({ "id": "n1" }),
        json!({ "id": "n1", "body": "edited" }),
    ))
    .expect("hers to change");
    let read = pollster::block_on(one(
        &tables,
        &db,
        Tenancy::Sole,
        &as_caller("ada"),
        &scope(),
        "note",
        &json!({ "id": "n1" }),
    ))
    .expect("hers");
    assert_eq!(read["body"], json!("edited"));

    pollster::block_on(remove(
        &tables,
        &db,
        Tenancy::Sole,
        &as_caller("ada"),
        &scope(),
        "note",
        &json!({ "id": "n1" }),
    ))
    .expect("hers to delete");
    assert!(
        pollster::block_on(one(
            &tables,
            &db,
            Tenancy::Sole,
            &as_caller("ada"),
            &scope(),
            "note",
            &json!({ "id": "n1" }),
        ))
        .is_err(),
        "it is gone"
    );
}

#[test]
fn a_body_that_is_not_a_legal_row_is_refused_before_the_database_sees_it() {
    let db = seeded();
    let tables = tables(Access::Owner);
    let refusal: Problem = pollster::block_on(create(
        &tables,
        &db,
        Tenancy::Sole,
        &as_caller("ada"),
        &scope(),
        "note",
        json!({ "id": "n9", "nope": "undeclared" }),
    ))
    .expect_err("not a row");
    assert_eq!(refusal.status.as_u16(), 422, "{}", refusal.slug);
}

#[test]
fn any_verified_caller_writes_any_row_of_a_tenant_table() {
    // Ada overwrites a row whose subject column says `grace`, which is
    // the level: `tenant-members` is not scoped to the caller's own rows.
    // It is not scoped to the caller's own *tenant* either — nothing here
    // makes Ada a member of one. What makes the write serve is the
    // tenancy shape, and `Tenancy::Sole` is the shape where the level
    // holds: no registry, one tenant, so "any verified caller" and
    // "a member of this tenant" are the same set (issue #385). Under
    // `Tenancy::FromRegistry` the same write refuses.
    let db = seeded();
    let tables = tables(Access::TenantMembers);
    pollster::block_on(replace(
        &tables,
        &db,
        Tenancy::Sole,
        &as_caller("ada"),
        &scope(),
        "note",
        &json!({ "id": "n2" }),
        json!({ "id": "n2", "author": "grace", "body": "edited by another caller" }),
    ))
    .expect("a verified caller reaches every row");
}

#[test]
fn an_anonymous_caller_may_not_write() {
    let db = seeded();
    let tables = tables(Access::Owner);
    let refusal = pollster::block_on(create(
        &tables,
        &db,
        Tenancy::Sole,
        &HeaderMap::new(),
        &scope(),
        "note",
        json!({ "id": "n9", "body": "mine" }),
    ))
    .expect_err("not signed in");
    assert_eq!(refusal.status.as_u16(), 401);
}
