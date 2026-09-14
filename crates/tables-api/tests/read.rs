//! Reading a declared table, against a real database.
//!
//! The access tests next door decide in the abstract; these check the
//! decision actually reaches the SQL. The one that matters most is
//! `a_page_of_an_owner_table_holds_only_the_callers_rows`: an access rule
//! that is decided correctly and then not applied is worse than no rule,
//! because the tests for the decision still pass.

use std::sync::Arc;

use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_core::{Config, Database, ModuleContext, Ports, Statement};
use cratefield_manifest::Access;
use cratefield_tables::{Schema, TableDef};
use cratefield_tables_api::{Asked, TableApi, Tables, one, page};
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

/// A database holding three notes: two of ada's and one of grace's.
fn seeded() -> SqliteDatabase {
    let db = SqliteDatabase::in_memory().expect("in-memory sqlite");
    pollster::block_on(async {
        db.execute(&Statement::new(
            "CREATE TABLE note (id TEXT PRIMARY KEY NOT NULL, author TEXT NOT NULL, body TEXT)",
        ))
        .await
        .expect("the table is created");
        for (id, author, body) in [
            ("n1", "ada", "first"),
            ("n2", "grace", "hers"),
            ("n3", "ada", "second"),
        ] {
            db.execute(&Statement::with_values(
                "INSERT INTO note (id, author, body) VALUES (?, ?, ?)".to_owned(),
                vec![id.into(), author.into(), body.into()],
            ))
            .await
            .expect("the row is inserted");
        }
    });
    db
}

fn tables(access: Access, auth: AuthMode) -> Tables {
    let mut ports = Ports::empty();
    ports.auth = Some(Arc::new(FakeAuth::new(auth)));
    Tables {
        tables: vec![TableApi {
            table: note(),
            access,
            subject: Some("author".to_owned()),
        }],
        ctx: Arc::new(context(ports)),
    }
}

fn context(ports: Ports) -> ModuleContext {
    let config: Arc<dyn Config> = Arc::clone(&ports.config);
    ModuleContext {
        ports,
        config,
        events: cratefield_core::EventBus::default(),
        templates: Arc::new(cratefield_core::TemplateRegistry::default()),
        venture: Arc::new(cratefield_core::Venture::new("acme", "acme.test")),
        unprotected_writes_accepted: false,
        personal_data: Arc::new(cratefield_core::PersonalDataCatalog::default()),
        ui_mounted: false,
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

fn ids(page: &Value) -> Vec<String> {
    page["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|row| row["id"].as_str().expect("an id").to_owned())
        .collect()
}

#[test]
fn a_page_of_a_public_table_holds_every_row() {
    let db = seeded();
    let tables = tables(Access::PublicRead, AuthMode::TokenIsTheSubject);
    let out = pollster::block_on(page(
        &tables,
        &db,
        &HeaderMap::new(),
        &scope(),
        Asked {
            table: "note",
            after: None,
            filters: &[],
            sort: None,
        },
    ))
    .expect("public");
    assert_eq!(ids(&out), ["n1", "n2", "n3"]);
}

#[test]
fn a_page_of_an_owner_table_holds_only_the_callers_rows() {
    // The one that matters. A rule decided correctly and then not applied
    // is worse than no rule: the tests for the decision still pass.
    let db = seeded();
    let tables = tables(Access::Owner, AuthMode::TokenIsTheSubject);
    let out = pollster::block_on(page(
        &tables,
        &db,
        &as_caller("ada"),
        &scope(),
        Asked {
            table: "note",
            after: None,
            filters: &[],
            sort: None,
        },
    ))
    .expect("ada is signed in");
    assert_eq!(ids(&out), ["n1", "n3"], "grace's row was in ada's page");
}

#[test]
fn another_subject_gets_their_own_rows_and_not_the_first_ones() {
    let db = seeded();
    let tables = tables(Access::Owner, AuthMode::TokenIsTheSubject);
    let out = pollster::block_on(page(
        &tables,
        &db,
        &as_caller("grace"),
        &scope(),
        Asked {
            table: "note",
            after: None,
            filters: &[],
            sort: None,
        },
    ))
    .expect("grace is signed in");
    assert_eq!(ids(&out), ["n2"]);
}

#[test]
fn someone_elses_row_is_not_found_rather_than_forbidden() {
    // A 403 is an answer about a row the caller was never in a position
    // to learn exists. The scope produces the right answer by
    // construction: the subject condition and the key are in the same
    // `WHERE`, so the row does not match.
    let db = seeded();
    let tables = tables(Access::Owner, AuthMode::TokenIsTheSubject);
    let refusal = pollster::block_on(one(
        &tables,
        &db,
        &as_caller("ada"),
        &scope(),
        "note",
        &json!({ "id": "n2" }),
    ))
    .expect_err("grace's row");
    assert_eq!(
        refusal.status.as_u16(),
        404,
        "a 403 would confirm it exists"
    );

    // And the answer for a row that truly is not there is identical.
    let absent = pollster::block_on(one(
        &tables,
        &db,
        &as_caller("ada"),
        &scope(),
        "note",
        &json!({ "id": "nope" }),
    ))
    .expect_err("no such row");
    assert_eq!(absent.slug, refusal.slug);
    assert_eq!(absent.status, refusal.status);
}

#[test]
fn a_callers_own_row_is_served() {
    let db = seeded();
    let tables = tables(Access::Owner, AuthMode::TokenIsTheSubject);
    let row = pollster::block_on(one(
        &tables,
        &db,
        &as_caller("ada"),
        &scope(),
        "note",
        &json!({ "id": "n1" }),
    ))
    .expect("hers");
    assert_eq!(row["body"], json!("first"));
}

#[test]
fn an_anonymous_caller_is_told_to_sign_in_rather_than_handed_an_empty_page() {
    let db = seeded();
    let tables = tables(Access::Owner, AuthMode::TokenIsTheSubject);
    let refusal = pollster::block_on(page(
        &tables,
        &db,
        &HeaderMap::new(),
        &scope(),
        Asked {
            table: "note",
            after: None,
            filters: &[],
            sort: None,
        },
    ))
    .expect_err("not signed in");
    assert_eq!(refusal.status.as_u16(), 401);
}

#[test]
fn a_credential_that_does_not_verify_is_refused_even_on_a_public_table() {
    // The rule the `Auth` port exists to keep (#362). An expired token
    // reading a public table must not succeed quietly and leave its
    // holder believing they are still signed in.
    let db = seeded();
    let tables = tables(Access::PublicRead, AuthMode::NotVerified);
    let refusal = pollster::block_on(page(
        &tables,
        &db,
        &as_caller("expired"),
        &scope(),
        Asked {
            table: "note",
            after: None,
            filters: &[],
            sort: None,
        },
    ))
    .expect_err("the token is bad");
    assert_eq!(refusal.status.as_u16(), 401);

    // With no credential at all, the same public table serves.
    let out = pollster::block_on(page(
        &tables,
        &db,
        &HeaderMap::new(),
        &scope(),
        Asked {
            table: "note",
            after: None,
            filters: &[],
            sort: None,
        },
    ))
    .expect("public");
    assert_eq!(ids(&out).len(), 3);
}

#[test]
fn a_verifier_that_cannot_answer_is_a_503_and_not_a_401() {
    let db = seeded();
    let tables = tables(Access::Owner, AuthMode::Unavailable);
    let refusal = pollster::block_on(page(
        &tables,
        &db,
        &as_caller("ada"),
        &scope(),
        Asked {
            table: "note",
            after: None,
            filters: &[],
            sort: None,
        },
    ))
    .expect_err("the verifier is down");
    assert_eq!(
        refusal.status.as_u16(),
        503,
        "telling a user to sign in again during an outage is advice that will not help"
    );
}

#[test]
fn a_table_that_is_not_declared_is_not_found() {
    let db = seeded();
    let tables = tables(Access::PublicRead, AuthMode::TokenIsTheSubject);
    let refusal = pollster::block_on(page(
        &tables,
        &db,
        &HeaderMap::new(),
        &scope(),
        Asked {
            table: "ledger",
            after: None,
            filters: &[],
            sort: None,
        },
    ))
    .expect_err("not declared");
    assert_eq!(refusal.status.as_u16(), 404);
    assert_eq!(refusal.slug, "no-such-table");
}

#[test]
fn a_cursor_names_the_last_row_on_the_page() {
    let db = seeded();
    let tables = tables(Access::PublicRead, AuthMode::TokenIsTheSubject);
    let out = pollster::block_on(page(
        &tables,
        &db,
        &HeaderMap::new(),
        &scope(),
        Asked {
            table: "note",
            after: None,
            filters: &[],
            sort: None,
        },
    ))
    .expect("public");
    // Three rows is short of a page, so there is nothing after them and
    // the cursor says so rather than costing the client a request whose
    // whole result is learning that.
    assert_eq!(out["next"], Value::Null, "a short page claimed more");

    // A cursor handed back resumes after it rather than repeating it.
    let after = pollster::block_on(page(
        &tables,
        &db,
        &HeaderMap::new(),
        &scope(),
        Asked {
            table: "note",
            after: Some(&json!({ "id": "n1" })),
            filters: &[],
            sort: None,
        },
    ))
    .expect("public");
    assert_eq!(ids(&after), ["n2", "n3"]);
}

#[test]
fn a_full_page_hands_back_a_cursor_and_a_short_one_does_not() {
    // `next` has to mean "there is more", or a client either loops one
    // extra time for nothing or stops one page early.
    let db = seeded();
    for n in 4..=(cratefield_tables_api::PAGE + 1) {
        pollster::block_on(db.execute(&Statement::with_values(
            "INSERT INTO note (id, author, body) VALUES (?, ?, ?)".to_owned(),
            vec![format!("n{n:03}").into(), "ada".into(), "filler".into()],
        )))
        .expect("the row is inserted");
    }
    let tables = tables(Access::PublicRead, AuthMode::TokenIsTheSubject);
    let first = pollster::block_on(page(
        &tables,
        &db,
        &HeaderMap::new(),
        &scope(),
        Asked {
            table: "note",
            after: None,
            filters: &[],
            sort: None,
        },
    ))
    .expect("public");
    assert_eq!(
        first["rows"].as_array().expect("rows").len() as u64,
        cratefield_tables_api::PAGE
    );
    assert!(!first["next"].is_null(), "a full page has more after it");

    let second = pollster::block_on(page(
        &tables,
        &db,
        &HeaderMap::new(),
        &scope(),
        Asked {
            table: "note",
            after: Some(&first["next"]),
            filters: &[],
            sort: None,
        },
    ))
    .expect("public");
    assert!((second["rows"].as_array().expect("rows").len() as u64) < cratefield_tables_api::PAGE);
    assert_eq!(second["next"], Value::Null, "the last page claimed more");
}
