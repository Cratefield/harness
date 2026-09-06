//! `Database` port behaviour on Postgres 16 (issue #18): placeholder
//! rebinding, value binding, row decoding, the shared `ON CONFLICT` /
//! `RETURNING` syntax, and `batch` atomicity.
//!
//! Skipped with a printed reason when `FZ_TEST_POSTGRES_URL` is unset; CI
//! provides a `postgres:16` service container.

mod common;

use common::{TempDb, base_url, skip_reason};
use factory0_adapter_postgres::Postgres;
use factory0_core::{Database, DbError, Row, Statement};
use sea_query::Value as Sea;
use std::sync::Arc;

async fn fresh_db() -> Option<(Postgres, TempDb)> {
    let base = base_url()?;
    let temp = TempDb::create(&base, "db").await?;
    temp.assert_postgres_16().await;
    let db = Postgres::connect(&temp.url).await.expect("connect");
    db.execute(&Statement::new(
        "CREATE TABLE things (
             id TEXT PRIMARY KEY,
             label TEXT NOT NULL,
             n INTEGER NOT NULL,
             big BIGINT,
             ratio REAL,
             note TEXT,
             seen INTEGER NOT NULL DEFAULT 0
         )",
    ))
    .await
    .expect("create things");
    Some((db, temp))
}

fn insert(id: &str, label: &str, n: i32) -> Statement {
    Statement::with_values(
        "INSERT INTO things (id, label, n, seen) VALUES (?, ?, ?, ?)",
        vec![
            Sea::String(Some(Box::new(id.to_owned()))),
            Sea::String(Some(Box::new(label.to_owned()))),
            Sea::Int(Some(n)),
            Sea::Bool(Some(true)), // binds as SMALLINT 1 (INTEGER 0/1 convention)
        ],
    )
}

#[tokio::test]
async fn execute_reports_rows_affected() {
    let Some((db, temp)) = fresh_db().await else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    assert_eq!(db.execute(&insert("01", "first", 1)).await.unwrap(), 1);
    assert_eq!(db.execute(&insert("02", "second", 2)).await.unwrap(), 1);
    let updated = db
        .execute(&Statement::with_values(
            "UPDATE things SET n = ? WHERE n <= ?",
            vec![Sea::Int(Some(9)), Sea::Int(Some(1))],
        ))
        .await
        .unwrap();
    assert_eq!(updated, 1, "only the first row matched");
    temp.finish().await;
}

#[tokio::test]
async fn query_maps_postgres_types_to_sea_values() {
    let Some((db, temp)) = fresh_db().await else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    db.execute(&Statement::with_values(
        "INSERT INTO things (id, label, n, big, ratio, note, seen) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
        vec![
            Sea::String(Some(Box::new("01".to_owned()))),
            Sea::String(Some(Box::new("row one".to_owned()))),
            Sea::Int(Some(7)),
            Sea::BigInt(Some(i64::MAX)),
            Sea::Double(Some(1.25)),
            Sea::String(None), // SQL NULL
            Sea::Bool(Some(true)),
        ],
    ))
    .await
    .unwrap();

    let rows = db
        .query(&Statement::new("SELECT * FROM things WHERE id = '01'"))
        .await
        .unwrap();
    let row = rows.first().expect("one row");
    assert_eq!(row.get::<String>("id"), Some("01".to_owned()));
    assert_eq!(row.get::<String>("label"), Some("row one".to_owned()));
    assert_eq!(row.get::<i32>("n"), Some(7));
    assert_eq!(row.get::<i64>("big"), Some(i64::MAX));
    assert_eq!(row.get::<f64>("ratio"), Some(1.25));
    assert_eq!(row.get::<Option<String>>("note"), Some(None));
    assert_eq!(row.get::<String>("note"), None, "NULL reads as None");
    assert_eq!(
        row.get::<bool>("seen"),
        Some(true),
        "INTEGER 1 reads as true"
    );
    assert_eq!(row.get::<String>("missing_column"), None);
    temp.finish().await;
}

#[tokio::test]
async fn question_marks_inside_literals_are_not_placeholders() {
    let Some((db, temp)) = fresh_db().await else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    db.execute(&Statement::new(
        "INSERT INTO things (id, label, n, seen) \
         VALUES ('q1', 'what? -- really? ''yes''', 1, 0)",
    ))
    .await
    .expect("literal ? and -- survive the rewrite");

    let rows = db
        .query(&Statement::with_values(
            "SELECT label FROM things WHERE label LIKE ? -- find the ? row\n-- ? trailing",
            vec![Sea::String(Some(Box::new("what?%".to_owned())))],
        ))
        .await
        .expect("binds alongside a literal '?' and comments");
    let label: Option<String> = rows.first().and_then(|row| row.get("label"));
    assert_eq!(
        label.as_deref(),
        Some("what? -- really? 'yes'"),
        "the literal arrived byte-for-byte"
    );
    temp.finish().await;
}

#[tokio::test]
async fn on_conflict_and_returning_run_untouched() {
    let Some((db, temp)) = fresh_db().await else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    // The shared INSERT … ON CONFLICT … DO UPDATE and RETURNING syntax is
    // the reason the portable subset needs no postgres overrides (ADR 0004).
    let upsert = |n: i32| {
        Statement::with_values(
            "INSERT INTO things (id, label, n, seen) VALUES (?, 'up', ?, 0) \
             ON CONFLICT (id) DO UPDATE SET n = excluded.n \
             RETURNING id, n",
            vec![
                Sea::String(Some(Box::new("up1".to_owned()))),
                Sea::Int(Some(n)),
            ],
        )
    };
    let first = db.query(&upsert(1)).await.unwrap();
    assert_eq!(first.first().and_then(|row| row.get::<i32>("n")), Some(1));
    let second = db.query(&upsert(5)).await.unwrap();
    assert_eq!(
        second.first().and_then(|row| row.get::<i32>("n")),
        Some(5),
        "the conflict path updated n and RETURNING read it back"
    );
    let count = db
        .query(&Statement::new("SELECT COUNT(*) AS c FROM things"))
        .await
        .unwrap();
    assert_eq!(count.first().and_then(|row| row.get::<i64>("c")), Some(1));
    temp.finish().await;
}

#[tokio::test]
async fn batch_is_atomic_and_rolls_back_on_failure() {
    let Some((db, temp)) = fresh_db().await else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    let failing: Vec<Statement> = vec![
        insert("b1", "kept?", 1),
        Statement::new(
            "INSERT INTO things (id, label, n, seen) \
                        VALUES ('b2', 'ghost', 2, 0), ('b1', 'dup pk', 3, 0)",
        ),
    ];
    let err = db.batch(&failing).await.expect_err("duplicate pk fails");
    assert!(matches!(err, DbError::Batch(_)), "got {err:?}");

    let rows = db
        .query(&Statement::new("SELECT id FROM things"))
        .await
        .unwrap();
    assert!(
        rows.is_empty(),
        "the first statement rolled back with the failed one"
    );

    db.batch(&[insert("b1", "ok", 1), insert("b2", "ok", 2)])
        .await
        .expect("a clean batch commits");
    let rows = db
        .query(&Statement::new("SELECT id FROM things ORDER BY id"))
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    temp.finish().await;
}

#[tokio::test]
async fn works_as_arc_dyn_database() {
    let Some((db, temp)) = fresh_db().await else {
        eprintln!("SKIPPED: {}", skip_reason());
        return;
    };
    let port: Arc<dyn Database> = Arc::new(db);
    port.execute(&insert("a1", "via port", 1)).await.unwrap();
    let rows = port
        .query(&Statement::with_values(
            "SELECT id FROM things WHERE seen = ?",
            vec![Sea::Int(Some(1))],
        ))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    temp.finish().await;
}

#[tokio::test]
async fn row_helper_types_behave() {
    // No server needed: the owned row model is pure.
    let row = Row::new(vec![
        ("seen".to_owned(), Sea::Int(Some(1))),
        ("note".to_owned(), Sea::String(None)),
    ]);
    assert_eq!(row.get::<bool>("seen"), Some(true));
    assert_eq!(row.get::<Option<String>>("note"), Some(None));
}
