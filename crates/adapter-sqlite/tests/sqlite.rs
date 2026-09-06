//! adapter-sqlite: migrations apply (idempotent) and a row round-trips
//! through sea-query-rendered statements (issue #8 acceptance; the
//! fixture modules live in the CLI crate's tests).

use factory0_adapter_sqlite::SqliteDatabase;
use factory0_core::{Database, Row, Rows, SqlMigration, Statement};

const SUBSCRIBERS_INIT: SqlMigration = SqlMigration {
    id: "0001",
    name: "init",
    sql: "CREATE TABLE IF NOT EXISTS subscribers (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        status TEXT NOT NULL
    );",
};

const WAITLIST_INIT: SqlMigration = SqlMigration {
    id: "0001",
    name: "init",
    sql: "CREATE TABLE IF NOT EXISTS waitlist_entries (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        product TEXT NOT NULL
    );",
};

#[pollster::test]
async fn applies_fixture_migrations_and_round_trips_a_row() {
    let db = SqliteDatabase::in_memory().expect("in-memory db");

    db.apply_migrations("email-signup", &[SUBSCRIBERS_INIT])
        .expect("email-signup migrations apply");
    db.apply_migrations("waitlist", &[WAITLIST_INIT])
        .expect("waitlist migrations apply");

    // Idempotent: applying again changes nothing and does not fail.
    db.apply_migrations("email-signup", &[SUBSCRIBERS_INIT])
        .expect("re-apply is a no-op");

    let insert = factory0_core::Statement::with_values(
        "INSERT INTO subscribers (id, email, status) VALUES (?, ?, ?)",
        vec![
            sea_query::Value::String(Some(Box::new("01TEST".to_string()))),
            sea_query::Value::String(Some(Box::new("nick@example.com".to_string()))),
            sea_query::Value::String(Some(Box::new("pending".to_string()))),
        ],
    );
    let changed = db.execute(&insert).await.expect("insert works");
    assert_eq!(changed, 1);

    let select = Statement::with_values(
        "SELECT id, email, status FROM subscribers WHERE email = ?",
        vec![sea_query::Value::String(Some(Box::new(
            "nick@example.com".to_string(),
        )))],
    );
    let rows: Rows = db.query(&select).await.expect("select works");
    assert_eq!(rows.len(), 1);
    let row: &Row = rows.first().expect("one row");
    assert_eq!(row.get::<String>("id"), Some("01TEST".to_string()));
    assert_eq!(row.get::<String>("status"), Some("pending".to_string()));
}

#[pollster::test]
async fn batch_is_atomic() {
    let db = SqliteDatabase::in_memory().expect("db");
    db.apply_migrations("m", &[SUBSCRIBERS_INIT])
        .expect("apply");
    let ok = vec![
        Statement::new(
            "INSERT INTO subscribers (id, email, status) VALUES ('a', 'a@x.dev', 'pending')",
        ),
        Statement::new(
            "INSERT INTO subscribers (id, email, status) VALUES ('b', 'b@x.dev', 'pending')",
        ),
    ];
    db.batch(&ok).await.expect("batch commits");
    let bad = vec![
        Statement::new(
            "INSERT INTO subscribers (id, email, status) VALUES ('c', 'c@x.dev', 'pending')",
        ),
        Statement::new("THIS IS NOT SQL"),
    ];
    assert!(db.batch(&bad).await.is_err(), "bad batch fails");
    // 'c' rolled back with the failed batch.
    let count = db
        .query(&Statement::new("SELECT id FROM subscribers"))
        .await
        .expect("select");
    assert_eq!(count.len(), 2, "only a and b survive");
}
