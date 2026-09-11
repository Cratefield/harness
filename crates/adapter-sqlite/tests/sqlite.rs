//! adapter-sqlite: migrations apply (idempotent) and a row round-trips
//! through sea-query-rendered statements (issue #8 acceptance; the
//! fixture modules live in the CLI crate's tests).

use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_core::{Database, Row, Rows, SqlMigration, Statement};

const SUBSCRIBERS_INIT: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    "CREATE TABLE IF NOT EXISTS subscribers (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        status TEXT NOT NULL
    );",
);

const WAITLIST_INIT: SqlMigration = SqlMigration::new(
    "0001",
    "init",
    "CREATE TABLE IF NOT EXISTS waitlist_entries (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        product TEXT NOT NULL
    );",
);

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

    let insert = cratefield_core::Statement::with_values(
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

/// sea-query renders `LIMIT n` as `Value::BigUnsigned`; the adapter must
/// widen it to INTEGER instead of falling through to a TEXT debug string
/// (SQLite then fails the statement with a datatype mismatch).
#[pollster::test]
async fn sea_query_limit_binds_as_integer() {
    let db = SqliteDatabase::in_memory().expect("db");
    db.apply_migrations("m", &[SUBSCRIBERS_INIT])
        .expect("apply");
    db.execute(&Statement::new(
        "INSERT INTO subscribers (id, email, status) VALUES ('a', 'nick@example.com', 'pending')",
    ))
    .await
    .expect("insert");
    let mut select = sea_query::Query::select();
    select.column("id").from("subscribers");
    let query = select
        .and_where(sea_query::Expr::col("email").eq("nick@example.com"))
        .limit(1)
        .to_owned();
    let rows: Rows = db.query(&Statement::render(&query)).await.expect("select");
    assert_eq!(rows.len(), 1);
}

/// Forward-only means an applied migration is never edited. The lockfile
/// enforces that inside one repository; the database has to enforce it
/// across every deployment that already ran the old SQL (issues #28,
/// #34). A changed migration is an error, not a silent skip.
#[pollster::test]
async fn an_edited_migration_is_refused_by_the_database() {
    let db = SqliteDatabase::in_memory().expect("in-memory db");
    let first = [SqlMigration::new(
        "0001",
        "init",
        "CREATE TABLE IF NOT EXISTS widgets (id TEXT PRIMARY KEY);",
    )];
    db.apply_migrations("widgets", &first).expect("first apply");
    // Re-applying the same SQL is a no-op, not an error.
    db.apply_migrations("widgets", &first).expect("idempotent");

    let edited = [SqlMigration::new(
        "0001",
        "init",
        "CREATE TABLE IF NOT EXISTS widgets (id TEXT PRIMARY KEY, colour TEXT);",
    )];
    let err = db
        .apply_migrations("widgets", &edited)
        .expect_err("an edited migration must be refused");
    let message = err.to_string();
    assert!(message.contains("widgets/0001"), "{message}");
    assert!(message.contains("already applied"), "{message}");
    assert!(message.contains("write a new migration"), "{message}");
}

/// A database migrated before checksums were recorded has the old
/// two-column table and rows with no hash. It keeps working, and its
/// unverifiable rows are treated as applied rather than as mismatches.
#[pollster::test]
async fn a_pre_checksum_database_still_applies_and_does_not_cry_mismatch() {
    let db = SqliteDatabase::in_memory().expect("in-memory db");
    for sql in [
        "CREATE TABLE harness_migrations (id TEXT PRIMARY KEY, applied_at TEXT NOT NULL)",
        "INSERT INTO harness_migrations (id, applied_at) \
         VALUES ('widgets/0001', '2026-01-01T00:00:00Z')",
        "CREATE TABLE widgets (id TEXT PRIMARY KEY)",
    ] {
        db.execute(&Statement::new(sql))
            .await
            .expect("old-style tracking table");
    }

    // 0001 is recorded with no checksum: applied, unverifiable, skipped
    // even though the SQL here differs. 0002 is new and applies.
    let migrations = [
        SqlMigration::new(
            "0001",
            "init",
            "CREATE TABLE IF NOT EXISTS widgets (id TEXT PRIMARY KEY, colour TEXT);",
        ),
        SqlMigration::new(
            "0002",
            "add_gadgets",
            "CREATE TABLE IF NOT EXISTS gadgets (id TEXT PRIMARY KEY);",
        ),
    ];
    db.apply_migrations("widgets", &migrations)
        .expect("an old database keeps working");

    // And the new row carries a checksum, so the next edit is caught.
    let edited = [SqlMigration::new(
        "0002",
        "add_gadgets",
        "CREATE TABLE IF NOT EXISTS gadgets (id TEXT PRIMARY KEY, size INTEGER);",
    )];
    assert!(
        db.apply_migrations("widgets", &edited).is_err(),
        "rows written from now on are verifiable"
    );
}

/// A non-transactional migration (RECONCILIATION.md §4) runs outside the
/// per-migration transaction, so its SQL must be idempotent: re-running
/// after a crash between the DDL and the tracking row has to be safe.
#[pollster::test]
async fn non_transactional_migration_applies_and_re_applies_idempotently() {
    use cratefield_core::SqlMigration;

    let db = SqliteDatabase::in_memory().expect("in-memory database");
    let migrations = [SqlMigration::new(
        "0001",
        "guarded",
        "CREATE TABLE IF NOT EXISTS nt_guard (id TEXT PRIMARY KEY);",
    )
    .non_transactional()];
    db.apply_migrations("probe", &migrations)
        .expect("first apply");
    db.apply_migrations("probe", &migrations)
        .expect("re-apply is a no-op, not a duplicate-table error");

    let applied: String = db
        .query(&cratefield_core::Statement::with_values(
            "SELECT id FROM harness_migrations WHERE id = ?".to_owned(),
            vec!["probe/0001".to_owned().into()],
        ))
        .await
        .expect("tracking row readable")
        .rows
        .iter()
        .filter_map(|row| row.get::<String>("id"))
        .collect();
    assert_eq!(applied, "probe/0001");
}

/// The runner refuses a non-transactional migration with no idempotence
/// guard: a crash mid-apply would leave it re-run against who knows what.
#[pollster::test]
async fn non_transactional_migration_without_a_guard_is_refused() {
    use cratefield_core::SqlMigration;

    let db = SqliteDatabase::in_memory().expect("in-memory database");
    let migrations = [SqlMigration::new(
        "0001",
        "unguarded",
        "CREATE TABLE nt_unguarded (id TEXT PRIMARY KEY);",
    )
    .non_transactional()];
    let err = db
        .apply_migrations("probe", &migrations)
        .expect_err("unguarded SQL is refused");
    let message = err.to_string();
    assert!(
        message.contains("IF NOT EXISTS"),
        "the refusal names the rule: {message}"
    );
    // And nothing was applied, not even partially.
    let rows = db
        .query(&cratefield_core::Statement::new(
            "SELECT COUNT(*) AS n FROM harness_migrations".to_owned(),
        ))
        .await
        .expect("tracking readable");
    assert_eq!(rows.rows[0].get::<i64>("n"), Some(0));
}
