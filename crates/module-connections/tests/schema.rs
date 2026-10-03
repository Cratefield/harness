//! The storage promises, read straight off the migration (issue #624): both
//! tokens are only ever stored sealed, the state only ever as a hash, and the
//! columns every query filters on are indexed.

mod support;

use cratefield_core::Module;

use support::module;

/// The one migration, exactly as it ships.
const SQL: &str = include_str!("../migrations/sqlite/0001_init.sql");

/// The column names of every `CREATE TABLE` in the migration, lower-cased.
fn columns(sql: &str) -> Vec<String> {
    sql.split("CREATE TABLE")
        .skip(1)
        .flat_map(|block| {
            let open = block.find('(').expect("the column list opens");
            let close = open + block[open..].find(')').expect("the column list closes");
            block[open + 1..close]
                .split(',')
                .map(|line| {
                    line.split_whitespace()
                        .next()
                        .expect("a column definition names a column")
                        .to_ascii_lowercase()
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The tables the migration creates are the tables the module declares, so
/// export, erasure and the drift guards all see them.
#[test]
fn the_migration_creates_the_declared_tables() {
    let module = module();
    assert_eq!(module.tables(), ["connection", "connection_state"]);
    for table in module.tables() {
        assert!(
            SQL.contains(&format!("CREATE TABLE IF NOT EXISTS {table}")),
            "the migration and the declaration name the same table: {table}"
        );
    }
}

/// Nothing replayable is stored in the clear: every column carrying a token
/// or a PKCE verifier is sealed, and the state is present only as a hash.
#[test]
fn no_token_or_verifier_is_stored_in_the_clear() {
    let columns = columns(SQL);
    assert!(
        columns.len() > 10,
        "the column scan found too little: {columns:?}"
    );

    for column in &columns {
        for stem in ["token", "verifier"] {
            if column.contains(stem) {
                assert!(
                    column.ends_with("_sealed"),
                    "column `{column}` carries the stem `{stem}` but is not sealed: it would \
                     store a usable credential"
                );
            }
        }
        for bare in [
            "token",
            "access_token",
            "refresh_token",
            "code",
            "verifier",
            "secret",
            "state",
        ] {
            assert_ne!(
                column, bare,
                "column `{column}` stores a value in the clear"
            );
        }
    }

    assert!(columns.contains(&"access_token_sealed".to_owned()));
    assert!(columns.contains(&"refresh_token_sealed".to_owned()));
    assert!(columns.contains(&"verifier_sealed".to_owned()));
    // The state is the one value that reaches the table as a hash.
    assert!(columns.contains(&"state_hash".to_owned()));
    assert!(!columns.contains(&"state".to_owned()));
}

/// The `state` hash is the key, so a state cannot collide with one in flight,
/// and the guarded consume is a plain `UPDATE ... WHERE spent_at IS NULL`.
#[test]
fn the_state_hash_is_the_key_and_the_consume_is_guarded() {
    assert!(
        SQL.contains("state_hash TEXT PRIMARY KEY"),
        "the state hash is the primary key"
    );
    assert!(
        SQL.contains("spent_at TEXT"),
        "the spent marker the guarded consume sets must exist"
    );
    assert!(
        SQL.contains("expires_at TEXT NOT NULL"),
        "the state must carry its own deadline"
    );
}

/// The columns the queries filter on are indexed: a subject's connections,
/// the refresh scan by `(status, access_expires_at)`, and the purge by
/// `expires_at`.
#[test]
fn the_columns_the_queries_filter_on_are_indexed() {
    assert!(SQL.contains("connection_subject_idx ON connection (subject)"));
    assert!(SQL.contains("connection_refresh_idx ON connection (status, access_expires_at)"));
    assert!(SQL.contains("connection_state_expires_idx ON connection_state (expires_at)"));
}
