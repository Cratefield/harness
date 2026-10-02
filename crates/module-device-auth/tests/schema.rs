//! The storage promise, read straight off the migration (issue #587): both
//! codes reach the database only as SHA-256 hashes. The device code is a
//! bearer credential and the user code is eight letters off a screen, so a
//! dump, a backup or a query log must hold neither in the clear — and the
//! way to say that in a test is to read the SQL and refuse the column
//! names that would break it.

mod support;

use cratefield_core::Module;
use cratefield_module_device_auth::{DeviceAuth, DeviceClient};

use support::{CountingIssuer, SeqRandom};

/// The one migration, exactly as it ships.
const SQL: &str = include_str!("../migrations/sqlite/0001_init.sql");

/// The column names of the single `CREATE TABLE` in the migration.
fn columns(sql: &str) -> Vec<String> {
    let start = sql
        .find("CREATE TABLE")
        .expect("the migration creates a table");
    let open = start + sql[start..].find('(').expect("the column list opens");
    let close = open + sql[open..].find(')').expect("the column list closes");
    sql[open + 1..close]
        .split(',')
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            line.split_whitespace()
                .next()
                .expect("a column definition names a column")
                .to_ascii_lowercase()
        })
        .collect()
}

fn module() -> DeviceAuth {
    DeviceAuth::builder()
        .client(DeviceClient::new("sealb-cli").scopes(["read", "write"]))
        .issuer(CountingIssuer::new())
        .random(SeqRandom::new())
        .build()
}

/// The table the migration creates is the table the module declares, so
/// export, erasure and the drift guards all see it.
#[test]
fn the_migration_creates_the_declared_table() {
    let module = module();
    assert_eq!(module.tables(), ["device_auth_codes"]);
    assert!(
        SQL.contains("CREATE TABLE IF NOT EXISTS device_auth_codes"),
        "the migration and the declaration name the same table"
    );
}

/// Nothing that could be replayed as a credential is stored in the clear:
/// a column whose name carries a code, token or secret stem must be a
/// hash, and no bare `device_code`, `user_code`, `token` or `secret`
/// column exists.
#[test]
fn no_clear_text_code_or_secret_column_exists() {
    let columns = columns(SQL);
    assert!(!columns.is_empty(), "the column scan found nothing");

    for column in &columns {
        for stem in ["code", "token", "secret"] {
            if column.contains(stem) {
                assert!(
                    column.ends_with("_hash"),
                    "column `{column}` carries the stem `{stem}` but is not a hash: \
                     it would store a replayable value"
                );
            }
        }
        for bare in [
            "code",
            "token",
            "secret",
            "device_code",
            "user_code",
            "access_token",
            "refresh_token",
        ] {
            assert_ne!(
                column, bare,
                "column `{column}` stores a value in the clear"
            );
        }
    }

    // The two hashes the flow depends on are actually present.
    for hash in ["device_code_hash", "user_code_hash"] {
        assert!(
            columns.contains(&hash.to_owned()),
            "missing {hash}: {columns:?}"
        );
    }
}

/// The two columns a hashed code lands in are the keys, so a collision
/// cannot silently overwrite a live request.
#[test]
fn the_code_hashes_are_the_keys() {
    assert!(
        SQL.contains("device_code_hash TEXT PRIMARY KEY"),
        "the device code hash is the primary key"
    );
    assert!(
        SQL.contains("user_code_hash TEXT NOT NULL UNIQUE"),
        "the user code hash is present and unique"
    );
}

/// The purge and the interval gate both read `expires_at` and `status`
/// under a predicate, so both are indexed.
#[test]
fn the_columns_the_queries_filter_on_are_indexed() {
    assert!(SQL.contains("device_auth_codes_expires_idx ON device_auth_codes (expires_at)"));
    assert!(SQL.contains("device_auth_codes_status_idx ON device_auth_codes (status)"));
}
