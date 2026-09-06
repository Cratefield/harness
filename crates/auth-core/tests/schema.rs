//! Issue #5 acceptance, schema half:
//!
//! - the forbidden-names grep: no column can hold a raw session value,
//!   password, magic-link token or client secret — anything named after
//!   one must be a `*_hash` column, and a hard denylist of clear-storage
//!   names can never pass;
//! - the harness portable-SQL lint tokens (`fz doctor`'s list, pinned
//!   here so the schema cannot regress between CLI runs);
//! - the constraints the issue names: one identity per
//!   `(provider, provider_subject)`, unique passkey credential ids, and
//!   the four indexes.
//!
//! Everything runs against the embedded migrations — the same bytes
//! `fz migrations collect` writes and the conformance kit applies.

use factory0_auth_core::AuthCore;
use factory0_core::Module;

/// Column names that are never valid, regardless of suffix: adding any of
/// them means a raw secret went into the clear.
const FORBIDDEN_EXACT: &[&str] = &[
    "password",
    "secret",
    "token",
    "cookie",
    "value",
    "code",
    "session",
    "private_key",
];

/// Name stems that may appear only on hash columns (suffix `_hash`).
const SECRET_STEMS: &[&str] = &["password", "secret", "token", "cookie"];

/// The harness portable-SQL lint (fz `lint.rs`, issue #8): tokens SQLite
/// and Postgres disagree about, or that betray non-portable DDL.
const BANNED_SQL_TOKENS: &[&str] = &[
    "autoincrement",
    "datetime(",
    "serial",
    "now()",
    "json_extract",
    "`",
];

fn migration_sqls() -> Vec<&'static str> {
    AuthCore::new()
        .migrations()
        .sqlite
        .iter()
        .map(|migration| migration.sql)
        .collect()
}

/// `(table, column)` pairs parsed out of the DDL, in file order.
fn columns(sql: &str) -> Vec<(String, String)> {
    const TYPES: [&str; 4] = ["TEXT", "INTEGER", "BLOB", "REAL"];
    let mut out = Vec::new();
    let mut table = None;
    for raw in sql.lines() {
        let line = raw.split_once("--").map_or(raw, |(code, _)| code).trim();
        let lowered = line.to_ascii_lowercase();
        if let Some(rest) = lowered.strip_prefix("create table") {
            let rest = rest
                .trim_start()
                .strip_prefix("if not exists")
                .map_or(rest.trim_start(), str::trim_start);
            table = rest.split_whitespace().next().map(str::to_owned);
            continue;
        }
        if line.starts_with(')') || lowered.starts_with("create index") {
            table = None;
        }
        let Some(table) = table.clone() else {
            continue;
        };
        let mut tokens = line.split_whitespace();
        if let (Some(name), Some(kind)) = (tokens.next(), tokens.next()) {
            let name = name.trim_end_matches(',');
            let kind = kind.trim_end_matches(',');
            if TYPES.contains(&kind.to_ascii_uppercase().as_str()) {
                out.push((table, name.to_owned()));
            }
        }
    }
    out
}

#[test]
fn no_column_can_hold_a_login_secret_in_the_clear() {
    let sqls = migration_sqls();
    assert!(!sqls.is_empty());
    for sql in &sqls {
        let columns = columns(sql);
        assert!(!columns.is_empty(), "parsed the columns of {sql:?}");

        for (table, column) in &columns {
            assert!(
                !FORBIDDEN_EXACT.contains(&column.as_str()),
                "{table}.{column}: forbidden column name (raw secret storage)"
            );
            if let Some(stem) = SECRET_STEMS.iter().find(|stem| column.contains(*stem)) {
                assert!(
                    column.ends_with("_hash"),
                    "{table}.{column}: a `{stem}` column must end in `_hash` — \
                     nothing that can log a user in is stored in the clear"
                );
            }
        }
    }

    // The hash columns the two rules require are all present.
    let all_columns = sqls.iter().flat_map(|sql| columns(sql)).collect::<Vec<_>>();
    for (table, column) in [
        ("sessions", "token_hash"),
        ("single_use_tokens", "token_hash"),
        ("credentials", "password_hash"),
        ("clients", "secret_hash"),
    ] {
        assert!(
            all_columns.iter().any(|(t, c)| t == table && c == column),
            "{table}.{column} missing: the schema must store this value only as a hash"
        );
    }
}

#[test]
fn schema_passes_the_portable_sql_lint() {
    for sql in migration_sqls() {
        let haystack = sql.to_ascii_lowercase();
        for token in BANNED_SQL_TOKENS {
            assert!(
                !haystack.contains(token),
                "non-portable SQL token {token:?} — the harness portable-SQL lint rejects it"
            );
        }
    }
}

#[test]
fn schema_declares_the_issue_constraints() {
    let joined = migration_sqls()
        .iter()
        .map(|sql| sql.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        joined.contains("unique (provider, provider_subject)"),
        "identities: one row per (provider, subject)"
    );
    assert!(
        joined.contains("unique (passkey_credential_id)"),
        "credentials: unique passkey credential ids"
    );
    for index in [
        "idx_sessions_user_id",
        "idx_identities_user_id",
        "idx_credentials_user_id",
        "idx_single_use_tokens_expires_at",
    ] {
        assert!(joined.contains(index), "missing index {index}");
    }
}
