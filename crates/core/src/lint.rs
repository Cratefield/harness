//! The portable-SQL lint (ADR 0004): flags tokens that SQLite and Postgres
//! disagree about, or that betray non-portable DDL. One canonical definition
//! shared by `fz doctor` and the Postgres migration runner's set selection
//! (issue #18) so the two can never drift.

/// Returns `(token, explanation)` pairs found in `sql`.
///
/// This is the predicate behind both `fz doctor`'s migration lint and the
/// `factory0-adapter-postgres` runner's rule that a module's `sqlite`
/// migration set may be applied to Postgres only when it passes.
#[must_use]
pub fn lint_portable_sql(sql: &str) -> Vec<(&'static str, &'static str)> {
    const BANNED: &[(&str, &str)] = &[
        (
            "AUTOINCREMENT",
            "SQLite-only; use plain INTEGER PRIMARY KEY (ULID ids instead of autoincrement)",
        ),
        (
            "datetime(",
            "dialect function; store ISO-8601 TEXT and compute in code",
        ),
        ("SERIAL", "Postgres-only; use TEXT ULID ids"),
        (
            "NOW()",
            "dialect function; bind an ISO-8601 timestamp instead",
        ),
        (
            "json_extract",
            "SQLite-only JSON function; parse JSON in code",
        ),
        (
            "`",
            "backtick quoting is MySQL/SQLite; use double quotes or none",
        ),
        (
            "BLOB",
            "SQLite-only type; Postgres has BYTEA — ship a migrations/postgres override",
        ),
    ];

    let haystack = sql.to_ascii_lowercase();
    BANNED
        .iter()
        .filter(|(token, _)| {
            if *token == "`" {
                haystack.contains('`')
            } else {
                haystack.contains(&token.to_ascii_lowercase())
            }
        })
        .copied()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::lint_portable_sql;

    #[test]
    fn clean_portable_sql_passes() {
        let sql = "CREATE TABLE t (id TEXT PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0, \
                   created_at TEXT NOT NULL, UNIQUE(id));";
        assert!(lint_portable_sql(sql).is_empty());
    }

    #[test]
    fn every_banned_token_is_flagged() {
        let sql = "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, \
                   at datetime('now'), s SERIAL, n NOW(), j json_extract(x,'$'), c `col`);";
        let found = lint_portable_sql(sql);
        let tokens: Vec<&str> = found.iter().map(|(token, _)| *token).collect();
        assert_eq!(
            tokens,
            [
                "AUTOINCREMENT",
                "datetime(",
                "SERIAL",
                "NOW()",
                "json_extract",
                "`"
            ]
        );
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert!(
            lint_portable_sql("SELECT autoincrement FROM t;")
                .iter()
                .any(|(token, _)| *token == "AUTOINCREMENT")
        );
    }

    #[test]
    fn now_without_parens_is_not_flagged() {
        // `NOW()` is the dialect function; the word "now" in prose or a
        // column name is not.
        assert!(lint_portable_sql("SELECT now FROM t;").is_empty());
    }
}
