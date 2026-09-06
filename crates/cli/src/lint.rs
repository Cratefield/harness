//! The portable-SQL lint (issue #8): flags tokens that SQLite and Postgres
//! disagree about, or that betray non-portable DDL.

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
];

/// Returns `(token, explanation)` pairs found in `sql`.
#[must_use]
pub fn banned_tokens(sql: &str) -> Vec<(&'static str, &'static str)> {
    let haystack = sql.to_ascii_lowercase();
    BANNED
        .iter()
        .filter(|(token, _)| {
            let lowered = token.to_ascii_lowercase();
            if token == &"`" {
                haystack.contains('`')
            } else {
                haystack.contains(&lowered)
            }
        })
        .copied()
        .collect()
}
