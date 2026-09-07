//! The portable-SQL lint (ADR 0004): flags tokens that SQLite and Postgres
//! disagree about, or that betray non-portable DDL. One canonical definition
//! shared by `fz doctor` and the Postgres migration runner's set selection
//! (issue #18) so the two can never drift.
//!
//! The lint reads **DDL**, not the whole file. Comments and string
//! literals are stripped first, because neither is executed: a migration
//! that explains itself in prose, or stores the word `blob` as data, is
//! portable. Scanning them produced false positives that failed a module
//! for a backtick inside a `--` comment.

/// Returns `(token, explanation)` pairs found in `sql`.
///
/// This is the predicate behind both `fz doctor`'s migration lint and the
/// `cratefield-adapter-postgres` runner's rule that a module's `sqlite`
/// migration set may be applied to Postgres only when it passes.
///
/// SQL comments (`-- ...`, `/* ... */`) and single-quoted string literals
/// are ignored: they are not DDL. Double-quoted identifiers are not
/// ignored, because they are DDL and portable in both dialects.
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

    let haystack = strip_non_ddl(sql).to_ascii_lowercase();
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

/// Card-data fragments the harness never stores (PCI DSS, posture SAQ A):
/// Stripe owns the primary account number, verification code and expiry, and we
/// keep only its identifiers. Deliberately the *specific* forms and not bare
/// `pan`, `track` or `expiry`, which collide with legitimate columns — an audio
/// `pan`, a music `track`, a `session_expiry` (issue #44).
const CARD_DATA: &[&str] = &[
    "card_number",
    "cardnumber",
    "card_no",
    "cardno",
    "primary_account_number",
    "full_pan",
    "cvv",
    "cvc",
    "cvv2",
    "cvc2",
    "card_cvv",
    "card_cvc",
    "exp_month",
    "exp_year",
    "card_expiry",
    "expiry_date",
    "expiration_date",
    "track_data",
    "magstripe",
    "magnetic_stripe",
];

/// The first card-data fragment `text` contains (case-insensitive), or `None`.
/// Keeps primary account numbers, verification codes and full expiry out of
/// migrations and secret names (issue #44).
#[must_use]
pub fn card_data_hit(text: &str) -> Option<&'static str> {
    let hay = text.to_ascii_lowercase();
    CARD_DATA.iter().copied().find(|frag| hay.contains(frag))
}

/// Card-data column or table names found in `sql`, as `(fragment, why)` pairs.
/// Comments and string literals are ignored, so documenting the rule does not
/// trip it.
#[must_use]
pub fn lint_card_data(sql: &str) -> Vec<(&'static str, &'static str)> {
    match card_data_hit(&strip_non_ddl(sql)) {
        Some(frag) => vec![(
            frag,
            "looks like card data; the harness never stores PANs, verification codes or \
             expiry (PCI DSS SAQ A). Keep only Stripe's identifiers",
        )],
        None => Vec::new(),
    }
}

/// Replaces every SQL comment and single-quoted string literal with spaces,
/// leaving the executable DDL and its byte positions alone.
///
/// Block comments nest in Postgres and do not in SQLite; this counts depth,
/// which is right for Postgres and harmless for SQLite (a migration relying
/// on the difference is not portable anyway). An unterminated comment or
/// literal swallows the rest of the input rather than panicking — the
/// database will reject it long before the lint matters.
fn strip_non_ddl(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0;
    while i < bytes.len() {
        // `--` to end of line.
        if bytes[i] == b'-' && bytes.get(i + 1) == Some(&b'-') {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }
        // `/* ... */`, nesting.
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            let mut depth = 1_usize;
            out.push_str("  ");
            i += 2;
            while i < bytes.len() && depth > 0 {
                if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    out.push_str("  ");
                    i += 2;
                } else if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    out.push_str("  ");
                    i += 2;
                } else {
                    out.push(if bytes[i] == b'\n' { '\n' } else { ' ' });
                    i += 1;
                }
            }
            continue;
        }
        // `'...'`, with `''` as the escape.
        if bytes[i] == b'\'' {
            out.push(' ');
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\'' {
                    if bytes.get(i + 1) == Some(&b'\'') {
                        out.push_str("  ");
                        i += 2;
                        continue;
                    }
                    out.push(' ');
                    i += 1;
                    break;
                }
                out.push(if bytes[i] == b'\n' { '\n' } else { ' ' });
                i += 1;
            }
            continue;
        }
        // Not a byte we rewrite: copy the whole UTF-8 character.
        let start = i;
        i += 1;
        while i < bytes.len() && (bytes[i] & 0xC0) == 0x80 {
            i += 1;
        }
        out.push_str(&sql[start..i]);
    }
    out
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
    fn prose_in_a_comment_is_not_ddl() {
        // The regression: `module-cms` explains its tables in a `--`
        // comment, and markdown-style backticks around a table name failed
        // the whole module for MySQL quoting it does not use.
        let sql = "-- A small content store. `cms_item` is the working copy;\n\
                   -- `cms_revision` is append-only history (stored as BLOB\n\
                   -- in some other database, but not here).\n\
                   CREATE TABLE cms_item (id TEXT PRIMARY KEY);";
        assert_eq!(lint_portable_sql(sql), vec![]);
    }

    #[test]
    fn a_block_comment_is_not_ddl_and_may_nest() {
        let sql = "/* uses `backticks` and /* nests, mentioning SERIAL */ still inside */ \
                   CREATE TABLE t (id TEXT PRIMARY KEY);";
        assert_eq!(lint_portable_sql(sql), vec![]);
    }

    #[test]
    fn a_string_literal_is_data_not_ddl() {
        // Storing the word as a value says nothing about the column type.
        let sql = "INSERT INTO kinds (name) VALUES ('blob'), ('serial'), \
                   ('it''s NOW() in prose');";
        assert_eq!(lint_portable_sql(sql), vec![]);
    }

    #[test]
    fn stripping_comments_does_not_hide_real_ddl() {
        // The other half: the same tokens outside a comment still fail, and
        // a comment must not swallow the statement that follows it.
        let sql = "-- a note about ids\n\
                   CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, c `col` TEXT);";
        let tokens: Vec<&str> = lint_portable_sql(sql)
            .iter()
            .map(|(token, _)| *token)
            .collect();
        assert_eq!(tokens, ["AUTOINCREMENT", "`"]);
    }

    #[test]
    fn a_double_quoted_identifier_is_still_ddl() {
        // Double quotes are portable, so they are not stripped: a banned
        // token inside them is a real column type, not prose.
        let tokens: Vec<&str> = lint_portable_sql(r#"CREATE TABLE t ("data" BLOB);"#)
            .iter()
            .map(|(token, _)| *token)
            .collect();
        assert_eq!(tokens, ["BLOB"]);
    }

    #[test]
    fn an_unterminated_comment_or_literal_does_not_panic() {
        // Malformed SQL is the database's problem, not the lint's.
        assert_eq!(lint_portable_sql("/* never closed"), vec![]);
        assert_eq!(lint_portable_sql("SELECT 'never closed"), vec![]);
        assert_eq!(lint_portable_sql("-- never newline"), vec![]);
        // Multi-byte characters inside and outside the stripped spans.
        assert_eq!(
            lint_portable_sql("-- naïve ünicode ✓\nCREATE TABLE t (id TEXT);"),
            vec![]
        );
    }

    #[test]
    fn now_without_parens_is_not_flagged() {
        // `NOW()` is the dialect function; the word "now" in prose or a
        // column name is not.
        assert!(lint_portable_sql("SELECT now FROM t;").is_empty());
    }
}

#[cfg(test)]
mod card_data_tests {
    use super::{card_data_hit, lint_card_data};

    #[test]
    fn a_card_number_column_is_flagged() {
        let sql = "CREATE TABLE payment (id TEXT PRIMARY KEY, card_number TEXT)";
        assert_eq!(lint_card_data(sql).len(), 1);
        assert_eq!(lint_card_data(sql)[0].0, "card_number");
        assert!(card_data_hit("cvv").is_some());
        assert!(card_data_hit("exp_month").is_some());
    }

    #[test]
    fn card_data_only_in_a_comment_or_string_is_not_flagged() {
        // Documenting the rule must not trip it.
        let sql = "CREATE TABLE t (id TEXT) -- never store card_number here\n";
        assert!(lint_card_data(sql).is_empty());
        let sql2 = "INSERT INTO note (body) VALUES ('do not store card_number')";
        assert!(lint_card_data(sql2).is_empty());
    }

    #[test]
    fn ambiguous_words_do_not_false_positive() {
        // A music track, an audio pan, a session expiry are all legitimate.
        for sql in [
            "CREATE TABLE song (id TEXT, track INTEGER)",
            "CREATE TABLE mix (id TEXT, pan REAL)",
            "CREATE TABLE session (id TEXT, session_expiry TEXT)",
            "CREATE TABLE t (id TEXT, token_expiry TEXT)",
        ] {
            assert!(lint_card_data(sql).is_empty(), "false positive on: {sql}");
        }
    }
}
