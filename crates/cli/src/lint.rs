//! The portable-SQL lint (issue #8): flags tokens that SQLite and Postgres
//! disagree about, or that betray non-portable DDL. The canonical definition
//! lives in `factory0-core` ([`lint_portable_sql`]) so the Postgres
//! migration runner selects against the identical predicate (issue #18).

pub use factory0_core::lint_portable_sql;

/// Returns `(token, explanation)` pairs found in `sql`.
///
/// Kept as an alias for `fz doctor`; see [`lint_portable_sql`].
#[must_use]
pub fn banned_tokens(sql: &str) -> Vec<(&'static str, &'static str)> {
    lint_portable_sql(sql)
}
