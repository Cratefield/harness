//! Value and SQL conversion between the port's engine-agnostic statement
//! model and sqlx Postgres types (ADR 0004). Pure functions; unit-tested
//! without a server.

#![allow(clippy::module_name_repetitions)] // ..._to_row mirrors the other adapters

use factory0_core::{DbError, Row};
use sea_query::Value as SeaValue;
use sqlx::postgres::{PgArguments, PgRow};
use sqlx::{Arguments as _, Column as _, Row as _, TypeInfo as _};

/// Rewrites positional `?` placeholders to Postgres `$n` placeholders.
///
/// The port's [`factory0_core::Statement`] carries SQL rendered by
/// sea-query's `SqliteQueryBuilder` (the portable wire form the D1 and
/// rusqlite adapters execute directly); Postgres binds `$1, $2, …`. The
/// rewrite walks the statement skipping string literals (`'…'`, `''`
/// escape), quoted identifiers (`"…"`, `` `…` ``) and SQL comments
/// (`--…`, `/*…*/`), so a `?` inside a literal never becomes a
/// placeholder. Input is machine-rendered sea-query SQL, never arbitrary
/// user text.
pub(crate) fn rebind_placeholders(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() + 8);
    let mut placeholder = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'\'' => {
                out.push(b);
                i += 1;
                // Consume until the closing quote; '' is an escaped quote
                // and stays inside the literal.
                while i < bytes.len() {
                    out.push(bytes[i]);
                    if bytes[i] == b'\'' {
                        i += 1;
                        if i < bytes.len() && bytes[i] == b'\'' {
                            out.push(bytes[i]);
                            i += 1;
                        } else {
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
            }
            b'"' => {
                out.push(b);
                i += 1;
                // Quoted identifier; "" is an escaped double quote.
                while i < bytes.len() {
                    out.push(bytes[i]);
                    if bytes[i] == b'"' {
                        i += 1;
                        if i < bytes.len() && bytes[i] == b'"' {
                            out.push(bytes[i]);
                            i += 1;
                        } else {
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
            }
            b'`' => {
                out.push(b);
                i += 1;
                while i < bytes.len() && bytes[i] != b'`' {
                    out.push(bytes[i]);
                    i += 1;
                }
                if i < bytes.len() {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                out.push(b'/');
                out.push(b'*');
                i += 2;
                while i < bytes.len() {
                    out.push(bytes[i]);
                    if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
                        out.push(b'/');
                        i += 2;
                        break;
                    }
                    i += 1;
                }
            }
            b'?' => {
                placeholder += 1;
                out.extend_from_slice(format!("${placeholder}").as_bytes());
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    // Only ASCII '?' (single byte) was rewritten; the rest is copied
    // verbatim, so the output stays valid UTF-8.
    String::from_utf8(out).expect("rebinding preserves UTF-8")
}

/// Binds the statement's sea-query values onto Postgres arguments.
///
/// Mapping notes (the SQLite-to-Postgres convention, documented on the
/// crate): booleans bind as `SMALLINT` 0/1 — modules store booleans as
/// `INTEGER` by convention and never compare against SQL `BOOLEAN` — and
/// sea-query's unsigned variants (rendered by `LIMIT n` and friends) widen
/// to the next signed Postgres type.
///
/// # Errors
///
/// [`DbError::Execute`] when a `u64` value does not fit Postgres `i64`
/// (impossible for the portable subset's TEXT ids and INTEGER counters).
pub(crate) fn bind_values(args: &mut PgArguments, values: &[SeaValue]) -> Result<(), DbError> {
    for value in values {
        bind_one(args, value)?;
    }
    Ok(())
}

fn bind_one(args: &mut PgArguments, value: &SeaValue) -> Result<(), DbError> {
    let result = match value {
        // Booleans cross the wire as INTEGER 0/1 (crate convention); SQL
        // NULL binds as a typed NULL of the widened variant's Postgres
        // type.
        SeaValue::Bool(Some(v)) => args.add(i16::from(*v)),
        SeaValue::Bool(None) | SeaValue::SmallInt(None) | SeaValue::TinyUnsigned(None) => {
            args.add(Option::<i16>::None)
        }
        SeaValue::TinyInt(Some(v)) => args.add(*v),
        SeaValue::TinyInt(None) => args.add(Option::<i8>::None),
        SeaValue::SmallInt(Some(v)) => args.add(*v),
        SeaValue::Int(Some(v)) => args.add(*v),
        SeaValue::Int(None) | SeaValue::SmallUnsigned(None) => args.add(Option::<i32>::None),
        SeaValue::BigInt(Some(v)) => args.add(*v),
        // Postgres has no unsigned wire types: widen to the next signed.
        SeaValue::TinyUnsigned(Some(v)) => args.add(i16::from(*v)),
        SeaValue::SmallUnsigned(Some(v)) => args.add(i32::from(*v)),
        SeaValue::Unsigned(Some(v)) => args.add(i64::from(*v)),
        SeaValue::BigUnsigned(Some(v)) => {
            let widened = i64::try_from(*v).map_err(|_| {
                DbError::Execute(format!("u64 value {v} does not fit Postgres BIGINT"))
            })?;
            args.add(widened)
        }
        SeaValue::BigInt(None) | SeaValue::Unsigned(None) | SeaValue::BigUnsigned(None) => {
            args.add(Option::<i64>::None)
        }
        SeaValue::Float(Some(v)) => args.add(*v),
        SeaValue::Float(None) => args.add(Option::<f32>::None),
        SeaValue::Double(Some(v)) => args.add(*v),
        SeaValue::Double(None) => args.add(Option::<f64>::None),
        SeaValue::String(Some(v)) => args.add(v.as_str()),
        SeaValue::String(None) => args.add(Option::<&str>::None),
        SeaValue::Char(Some(v)) => args.add(v.to_string()),
        SeaValue::Char(None) => args.add(Option::<String>::None),
        SeaValue::Bytes(Some(v)) => args.add::<&[u8]>(&**v),
        SeaValue::Bytes(None) => args.add(Option::<Vec<u8>>::None),
    };
    result.map_err(|err| DbError::Execute(err.to_string()))
}

/// Converts one sqlx row to the port's owned row model. Decoding is driven
/// by the column's Postgres type name; SQL NULL maps to the sea-query
/// "variant holding `None`" convention (as the SQLite adapter does), and a
/// type this mapping does not know degrades to that same NULL form rather
/// than failing the query.
pub(crate) fn pg_row_to_row(row: &PgRow) -> Row {
    let mut columns = Vec::with_capacity(row.columns().len());
    for (index, column) in row.columns().iter().enumerate() {
        let name = column.name().to_string();
        let type_name = column.type_info().name().to_ascii_uppercase();
        let value = match type_name.as_str() {
            "BOOL" => row
                .try_get::<Option<bool>, usize>(index)
                .ok()
                .flatten()
                .map_or(SeaValue::Bool(None), |v| SeaValue::Bool(Some(v))),
            "INT2" | "SMALLINT" => row
                .try_get::<Option<i16>, usize>(index)
                .ok()
                .flatten()
                .map_or(SeaValue::SmallInt(None), |v| SeaValue::SmallInt(Some(v))),
            "INT4" | "INT" | "INTEGER" => row
                .try_get::<Option<i32>, usize>(index)
                .ok()
                .flatten()
                .map_or(SeaValue::Int(None), |v| SeaValue::Int(Some(v))),
            "INT8" | "BIGINT" => row
                .try_get::<Option<i64>, usize>(index)
                .ok()
                .flatten()
                .map_or(SeaValue::BigInt(None), |v| SeaValue::BigInt(Some(v))),
            "FLOAT4" | "REAL" => row
                .try_get::<Option<f32>, usize>(index)
                .ok()
                .flatten()
                .map_or(SeaValue::Float(None), |v| SeaValue::Float(Some(v))),
            "FLOAT8" | "DOUBLE PRECISION" => row
                .try_get::<Option<f64>, usize>(index)
                .ok()
                .flatten()
                .map_or(SeaValue::Double(None), |v| SeaValue::Double(Some(v))),
            "BYTEA" => row
                .try_get::<Option<Vec<u8>>, usize>(index)
                .ok()
                .flatten()
                .map_or(SeaValue::Bytes(None), |v| {
                    SeaValue::Bytes(Some(Box::new(v)))
                }),
            // TEXT, VARCHAR, CHAR, BPCHAR, NAME, enum labels and anything
            // else textual decode as strings.
            _ => row
                .try_get::<Option<String>, usize>(index)
                .ok()
                .flatten()
                .map_or(SeaValue::String(None), |v| {
                    SeaValue::String(Some(Box::new(v)))
                }),
        };
        columns.push((name, value));
    }
    Row::new(columns)
}

#[cfg(test)]
mod tests {
    use super::rebind_placeholders;

    #[test]
    fn rewrites_placeholders_positionally() {
        assert_eq!(
            rebind_placeholders("INSERT INTO t (a, b) VALUES (?, ?)"),
            "INSERT INTO t (a, b) VALUES ($1, $2)"
        );
    }

    #[test]
    fn leaves_question_marks_in_string_literals_alone() {
        assert_eq!(
            rebind_placeholders("INSERT INTO t VALUES ('what?', ?, 'a''?b')"),
            "INSERT INTO t VALUES ('what?', $1, 'a''?b')"
        );
    }

    #[test]
    fn leaves_question_marks_in_identifiers_and_comments_alone() {
        assert_eq!(
            rebind_placeholders("SELECT \"col?\" FROM t -- real ?\nWHERE id = ? /* ? */"),
            "SELECT \"col?\" FROM t -- real ?\nWHERE id = $1 /* ? */"
        );
    }

    #[test]
    fn handles_empty_and_placeholder_free_sql() {
        assert_eq!(rebind_placeholders("SELECT 1"), "SELECT 1");
        assert_eq!(rebind_placeholders(""), "");
    }

    #[test]
    fn handles_backtick_quoted_and_escaped_strings() {
        assert_eq!(
            rebind_placeholders("UPDATE `t?` SET a = ?"),
            "UPDATE `t?` SET a = $1"
        );
    }
}
