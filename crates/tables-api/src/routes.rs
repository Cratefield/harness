//! The axum routes over a venture's declared tables (issue #153).
//!
//! Two, both reads:
//!
//! | route | answers |
//! |---|---|
//! | `GET /{table}` | a page of rows, and a cursor when there is another |
//! | `GET /{table}/{key}` | one row by its primary key |
//!
//! Mounted under the generated module's name, so a venture's `note`
//! table is at `/v1/tables/note`.
//!
//! This is the layer that insists on a [`TenantConn`]. The functions in
//! [`crate::read`] take a `&dyn Database` so they can be exercised
//! without an HTTP stack; here the handle comes from the extractor, which
//! can only hand back the one the resolution layer resolved for this
//! request's tenant. `ctx.ports.db` is captured once in handler state and
//! is the same handle for every request whoever asked — for a venture's
//! own rows that is the difference between serving a row and serving one
//! tenant's customer their neighbour's data.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::routing::get;
use cratefield_core::{Problem, ProblemDef, Scope, TenantConn};
use cratefield_tables::{FieldKind, TableDef};
use http::{HeaderMap, StatusCode};
use serde_json::{Value, json};

use crate::read::{Tables, one, page};

/// The key in the path is not one this table can be addressed by.
pub const BAD_KEY: ProblemDef = ProblemDef {
    slug: "bad-key",
    status: StatusCode::BAD_REQUEST,
    title: "Not a key for this table",
    description: "The path segment is not a value of the table's primary-key column.",
};

/// The table's primary key is more than one column.
///
/// A composite key has no single path segment to be, and inventing a
/// separator would make a key containing that separator unaddressable —
/// silently, and only for the rows that contain it.
pub const COMPOSITE_KEY: ProblemDef = ProblemDef {
    slug: "composite-key",
    status: StatusCode::BAD_REQUEST,
    title: "This table's rows are not addressable by path",
    description: "The table's primary key is more than one column; read it through the page.",
};

/// The routes, over the declared tables in `tables`.
pub fn router(tables: Arc<Tables>) -> Router {
    Router::new()
        .route("/{table}", get(page_route))
        .route("/{table}/{key}", get(one_route))
        .with_state(tables)
}

/// `?after=<key>` — where the next page starts.
#[derive(serde::Deserialize)]
struct Cursor {
    after: Option<String>,
}

async fn page_route(
    scope: Scope,
    conn: TenantConn,
    State(tables): State<Arc<Tables>>,
    Path(table): Path<String>,
    Query(cursor): Query<Cursor>,
    headers: HeaderMap,
) -> Result<axum::Json<Value>, Problem> {
    // The cursor is parsed against the same table the page is of, so a
    // cursor for a different table's key shape is a 400 here rather than
    // a `WHERE` comparing a string to an integer further down.
    let after = match (&cursor.after, tables.declared(&table)) {
        (Some(raw), Some(api)) => Some(key_from_path(&api.table, raw)?),
        _ => None,
    };
    let body = page(
        &tables,
        &conn,
        &headers,
        &scope,
        &table,
        after.as_ref().map(|value| &value.0),
    )
    .await?;
    Ok(axum::Json(body))
}

async fn one_route(
    scope: Scope,
    conn: TenantConn,
    State(tables): State<Arc<Tables>>,
    Path((table, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<axum::Json<Value>, Problem> {
    // The table is looked up twice — here to shape the key, and again
    // inside `one` to decide access. Two lookups over a handful of
    // declared tables, and the alternative is a key parsed against a
    // table the caller may not be allowed to know exists.
    let api = tables
        .declared(&table)
        .ok_or_else(|| Problem::new(&crate::read::NO_SUCH_TABLE))?;
    let key = key_from_path(&api.table, &key)?;
    let body = one(&tables, &conn, &headers, &scope, &table, &key.0).await?;
    Ok(axum::Json(body))
}

/// A primary key, built from a path segment.
///
/// Wrapped so the JSON object it becomes is not mistaken for a row.
pub struct Key(pub Value);

/// Turns one path segment into the table's primary key.
///
/// # Errors
///
/// [`COMPOSITE_KEY`] when the table's key is more than one column, and
/// [`BAD_KEY`] when the segment is not a value of that column's kind.
pub fn key_from_path(table: &TableDef, segment: &str) -> Result<Key, Problem> {
    let [column] = table.primary_key.as_slice() else {
        return Err(Problem::new(&COMPOSITE_KEY));
    };
    let field = table
        .fields
        .iter()
        .find(|field| &field.name == column)
        // A primary key naming a column the table does not have is a
        // manifest `fz build` refuses, so this is a deployment running a
        // composition its manifest would not have produced.
        .ok_or_else(|| Problem::new(&crate::access::MISDECLARED))?;

    let value = match &field.kind {
        // A path segment is text, and these kinds are text.
        FieldKind::Text { .. }
        | FieldKind::Uuid
        | FieldKind::Timestamp
        | FieldKind::Enum { .. } => Value::String(segment.to_owned()),
        FieldKind::Integer { .. } => segment
            .parse::<i64>()
            .map(Value::from)
            .map_err(|_ignored| Problem::new(&BAD_KEY))?,
        // Neither is a key anybody should have declared, and `fz build`
        // does not stop them. Refusing is better than guessing: a float
        // compared for equality is a key that sometimes matches nothing,
        // and a JSON blob has no canonical text to be a path segment.
        FieldKind::Real { .. } | FieldKind::Boolean | FieldKind::Json => {
            return Err(Problem::new(&BAD_KEY));
        }
    };
    Ok(Key(json!({ column.as_str(): value })))
}
