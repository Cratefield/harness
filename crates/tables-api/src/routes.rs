//! The axum routes over a venture's declared tables (issue #153).
//!
//! | route | answers |
//! |---|---|
//! | `GET /{table}` | a page of rows, and a cursor when there is another |
//! | `POST /{table}` | the row it created |
//! | `GET /{table}/{key}` | one row by its primary key |
//! | `PUT /{table}/{key}` | the row it replaced |
//! | `DELETE /{table}/{key}` | `204`, and nothing |
//!
//! These are the five the surface publishes. A published action whose
//! route does not exist is worse than an unpublished one: a generated UI
//! renders the form and the submission 404s.
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
use axum::routing::{get, post};
use cratefield_core::{Problem, ProblemDef, Scope, TenantConn};
use cratefield_tables::{FieldKind, Filter, TableDef};
use http::{HeaderMap, StatusCode};
use serde_json::{Value, json};

use crate::batch::{Batch, PATH};
use crate::read::{Tables, one, page};

/// The cursor is not one this table hands out.
pub const BAD_CURSOR: ProblemDef = ProblemDef {
    slug: "bad-cursor",
    status: StatusCode::BAD_REQUEST,
    title: "Not a cursor for this table",
    description: "The `after` parameter is not the `next` value from a previous page of this table.",
};

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
        // Before `/{table}`, though it cannot collide: `__batch` is not a
        // legal declared table name — a name starts with a lowercase
        // letter and may not contain `__` — so a venture cannot declare a
        // table that shadows this. Registered first anyway, because
        // "cannot collide" is a fact about a validator somewhere else.
        .route(PATH, post(batch_route))
        .route("/{table}", get(page_route).post(create_route))
        .route(
            "/{table}/{key}",
            get(one_route).put(replace_route).delete(remove_route),
        )
        .with_state(tables)
}

/// The query string of a page request.
///
/// `after` is the cursor; **every other parameter is a filter**, named
/// for the column it narrows. That is the whole vocabulary: equality on a
/// declared column, and nothing that reaches another row or another
/// request — the rule #153 sets for the declaration surface, applied to
/// what a caller may ask of it.
///
/// Collected rather than declared, because the columns are a venture's
/// and this type is the harness's.
#[derive(serde::Deserialize)]
struct PageQuery {
    #[serde(default)]
    after: Option<String>,
    /// `?sort=column` or `?sort=-column`. One column: a second is a
    /// tiebreaker and the primary key is already that.
    #[serde(default)]
    sort: Option<String>,
    #[serde(flatten)]
    filters: std::collections::BTreeMap<String, String>,
}

async fn page_route(
    scope: Scope,
    conn: TenantConn,
    State(tables): State<Arc<Tables>>,
    Path(table): Path<String>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<axum::Json<Value>, Problem> {
    // The cursor is parsed against the same table the page is of, so a
    // cursor for a different table's key shape is a 400 here rather than
    // a `WHERE` comparing a string to an integer further down.
    let declared = tables.declared(&table);
    // The sort is read before the cursor, because a sorted page's cursor
    // names the sort column as well as the key — so what counts as a
    // well-formed cursor depends on it.
    let sort = sort_of(query.sort.as_deref());
    let after = match (&query.after, declared) {
        (Some(raw), Some(api)) => Some(cursor_from_query(&api.table, raw, sort)?),
        _ => None,
    };
    let filters = match declared {
        Some(api) => filters_from_query(&api.table, &query.filters)?,
        // The table is not declared. `page` answers the 404, and parsing
        // filters against a table the caller may not be allowed to know
        // exists would answer a different question first.
        None => Vec::new(),
    };
    let body = page(
        &tables,
        &conn,
        &headers,
        &scope,
        crate::read::Asked {
            table: &table,
            after: after.as_ref().map(|value| &value.0),
            filters: &filters,
            sort,
        },
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

async fn create_route(
    scope: Scope,
    conn: TenantConn,
    State(tables): State<Arc<Tables>>,
    Path(table): Path<String>,
    headers: HeaderMap,
    body: axum::Json<Value>,
) -> Result<(StatusCode, axum::Json<Value>), Problem> {
    let row = crate::write::create(&tables, &conn, &headers, &scope, &table, body.0).await?;
    // 201, because a create that answers 200 is indistinguishable from an
    // update to a client that is watching status codes.
    Ok((StatusCode::CREATED, axum::Json(row)))
}

async fn replace_route(
    scope: Scope,
    conn: TenantConn,
    State(tables): State<Arc<Tables>>,
    Path((table, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::Json<Value>,
) -> Result<axum::Json<Value>, Problem> {
    let api = tables
        .declared(&table)
        .ok_or_else(|| Problem::new(&crate::read::NO_SUCH_TABLE))?;
    let key = key_from_path(&api.table, &key)?;
    let row =
        crate::write::replace(&tables, &conn, &headers, &scope, &table, &key.0, body.0).await?;
    Ok(axum::Json(row))
}

async fn remove_route(
    scope: Scope,
    conn: TenantConn,
    State(tables): State<Arc<Tables>>,
    Path((table, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, Problem> {
    let api = tables
        .declared(&table)
        .ok_or_else(|| Problem::new(&crate::read::NO_SUCH_TABLE))?;
    let key = key_from_path(&api.table, &key)?;
    crate::write::remove(&tables, &conn, &headers, &scope, &table, &key.0).await?;
    // No body: there is nothing left to describe, and inventing one
    // ("deleted": true) is a second thing to keep true.
    Ok(StatusCode::NO_CONTENT)
}

/// The query string's non-cursor parameters, as filters on declared
/// columns.
///
/// A parameter naming a column the table does not declare is a `400`, not
/// a parameter ignored. Ignoring it answers a question the caller did not
/// ask, with more rows than they asked for — and a client that misspells
/// a column would get a page that looks right.
///
/// # Errors
///
/// [`crate::read::BAD_FILTER`] naming the parameter.
fn filters_from_query(
    table: &TableDef,
    given: &std::collections::BTreeMap<String, String>,
) -> Result<Vec<Filter>, Problem> {
    let mut filters = Vec::with_capacity(given.len());
    for (column, raw) in given {
        let field = table
            .fields
            .iter()
            .find(|field| &field.name == column)
            .ok_or_else(|| {
                Problem::new(&crate::read::BAD_FILTER)
                    .with_detail(format!("`{column}` is not a field of this table"))
            })?;
        filters.push(Filter {
            column: column.clone(),
            // A query string is text; the column's kind says what that
            // text means. `key_from_path` answers the same question for a
            // path segment, and this is the one place they differ: a
            // filter may name any declared column, not only a key, so a
            // `real` or `boolean` column is filterable where it is not
            // addressable.
            value: value_from_text(field, raw)?,
        });
    }
    Ok(filters)
}

/// One query-string value, as the JSON its column's kind calls for.
fn value_from_text(field: &cratefield_tables::FieldDef, raw: &str) -> Result<Value, Problem> {
    let bad = || {
        Problem::new(&crate::read::BAD_FILTER).with_detail(format!(
            "`{}` is {} and `{raw}` is not",
            field.name,
            field.kind.as_str()
        ))
    };
    Ok(match &field.kind {
        FieldKind::Text { .. }
        | FieldKind::Uuid
        | FieldKind::Timestamp
        | FieldKind::Enum { .. } => Value::String(raw.to_owned()),
        FieldKind::Integer { .. } => raw.parse::<i64>().map(Value::from).map_err(|_e| bad())?,
        FieldKind::Real { .. } => raw.parse::<f64>().map(Value::from).map_err(|_e| bad())?,
        FieldKind::Boolean => match raw {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            // Not `1`/`0`/`yes`: the declared kind is a boolean and the
            // wire form for one is `true` or `false`. Guessing at the
            // others is a vocabulary nobody wrote down.
            _ => return Err(bad()),
        },
        // A JSON column has no single text form to compare for equality,
        // and comparing serialized text would make the answer depend on
        // key order and spacing.
        FieldKind::Json => return Err(bad()),
    })
}

/// The `?after=` cursor, which is the `next` the server handed back.
///
/// JSON, not a bare value, and the same shape `next` is emitted in — a
/// client pages by sending back what it was given, and two shapes would
/// mean every client carries the translation between them. The only place
/// that knowledge exists is here.
///
/// [`key_from_path`] is the wrong parser for this even for a
/// single-column key: it exists for a **path segment**, which can carry
/// one value, so it refuses a composite key. A query parameter has no
/// such constraint, and refusing there made a composite-key table
/// unpageable past its first page over HTTP while `select_page` could
/// express the query perfectly well.
///
/// # Errors
///
/// [`BAD_CURSOR`] when the value is not JSON, is not an object, or does
/// not carry every primary-key column as its declared kind.
pub fn cursor_from_query(
    table: &TableDef,
    raw: &str,
    sort: Option<cratefield_tables::Sort<'_>>,
) -> Result<Key, Problem> {
    let value: Value = serde_json::from_str(raw).map_err(|_ignored| {
        Problem::new(&BAD_CURSOR).with_detail(
            "the cursor is the `next` value from a previous page, sent back as it was given",
        )
    })?;
    let Some(object) = value.as_object() else {
        return Err(Problem::new(&BAD_CURSOR)
            .with_detail("the cursor names each primary-key column, so it is a JSON object"));
    };
    // Every column the page is ordered by: the sort column, then the
    // key. A cursor short of any of them cannot say where to resume.
    let ordered: Vec<&str> = sort
        .map(|sort| sort.column)
        .into_iter()
        .chain(table.primary_key.iter().map(String::as_str))
        .collect();
    for column in ordered {
        let Some(given) = object.get(column).filter(|value| !value.is_null()) else {
            return Err(Problem::new(&BAD_CURSOR)
                .with_detail(format!("the cursor does not name `{column}`")));
        };
        let field = table
            .fields
            .iter()
            .find(|field| field.name == column)
            .ok_or_else(|| {
                Problem::new(&BAD_CURSOR)
                    .with_detail(format!("`{column}` is not a field of this table"))
            })?;
        if cratefield_tables::to_sql(field, Some(given)).is_none() {
            return Err(Problem::new(&BAD_CURSOR).with_detail(format!(
                "`{column}` is {} and the cursor's value is not",
                field.kind.as_str()
            )));
        }
    }
    Ok(Key(value))
}

async fn batch_route(
    scope: Scope,
    conn: TenantConn,
    State(tables): State<Arc<Tables>>,
    headers: HeaderMap,
    body: axum::Json<Batch>,
) -> Result<axum::Json<Value>, Problem> {
    let answer = crate::batch::run(&tables, &conn, &headers, &scope, &body.0).await?;
    Ok(axum::Json(answer))
}

/// `?sort=column` or `?sort=-column`.
///
/// `-` for descending, the shape a query string can carry without a
/// second parameter to keep in step with the first. Whether the column
/// exists and can be ordered by is the query layer's answer, not this
/// one's — there is one declaration and it should be read in one place.
pub(crate) fn sort_of(raw: Option<&str>) -> Option<cratefield_tables::Sort<'_>> {
    raw.map(|raw| {
        raw.strip_prefix('-').map_or(
            cratefield_tables::Sort {
                column: raw,
                descending: false,
            },
            |column| cratefield_tables::Sort {
                column,
                descending: true,
            },
        )
    })
}
