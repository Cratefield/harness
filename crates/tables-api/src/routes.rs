//! The axum routes over a venture's declared tables (issue #153).
//!
//! | route | answers |
//! |---|---|
//! | `GET /{table}` | a page of rows, and a cursor when there is another |
//! | `POST /{table}` | the row it created |
//! | `GET /{table}/{key}` | one row by its primary key |
//! | `PUT /{table}/{key}` | the row it replaced |
//! | `DELETE /{table}/{key}` | `204`, and nothing |
//! | `GET /{table}/__by?<column>=<value>&…` | one row by its primary key, named in the query |
//! | `PUT /{table}/__by?…` | the row it replaced |
//! | `DELETE /{table}/__by?…` | `204`, and nothing |
//!
//! The first five are what the surface publishes, a `{key}` spelling for
//! a single-column key and the `__by` spelling for a wider one. A
//! published action whose route does not exist is worse than an
//! unpublished one: a generated UI renders the form and the submission
//! 404s.
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
//! tenant's customer their neighbour's data. The tenancy rides out of the
//! same extractor — `conn.tenancy()` — because the access decision about
//! who may use this connection has to know whether a registry named its
//! tenant (#385), and the extractor is the only place that fact exists.

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

/// The key in the path, and the table's primary key is more than one
/// column.
///
/// The path route refuses it rather than joining the values with a
/// separator that could occur inside one — silently unaddressable, and
/// only for the rows that contain it. The key is named in the query
/// instead, at `/{table}/__by?<column>=<value>` (ADR 0018).
pub const COMPOSITE_KEY: ProblemDef = ProblemDef {
    slug: "composite-key",
    status: StatusCode::BAD_REQUEST,
    title: "A composite key does not fit in one path segment",
    description: "The table's primary key is more than one column, so `/{table}/{key}` cannot name a row; name the key in the query at `/{table}/__by?<column>=<value>` instead.",
};

/// The `__by` query named some of the primary-key columns but not all.
///
/// `select_one` refuses a half key for the same reason, rather than
/// matching every row that shares the named prefix.
pub const PARTIAL_KEY: ProblemDef = ProblemDef {
    slug: "partial-key",
    status: StatusCode::BAD_REQUEST,
    title: "The key is not complete",
    description: "Name every primary-key column of the table once: a row is addressed by its whole key. `after` and `sort` are the page's parameters on this route and cannot name a key column, so a table whose key uses one of those names has no address here.",
};

/// The `__by` query named a column the primary key does not have.
pub const NOT_A_KEY_COLUMN: ProblemDef = ProblemDef {
    slug: "not-a-key-column",
    status: StatusCode::BAD_REQUEST,
    title: "Not a key column for this table",
    description: "A `__by` query names primary-key columns only. To narrow by any other column, read the page and filter it.",
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
        // A static segment beats the dynamic `{key}` — in the one shared
        // router, for *every* table at once. So `__by` captures the row
        // whose key value is literally `__by` on every table, and serving
        // the route for single-column-key tables too is what gives that
        // row an address back (`/{table}/__by?id=__by`); serving it only
        // where a composite key needs it would strand the row for good.
        // Under a table mount, a segment beginning `__` belongs to the
        // harness (ADR 0018).
        .route(
            "/{table}/__by",
            get(one_by_route)
                .put(replace_by_route)
                .delete(remove_by_route),
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
        conn.tenancy(),
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
    let body = one(
        &tables,
        &conn,
        conn.tenancy(),
        &headers,
        &scope,
        &table,
        &key.0,
    )
    .await?;
    Ok(axum::Json(body))
}

/// One row by its primary key, named in the query: the spelling that
/// answers for a key of any arity, where `/{table}/{key}` answers for a
/// key of one. Same body, same statuses, same access decision — only
/// where the key travels is different.
async fn one_by_route(
    scope: Scope,
    conn: TenantConn,
    State(tables): State<Arc<Tables>>,
    Path(table): Path<String>,
    Query(query): Query<ByQuery>,
    headers: HeaderMap,
) -> Result<axum::Json<Value>, Problem> {
    let api = tables
        .declared(&table)
        .ok_or_else(|| Problem::new(&crate::read::NO_SUCH_TABLE))?;
    let key = key_from_query(&api.table, &query)?;
    let body = one(
        &tables,
        &conn,
        conn.tenancy(),
        &headers,
        &scope,
        &table,
        &key.0,
    )
    .await?;
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

    Ok(Key(json!({
        column.as_str(): key_value_from_text(field, segment)?
    })))
}

/// One key value, as the JSON its column's kind calls for.
///
/// The one coercion behind both spellings of a key — a path segment
/// ([`key_from_path`]) and a `__by` query parameter
/// ([`key_from_query`]) — so a `real`, `boolean` or `json` key is
/// refused wherever it is named, for the reason it is refused there: a
/// float compared for equality is a key that sometimes matches nothing,
/// and a JSON blob has no canonical text to be addressed by. A filter
/// may name those kinds — [`value_from_text`] answers that question —
/// because a filter narrows a page a key has already cut to one row.
///
/// # Errors
///
/// [`BAD_KEY`] when the text is not a value of the column's kind.
fn key_value_from_text(field: &cratefield_tables::FieldDef, raw: &str) -> Result<Value, Problem> {
    match &field.kind {
        // A path segment and a query parameter are text, and these kinds
        // are text.
        FieldKind::Text { .. }
        | FieldKind::Uuid
        | FieldKind::Timestamp
        | FieldKind::Enum { .. } => Ok(Value::String(raw.to_owned())),
        FieldKind::Integer { .. } => raw
            .parse::<i64>()
            .map(Value::from)
            .map_err(|_ignored| Problem::new(&BAD_KEY)),
        // Neither is a key anybody should have declared, and `fz build`
        // does not stop them. Refusing is better than guessing.
        FieldKind::Real { .. } | FieldKind::Boolean | FieldKind::Json => {
            Err(Problem::new(&BAD_KEY))
        }
    }
}

/// The query string of a `__by` request.
///
/// Every parameter but two names a primary-key column, and is collected
/// rather than declared because the key columns are a venture's and this
/// type is the harness's — the same shape [`PageQuery`] takes on the page
/// route. The two are `after` and `sort`, the harness's own parameters
/// here as on the page's: read into their fields so they can never be
/// read as a key column. A table whose key uses one of those names can
/// never complete its key on this route, and [`key_from_query`] refuses
/// it as partial rather than quietly reading the reserved parameter as a
/// value — which is the strand the reservation ties, stated (ADR 0018).
#[derive(serde::Deserialize)]
struct ByQuery {
    // Read into these fields only so they can never be read as a key
    // column; nothing in Rust reads them back, and the lint that notices
    // is told exactly that.
    #[serde(default)]
    #[expect(dead_code)]
    after: Option<String>,
    #[serde(default)]
    #[expect(dead_code)]
    sort: Option<String>,
    #[serde(flatten)]
    key: std::collections::BTreeMap<String, String>,
}

/// Turns the `__by` query into the table's primary key.
///
/// The columns are **named**, not positional: reordering a declaration
/// cannot quietly change what an existing URL means. A query naming a
/// column outside the key is refused — ignoring it would answer a
/// question the caller did not ask — and so is a query naming only some
/// of the key columns, matching the refusal `select_one` makes rather
/// than matching every row that shares the given prefix.
///
/// # Errors
///
/// [`NOT_A_KEY_COLUMN`] for a parameter that is not a primary-key
/// column, [`PARTIAL_KEY`] when a key column is not named, [`BAD_KEY`]
/// when a named value is not its column's kind, and
/// [`crate::access::MISDECLARED`] for a key naming a column the table
/// does not have.
fn key_from_query(table: &TableDef, query: &ByQuery) -> Result<Key, Problem> {
    // Named columns first, so a misspelled key column is answered as the
    // mistake it is rather than as a key that happens to be short.
    for column in query.key.keys() {
        if !table.primary_key.contains(column) {
            return Err(Problem::new(&NOT_A_KEY_COLUMN).with_detail(format!(
                "`{column}` is not a primary-key column of this table"
            )));
        }
    }
    let missing: Vec<&str> = table
        .primary_key
        .iter()
        .map(String::as_str)
        .filter(|column| !query.key.contains_key(*column))
        .collect();
    if !missing.is_empty() {
        return Err(Problem::new(&PARTIAL_KEY).with_detail(format!(
            "the query does not name `{}`",
            missing.join("`, `")
        )));
    }

    let mut object = serde_json::Map::with_capacity(table.primary_key.len());
    for column in &table.primary_key {
        let field = table
            .fields
            .iter()
            .find(|field| &field.name == column)
            .ok_or_else(|| Problem::new(&crate::access::MISDECLARED))?;
        let value = key_value_from_text(field, &query.key[column.as_str()])?;
        object.insert(column.clone(), value);
    }
    Ok(Key(Value::Object(object)))
}

async fn create_route(
    scope: Scope,
    conn: TenantConn,
    State(tables): State<Arc<Tables>>,
    Path(table): Path<String>,
    headers: HeaderMap,
    body: axum::Json<Value>,
) -> Result<(StatusCode, axum::Json<Value>), Problem> {
    let row = crate::write::create(
        &tables,
        &conn,
        conn.tenancy(),
        &headers,
        &scope,
        &table,
        body.0,
    )
    .await?;
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
    let row = crate::write::replace(
        &tables,
        &conn,
        conn.tenancy(),
        &headers,
        &scope,
        &table,
        &key.0,
        body.0,
    )
    .await?;
    Ok(axum::Json(row))
}

/// Replaces one row addressed through `__by`. The key rides the query,
/// the body is still the row — so the body names the key columns too,
/// and the `WHERE` is built from the query's spelling of them.
async fn replace_by_route(
    scope: Scope,
    conn: TenantConn,
    State(tables): State<Arc<Tables>>,
    Path(table): Path<String>,
    Query(query): Query<ByQuery>,
    headers: HeaderMap,
    body: axum::Json<Value>,
) -> Result<axum::Json<Value>, Problem> {
    let api = tables
        .declared(&table)
        .ok_or_else(|| Problem::new(&crate::read::NO_SUCH_TABLE))?;
    let key = key_from_query(&api.table, &query)?;
    let row = crate::write::replace(
        &tables,
        &conn,
        conn.tenancy(),
        &headers,
        &scope,
        &table,
        &key.0,
        body.0,
    )
    .await?;
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
    crate::write::remove(
        &tables,
        &conn,
        conn.tenancy(),
        &headers,
        &scope,
        &table,
        &key.0,
    )
    .await?;
    // No body: there is nothing left to describe, and inventing one
    // ("deleted": true) is a second thing to keep true.
    Ok(StatusCode::NO_CONTENT)
}

/// Removes one row addressed through `__by`, answering `204` and
/// nothing, as the path route does.
async fn remove_by_route(
    scope: Scope,
    conn: TenantConn,
    State(tables): State<Arc<Tables>>,
    Path(table): Path<String>,
    Query(query): Query<ByQuery>,
    headers: HeaderMap,
) -> Result<StatusCode, Problem> {
    let api = tables
        .declared(&table)
        .ok_or_else(|| Problem::new(&crate::read::NO_SUCH_TABLE))?;
    let key = key_from_query(&api.table, &query)?;
    crate::write::remove(
        &tables,
        &conn,
        conn.tenancy(),
        &headers,
        &scope,
        &table,
        &key.0,
    )
    .await?;
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
    let answer =
        crate::batch::run(&tables, &conn, conn.tenancy(), &headers, &scope, &body.0).await?;
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
