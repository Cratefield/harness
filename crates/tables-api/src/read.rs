//! Reading a declared table's rows (issue #153).
//!
//! Two routes: a page of a table, and one row by its primary key. Both go
//! through [`crate::access::may_read`] first and carry its answer into
//! the `WHERE` rather than applying it to rows already fetched — see
//! [`cratefield_tables::Owned`] for why that distinction is not a
//! refactoring preference.
//!
//! # The database handle
//!
//! These take a `&dyn Database`, and the router hands them a
//! `cratefield_core::TenantConn` — never `ctx.ports.db`. The context is
//! built once and captured in handler state, so `ports.db` is the same
//! handle for every request whoever asked; `TenantConn` is the one the
//! resolution layer resolved for *this* request's tenant. For a venture's
//! own declared tables that is the difference between serving a row and
//! serving somebody else's customer their neighbour's data.
//!
//! The functions take the trait rather than the `TenantConn` so they can
//! be exercised against a real database without an HTTP stack —
//! `TenantConn` has no constructor, which is the point of it. The routes
//! below are where the tenant-bound handle is insisted on.

use std::sync::Arc;

use cratefield_core::{Caller, Database, ModuleContext, Problem, ProblemDef, Scope, require_admin};
use cratefield_tables::{Owned, TableDef};
use http::{HeaderMap, StatusCode};
use serde_json::{Value, json};

use crate::access::{Reach, TableApi, may_read};

/// The default page size, and the most a caller may ask for.
///
/// One number for both: a cap that differs from the default is a cap
/// nobody meets until they ask for more, and then meets by surprise.
pub const PAGE: u64 = 50;

/// No table of that name is declared.
pub const NO_SUCH_TABLE: ProblemDef = ProblemDef {
    slug: "no-such-table",
    status: StatusCode::NOT_FOUND,
    title: "No such table",
    description: "This venture declares no table by that name.",
};

/// The row is not there — or is not the caller's, which is deliberately
/// the same answer.
pub const NO_SUCH_ROW: ProblemDef = ProblemDef {
    slug: "no-such-row",
    status: StatusCode::NOT_FOUND,
    title: "No such row",
    description: "No row of this table has that key.",
};

/// The deployment cannot identify a caller for a table that needs one.
pub const NO_VERIFIER: ProblemDef = ProblemDef {
    slug: "no-verifier",
    status: StatusCode::INTERNAL_SERVER_ERROR,
    title: "Cannot identify the caller",
    description: "This table is not public and the deployment wired no way to verify a caller.",
};

/// The credential was presented and could not be checked right now.
pub const VERIFIER_UNAVAILABLE: ProblemDef = ProblemDef {
    slug: "verifier-unavailable",
    status: StatusCode::SERVICE_UNAVAILABLE,
    title: "Cannot check the credential",
    description: "The service that verifies credentials could not answer. Try again shortly.",
};

/// The caller ordered by something this table cannot be ordered by.
pub const BAD_SORT: ProblemDef = ProblemDef {
    slug: "bad-sort",
    status: StatusCode::BAD_REQUEST,
    title: "Not a sort for this table",
    description: "The `sort` parameter names a column the table does not declare, or one whose nulls the engines order differently.",
};

/// The caller narrowed by something this table cannot be narrowed by.
pub const BAD_FILTER: ProblemDef = ProblemDef {
    slug: "bad-filter",
    status: StatusCode::BAD_REQUEST,
    title: "Not a filter for this table",
    description: "A query parameter names a column the table does not declare, or a value that is not that column's kind.",
};

/// A credential was presented and did not verify.
pub const NOT_VERIFIED: ProblemDef = ProblemDef {
    slug: "unauthenticated",
    status: StatusCode::UNAUTHORIZED,
    title: "Not signed in",
    description: "The request carried a credential that did not verify.",
};

/// What the routes are built over.
pub struct Tables {
    /// Every declared table, with its access level and subject column.
    pub tables: Vec<TableApi>,
    /// The composed context, for the `Auth` port and the config.
    pub ctx: Arc<ModuleContext>,
}

impl Tables {
    /// The declared table of that name, if the venture declares one.
    #[must_use]
    pub fn declared(&self, name: &str) -> Option<&TableApi> {
        self.tables.iter().find(|api| api.table.name == name)
    }

    fn find(&self, name: &str) -> Result<&TableApi, Problem> {
        self.tables
            .iter()
            .find(|api| api.table.name == name)
            .ok_or_else(|| Problem::new(&NO_SUCH_TABLE))
    }
}

/// Who is asking, or the refusal to answer at all.
///
/// A credential presented and not verified is a refusal even on a public
/// table, which is the rule the `Auth` port exists to keep (#362): an
/// expired token reading a public table must not succeed quietly and
/// leave its holder believing they are signed in.
pub(crate) async fn who(
    tables: &Tables,
    headers: &HeaderMap,
    api: &TableApi,
) -> Result<Caller, Problem> {
    let Some(auth) = tables.ctx.ports.auth.as_ref() else {
        // A deployment with no verifier can still serve a public table,
        // because nothing about it depends on who is asking. Anything
        // else is a composition that should not have booted — a module
        // serving a non-public table declares `Port::Auth`, and the
        // harness refuses a module whose required port is not provided.
        if api.access == cratefield_manifest::Access::PublicRead {
            return Ok(Caller::Anonymous);
        }
        return Err(Problem::new(&NO_VERIFIER));
    };
    auth.identify(headers).await.map_err(|err| match err {
        cratefield_core::AuthError::NotVerified => Problem::new(&NOT_VERIFIED),
        // A different refusal on purpose: telling a caller to sign in
        // again while the verifier is down is advice they will follow and
        // that will not help.
        cratefield_core::AuthError::Unavailable(_) => Problem::new(&VERIFIER_UNAVAILABLE),
        // `AuthError` is `#[non_exhaustive]`. A refusal this build cannot
        // read is a fact about the deployment, not about the caller's
        // credential, so it answers 503: "try again" asserts nothing
        // false, where "sign in again" would.
        other => {
            tracing::error!(error = %other, "a refusal this build does not understand");
            Problem::new(&VERIFIER_UNAVAILABLE)
        }
    })
}

/// The scope `may_read` decided, as the condition a statement takes.
fn owned<'a>(reach: &'a Reach, subject: &'a Value) -> Option<Owned<'a>> {
    match reach {
        Reach::Everything => None,
        Reach::OwnedBy { column, .. } => Some(Owned { column, subject }),
    }
}

/// The subject a scope matches on, as JSON, so it can be bound.
fn subject_value(reach: &Reach) -> Value {
    match reach {
        Reach::Everything => Value::Null,
        Reach::OwnedBy { subject, .. } => Value::String(subject.clone()),
    }
}

/// What a caller asked a page for.
///
/// A struct because the four of them are one thing — which rows, in what
/// order, from where — and because `page` had grown to eight positional
/// arguments, three of them optional and adjacent. A call site that
/// swapped two would have compiled.
#[derive(Debug, Clone, Copy)]
pub struct Asked<'a> {
    /// The declared table.
    pub table: &'a str,
    /// The cursor from a previous page.
    pub after: Option<&'a Value>,
    /// What to narrow by.
    pub filters: &'a [cratefield_tables::Filter],
    /// What to order by.
    pub sort: Option<cratefield_tables::Sort<'a>>,
}

/// A page of one table.
///
/// # Errors
///
/// The access decision's refusal, or a database or decoding failure.
pub async fn page(
    tables: &Tables,
    conn: &dyn Database,
    headers: &HeaderMap,
    scope: &Scope,
    asked: Asked<'_>,
) -> Result<Value, Problem> {
    let Asked {
        table: name,
        after,
        filters,
        sort,
    } = asked;
    let api = tables.find(name)?;
    let caller = who(tables, headers, api).await?;
    let reach = may_read(
        api,
        &caller,
        require_admin(tables.ctx.config.as_ref(), headers),
    )?;
    let subject = subject_value(&reach);

    let statement = cratefield_tables::select_page(
        &api.table,
        cratefield_tables::Page {
            limit: PAGE,
            after,
            // The scope first, and the filters after: both stand, so a
            // caller filtering on the subject column narrows their own
            // rows and cannot reach anybody else's.
            owned: owned(&reach, &subject),
            filters,
            sort,
        },
    )
    .map_err(|err| bad_page(scope, &err, api, sort))?;
    let rows = conn
        .query(&statement)
        .await
        .map_err(|err| unavailable(scope, &err))?;

    let mut out = Vec::with_capacity(rows.len());
    for row in &rows.rows {
        out.push(cratefield_tables::row_json(&api.table, row).map_err(|err| drifted(scope, &err))?);
    }
    // Only on a full page. A cursor handed back with a short one says
    // "there is more" when there is not, and a client that believes it
    // makes a request whose whole result is learning that.
    let next = if out.len() as u64 == PAGE {
        next_cursor(&api.table, out.last(), sort)
    } else {
        Value::Null
    };
    Ok(json!({ "rows": out, "next": next }))
}

/// One row by primary key.
///
/// # Errors
///
/// [`NO_SUCH_ROW`] when there is no such row **or** it belongs to
/// somebody else — the same answer on purpose, because a distinguishable
/// one confirms a row the caller was never in a position to learn exists.
pub async fn one(
    tables: &Tables,
    conn: &dyn Database,
    headers: &HeaderMap,
    scope: &Scope,
    name: &str,
    key: &Value,
) -> Result<Value, Problem> {
    let api = tables.find(name)?;
    let caller = who(tables, headers, api).await?;
    let reach = may_read(
        api,
        &caller,
        require_admin(tables.ctx.config.as_ref(), headers),
    )?;
    let subject = subject_value(&reach);

    let statement = cratefield_tables::select_one(&api.table, key, owned(&reach, &subject))
        .map_err(|err| misdeclared(scope, &err))?;
    let rows = conn
        .query(&statement)
        .await
        .map_err(|err| unavailable(scope, &err))?;
    let row = rows.first().ok_or_else(|| Problem::new(&NO_SUCH_ROW))?;
    cratefield_tables::row_json(&api.table, row).map_err(|err| drifted(scope, &err))
}

/// The key of the last row on the page, for the next request's cursor.
///
/// The caller decides whether to ask; this only builds it.
fn next_cursor(
    table: &TableDef,
    last: Option<&Value>,
    sort: Option<cratefield_tables::Sort<'_>>,
) -> Value {
    let Some(last) = last else {
        return Value::Null;
    };
    let mut cursor = serde_json::Map::new();
    // The sort column first, because the cursor walks the ordering the
    // page is in. One carrying only the key resumes in key order, which
    // silently reshuffles everything after the first page.
    if let Some(sort) = sort {
        let Some(value) = last.get(sort.column) else {
            return Value::Null;
        };
        cursor.insert(sort.column.to_owned(), value.clone());
    }
    for column in &table.primary_key {
        let Some(value) = last.get(column) else {
            return Value::Null;
        };
        cursor.insert(column.clone(), value.clone());
    }
    Value::Object(cursor)
}

/// A page the caller asked for that this table cannot answer.
///
/// A filter naming a column the table does not have, or a value that is
/// not that column's kind, is the caller's mistake and says so — with the
/// column name, which they sent. A failure that names nothing else is a
/// misdeclaration, and that is ours.
fn bad_page(
    scope: &Scope,
    err: &cratefield_tables::DecodeError,
    api: &TableApi,
    sort: Option<cratefield_tables::Sort<'_>>,
) -> Problem {
    // A refusal about the sort column is a sort problem, whatever else it
    // resembles. Labelling it `bad-filter` would be a slug a client
    // branches on saying the wrong thing about what they sent.
    if sort.is_some_and(|sort| sort.column == err.column) {
        return Problem::new(&BAD_SORT).with_detail(format!("`{}` {}", err.column, err.detail));
    }
    if api
        .table
        .fields
        .iter()
        .any(|field| field.name == err.column)
        || !api.table.primary_key.contains(&err.column)
    {
        return Problem::new(&BAD_FILTER).with_detail(format!("`{}` {}", err.column, err.detail));
    }
    misdeclared(scope, err)
}

/// A statement that could not be built from the declaration.
///
/// The detail is logged and never returned: it names columns, and a
/// caller learning which column a table's subject is would learn part of
/// its shape from an error.
fn misdeclared(scope: &Scope, err: &cratefield_tables::DecodeError) -> Problem {
    tracing::error!(error = %err, "a declared table's read could not be built");
    Problem::new(&crate::access::MISDECLARED).instance(&scope.request_id)
}

/// The database could not answer.
fn unavailable(scope: &Scope, err: &cratefield_core::DbError) -> Problem {
    tracing::error!(error = %err, "a declared table's read failed");
    Problem::internal().instance(&scope.request_id)
}

/// A row that does not match its declaration: the database has drifted.
///
/// A `500`, because the caller did nothing wrong and the answer would be
/// wrong data. `fz tables drift` is the command that says what changed.
fn drifted(scope: &Scope, err: &cratefield_tables::DecodeError) -> Problem {
    tracing::error!(error = %err, "a row does not match the declaration; run `fz tables drift`");
    Problem::internal().instance(&scope.request_id)
}
