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
async fn who(tables: &Tables, headers: &HeaderMap, api: &TableApi) -> Result<Caller, Problem> {
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
    name: &str,
    after: Option<&Value>,
) -> Result<Value, Problem> {
    let api = tables.find(name)?;
    let caller = who(tables, headers, api).await?;
    let reach = may_read(
        api,
        &caller,
        require_admin(tables.ctx.config.as_ref(), headers),
    )?;
    let subject = subject_value(&reach);

    let statement =
        cratefield_tables::select_page(&api.table, PAGE, after, owned(&reach, &subject))
            .map_err(|err| misdeclared(scope, &err))?;
    let rows = conn
        .query(&statement)
        .await
        .map_err(|err| unavailable(scope, &err))?;

    let mut out = Vec::with_capacity(rows.len());
    for row in &rows.rows {
        out.push(cratefield_tables::row_json(&api.table, row).map_err(|err| drifted(scope, &err))?);
    }
    let next = next_cursor(&api.table, out.last());
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
fn next_cursor(table: &TableDef, last: Option<&Value>) -> Value {
    let Some(last) = last else {
        return Value::Null;
    };
    let mut cursor = serde_json::Map::new();
    for column in &table.primary_key {
        let Some(value) = last.get(column) else {
            return Value::Null;
        };
        cursor.insert(column.clone(), value.clone());
    }
    Value::Object(cursor)
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
