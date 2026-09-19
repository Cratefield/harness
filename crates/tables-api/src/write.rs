//! Writing a declared table's rows (issue #153).
//!
//! Three: create a row, replace one, delete one. Each goes through
//! [`crate::access::may_write`] first — a separate decision from the read
//! one, because `public-read` reads for everybody and writes for nobody
//! and a single function answering both would need a parameter saying
//! which.
//!
//! # A row a caller writes is a row they own
//!
//! Under `owner` the subject column is settled by the harness rather than
//! taken from the body, so a caller cannot write a row into somebody
//! else's name. See [`crate::access::settle_subject`] for why a body
//! naming a different subject is refused rather than quietly corrected.
//!
//! # Replace, not merge
//!
//! `replace` writes every declared non-key field from the body. A merge
//! would make "unset this field" unexpressible: an absent key and a null
//! one would both have to mean "leave it".
//!
//! # A conflict, and whose it is
//!
//! A unique violation on create says *a* row holds the values already;
//! under `owner` whose row it is decides what may be said about it. The
//! caller's own row is a conflict they can act on, and 409 says so. A
//! row belonging to somebody else is answered like any other rejected
//! write: a 409 would confirm a row the reads refuse to confirm, which
//! is why they answer 404 for one. See this module's `taken`.

use cratefield_core::{Caller, Database, Problem, ProblemDef, Scope, Tenancy, require_admin};
use cratefield_tables::{Owned, TableDef, UpdateError};
use http::{HeaderMap, StatusCode};
use serde_json::{Map, Value};

use crate::access::{Reach, may_write, settle_subject};
use crate::read::{NO_SUCH_ROW, Tables, who};

/// The body was not a legal row for this table.
pub const NOT_A_ROW: ProblemDef = ProblemDef {
    slug: "validation-failed",
    status: StatusCode::UNPROCESSABLE_ENTITY,
    title: "Not a row of this table",
    description: "The body does not match the table's declared columns.",
};

/// A row with that key already exists.
pub const ALREADY_EXISTS: ProblemDef = ProblemDef {
    slug: "already-exists",
    status: StatusCode::CONFLICT,
    title: "That key is taken",
    description: "A row of this table already has that primary key.",
};

/// The decision and the scope for a write, shared by all three.
async fn permit(
    tables: &Tables,
    tenancy: Tenancy,
    headers: &HeaderMap,
    name: &str,
) -> Result<(crate::access::TableApi, Reach), Problem> {
    let api = tables.declared(name).cloned().ok_or_else(|| {
        // The same 404 a read gives for a table nobody declared: a
        // distinguishable answer would say which names exist.
        Problem::new(&crate::read::NO_SUCH_TABLE)
    })?;
    let caller: Caller = who(tables, headers, &api).await?;
    let reach = may_write(
        &api,
        tenancy,
        &caller,
        require_admin(tables.ctx.config.as_ref(), headers),
    )?;
    Ok((api, reach))
}

/// The scope as the condition a statement takes.
fn owned<'a>(reach: &'a Reach, subject: &'a Value) -> Option<Owned<'a>> {
    match reach {
        Reach::Everything => None,
        Reach::OwnedBy { column, .. } => Some(Owned { column, subject }),
    }
}

fn subject_value(reach: &Reach) -> Value {
    match reach {
        Reach::Everything => Value::Null,
        Reach::OwnedBy { subject, .. } => Value::String(subject.clone()),
    }
}

/// Creates one row.
///
/// # Errors
///
/// The access decision's refusal, [`NOT_A_ROW`] when the body is not a
/// legal row, [`ALREADY_EXISTS`] when the key collides with a row the
/// caller may be told about — under `owner`, their own — the ordinary
/// rejection when it collides with one they may not, or a database
/// failure.
pub async fn create(
    tables: &Tables,
    conn: &dyn Database,
    tenancy: Tenancy,
    headers: &HeaderMap,
    scope: &Scope,
    name: &str,
    body: Value,
) -> Result<Value, Problem> {
    let (api, reach) = permit(tables, tenancy, headers, name).await?;
    let mut row = body;
    settle_subject(&reach, &mut row)?;

    let statement = cratefield_tables::insert(&api.table, &row)
        .map_err(|errors| Problem::new(&NOT_A_ROW).with_detail(errors.detail()))?;
    match conn.execute(&statement).await {
        Ok(_) => Ok(row),
        // A unique violation is *a* row holding the values already;
        // whose row it is decides the answer, and deciding takes a
        // re-select (`taken`). Anything else is ours. The adapters do
        // not give a typed constraint error, so this reads the message —
        // and answers the generic failure when it cannot tell, rather
        // than claiming a conflict it has not established.
        Err(err) if looks_like_a_conflict(&err) => {
            Err(taken(conn, &api, &reach, &row, scope).await)
        }
        Err(err) => {
            tracing::error!(error = %err, "a declared table's insert failed");
            Err(Problem::internal().instance(&scope.request_id))
        }
    }
}

/// What a collision on insert means, under the reach the write was
/// permitted with.
///
/// A unique violation establishes that a row holds the values already;
/// whose row it is decides what may be said about it. Where the reach is
/// not the caller's own rows, every row is theirs to collide with, and
/// [`ALREADY_EXISTS`] is the whole answer.
///
/// Under [`Reach::OwnedBy`] it is not. A 409 for a collision with a row
/// belonging to somebody else would confirm a row the caller was never
/// in a position to learn exists — the fact the reads refuse to confirm
/// by answering 404 for a row that is not there *or* not theirs
/// ([`crate::read::one`]). So the conflicting row is selected again with
/// the owner predicate applied — `select_one`, the statement a read by
/// key takes, built from the same `owned` scope the writes already
/// thread through, so the two cannot drift — and 409 is answered only
/// when that select matches: the caller's own row is the collision, and
/// the conflict is theirs to fix.
///
/// Every other outcome declines to assert a conflict nothing selected.
/// A key the row does not carry, so the select cannot even be built (a
/// collision on a column `unique` beyond the key lands here, and the
/// own-row 409 it gives up is the price of never claiming one), answers
/// [`NOT_A_ROW`]; so does a select that built and matched nothing — the
/// ordinary rejection of a write, which says this write did not happen
/// and nothing about the table. A select that will not build is a
/// declaration the serving code did not expect, and a database that
/// would not answer it is down; both are 500s, logged where constructed
/// as every other failure to reach the database here is.
///
/// The re-select runs on both sides of the answer, so an own-row
/// conflict and somebody else's do the same work and are told apart
/// only by the answer each earned.
async fn taken(
    conn: &dyn Database,
    api: &crate::access::TableApi,
    reach: &Reach,
    row: &Value,
    scope: &Scope,
) -> Problem {
    let subject = subject_value(reach);
    let Some(owned_rows) = owned(reach, &subject) else {
        return Problem::new(&ALREADY_EXISTS);
    };
    let Some(key) = key_of(&api.table, row) else {
        return Problem::new(&NOT_A_ROW);
    };
    let statement = match cratefield_tables::select_one(&api.table, &key, Some(owned_rows)) {
        Ok(statement) => statement,
        // The subject column was checked when the reach was decided (in
        // `access`), so this is not a refusal about the caller.
        Err(err) => {
            tracing::error!(
                error = %err,
                "a declared table's conflict re-select could not be built"
            );
            return Problem::new(&crate::access::MISDECLARED).instance(&scope.request_id);
        }
    };
    match conn.query(&statement).await {
        // The row the key selects is the caller's own: the conflict is
        // real, and the key is theirs to pick again.
        Ok(rows) if !rows.is_empty() => Problem::new(&ALREADY_EXISTS),
        // Nothing of theirs holds the key, so the collision is with a
        // row the caller may not be told about — or, on a second look,
        // with nothing at all. The ordinary rejection says the same
        // thing about both.
        Ok(_) => Problem::new(&NOT_A_ROW),
        Err(err) => {
            tracing::error!(error = %err, "a declared table's conflict re-select failed");
            Problem::internal().instance(&scope.request_id)
        }
    }
}

/// The row's own primary key, as the JSON `select_one` takes it — or
/// `None` when the row does not carry every key column, and no select
/// could be built from it. A null counts as not carried: a key column
/// is `NOT NULL`, so a null key never collided and says nothing about
/// the row that did.
fn key_of(table: &TableDef, row: &Value) -> Option<Value> {
    let mut key = Map::new();
    for column in &table.primary_key {
        let value = row.get(column)?;
        if value.is_null() {
            return None;
        }
        key.insert(column.clone(), value.clone());
    }
    Some(Value::Object(key))
}

/// Whether a database error is a primary-key or unique collision.
///
/// Message matching, which is why it is written down rather than inlined:
/// the `Database` port has no typed constraint error, so the two engines'
/// own phrases are what there is — SQLite and D1 say `UNIQUE constraint
/// failed`, Postgres says `duplicate key value violates unique
/// constraint`.
///
/// **The phrases, not the word.** Matching a bare `unique` matched the
/// table's *name* too: a venture may declare a table called
/// `unique_codes`, and then `no such table: unique_codes` — the shape of
/// a half-applied migration — came back as `409 already-exists`. The
/// caller is told the key is taken, tries another, and is told the same;
/// the real failure never appears, because the conflict branch does not
/// log. Both phrases contain a space, which a declared name cannot.
///
/// A message that matches neither falls through to the generic failure,
/// which is the safe direction: a 500 where a 409 was due costs a
/// retry, and a 409 that did not happen sends a caller looking for a row
/// that is not there.
fn looks_like_a_conflict(err: &cratefield_core::DbError) -> bool {
    let text = format!("{err:?}").to_ascii_lowercase();
    text.contains("unique constraint failed") || text.contains("violates unique constraint")
}

/// Replaces one row, by key.
///
/// # Errors
///
/// The access decision's refusal, [`NOT_A_ROW`], [`NO_SUCH_ROW`] when
/// nothing was changed — which under `owner` also covers a row belonging
/// to somebody else — or a database failure.
// One over the lint's seven: the tenancy arrived and every argument
// earns its place. Folding the rest into a struct to hide the count
// would trade a visible signature for a `Asked`-style one nobody asked
// for — `page` earned that struct; this grew by one parameter, once.
#[allow(clippy::too_many_arguments)]
pub async fn replace(
    tables: &Tables,
    conn: &dyn Database,
    tenancy: Tenancy,
    headers: &HeaderMap,
    scope: &Scope,
    name: &str,
    key: &Value,
    body: Value,
) -> Result<Value, Problem> {
    let (api, reach) = permit(tables, tenancy, headers, name).await?;
    let mut row = body;
    settle_subject(&reach, &mut row)?;
    let subject = subject_value(&reach);

    let statement = cratefield_tables::update(&api.table, key, &row, owned(&reach, &subject))
        .map_err(|err| match err {
            UpdateError::Row(errors) => Problem::new(&NOT_A_ROW).with_detail(errors.detail()),
            UpdateError::Key(err) => {
                tracing::error!(error = %err, "a declared table's update could not be built");
                Problem::new(&crate::access::MISDECLARED).instance(&scope.request_id)
            }
            // `UpdateError` is `#[non_exhaustive]`. A refusal this build
            // cannot read is not one it can attribute to the caller, so
            // it does not: 500, with the reason in the log.
            other => {
                tracing::error!(error = %other, "a refusal this build does not understand");
                Problem::internal().instance(&scope.request_id)
            }
        })?;
    let changed = conn.execute(&statement).await.map_err(|err| {
        tracing::error!(error = %err, "a declared table's update failed");
        Problem::internal().instance(&scope.request_id)
    })?;
    if changed == 0 {
        // No row, or not this caller's row. The same answer on purpose:
        // a distinguishable one confirms a row they were never in a
        // position to learn exists.
        return Err(Problem::new(&NO_SUCH_ROW));
    }
    Ok(row)
}

/// Deletes one row, by key.
///
/// # Errors
///
/// The access decision's refusal, [`NO_SUCH_ROW`] when nothing was
/// deleted, or a database failure.
pub async fn remove(
    tables: &Tables,
    conn: &dyn Database,
    tenancy: Tenancy,
    headers: &HeaderMap,
    scope: &Scope,
    name: &str,
    key: &Value,
) -> Result<(), Problem> {
    let (api, reach) = permit(tables, tenancy, headers, name).await?;
    let subject = subject_value(&reach);

    let statement =
        cratefield_tables::delete(&api.table, key, owned(&reach, &subject)).map_err(|err| {
            tracing::error!(error = %err, "a declared table's delete could not be built");
            Problem::new(&crate::access::MISDECLARED).instance(&scope.request_id)
        })?;
    let removed = conn.execute(&statement).await.map_err(|err| {
        tracing::error!(error = %err, "a declared table's delete failed");
        Problem::internal().instance(&scope.request_id)
    })?;
    if removed == 0 {
        return Err(Problem::new(&NO_SUCH_ROW));
    }
    Ok(())
}
