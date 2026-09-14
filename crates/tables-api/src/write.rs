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

use cratefield_core::{Caller, Database, Problem, ProblemDef, Scope, require_admin};
use cratefield_tables::{Owned, UpdateError};
use http::{HeaderMap, StatusCode};
use serde_json::Value;

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
/// legal row, [`ALREADY_EXISTS`] when the key is taken, or a database
/// failure.
pub async fn create(
    tables: &Tables,
    conn: &dyn Database,
    headers: &HeaderMap,
    scope: &Scope,
    name: &str,
    body: Value,
) -> Result<Value, Problem> {
    let (api, reach) = permit(tables, headers, name).await?;
    let mut row = body;
    settle_subject(&reach, &mut row)?;

    let statement = cratefield_tables::insert(&api.table, &row)
        .map_err(|errors| Problem::new(&NOT_A_ROW).with_detail(errors.detail()))?;
    match conn.execute(&statement).await {
        Ok(_) => Ok(row),
        // A unique violation is the key being taken, which is the
        // caller's to fix; anything else is ours. The adapters do not
        // give a typed constraint error, so this reads the message —
        // and answers the generic failure when it cannot tell, rather
        // than claiming a conflict it has not established.
        Err(err) if looks_like_a_conflict(&err) => Err(Problem::new(&ALREADY_EXISTS)),
        Err(err) => {
            tracing::error!(error = %err, "a declared table's insert failed");
            Err(Problem::internal().instance(&scope.request_id))
        }
    }
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
pub async fn replace(
    tables: &Tables,
    conn: &dyn Database,
    headers: &HeaderMap,
    scope: &Scope,
    name: &str,
    key: &Value,
    body: Value,
) -> Result<Value, Problem> {
    let (api, reach) = permit(tables, headers, name).await?;
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
    headers: &HeaderMap,
    scope: &Scope,
    name: &str,
    key: &Value,
) -> Result<(), Problem> {
    let (api, reach) = permit(tables, headers, name).await?;
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
