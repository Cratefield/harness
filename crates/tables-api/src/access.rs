//! Who may reach a declared table's rows, and which of them (issue #153).
//!
//! The manifest declares an access level per table (#359) and the harness
//! can now identify a caller (#362). This is the decision between them,
//! and it is kept apart from the handlers on purpose: it is the part that
//! decides who sees whose rows, it has no HTTP in it, and every case can
//! be stated as a value rather than as a request.
//!
//! # Refusals say as little as possible
//!
//! Under `owner`, a row belonging to somebody else is **not found**, not
//! forbidden. A `403` is an answer about a row the caller was told
//! exists, which is a fact they had no way to learn. The design produces
//! that answer by construction rather than by remembering to: the
//! subject filter is part of the same `WHERE` as the key, so the row
//! simply does not match.
//!
//! # `tenant-members` checks that a caller is verified, not that they are
//! a member
//!
//! There is no membership fact to check. A [`Caller`] is an id, a session
//! and an address; `Ports::tenants` is not a [`Port`](cratefield_core::Port)
//! and `view_for` never copies it, so a module cannot ask which tenant it
//! is serving either. The level therefore admits every subject the
//! deployment's one verifier accepts.
//!
//! Where declared tables run today that is the same set: a venture `fz
//! build` generates has no tenant registry, so it has one tenant and every
//! verified subject is a member of it. It stops being the same set on a
//! deployment with a registry, where the tenant comes from the `Host`
//! header and the verifier does not — issue #385.

use cratefield_core::{Caller, Problem, ProblemDef};
use cratefield_manifest::Access;
use cratefield_tables::TableDef;
use http::StatusCode;
use serde_json::Value;

/// A caller presented no credential where one is required.
pub const UNAUTHENTICATED: ProblemDef = ProblemDef {
    slug: "unauthenticated",
    status: StatusCode::UNAUTHORIZED,
    title: "Not signed in",
    description: "This table is not public; the request carried no verified credential.",
};

/// A caller is signed in and still may not reach this table.
pub const FORBIDDEN: ProblemDef = ProblemDef {
    slug: "table-forbidden",
    status: StatusCode::FORBIDDEN,
    title: "Not yours to reach",
    description: "The table's declared access level does not admit this caller.",
};

/// The declaration names a subject column the table does not have, or
/// none at all.
///
/// A manifest that would do this is refused by `fz build`
/// (`cratefield_manifest::access::validate`), so reaching this means a
/// deployment is running a composition its manifest would not produce.
/// It is a `500` and not a `403`: nothing the caller did is wrong.
pub const MISDECLARED: ProblemDef = ProblemDef {
    slug: "table-misdeclared",
    status: StatusCode::INTERNAL_SERVER_ERROR,
    title: "Table declaration cannot be enforced",
    description: "The table declares owner access without a subject column to match a caller against.",
};

/// One declared table, with everything a request needs to decide about it.
#[derive(Debug, Clone)]
pub struct TableApi {
    /// The columns, key and constraints the manifest declared.
    pub table: TableDef,
    /// Who may reach it.
    pub access: Access,
    /// The column naming whose each row is, from the table's privacy
    /// declaration. `Some` exactly when that declaration is `personal`.
    pub subject: Option<String>,
}

/// How much of a table this request reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reach {
    /// Every row.
    Everything,
    /// Only rows whose `column` holds `subject`.
    OwnedBy {
        /// The table's subject column.
        column: String,
        /// The caller's own id.
        subject: String,
    },
}

/// Whether this caller may read this table, and which rows.
///
/// `admin` is the outcome of `cratefield_core::require_admin`, passed in
/// rather than computed here so the decision stays a function of values.
/// Its own refusal is propagated unchanged: it distinguishes "admin
/// endpoints are disabled or you sent no token" from "the token is
/// wrong", and re-deciding that here would lose the difference.
///
/// # Errors
///
/// [`UNAUTHENTICATED`] when the level needs a signed-in caller and there
/// is none, the admin check's own problem for `admin`, and
/// [`MISDECLARED`] when `owner` has no subject column to match against.
pub fn may_read(
    api: &TableApi,
    caller: &Caller,
    admin: Result<(), Problem>,
) -> Result<Reach, Problem> {
    match api.access {
        // The one level an anonymous caller reaches. Writes are a
        // separate decision and this function does not grant them.
        Access::PublicRead => Ok(Reach::Everything),
        Access::TenantMembers => {
            caller.id().ok_or_else(|| Problem::new(&UNAUTHENTICATED))?;
            Ok(Reach::Everything)
        }
        // `fz build` refuses a manifest that declares `owner` on a table
        // holding nothing personal, so a missing subject column is a
        // deployment that did not come from one. Refusing is the only
        // safe answer: with no column to match, "everything" and
        // "nothing" are both wrong and one of them is a leak.
        Access::Owner => owner_scope(api, caller),
        Access::Admin => {
            admin?;
            Ok(Reach::Everything)
        }
        // `Access` is `#[non_exhaustive]`, so a level added later has to
        // arrive here rather than fall into one of the four above. The
        // safe answer for a level this build does not understand is no.
        _ => Err(Problem::new(&FORBIDDEN)),
    }
}

/// A table nobody may write through this API.
pub const READ_ONLY: ProblemDef = ProblemDef {
    slug: "table-read-only",
    status: StatusCode::FORBIDDEN,
    title: "Not writable",
    description: "This table's declared access is public-read: it is served, never written.",
};

/// A write that would give a row to somebody other than its writer.
pub const NOT_YOURS_TO_GIVE: ProblemDef = ProblemDef {
    slug: "not-yours-to-give",
    status: StatusCode::FORBIDDEN,
    title: "That row would not be yours",
    description: "The subject column names a different caller; a row written here is your own.",
};

/// Whether this caller may write this table, and which rows.
///
/// The same shape as [`may_read`] and deliberately a separate function:
/// `public-read` reads for everybody and writes for nobody, so one
/// function answering both would need a parameter saying which — and the
/// day somebody passes the wrong one, a public table becomes writable.
///
/// # Errors
///
/// [`READ_ONLY`] for `public-read`, [`UNAUTHENTICATED`] when the level
/// needs a signed-in caller and there is none, the admin check's own
/// problem for `admin`, and [`MISDECLARED`] when `owner` has no subject
/// column to match against.
pub fn may_write(
    api: &TableApi,
    caller: &Caller,
    admin: Result<(), Problem>,
) -> Result<Reach, Problem> {
    match api.access {
        // Read by everybody, written by nobody. A venture that wants
        // public rows written has not declared `public-read`.
        Access::PublicRead => Err(Problem::new(&READ_ONLY)),
        Access::TenantMembers => {
            caller.id().ok_or_else(|| Problem::new(&UNAUTHENTICATED))?;
            Ok(Reach::Everything)
        }
        Access::Owner => owner_scope(api, caller),
        Access::Admin => {
            admin?;
            Ok(Reach::Everything)
        }
        _ => Err(Problem::new(&FORBIDDEN)),
    }
}

/// The `owner` scope, shared by reads and writes because getting it
/// right twice is how the two drift apart.
fn owner_scope(api: &TableApi, caller: &Caller) -> Result<Reach, Problem> {
    let subject = caller
        .id()
        .ok_or_else(|| Problem::new(&UNAUTHENTICATED))?
        .to_owned();
    let column = api
        .subject
        .clone()
        .ok_or_else(|| Problem::new(&MISDECLARED))?;
    // The column has to exist and it has to be able to hold a caller's
    // id. Without the second, a subject column declared `integer` binds
    // nothing and the read fails further down while its statement is
    // built — which answered `400 bad-filter` naming the subject column,
    // blaming the caller for a filter they never sent and telling them
    // part of the table's shape. `fz build` refuses such a declaration;
    // this is the same rule where the serving happens.
    let holds_a_subject = api
        .table
        .fields
        .iter()
        .find(|field| field.name == column)
        .is_some_and(|field| field.kind.can_hold_a_subject());
    if !holds_a_subject {
        return Err(Problem::new(&MISDECLARED));
    }
    Ok(Reach::OwnedBy { column, subject })
}

/// Settles the subject column of a row about to be written.
///
/// Under [`Reach::OwnedBy`] the harness sets it, not the caller:
///
/// - absent, or null, and it is filled in with the caller's own id;
/// - already the caller's, and it is left alone;
/// - somebody else's, and the write is refused.
///
/// The third is the one worth arguing about. Overwriting silently would
/// be safe — the row would still be the caller's — but the client asked
/// for something and got something else without being told, which is how
/// a bug in a client becomes data nobody can explain. Refusing says what
/// happened.
///
/// # Errors
///
/// [`NOT_YOURS_TO_GIVE`] when the row names a different subject.
pub fn settle_subject(reach: &Reach, row: &mut Value) -> Result<(), Problem> {
    let Reach::OwnedBy { column, subject } = reach else {
        return Ok(());
    };
    let Some(object) = row.as_object_mut() else {
        // Not an object: the row validator refuses it with a message
        // about that, which is the more useful one.
        return Ok(());
    };
    match object.get(column) {
        None | Some(Value::Null) => {
            object.insert(column.clone(), Value::String(subject.clone()));
            Ok(())
        }
        Some(Value::String(named)) if named == subject => Ok(()),
        Some(_) => Err(Problem::new(&NOT_YOURS_TO_GIVE)),
    }
}
