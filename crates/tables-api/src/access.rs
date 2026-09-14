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

use cratefield_core::{Caller, Problem, ProblemDef};
use cratefield_manifest::Access;
use cratefield_tables::TableDef;
use http::StatusCode;

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
        Access::Owner => {
            let subject = caller
                .id()
                .ok_or_else(|| Problem::new(&UNAUTHENTICATED))?
                .to_owned();
            // `fz build` refuses a manifest that declares `owner` on a
            // table holding nothing personal, so this is a deployment
            // that did not come from one. Refusing is the only safe
            // answer: with no column to match, "everything" and "nothing"
            // are both wrong and one of them is a leak.
            let column = api
                .subject
                .clone()
                .ok_or_else(|| Problem::new(&MISDECLARED))?;
            if !api.table.fields.iter().any(|field| field.name == column) {
                return Err(Problem::new(&MISDECLARED));
            }
            Ok(Reach::OwnedBy { column, subject })
        }
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
