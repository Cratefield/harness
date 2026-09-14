//! What a venture publishes about the tables it declares (issue #153).
//!
//! `/__surface` is the machine-readable list of a venture's actions — what
//! a generated UI renders forms from, and what the control-plane
//! dashboard lists. A declared table that is served and absent from it is
//! a venture whose published contract is smaller than the venture.
//!
//! # What a surface can and cannot say
//!
//! It says a route exists, what it takes, and whether a credential is
//! needed. It does **not** say which rows the caller will get: that is
//! the table's access level, decided per request against the caller's own
//! id. So `owner` and `tenant-members` both publish as
//! [`Audience::Subject`] — a credential is needed either way — and the
//! difference between them is not a fact about the route.
//!
//! A `public-read` table publishes its reads and **not** its writes,
//! because there are none: the level is exactly that.

use cratefield_core::{Action, Audience, Outcome, Surface};
use cratefield_manifest::Access;
use http::Method;

use crate::access::TableApi;

/// The surface for a venture's declared tables.
///
/// Two actions per readable table — the page and the single row — and
/// three more for a writable one.
#[must_use]
pub fn surface(tables: &[TableApi]) -> Surface {
    let mut out = Surface::new();
    for api in tables {
        let name = &api.table.name;
        let audience = audience(api.access);
        out = out
            .action(
                Action::new(format!("list-{name}"), Method::GET, format!("/{name}"))
                    .audience(audience)
                    .outcome(Outcome::Json),
            )
            .action(
                Action::new(
                    format!("read-{name}"),
                    Method::GET,
                    format!("/{name}/{{key}}"),
                )
                .audience(audience)
                .outcome(Outcome::Json),
            );
        if !writable(api.access) {
            continue;
        }
        out = out
            .action(
                Action::new(format!("create-{name}"), Method::POST, format!("/{name}"))
                    .audience(audience)
                    .input_schema(body_schema(&api.table))
                    .outcome(Outcome::Json),
            )
            .action(
                Action::new(
                    format!("replace-{name}"),
                    Method::PUT,
                    format!("/{name}/{{key}}"),
                )
                .audience(audience)
                .input_schema(body_schema(&api.table))
                .outcome(Outcome::Json),
            )
            .action(
                Action::new(
                    format!("delete-{name}"),
                    Method::DELETE,
                    format!("/{name}/{{key}}"),
                )
                .audience(audience)
                .outcome(Outcome::Json),
            );
    }
    out
}

/// The audience a level publishes as.
///
/// `owner` and `tenant-members` are both [`Audience::Subject`]: a surface
/// says a credential is needed, not which rows it opens.
fn audience(access: Access) -> Audience {
    match access {
        Access::PublicRead => Audience::Public,
        Access::Admin => Audience::Admin,
        // `Owner` and `TenantMembers` need a credential and differ only
        // in which rows it opens, which a surface does not say. A level
        // this build does not know joins them for a different reason: a
        // surface that guessed `Public` would advertise a form for
        // something it cannot describe, so the safe guess is that it asks
        // who you are.
        Access::Owner | Access::TenantMembers | _ => Audience::Subject,
    }
}

/// Whether the level admits writes at all.
///
/// `public-read` does not, which is the whole level — so it publishes its
/// reads and nothing else, rather than publishing a create a caller would
/// always be refused.
fn writable(access: Access) -> bool {
    !matches!(access, Access::PublicRead)
}

/// The declared table's JSON Schema, as `schemars` holds one.
///
/// `cratefield_tables::json_schema` answers a `serde_json::Value` — it is
/// the contract a second implementation reads, and it predates anything
/// `schemars`. A surface carries `schemars::Schema`, which wraps a
/// `Value`, so this is a rewrap rather than a translation: the published
/// schema and the one the row validator enforces are the same bytes.
fn body_schema(table: &cratefield_tables::TableDef) -> schemars::Schema {
    schemars::Schema::try_from(cratefield_tables::json_schema(table))
        .unwrap_or_else(|_never| schemars::Schema::default())
}
