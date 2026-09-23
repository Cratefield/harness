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
//! the table's access level, decided per request — against the caller's
//! own id, and for `tenant-members` against the request's tenancy
//! first, which refuses the level to everyone where a registry named
//! the tenant (#385). So `owner` and `tenant-members` both publish as
//! [`Audience::Subject`] — a credential is needed either way — and the
//! difference between them is not a fact about the route.
//!
//! A `public-read` table publishes its reads and **not** its writes,
//! because there are none: the level is exactly that.
//!
//! A read publishes what it answers as its output: the row schema for the
//! single row, and for the page an envelope of those rows beside the
//! `next` cursor. It is the same derived schema a write takes as its body,
//! so a consumer of a table it may only read still learns what a row is.
//!
//! Where a table's single-row actions address a row depends on its key's
//! arity, and the published path says which: `/{table}/{key}` puts the
//! key in the path — a key of one column — and `/{table}/__by` puts it in
//! the query, one parameter per primary-key column (ADR 0018). A consumer
//! generating a client can tell the two apart: a `{key}` placeholder in
//! the path is a path parameter, and an input schema on a `GET` or a
//! `DELETE` is the query. A `PUT` takes a body *and* that query; its
//! input stays the body — the row — and the query rides on it as an
//! `x-cf-query` extension. That keyword is introduced by this crate —
//! it is not one of the harness's field hints, and a reader will not
//! find it in `cratefield_core` — riding under the harness's `x-cf-*`
//! namespace, where a consumer that does not know it ignores it the way
//! it ignores every `x-cf-*` keyword it was built before.

use cratefield_core::{Action, Audience, Outcome, Surface};
use cratefield_manifest::Access;
use http::Method;

use crate::access::TableApi;

/// The surface for a venture's declared tables.
///
/// Two actions per readable table — the page and the single row, each
/// publishing the shape it answers with as its output — and three more
/// for a writable one.
#[must_use]
pub fn surface(tables: &[TableApi]) -> Surface {
    let mut out = Surface::new();
    for api in tables {
        let name = &api.table.name;
        let audience = audience(api.access);
        out = out.action(
            Action::new(format!("list-{name}"), Method::GET, format!("/{name}"))
                .audience(audience)
                .outcome(Outcome::Json)
                .output_schema(page_schema(&api.table)),
        );
        // The single-row spelling. A key of one column is a path segment;
        // a wider key is named in the query, at the harness's reserved
        // `__by` sub-path. The route under either spelling answers for
        // what it publishes — `every_published_action_is_a_route_that_exists`
        // is what keeps the two lists the same.
        let by_path = api.table.primary_key.len() == 1;
        let row_path = if by_path {
            format!("/{name}/{{key}}")
        } else {
            format!("/{name}/__by")
        };
        let mut read = Action::new(format!("read-{name}"), Method::GET, row_path.clone())
            .audience(audience)
            .outcome(Outcome::Json)
            .output_schema(body_schema(&api.table));
        if !by_path {
            // The path carries no key, so the query does — and a GET's
            // input is its query, so the published schema is what names
            // the key columns. Without it, a consumer would know the
            // route exists and not what to ask it with.
            read = read.input_schema(by_query_schema(&api.table));
        }
        out = out.action(read);
        if !writable(api.access) {
            continue;
        }
        out = out.action(
            Action::new(format!("create-{name}"), Method::POST, format!("/{name}"))
                .audience(audience)
                .input_schema(body_schema(&api.table))
                .outcome(Outcome::Json),
        );
        out = out.action(
            Action::new(format!("replace-{name}"), Method::PUT, row_path.clone())
                .audience(audience)
                .input_schema(if by_path {
                    body_schema(&api.table)
                } else {
                    // The path carries no key, so the query must — but a
                    // PUT's input is its body, and `input` has one slot.
                    // The body keeps it and the query rides beside it as
                    // `x-cf-query` (see `replace_input`); folding the key
                    // columns into the body's properties instead would
                    // publish a row the route refuses, a `400 partial-key`
                    // the contract itself invited.
                    replace_input(&api.table)
                })
                .outcome(Outcome::Json),
        );
        let mut delete = Action::new(format!("delete-{name}"), Method::DELETE, row_path)
            .audience(audience)
            .outcome(Outcome::Json);
        if !by_path {
            // A delete has no body, so its input is its query — the same
            // schema the read takes.
            delete = delete.input_schema(by_query_schema(&api.table));
        }
        out = out.action(delete);
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

/// The page `list-*` answers with: the rows, each described by the row
/// schema, and `next`, the cursor to send back as `?after=` — `null` on a
/// page that came back short, the last. The rows' schema drops `$schema`,
/// which belongs at the root of a document and not inside one.
fn page_schema(table: &cratefield_tables::TableDef) -> schemars::Schema {
    let mut row = cratefield_tables::json_schema(table);
    if let Some(object) = row.as_object_mut() {
        object.remove("$schema");
    }
    let page = serde_json::json!({
        "type": "object",
        "properties": {
            "rows": { "type": "array", "items": row },
            "next": {
                "type": ["object", "null"],
                "description": "The cursor to send back as `?after=`; null on the last page.",
            },
        },
        "required": ["rows", "next"],
    });
    schemars::Schema::try_from(page).unwrap_or_else(|_never| schemars::Schema::default())
}

/// The `__by` query's JSON Schema: one property per primary-key column,
/// every one of them required, each described exactly as the row schema
/// describes it — the same derived bytes, cut down to the columns the
/// route reads. `additionalProperties: false`, because a query naming a
/// column outside the key is refused, and a published contract looser
/// than the route would be a form that renders inputs the request
/// refuses.
fn by_query_schema(table: &cratefield_tables::TableDef) -> schemars::Schema {
    schemars::Schema::try_from(by_query_value(table))
        .unwrap_or_else(|_never| schemars::Schema::default())
}

/// [`by_query_schema`] as the raw value, so a caller can embed it as a
/// keyword inside another schema without a serialize round-trip.
fn by_query_value(table: &cratefield_tables::TableDef) -> serde_json::Value {
    let row = cratefield_tables::json_schema(table);
    let mut properties = serde_json::Map::new();
    let mut required = Vec::with_capacity(table.primary_key.len());
    for column in &table.primary_key {
        if let Some(property) = row.get("properties").and_then(|props| props.get(column)) {
            properties.insert(column.clone(), property.clone());
        }
        required.push(serde_json::Value::String(column.clone()));
    }
    serde_json::json!({
        "type": "object",
        "properties": serde_json::Value::Object(properties),
        "required": required,
        "additionalProperties": false,
    })
}

/// A composite-key table's `replace` input: the row schema a form renders
/// from, carrying the `__by` query it must also send as an `x-cf-query`
/// extension.
///
/// A PUT is the one single-row action that takes both a body and a query,
/// and an [`Action`] has one `input` slot — the body for a writing
/// method. The row keeps it: folding the key columns into the body's own
/// properties instead would publish a row the route refuses (the key is
/// read from the query and a `400 partial-key` says so), and a contract
/// looser than the route is the failure `/__surface` exists to prevent.
/// So the query rides on the schema as an `x-cf-*` keyword — the channel
/// the harness already defines for facts that ride beside the derived
/// schema, which a consumer built before the keyword ignores, never an
/// error.
fn replace_input(table: &cratefield_tables::TableDef) -> schemars::Schema {
    let mut row = cratefield_tables::json_schema(table);
    if let Some(object) = row.as_object_mut() {
        object.insert("x-cf-query".to_owned(), by_query_value(table));
    }
    schemars::Schema::try_from(row).unwrap_or_else(|_never| schemars::Schema::default())
}
