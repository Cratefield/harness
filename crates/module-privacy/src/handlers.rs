//! The two read-only routes, and the statement builder they share.

use axum::extract::{Query, State};
use axum::routing::get;
use cratefield_core::{
    CatalogEntry, Disposition, Json, ModuleContext, Problem, Scope, Statement, is_plain_identifier,
    require_admin,
};
use http::HeaderMap;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::sync::Arc;

/// The most rows one table may contribute to a single export.
///
/// An export is one response, and a subject with a pathological number of rows
/// would otherwise build a body no runtime will send and no phone will parse.
/// Truncation is reported per table rather than silently: an export that
/// quietly stopped early is worse than one that says it did, because the reader
/// is checking whether anything is missing.
const MAX_ROWS_PER_TABLE: usize = 10_000;

#[derive(Clone)]
struct PrivacyState {
    ctx: Arc<ModuleContext>,
}

pub(crate) fn router(ctx: Arc<ModuleContext>) -> axum::Router {
    let state = PrivacyState { ctx };
    axum::Router::new()
        .route("/manifest", get(manifest))
        .route("/export", get(export))
        .with_state(state)
}

/// `GET /v1/privacy/manifest` — what this deployment holds, per table.
///
/// Unauthenticated on purpose. It describes the deployment rather than any
/// person, it is exactly what a privacy page needs to render, and a privacy
/// disclosure behind a login is not a disclosure.
async fn manifest(State(state): State<PrivacyState>) -> Json<Value> {
    let catalog = &state.ctx.personal_data;
    let mut holds = Vec::new();
    let mut not_personal = Vec::new();

    for entry in catalog.entries() {
        if entry.set.is_none() {
            let reason = match entry.set.disposition {
                Disposition::Retain(reason) => reason,
                _ => "",
            };
            not_personal.push(json!({
                "module": entry.module,
                "table": entry.set.table,
                "reason": reason,
            }));
            continue;
        }
        holds.push(json!({
            "module": entry.module,
            "table": entry.set.table,
            "kind": entry.set.kind.as_str(),
            "description": entry.set.description,
            "on_erasure": erasure_json(entry.set.disposition),
        }));
    }

    Json(json!({
        "holds": holds,
        "not_personal": not_personal,
        // A deployment that holds nothing says so in one field, rather than
        // leaving a reader to infer it from an empty list that might equally
        // mean nobody declared anything.
        "holds_personal_data": !catalog.is_empty(),
    }))
}

fn erasure_json(disposition: Disposition) -> Value {
    match disposition {
        Disposition::Erase => json!({ "action": "erase" }),
        Disposition::Anonymise(columns) => json!({
            "action": "anonymise",
            "columns": columns,
        }),
        Disposition::Retain(reason) => json!({
            "action": "retain",
            "reason": reason,
        }),
        // `Disposition` is non_exhaustive. A variant added to core after this
        // module was built must not be rendered as one of the three above: a
        // reader deciding whether to trust an erasure needs "this deployment
        // does something this page cannot describe" rather than a confident
        // wrong answer.
        _ => json!({ "action": "unknown" }),
    }
}

#[derive(Deserialize)]
struct ExportQuery {
    subject: String,
}

/// `GET /v1/privacy/export?subject=<id>` — every row every module holds for one
/// subject.
///
/// Admin-guarded: it returns somebody's data, and the module has no way to know
/// whether the caller is that somebody. A venture putting this behind a
/// member-facing "download my data" button is expected to check the session
/// itself and call this with the authenticated subject, which is the same shape
/// every other admin route here has.
async fn export(
    State(state): State<PrivacyState>,
    scope: Scope,
    headers: HeaderMap,
    Query(query): Query<ExportQuery>,
) -> Result<Json<Value>, Problem> {
    require_admin(&*state.ctx.config, &headers)
        .map_err(|problem| problem.instance(&scope.request_id))?;

    let subject = query.subject.trim();
    if subject.is_empty() {
        return Err(
            Problem::validation_failed("subject must not be empty").instance(&scope.request_id)
        );
    }

    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(Problem::internal().instance(&scope.request_id));
    };

    let mut tables = Vec::new();
    for entry in state.ctx.personal_data.subject_sets() {
        // Unreachable through `HarnessBuilder::build`, which refuses a
        // declaration whose names are not plain identifiers. Re-checked rather
        // than assumed: the cost of being wrong is a generated statement that
        // means something else.
        let Some(statement) = select_for(entry, subject) else {
            tracing::error!(
                table = entry.set.table,
                "a personal-data declaration is not safe to query"
            );
            return Err(Problem::internal().instance(&scope.request_id));
        };

        let rows = match db.query(&statement).await {
            Ok(rows) => rows,
            Err(err) => {
                tracing::error!(table = entry.set.table, error = %err, "privacy export query failed");
                return Err(Problem::internal().instance(&scope.request_id));
            }
        };

        let truncated = rows.rows.len() > MAX_ROWS_PER_TABLE;
        let taken: Vec<Value> = rows
            .rows
            .iter()
            .take(MAX_ROWS_PER_TABLE)
            .map(row_to_json)
            .collect();

        tables.push(json!({
            "module": entry.module,
            "table": entry.set.table,
            "kind": entry.set.kind.as_str(),
            "description": entry.set.description,
            "rows": taken,
            "truncated": truncated,
        }));
    }

    Ok(Json(json!({
        "subject": subject,
        "tables": tables,
    })))
}

/// `SELECT * FROM <table> WHERE <subject> = ?`, or `None` when either name is
/// not a plain identifier.
///
/// The subject value is bound, never interpolated. The two names are
/// interpolated because SQL has no parameter form for an identifier — which is
/// exactly why they are constrained at declaration and re-checked here.
fn select_for(entry: &CatalogEntry, subject: &str) -> Option<Statement> {
    if !is_plain_identifier(entry.set.table) || !is_plain_identifier(entry.set.subject) {
        return None;
    }
    Some(Statement::with_values(
        format!(
            "SELECT * FROM {} WHERE {} = ? LIMIT {}",
            entry.set.table,
            entry.set.subject,
            MAX_ROWS_PER_TABLE + 1
        ),
        vec![subject.into()],
    ))
}

fn row_to_json(row: &cratefield_core::Row) -> Value {
    let mut object = Map::new();
    for (column, value) in row.columns() {
        object.insert(column.to_owned(), value_to_json(value));
    }
    Value::Object(object)
}

/// A sea-query value as JSON.
///
/// Deliberately plain rather than clever. An export is read by a person and by
/// whatever tool they hand it to, so numbers stay numbers and text stays text;
/// a blob is reported by its length rather than base64, because a subject
/// access request is answered honestly by "we hold 41 KB of something here"
/// and is not improved by inlining it into a document somebody has to scroll.
/// Anything this does not recognise is rendered by its `Debug` form and marked,
/// which is the honest alternative to a `null` that would read as "we hold
/// nothing there".
fn value_to_json(value: &sea_query::Value) -> Value {
    use sea_query::Value as V;
    match value {
        V::Bool(Some(b)) => json!(b),
        V::TinyInt(Some(n)) => json!(n),
        V::SmallInt(Some(n)) => json!(n),
        V::Int(Some(n)) => json!(n),
        V::BigInt(Some(n)) => json!(n),
        V::TinyUnsigned(Some(n)) => json!(n),
        V::SmallUnsigned(Some(n)) => json!(n),
        V::Unsigned(Some(n)) => json!(n),
        V::BigUnsigned(Some(n)) => json!(n),
        V::Float(Some(n)) => json!(n),
        V::Double(Some(n)) => json!(n),
        V::String(Some(text)) => json!(text.as_str()),
        V::Char(Some(c)) => json!(c.to_string()),
        V::Bytes(Some(bytes)) => json!({ "bytes": bytes.len() }),
        other if is_null(other) => Value::Null,
        other => json!({ "unrendered": format!("{other:?}") }),
    }
}

/// Whether a sea-query value is the `None` of its variant.
///
/// Matched by rendering rather than by listing every variant: the enum is
/// feature-gated (dates, decimals, uuids appear with features this crate does
/// not enable), so an exhaustive match here would break the day somebody turns
/// one on, and a wildcard arm that assumed NULL would report real data as
/// absent.
fn is_null(value: &sea_query::Value) -> bool {
    format!("{value:?}").ends_with("(None)")
}
