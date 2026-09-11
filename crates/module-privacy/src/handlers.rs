//! The two read-only routes, and the statement builder they share.

use crate::erase;
use axum::extract::{Query, State};
use axum::routing::{get, post};
use cratefield_core::{
    CatalogEntry, Disposition, Json, ModuleContext, PersonalDataSet, Problem, Scope, Statement,
    is_plain_identifier, require_admin,
};
use cratefield_core::{Clock, SystemClock};
use http::HeaderMap;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::sync::Arc;

/// Wall-clock seconds, from the system clock rather than the injected one.
///
/// The token's expiry is judged by `Signer::verify`, which reads real time. A
/// token minted against a test fixture's frozen clock would be born expired —
/// and the failure looks like a bad signature, which is a long way from the
/// cause. The same reason `module-email-signup` does this.
fn unix_now() -> u64 {
    u64::try_from(SystemClock.now().unix_timestamp().max(0)).unwrap_or(0)
}

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
        .route("/erase", post(erase))
        .route("/erase/confirm", post(erase_confirm))
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
    let mut unreachable = Vec::new();

    for entry in catalog.entries() {
        // Before the blank-subject bucket: an unreachable declaration also
        // has a blank subject, and a blank subject on its own means "nothing
        // to query". Bucketing one of these under `not_personal` would tell
        // the subject that a table holding their message holds nothing about
        // anybody (issue #274).
        if entry.set.is_unreachable() {
            let reason = match entry.set.disposition {
                Disposition::Unreachable(reason) => reason,
                _ => "",
            };
            unreachable.push(json!({
                "module": entry.module,
                "table": entry.set.table,
                "kind": entry.set.kind.as_str(),
                "description": entry.set.description,
                "reason": reason,
            }));
            continue;
        }
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
            // Named, not hidden. A column an export refuses to copy is still
            // something the deployment holds, and a privacy page that said
            // nothing about it would be describing less than the export does.
            "redacted": entry.set.redacted,
        }));
    }

    Json(json!({
        "holds": holds,
        "not_personal": not_personal,
        // Data the deployment holds and cannot erase. Its own bucket, not
        // folded into either neighbour: it is not exportable like `holds`
        // and it is not "nothing personal" like `not_personal`.
        "unreachable": unreachable,
        // Counts the unreachable bucket: a deployment holding data it cannot
        // erase does hold data, whatever an export over it returns.
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
            .map(|row| row_to_json(row, entry.set.redacted))
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

/// `Some(…)` when a declaration reaches its subject through another table:
/// the rows are found by `IN (SELECT …)` over the named join rather than by
/// matching the subject value directly. Built once and used by every builder
/// — export, preview, delete, verify — because a table export finds and an
/// erasure cannot reach would be the same gap this exists to close, one room
/// over (issue #281).
pub(crate) fn subject_predicate(set: &PersonalDataSet) -> Option<String> {
    match set.subject_via {
        Some(via) => {
            if !is_plain_identifier(via.table)
                || !is_plain_identifier(via.subject)
                || !is_plain_identifier(via.key)
            {
                return None;
            }
            Some(format!(
                "{subject} IN (SELECT {key} FROM {table} WHERE {via_subject} = ?)",
                subject = set.subject,
                key = via.key,
                table = via.table,
                via_subject = via.subject,
            ))
        }
        None => Some(format!("{} = ?", set.subject)),
    }
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
    let predicate = subject_predicate(&entry.set)?;
    Some(Statement::with_values(
        format!(
            "SELECT * FROM {} WHERE {predicate} LIMIT {}",
            entry.set.table,
            MAX_ROWS_PER_TABLE + 1
        ),
        vec![subject.into()],
    ))
}

/// One row as JSON, with the declared credential columns named but not copied.
///
/// The column stays in the object with `[redacted]` for a value. Dropping it
/// would read as "we hold nothing there", which is the one thing a subject
/// access request must not say untruthfully; printing it would copy a bearer
/// capability into a file somebody forwards (ADR 0015).
fn row_to_json(row: &cratefield_core::Row, redacted: &[&'static str]) -> Value {
    let mut object = Map::new();
    for (column, value) in row.columns() {
        let rendered = if redacted.contains(&column) {
            json!(REDACTED)
        } else {
            value_to_json(value)
        };
        object.insert(column.to_owned(), rendered);
    }
    Value::Object(object)
}

/// What an export prints in place of a declared credential column. The same
/// marker the log redaction leaves, so one grep finds both.
const REDACTED: &str = "[redacted]";

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

#[derive(Deserialize)]
struct EraseRequest {
    subject: String,
}

/// `POST /v1/privacy/erase` — what erasure would do, and a token to do it.
///
/// Writes nothing. The response is the preview an operator reads before
/// committing: per table, the action and the number of rows it matches, with
/// retained tables and their reasons included, because "we keep your invoices
/// for seven years" is the part of the answer a subject is least likely to
/// expect.
async fn erase(
    State(state): State<PrivacyState>,
    scope: Scope,
    headers: HeaderMap,
    Json(body): Json<EraseRequest>,
) -> Result<Json<Value>, Problem> {
    require_admin(&*state.ctx.config, &headers)
        .map_err(|problem| problem.instance(&scope.request_id))?;
    let subject = body.subject.trim();
    if subject.is_empty() {
        return Err(
            Problem::validation_failed("subject must not be empty").instance(&scope.request_id)
        );
    }
    let (db, signer) = ports(&state, &scope)?;

    let planned = erase::plan(&db, &state.ctx.personal_data, subject)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "erasure plan failed");
            Problem::internal().instance(&scope.request_id)
        })?;

    Ok(Json(json!({
        "subject": subject,
        "plan": erase::render(&planned),
        "confirm_token": erase::mint(&signer, subject, unix_now()),
        "expires_in_seconds": erase::CONFIRM_TTL_SECS,
    })))
}

#[derive(Deserialize)]
struct ConfirmRequest {
    token: String,
}

/// `POST /v1/privacy/erase/confirm` — carries out a previewed erasure.
///
/// The subject comes from the signed token, never from the request body: a
/// confirmation that could name its own subject would be a one-step erasure
/// wearing two steps.
async fn erase_confirm(
    State(state): State<PrivacyState>,
    scope: Scope,
    headers: HeaderMap,
    Json(body): Json<ConfirmRequest>,
) -> Result<Json<Value>, Problem> {
    require_admin(&*state.ctx.config, &headers)
        .map_err(|problem| problem.instance(&scope.request_id))?;
    let (db, signer) = ports(&state, &scope)?;

    let Some(subject) = erase::subject_of(&signer, body.token.trim()) else {
        return Err(Problem::validation_failed(
            "the confirmation token is not valid for erasure, or has expired",
        )
        .instance(&scope.request_id));
    };

    let planned = erase::plan(&db, &state.ctx.personal_data, &subject)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "erasure plan failed");
            Problem::internal().instance(&scope.request_id)
        })?;

    let statements = erase::statements(&planned, &subject);
    if !statements.is_empty() {
        db.batch_atomic(&statements).await.map_err(|err| {
            tracing::error!(error = %err, "erasure batch failed");
            Problem::internal().instance(&scope.request_id)
        })?;
    }

    // The receipt says the rows are gone because this went back and counted.
    let remaining = erase::verify(&db, &planned, &subject)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "erasure verification failed");
            Problem::internal().instance(&scope.request_id)
        })?;
    if !remaining.is_empty() {
        tracing::error!(tables = ?remaining, "erasure did not remove everything it reported");
        return Err(erase::not_verified(&remaining).instance(&scope.request_id));
    }

    Ok(Json(json!({
        "subject": subject,
        "erased": erase::render(&planned),
        "verified": true,
    })))
}

/// The database and the signer, which erasure needs together: without the
/// signer there is no confirmation token, and a one-step erasure is not one
/// this module is willing to serve.
type ErasePorts = (
    Arc<dyn cratefield_core::Database>,
    Arc<dyn cratefield_core::Signer>,
);

/// Both ports, or a problem.
///
/// `Harness::build` already refuses a composition missing either, so reaching
/// an error arm here means the runtime handed over a port view that disagrees
/// with this module's own `requires()`.
fn ports(state: &PrivacyState, scope: &Scope) -> Result<ErasePorts, Problem> {
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(Problem::internal().instance(&scope.request_id));
    };
    let Some(signer) = state.ctx.ports.signer.clone() else {
        return Err(Problem::internal().instance(&scope.request_id));
    };
    Ok((db, signer))
}
