//! The provider server (issue #656): this deployment answering the signed
//! protocol it also calls out on.
//!
//! [`crate::provider`] is the client half — this deployment holding data in a
//! warehouse or a CRM. This module is the **server** half: a deployment that
//! holds such a system of its own, or is itself the system another
//! deployment's `module-privacy` reaches, answering the same three signed
//! POSTs over the same declarations. Enabling it is
//! [`Privacy::serve_provider`](crate::Privacy::serve_provider); the routes
//! are absent otherwise, so a deployment does not answer a contract it never
//! opted into.
//!
//! ```text
//! POST /v1/privacy/provider/export       {"subject": "…"}            → {"sections":[…]}
//! POST /v1/privacy/provider/erase/plan   {"subject": "…"}            → {"sections":[…]}
//! POST /v1/privacy/provider/erase/apply  {"subject": "…", "request_id": "…"} → {"applied": true, …}
//! ```
//!
//! **The signature is the authorisation.** No admin token: a caller on
//! another deployment has no account here and cannot hold one, so
//! [`require_admin`] would refuse every legitimate call and authorise
//! nothing this protocol needs. The HMAC over the raw body, checked by core's
//! [`WebhookVerifier`] in constant time, is what says "this deployment asked
//! for this subject's data" — so it is verified *before* the body is parsed
//! and a failure is one answer for a missing header, a wrong secret and a
//! timestamp outside the window alike. Distinguishing them would tell a
//! caller probing the endpoint how its secret is configured.
//!
//! **No two-step here.** Erasure elsewhere is two calls with a confirmation
//! token because an erasure cannot be undone and one HTTP call is not a
//! moment to reconsider. That reconsideration happened at the *caller*:
//! `POST /v1/privacy/erase` there previewed it and an admin confirmed the
//! token, and this route is reached only after that. Requiring a second
//! confirmation from a system that cannot show the operator the preview would
//! make the protocol impossible to complete honestly.
//!
//! **Idempotence is the database's.** `erase/apply` deletes rows with
//! `DELETE … WHERE subject = ?` and then re-counts them; run twice, the
//! second pass matches nothing, counts nothing and answers `200`. No
//! in-process record of applied ids is kept, deliberately: such a cache
//! would be per-isolate and per-process, so it would claim an idempotence it
//! cannot deliver across two Workers, and a cache that says "already applied"
//! for a request that never was is a lie with a status code on it. The SQL
//! is the mechanism, and it is the only one that is true everywhere.

use crate::erase;
use crate::handlers;
use crate::provider::SIGNATURE_HEADER;
use axum::Router;
use axum::extract::State;
use axum::routing::post;
use cratefield_core::{
    Disposition, Json, ModuleContext, Problem, ProblemDef, Scope, StripeStyle, WebhookVerifier,
};
use http::{HeaderMap, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

/// One refusal for every way a request fails to prove itself.
///
/// Deliberately one answer for a missing header, a wrong secret, a stale
/// timestamp and a body that has been tampered with: a caller learns whether
/// it signed correctly and nothing about how the endpoint is set up.
const UNVERIFIED: ProblemDef = ProblemDef {
    slug: "privacy-provider-unverified",
    status: StatusCode::UNAUTHORIZED,
    title: "Unverified provider call",
    description: "The request carried no signature this deployment could verify, or one that did not hold.",
};

#[derive(Clone)]
struct ProviderState {
    ctx: Arc<ModuleContext>,
    /// Which config/env variable holds the shared secret. The **name** is
    /// recorded at build; the value is read per request, as
    /// [`HttpProvider::secret_env`](crate::HttpProvider::secret_env) does for
    /// the calling side, so one build works in every environment.
    secret_env: Arc<str>,
}

/// The provider routes, for [`crate::Privacy::router`] to nest only when the
/// deployment opted in.
pub(crate) fn router(ctx: Arc<ModuleContext>, secret_env: Arc<str>) -> Router {
    axum::Router::new()
        .route("/provider/export", post(export))
        .route("/provider/erase/plan", post(erase_plan))
        .route("/provider/erase/apply", post(erase_apply))
        .with_state(ProviderState { ctx, secret_env })
}

/// What the caller sent. `request_id` rides every one of the three calls the
/// client makes — [`crate::provider::request_body`] writes both fields
/// whatever the route — and only `erase/apply` has an opinion about it.
#[derive(Deserialize)]
struct ProviderRequest {
    subject: String,
    #[serde(default)]
    request_id: String,
}

/// The signed subject, or the one validation answer.
///
/// A blank subject would otherwise reach the query builders and match
/// nothing, so the plan would report an erasure that erases nobody.
fn subject_of(request: &ProviderRequest) -> Result<&str, Problem> {
    let subject = request.subject.trim();
    if subject.is_empty() {
        return Err(Problem::validation_failed("subject must not be empty"));
    }
    Ok(subject)
}

/// Verifies the caller's signature over `body`, or the single refusal.
///
/// Reads the secret per request and refuses when it is missing, empty or
/// only whitespace: a deployment whose provider server is enabled but
/// unconfigured answers `not_ready` and names the variable to set, because
/// the operator has to be able to tell that apart from "the caller signed
/// wrong". Opening the door instead — treating an absent secret as matching
/// everything — would make a misconfigured deployment serve every subject's
/// data to anyone who found the URL.
fn verify(state: &ProviderState, headers: &HeaderMap, body: &[u8]) -> Result<(), Problem> {
    let Some(secret) = state
        .ctx
        .config
        .get(state.secret_env.as_ref())
        .filter(|secret| !secret.trim().is_empty())
    else {
        tracing::error!(
            env = %state.secret_env,
            "privacy: the provider server has no signing secret; every provider call is refused"
        );
        return Err(Problem::not_ready(
            "the privacy provider server has no signing secret configured",
        ));
    };

    // Core's verifier, over the raw bytes: constant-time comparison, no early
    // exit, fail-closed on every unreadable header, and the 300 s tolerance in
    // both directions. Never re-derived here — `module-webhooks` signs the
    // same layout and one receiver-side implementation covers both.
    let verified = WebhookVerifier::new(StripeStyle {
        header: SIGNATURE_HEADER,
    })
    .verify(
        &secret,
        headers,
        body,
        i64::try_from(handlers::unix_now()).unwrap_or(i64::MAX),
    );

    if verified {
        Ok(())
    } else {
        Err(Problem::new(&UNVERIFIED))
    }
}

/// The request body, read as raw bytes and only then parsed.
///
/// The signature covers the exact bytes sent; re-serialising parsed JSON
/// would verify a string the caller never signed. A body that does not
/// deserialize is a `400` — and never an echo of the body, which is the
/// subject's.
fn parse(body: &[u8]) -> Result<ProviderRequest, Problem> {
    serde_json::from_slice(body)
        .map_err(|_| Problem::validation_failed("the request body is not a provider request"))
}

/// `POST /v1/privacy/provider/export` — what this deployment holds for one
/// subject, in the shape the calling module's validator reads back.
///
/// One section per declared table, carrying the same rows, redactions and
/// truncation the local `/export` route renders: this is the same catalog
/// read by the same code ([`handlers::subject_tables`]), so a deployment
/// cannot answer a signed caller differently from an operator.
async fn export(
    State(state): State<ProviderState>,
    scope: Scope,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, Problem> {
    verify(&state, &headers, &body).map_err(|p| p.instance(&scope.request_id))?;
    let request = parse(&body).map_err(|p| p.instance(&scope.request_id))?;
    let subject = subject_of(&request).map_err(|p| p.instance(&scope.request_id))?;

    let tables = handlers::subject_tables(&state.ctx, subject)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "privacy provider export failed");
            Problem::internal().instance(&scope.request_id)
        })?;

    let sections = tables
        .iter()
        .map(|table| {
            let mut section = json!({
                "name": table["table"],
                "data": {
                    "module": table["module"],
                    "kind": table["kind"],
                    "rows": table["rows"],
                    "truncated": table["truncated"],
                },
            });
            // The description is the sentence the owning module wrote for a
            // person deciding whether to trust this. Sent when there is one.
            if !table["description"].as_str().unwrap_or_default().is_empty() {
                section["description"] = table["description"].clone();
            }
            section
        })
        .collect::<Vec<_>>();

    Ok(Json(json!({ "sections": sections })))
}

/// `POST /v1/privacy/provider/erase/plan` — what erasure would do here, per
/// table. Writes nothing.
///
/// The actions are this protocol's own vocabulary (`delete`, `anonymise`,
/// `retain`), which is not the local route's (`erase`, `anonymise`,
/// `retain`): a provider erases rows, while this deployment's preview
/// describes what its own erasure does. `retain` **must** carry a reason —
/// the calling module rejects a plan that keeps something silently, which is
/// the one thing a subject is most entitled to be told about — so a retained
/// table whose declaration somehow has no reason fails this request rather
/// than producing a plan the caller would discard.
async fn erase_plan(
    State(state): State<ProviderState>,
    scope: Scope,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, Problem> {
    verify(&state, &headers, &body).map_err(|p| p.instance(&scope.request_id))?;
    let request = parse(&body).map_err(|p| p.instance(&scope.request_id))?;
    let subject = subject_of(&request).map_err(|p| p.instance(&scope.request_id))?;

    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(Problem::internal().instance(&scope.request_id));
    };
    let planned = erase::plan(&db, &state.ctx.personal_data, subject)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "privacy provider erasure plan failed");
            Problem::internal().instance(&scope.request_id)
        })?;

    let sections = planned
        .iter()
        .map(plan_section)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            // A disposition this protocol cannot express is not something to
            // answer "retain" about: an omission in a plan reads to the
            // caller as "we keep this and here is why", and there is no why.
            tracing::error!(error = %error, "privacy provider plan cannot express a disposition");
            Problem::internal().instance(&scope.request_id)
        })?;

    Ok(Json(json!({ "sections": sections })))
}

/// One planned declaration as the protocol's plan section, or why it cannot
/// be one.
///
/// `rows` is not part of the protocol's contract — the calling module drops
/// it — but it is counted anyway by the shared plan, and an operator
/// debugging a provider deployment with `curl` reads a plan that says how
/// many rows each action matches rather than one that only says what kind of
/// action it is.
fn plan_section(step: &erase::Planned) -> Result<Value, String> {
    let name = step.entry.set.table;
    let rows = step.rows;
    match step.entry.set.disposition {
        Disposition::Erase => Ok(json!({ "name": name, "action": "delete", "rows": rows })),
        Disposition::Anonymise(columns) => Ok(json!({
            "name": name,
            "action": "anonymise",
            "columns": columns,
            "rows": rows,
        })),
        // **`Retain` and `Unreachable` are one answer, and that is the point.**
        // Neither erases anything — `Disposition::keeps_row` counts both — so
        // `delete` and `anonymise` would each be a claim about rows this
        // deployment never touched, and `retain` says only what is true: the
        // row stays. What separates the two declarations is *why*, and the
        // reason is carried verbatim into the plan, so a subject reading it
        // still hears "we keep these on purpose" or "we keep these because no
        // predicate reaches them" rather than one word standing for both. The
        // protocol has no fourth action to give it, and inventing one would be
        // a guess the caller acts on.
        //
        // The `Unreachable` half is not a hypothetical: `auth-passkeys`
        // declares its challenge budget that way and `AuthWorker::builder`
        // always mounts it, so an earlier version of this function that had no
        // arm for it answered `500` to every signed caller of every deployment
        // this crate builds. It reaches the plan even though the declaration's
        // own constructor (`PersonalDataSet::unreachable`) leaves the subject
        // column blank and so is skipped by `subject_sets`: `auth-passkeys`
        // writes the struct literal with a real column name, and `validate`
        // checks that form as an ordinary declaration, so nothing refuses it.
        //
        // `erase::statements` reads the same `disposition` and emits nothing
        // for either variant, so `erase/apply` cannot delete or blank a table
        // its own plan said it keeps.
        //
        // A reason that is blank is refused rather than passed on. `validate`
        // rejects one on a `Retain` and on a blank-subject `Unreachable`, but a
        // `Unreachable` written as a struct literal is checked as an ordinary
        // declaration and its reason is not looked at — and
        // `crate::provider`'s validator rejects a `retain` carrying no reason,
        // which would discard the whole plan over one line of it.
        Disposition::Retain(reason) | Disposition::Unreachable(reason)
            if reason.trim().is_empty() =>
        {
            Err(format!(
                "table `{name}` keeps rows the caller could not be told why for"
            ))
        }
        Disposition::Retain(reason) | Disposition::Unreachable(reason) => Ok(json!({
            "name": name,
            "action": "retain",
            "reason": reason,
            "rows": rows,
        })),
        // `Disposition` is non_exhaustive. A variant core gains after this
        // module was built has no word in this protocol, and inventing one
        // would be a guess the caller acts on.
        _ => Err(format!(
            "table `{name}` has a disposition this protocol cannot express"
        )),
    }
}

/// `POST /v1/privacy/provider/erase/apply` — carries out the erasure, in one
/// atomic batch, and counts what is left afterwards.
///
/// The `request_id` is echoed rather than stored, and nothing about it
/// changes the statements: the erasure is idempotent because a `DELETE`
/// matching no rows is not a failure and the verification below counts zero.
/// Re-running a genuinely new id does the same work again, which is what a
/// new erasure should do.
async fn erase_apply(
    State(state): State<ProviderState>,
    scope: Scope,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, Problem> {
    verify(&state, &headers, &body).map_err(|p| p.instance(&scope.request_id))?;
    let request = parse(&body).map_err(|p| p.instance(&scope.request_id))?;
    let subject = subject_of(&request).map_err(|p| p.instance(&scope.request_id))?;
    if request.request_id.trim().is_empty() {
        return Err(
            Problem::validation_failed("request_id must not be empty").instance(&scope.request_id)
        );
    }

    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(Problem::internal().instance(&scope.request_id));
    };

    let planned = erase::plan(&db, &state.ctx.personal_data, subject)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "privacy provider erasure plan failed");
            Problem::internal().instance(&scope.request_id)
        })?;

    let statements = erase::statements(&planned, subject);
    if !statements.is_empty() {
        db.batch_atomic(&statements).await.map_err(|error| {
            tracing::error!(error = %error, "privacy provider erasure batch failed");
            Problem::internal().instance(&scope.request_id)
        })?;
    }

    // Counted, not assumed: a statement returning without an error has proved
    // nothing, and a receipt saying it did would be the failure nobody catches
    // until it mattered.
    let remaining = erase::verify(&db, &planned, subject)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "privacy provider erasure verification failed");
            Problem::internal().instance(&scope.request_id)
        })?;
    if !remaining.is_empty() {
        tracing::error!(tables = ?remaining, "a provider erasure did not remove everything it reported");
        return Err(erase::not_verified(&remaining).instance(&scope.request_id));
    }

    Ok(Json(json!({
        "applied": true,
        "request_id": request.request_id,
        "subject": subject,
    })))
}
