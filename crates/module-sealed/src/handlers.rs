//! The routes: `/blobs` and `/blobs/{id}` `/wraps`, create, read, list,
//! wrap edit, rotation, erasure.
//!
//! Every route is subject-scoped through the [`Auth`](cratefield_core::Auth)
//! port: a module has no ambient request, and a subject id read from anywhere
//! else would be a claim the caller made about themselves. The handlers turn
//! bodies into store calls and store refusals into problem+json; the store
//! ([`crate::store`]) does the writing. The one route that serves a body —
//! the read — is rate-limited per subject and audited **before** it answers:
//! a download that could not be recorded is a 500, never an unaudited one.

use std::sync::Arc;

use axum::Router;
use axum::extract::{DefaultBodyLimit, FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use cratefield_core::{
    Auth, AuthError, Blob, Caller, Clock, Database, Json, Problem, ProblemDef, RateLimit,
    RateLimitFailure, SLUGS, Scope, SystemClock, check_rate_limit, rate_limited,
};

use crate::MAX_RECORD_BYTES;
use crate::audit::{self, Action as AuditAction, Event};
use crate::notify::{Notice, UnlockNotifier};
use crate::record::{CreateBlob, WrapEdit, validate_create, validate_wraps};
use crate::store::{self, StoreError};
use crate::{Sealed, SealedError};

/// No such blob for this subject — the same 404 whether the id exists under
/// someone else's name or not at all, so ids cannot be enumerated.
pub(crate) const NOT_FOUND: ProblemDef = ProblemDef {
    slug: "sealed-not-found",
    status: StatusCode::NOT_FOUND,
    title: "No such blob",
    description: "No blob the caller holds carries that id. A blob held by someone \
                  else answers the same way, so its existence is not disclosed.",
};

/// The blob id is already this subject's.
pub(crate) const ALREADY_EXISTS: ProblemDef = ProblemDef {
    slug: "sealed-already-exists",
    status: StatusCode::CONFLICT,
    title: "That blob id is already stored",
    description: "The client generated this blob id, and a record under it already \
                  exists for this subject. Nothing was changed.",
};

/// The mutation's `If-Match` names a revision the row no longer carries:
/// somebody wrote first, and this edit is refused rather than silently
/// overwriting theirs.
pub(crate) const PRECONDITION_FAILED: ProblemDef = ProblemDef {
    slug: "sealed-precondition-failed",
    status: StatusCode::PRECONDITION_FAILED,
    title: "The record has changed since you read it",
    description: "The `If-Match` revision is not the one the row holds now, so \
                  somebody else wrote to it in between. Read the record again, \
                  reapply your edit and retry with the fresh `ETag`.",
};

/// The mutation carried no `If-Match` at all. Wrap edits and rotations are
/// compare-and-swap writes: without the `ETag` a read returned, the server
/// would have no way to tell a current edit from a stale one.
pub(crate) const PRECONDITION_REQUIRED: ProblemDef = ProblemDef {
    slug: "sealed-precondition-required",
    status: StatusCode::PRECONDITION_REQUIRED,
    title: "An If-Match header is required",
    description: "Read the record first and send its `ETag` back as `If-Match`; a \
                  write without one is refused rather than applied blind.",
};

/// The ports and collaborators every handler needs, captured once at
/// construction. `kms` and `notifier` arrive through the module's
/// constructor ([`Sealed::new`]); the rest come from the composition.
pub(crate) struct RouteState {
    ctx: Arc<cratefield_core::ModuleContext>,
    kms: Arc<dyn cratefield_kms::Kms>,
    notifier: Arc<dyn UnlockNotifier>,
}

pub(crate) fn router(module: &Sealed, ctx: cratefield_core::ModuleContext) -> Router {
    let state = Arc::new(RouteState {
        ctx: Arc::new(ctx),
        kms: module.kms.clone(),
        notifier: module.notifier.clone(),
    });
    Router::new()
        .route("/blobs", get(list_blobs).post(create_blob))
        .route(
            "/blobs/{blob_id}",
            get(read_blob).put(rotate_blob).delete(erase_blob),
        )
        .route("/blobs/{blob_id}/wraps", put(replace_wraps))
        .layer(DefaultBodyLimit::max(MAX_RECORD_BYTES))
        .with_state(state)
}

impl RouteState {
    fn now(&self) -> String {
        stamp(now_of(&self.ctx))
    }

    fn blob(&self) -> Option<Arc<dyn Blob>> {
        self.ctx.ports.blob.clone()
    }
}

/// An RFC 3339 UTC timestamp with whole seconds, from the mounted clock or
/// the wall when none is — the only shape written to a timestamp column.
fn now_of(ctx: &cratefield_core::ModuleContext) -> OffsetDateTime {
    ctx.ports
        .clock
        .as_ref()
        .map_or_else(|| SystemClock.now(), |clock| clock.now())
}

fn stamp(at: OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .expect("truncation stays in range")
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// The signed-in subject, resolved once per request: the id every query is
/// bounded by, plus the **verified** address when the deployment's verifier
/// provides one — the unlock notice's destination. This extractor exists so
/// no handler can read a subject id from anywhere else: the only way to
/// obtain one is to present a credential the verifier accepts.
struct Subject(Identified);

struct Identified {
    id: String,
    email: Option<String>,
}

impl std::ops::Deref for Subject {
    type Target = Identified;

    fn deref(&self) -> &Identified {
        &self.0
    }
}

impl FromRequestParts<Arc<RouteState>> for Subject {
    type Rejection = Problem;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<RouteState>,
    ) -> Result<Self, Self::Rejection> {
        let Some(auth) = state.ctx.ports.auth.clone() else {
            tracing::error!(
                "sealed: no Auth port is mounted; every route answers 401 until a \
                 deployment provides a token verifier"
            );
            return Err(Problem::new(&SLUGS.unauthenticated));
        };
        match auth.identify(&parts.headers).await {
            Ok(Caller::Subject(subject)) => Ok(Self(Identified {
                id: subject.id,
                email: subject.email,
            })),
            // No credential at all, or one that did not verify: both are a
            // caller this route has not identified.
            Ok(Caller::Anonymous) | Err(AuthError::NotVerified) => {
                Err(Problem::new(&SLUGS.unauthenticated))
            }
            // The verifier could not answer. That is the deployment's problem,
            // not the caller's, and it is not a 401 — a 401 would tell a
            // signed-in person to sign in again.
            Err(AuthError::Unavailable(_)) => Err(Problem::internal()),
            // `Caller` and `AuthError` are `#[non_exhaustive]`.
            Ok(_) | Err(_) => Err(Problem::new(&SLUGS.unauthenticated)),
        }
    }
}

fn internal(scope: &Scope) -> Problem {
    Problem::internal().instance(&scope.request_id)
}

fn problem_of(err: StoreError, scope: &Scope) -> Problem {
    match err {
        StoreError::Taken => Problem::new(&ALREADY_EXISTS).instance(&scope.request_id),
        StoreError::NotFound => Problem::new(&NOT_FOUND).instance(&scope.request_id),
        StoreError::Stale => Problem::new(&PRECONDITION_FAILED).instance(&scope.request_id),
        StoreError::Tampered(what) => {
            Problem::validation_failed(format!("the stored body failed authentication: {what}"))
                .instance(&scope.request_id)
        }
        StoreError::Db(err) => {
            tracing::error!(error = %err, "sealed: a database statement failed");
            internal(scope)
        }
        StoreError::Kms(err) => {
            tracing::error!(error = %err, "sealed: the KMS refused");
            internal(scope)
        }
        StoreError::Internal(what) => {
            tracing::error!(what = %what, "sealed: an unexpected store state");
            internal(scope)
        }
    }
}

fn validation(err: &SealedError, scope: &Scope) -> Problem {
    Problem::validation_failed(err.to_string()).instance(&scope.request_id)
}

fn db_of(state: &RouteState, scope: &Scope) -> Result<Arc<dyn Database>, Problem> {
    state.ctx.ports.db.clone().ok_or_else(|| {
        tracing::error!("sealed: no Database port is mounted");
        internal(scope)
    })
}

fn not_found(scope: &Scope) -> Problem {
    Problem::new(&NOT_FOUND).instance(&scope.request_id)
}

/// The `ETag` every record response carries: the row's revision, quoted.
fn etag_of(revision: i64) -> HeaderValue {
    HeaderValue::from_str(&format!("\"{revision}\""))
        .expect("a quoted integer is a valid header value")
}

/// The revision a guarded mutation's `If-Match` names: `None` when the header
/// is absent — the caller's cue to answer 428 — a 400 when it is malformed.
/// `*` ("any state will do") is refused on purpose: it is precisely the
/// assertion a compare-and-swap write may not make.
fn if_match(headers: &HeaderMap, scope: &Scope) -> Result<Option<i64>, Problem> {
    let Some(raw) = headers.get(header::IF_MATCH).and_then(|v| v.to_str().ok()) else {
        return Ok(None);
    };
    let unquoted = raw
        .trim()
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(raw.trim());
    if unquoted == "*" {
        return Err(Problem::validation_failed(
            "`If-Match` must name a revision (an `ETag` from a read), not `*`",
        )
        .instance(&scope.request_id));
    }
    unquoted.parse::<i64>().map(Some).map_err(|_| {
        Problem::validation_failed("`If-Match` is not a revision this server issued")
            .instance(&scope.request_id)
    })
}

/// The revision a guarded mutation must carry — absent is a 428.
fn required_if_match(headers: &HeaderMap, scope: &Scope) -> Result<i64, Problem> {
    if_match(headers, scope)?
        .ok_or_else(|| Problem::new(&PRECONDITION_REQUIRED).instance(&scope.request_id))
}

fn ok_json() -> Response {
    Json(json!({ "ok": true })).into_response()
}

/// Appends one event to the audit chain.
///
/// # Errors
///
/// The audit problem (a 500): callers treat an audit failure as fatal for
/// the request.
async fn audited(
    db: &dyn Database,
    ts: &str,
    event: &Event<'_>,
    scope: &Scope,
) -> Result<(), Problem> {
    audit::append(db, ts, event).await.map_err(|err| {
        tracing::error!(error = %err, "sealed: an audit row could not be appended");
        internal(scope)
    })
}

/// Writes the outer body to the blob store before the row that names it
/// lands.
async fn park_body(
    state: &RouteState,
    key: &str,
    bytes: &[u8],
    scope: &Scope,
) -> Result<(), Problem> {
    let store = state.blob().ok_or_else(|| {
        tracing::error!("sealed: no Blob port is mounted, but the body needs one");
        internal(scope)
    })?;
    store
        .put(key, bytes, "application/octet-stream")
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "sealed: the blob store refused the body");
            internal(scope)
        })
}

/// Removes a parked object best-effort: after a refused create/rotate, so a
/// request that stored nothing leaves no body behind either.
async fn unpark_body(state: &RouteState, key: &str) {
    if let Some(store) = state.blob()
        && let Err(err) = store.delete(key).await
    {
        tracing::warn!(error = %err, "sealed: a parked body object could not be removed");
    }
}

/// The unlock notice, best-effort by contract: a notice that could not go
/// out is logged and the download proceeds — the mailer never stands
/// between a subject and their own ciphertext. Only a verified address is
/// notified.
async fn notify_unlock(state: &RouteState, subject: &Identified, row: &store::BlobRow) {
    let Some(email) = subject.email.clone() else {
        return;
    };
    let notice = Notice {
        subject: subject.id.clone(),
        email,
        blob_id: row.blob_id.clone(),
        purpose: row.purpose.clone(),
    };
    if let Err(err) = state.notifier.blob_unlocked(&notice).await {
        tracing::warn!(
            error = %err,
            blob_id = %row.blob_id,
            "sealed: the unlock notice was not sent"
        );
    }
}

/// `POST /blobs`: store a sealed record. The body is the client's
/// `CreateBlob`; the subject comes from the credential and
/// `created_by_credential` from the body, because the signed-in subject
/// carries no WebAuthn credential id and the client — which ran the
/// ceremony — records which one owns the PRF wrap. The server treats the
/// payload and every wrap as opaque.
async fn create_blob(
    scope: Scope,
    State(state): State<Arc<RouteState>>,
    Subject(subject): Subject,
    Json(blob): Json<CreateBlob>,
) -> Result<Response, Problem> {
    validate_create(&blob).map_err(|err| validation(&err, &scope))?;
    let db = db_of(&state, &scope)?;
    let ts = state.now();
    let body = store::decode_body(&blob).map_err(|err| problem_of(err, &scope))?;
    let sealed = store::seal_body(
        state.kms.as_ref(),
        &body,
        &subject.id,
        &blob.blob_id,
        blob.version,
    )
    .await
    .map_err(|err| problem_of(err, &scope))?;
    // The body goes to the blob store before the row that will name it.
    if let Some(key) = &sealed.object_key {
        park_body(&state, key, &sealed.outer_ct, &scope).await?;
    }
    if let Err(err) = store::insert(db.as_ref(), &subject.id, &blob, &sealed, &ts).await {
        if let Some(key) = &sealed.object_key {
            unpark_body(&state, key).await;
        }
        return Err(problem_of(err, &scope));
    }
    audited(
        db.as_ref(),
        &ts,
        &Event {
            subject: &subject.id,
            action: AuditAction::Create,
            blob_id: &blob.blob_id,
            version: blob.version,
        },
        &scope,
    )
    .await?;
    let row = stored_row(db.as_ref(), &subject.id, &blob.blob_id, &scope).await?;
    serve_record(&row, &subject.id, &body, &scope, StatusCode::CREATED)
}

/// `GET /blobs/{id}`: the record, payload included, to the subject it
/// belongs to and nobody else. Rate-limited per subject (failing open — the
/// durable backstops are the auth gate and the per-subject row scoping),
/// audited before the answer, and worth a notification per download.
async fn read_blob(
    scope: Scope,
    State(state): State<Arc<RouteState>>,
    Subject(subject): Subject,
    Path(blob_id): Path<String>,
) -> Result<Response, Problem> {
    let keys = vec![format!("sealed:read:{}", subject.id)];
    if let RateLimit::Denied { decision } = check_rate_limit(
        state.ctx.ports.rate_limiter.as_ref(),
        &keys,
        RateLimitFailure::FailOpen,
    )
    .await
    {
        return Ok(rate_limited(&decision));
    }
    let db = db_of(&state, &scope)?;
    let ts = state.now();
    let row = store::load(db.as_ref(), &subject.id, &blob_id)
        .await
        .map_err(|err| problem_of(err, &scope))?
        .ok_or_else(|| not_found(&scope))?;
    let body = store::open_body(
        state.kms.as_ref(),
        state.blob().as_deref(),
        db.as_ref(),
        &subject.id,
        &row,
    )
    .await
    .map_err(|err| problem_of(err, &scope))?;
    // The audit row precedes the answer.
    audited(
        db.as_ref(),
        &ts,
        &Event {
            subject: &subject.id,
            action: AuditAction::Read,
            blob_id: &row.blob_id,
            version: row.version,
        },
        &scope,
    )
    .await?;
    notify_unlock(&state, &subject, &row).await;
    serve_record(&row, &subject.id, &body, &scope, StatusCode::OK)
}

/// `GET /blobs`: the subject's blobs, metadata only — no bodies, so a list
/// can neither serve nor leak a payload.
async fn list_blobs(
    scope: Scope,
    State(state): State<Arc<RouteState>>,
    Subject(subject): Subject,
) -> Result<Response, Problem> {
    let db = db_of(&state, &scope)?;
    let rows = store::list(db.as_ref(), &subject.id)
        .await
        .map_err(|err| problem_of(err, &scope))?;
    let blobs: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "blob_id": row.blob_id,
                "version": row.version,
                "purpose": row.purpose,
                "alg": row.alg,
                "ciphertext_len": row.ciphertext_len,
                "created_by_credential": row.created_by_credential,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            })
        })
        .collect();
    let mut response = Json(json!({ "blobs": blobs })).into_response();
    // The newest revision among the subject's rows: the ETag a guarded
    // mutation can be answered with after a list.
    if let Some(revision) = rows.iter().map(|row| row.revision).max() {
        response
            .headers_mut()
            .insert(header::ETAG, etag_of(revision));
    }
    Ok(response)
}

/// `PUT /blobs/{id}/wraps`: replace the wrap set under a compare-and-swap on
/// the record's `ETag` (`If-Match`, required — 428 without it, 412 stale).
/// The payload — the ciphertext, the DEK, the version — is untouched, so this
/// is how a subject adds a recovery code or drops a lost passkey's wrap
/// without re-uploading anything.
async fn replace_wraps(
    scope: Scope,
    State(state): State<Arc<RouteState>>,
    Subject(subject): Subject,
    Path(blob_id): Path<String>,
    headers: HeaderMap,
    Json(edit): Json<WrapEdit>,
) -> Result<Response, Problem> {
    validate_wraps(&edit.wraps).map_err(|err| validation(&err, &scope))?;
    let expected_revision = required_if_match(&headers, &scope)?;
    let db = db_of(&state, &scope)?;
    let ts = state.now();
    let wraps = serde_json::to_string(&edit.wraps).map_err(|_| internal(&scope))?;
    store::replace_wraps(
        db.as_ref(),
        &subject.id,
        &blob_id,
        expected_revision,
        &wraps,
        &ts,
    )
    .await
    .map_err(|err| problem_of(err, &scope))?;
    audited(
        db.as_ref(),
        &ts,
        &Event {
            subject: &subject.id,
            action: AuditAction::Wraps,
            blob_id: &blob_id,
            version: edit.version,
        },
        &scope,
    )
    .await?;
    let row = stored_row(db.as_ref(), &subject.id, &blob_id, &scope).await?;
    let body = store::open_body(
        state.kms.as_ref(),
        state.blob().as_deref(),
        db.as_ref(),
        &subject.id,
        &row,
    )
    .await
    .map_err(|err| problem_of(err, &scope))?;
    serve_record(&row, &subject.id, &body, &scope, StatusCode::OK)
}

/// `PUT /blobs/{id}`: a content-key rotation. The client re-seals the same
/// plaintext under a new payload key and sends the whole `CreateBlob` with
/// `version` one past the row's; the server stores it under a **fresh**
/// DEK, so the old key material is not merely re-wrapped but replaced. Like
/// a wrap edit this is a compare-and-swap on the record's `ETag` (`If-Match`
/// required): of two concurrent rotations at most one lands, and the loser's
/// new body — parked under its own fresh object key — is unparked, never the
/// live one. The winner frees the previous body's object after the batch
/// commits.
async fn rotate_blob(
    scope: Scope,
    State(state): State<Arc<RouteState>>,
    Subject(subject): Subject,
    Path(blob_id): Path<String>,
    headers: HeaderMap,
    Json(blob): Json<CreateBlob>,
) -> Result<Response, Problem> {
    validate_create(&blob).map_err(|err| validation(&err, &scope))?;
    if blob.blob_id != blob_id {
        return Err(validation(
            &SealedError::BadInput("the body's blob_id must be the path's".into()),
            &scope,
        ));
    }
    let expected_revision = required_if_match(&headers, &scope)?;
    let db = db_of(&state, &scope)?;
    let ts = state.now();
    let body = store::decode_body(&blob).map_err(|err| problem_of(err, &scope))?;
    let sealed = store::seal_body(
        state.kms.as_ref(),
        &body,
        &subject.id,
        &blob.blob_id,
        blob.version,
    )
    .await
    .map_err(|err| problem_of(err, &scope))?;
    if let Some(key) = &sealed.object_key {
        park_body(&state, key, &sealed.outer_ct, &scope).await?;
    }
    if let Err(err) = store::rotate(
        db.as_ref(),
        &subject.id,
        &blob,
        &sealed,
        &ts,
        expected_revision,
        state.blob().as_deref(),
    )
    .await
    {
        if let Some(key) = &sealed.object_key {
            unpark_body(&state, key).await;
        }
        return Err(problem_of(err, &scope));
    }
    audited(
        db.as_ref(),
        &ts,
        &Event {
            subject: &subject.id,
            action: AuditAction::Rotate,
            blob_id: &blob.blob_id,
            version: blob.version,
        },
        &scope,
    )
    .await?;
    let row = stored_row(db.as_ref(), &subject.id, &blob.blob_id, &scope).await?;
    serve_record(&row, &subject.id, &body, &scope, StatusCode::OK)
}

/// `DELETE /blobs/{id}`: the crypto-shred. The DEK row goes first, then the
/// blob row, then the blob-store object; from the moment the DEK is gone
/// the body is inert no matter which copy survives. The erasure is audited
/// after it happens — an audit append that fails here is a 500 naming an
/// erasure that did occur, never a 200 for one that left no trace in the
/// chain.
async fn erase_blob(
    scope: Scope,
    State(state): State<Arc<RouteState>>,
    Subject(subject): Subject,
    Path(blob_id): Path<String>,
) -> Result<Response, Problem> {
    let db = db_of(&state, &scope)?;
    let ts = state.now();
    let row = store::load(db.as_ref(), &subject.id, &blob_id)
        .await
        .map_err(|err| problem_of(err, &scope))?
        .ok_or_else(|| not_found(&scope))?;
    let object_key = store::erase(db.as_ref(), &subject.id, &blob_id)
        .await
        .map_err(|err| problem_of(err, &scope))?;
    if let Some(key) = object_key {
        unpark_body(&state, &key).await;
    }
    audited(
        db.as_ref(),
        &ts,
        &Event {
            subject: &subject.id,
            action: AuditAction::Erase,
            blob_id: &row.blob_id,
            version: row.version,
        },
        &scope,
    )
    .await?;
    Ok(ok_json())
}

/// The row a mutation just wrote; `None` after a write is the unreachable
/// arm, because the same batch wrote it.
async fn stored_row(
    db: &dyn Database,
    subject: &str,
    blob_id: &str,
    scope: &Scope,
) -> Result<store::BlobRow, Problem> {
    store::load(db, subject, blob_id)
        .await
        .map_err(|err| problem_of(err, scope))?
        .ok_or_else(|| internal(scope))
}

/// The wire record for a row whose body is already open. The `ETag` is the
/// row's revision: the token the next wrap edit or rotation must echo back
/// as `If-Match`.
fn serve_record(
    row: &store::BlobRow,
    subject: &str,
    body: &[u8],
    scope: &Scope,
    status: StatusCode,
) -> Result<Response, Problem> {
    let record = store::wire_record(row, subject, body).map_err(|err| problem_of(err, scope))?;
    let mut response = (status, Json(record)).into_response();
    response
        .headers_mut()
        .insert(header::ETAG, etag_of(row.revision));
    Ok(response)
}
