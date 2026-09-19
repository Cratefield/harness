//! HTTP handlers for `/v1/telemetry` (issue #413). The ingest route is
//! public and unauthenticated by design — its caller is a CLI with no
//! browser and no session — so every guard on it is mechanical: the
//! `RateLimiter` port, the batch ceiling and a parser that admits only a
//! closed grammar. The client IP touches the request only as an in-memory
//! rate-limit key and is never written; `docs/PRIVACY.md` holds that rule
//! for the whole harness, and it is the load-bearing one for the one route
//! built to be safe to talk to.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{FromRequest, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use http::HeaderMap;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use cratefield_core::{
    Clock, Decision, Json, ModuleContext, Problem, ProblemDef, RateLimiter, Scope, SystemClock,
    client_ip, rate_limit_keys, rate_limited, require_admin,
};

use crate::consent;
use crate::payload::{Batch, Rejection, Vocabulary};
use crate::store;

/// The event emitted after an accepted batch (issue #413): counts only,
/// so a venture can react to volume without scraping its own tables.
pub(crate) const EVENT_RECORDED: &str = "telemetry.recorded";

/// A batch written in a schema version this collector does not parse. Its
/// own slug, not a payload rejection: the fix is a client upgrade, not a
/// payload fix, and an operator should be able to tell the two apart in
/// logs at a glance.
pub(crate) const SCHEMA_UNSUPPORTED: ProblemDef = ProblemDef {
    slug: "telemetry-schema-unsupported",
    status: axum::http::StatusCode::BAD_REQUEST,
    title: "Telemetry schema not supported",
    description: "The batch names a payload schema version this collector does not parse.",
};

/// A batch carrying a value outside the closed grammar the notice route
/// publishes. The body's detail names the field path and the rule and
/// never the value (`Rejection`'s rendering guarantees it).
pub(crate) const PAYLOAD_REJECTED: ProblemDef = ProblemDef {
    slug: "telemetry-payload-rejected",
    status: axum::http::StatusCode::BAD_REQUEST,
    title: "Telemetry payload rejected",
    description: "The batch carries a value outside the closed grammar the notice route publishes.",
};

/// The fixed `detail` for a body that is not JSON at all. It must stay
/// constant because the natural thing to put there — serde's parse error,
/// as axum's `Json` extractor would surface it — is not: the error is
/// prefixed with the JSON key the client chose, so the "message" is the
/// client's own bytes, echoed back and written to logs. This is the one
/// route built to keep `README.md`'s promise that rejections never echo
/// what the client sent, so it answers a malformed body with the rule
/// alone.
const NOT_JSON_DETAIL: &str = "the request body was not valid JSON, so no field in it was read";

/// The fixed `detail` for a request that did not name a JSON content
/// type. `RawBody` restored the header check axum's `Json` extractor
/// performs before it reads a body; the sentence stays constant for the
/// same reason [`NOT_JSON_DETAIL`] does. Axum's own wording is fixed too,
/// but this route owns every word of its rejections and states the rule
/// rather than quote back anything the client sent — a content-type
/// value is client-supplied bytes like any other. On its own axum
/// answers this case with a bare 415, but core's `Json` wrapper turned
/// every non-size rejection into the 400 `validation-failed` problem, so
/// 400 is what callers saw before and what this route answers with, under
/// its own payload slug.
const NOT_JSON_CONTENT_TYPE_DETAIL: &str =
    "the request did not name a JSON content type, so its body was not read";

/// The builder's settings, cloned into the router state.
#[derive(Clone)]
pub struct Settings {
    /// The event names and module names the collector will count. Both
    /// lists default to empty, which rejects every batch naming an event
    /// or a module — fail closed, on purpose (issue #413).
    pub vocabulary: Vocabulary,
    /// Retention for both tables, in days; the scheduled purge deletes
    /// buckets older than this (default 180).
    pub retention_days: u32,
    /// The one-line command that turns reporting off, as a client prints it.
    pub opt_out_command: String,
    /// The one-line command that prints the would-be payload, as a client
    /// prints it.
    pub status_command: String,
}

pub(crate) struct ModuleState {
    pub ctx: Arc<ModuleContext>,
    pub settings: Settings,
}

/// The module's routes, mounted at `/v1/telemetry`.
pub(crate) fn router(ctx: ModuleContext, settings: Settings) -> axum::Router {
    let state = Arc::new(ModuleState {
        ctx: Arc::new(ctx),
        settings,
    });
    axum::Router::new()
        .route("/events", post(record))
        .route("/notice", get(notice))
        .route("/admin/usage", get(admin_usage))
        .with_state(state)
}

/// "Now" through the Clock port when present, `SystemClock` otherwise —
/// the port is what makes the day buckets deterministic under the test
/// kit's fixed clock (issue #413).
pub(crate) fn now_of(ctx: &ModuleContext) -> OffsetDateTime {
    ctx.ports
        .clock
        .as_ref()
        .map_or_else(|| SystemClock.now(), |clock| clock.now())
}

/// The day bucket, `YYYY-MM-DD` — the retention and the aggregate axis.
/// A string, because ISO dates compare lexicographically and both
/// supported engines sort TEXT the same way.
pub(crate) fn day_of(at: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        at.year(),
        u8::from(at.month()),
        at.day()
    )
}

/// `first_seen_at`/`last_seen_at`, seconds precision like every other
/// timestamp in the harness.
fn rfc3339_seconds(at: OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .expect("truncation stays in range")
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// The `202 {"ok":true}` bytes, identical to every other accepting route
/// in the harness.
fn accepted() -> Response {
    (
        axum::http::StatusCode::ACCEPTED,
        Json(json!({ "ok": true })),
    )
        .into_response()
}

fn internal(scope: &Scope) -> Problem {
    Problem::internal().instance(&scope.request_id)
}

/// The 400 for a rejected batch. A schema mismatch is its own slug: the
/// fix is a client upgrade, not a payload fix (issue #413).
fn rejection_problem(scope: &Scope, rejection: Rejection) -> Problem {
    match rejection {
        Rejection::SchemaUnsupported => {
            Problem::new(&SCHEMA_UNSUPPORTED).instance(&scope.request_id)
        }
        other => Problem::new(&PAYLOAD_REJECTED)
            .with_detail(other.to_string())
            .instance(&scope.request_id),
    }
}

/// The 400 for a body that never parsed as JSON — same slug and status as
/// a grammar rejection, with the one detail that is safe to say.
fn not_json_problem(scope: &Scope) -> Problem {
    Problem::new(&PAYLOAD_REJECTED)
        .with_detail(NOT_JSON_DETAIL)
        .instance(&scope.request_id)
}

/// The rate-limit check for the ingest route, mirroring
/// `module-email-signup`: one check per key from the client IP, and
/// warn-and-allow when the limiter itself errors — the closed grammar and
/// the batch ceiling bound what a single request can do, so a limiter
/// outage must not take the ingest route down. The IP is the only thing
/// consulted, it is used in memory only, as a key, and it is never
/// written: `docs/PRIVACY.md` ("no IP addresses in the database") applies
/// doubly to the route that exists to carry nothing.
async fn rate_limit(state: &ModuleState, headers: &HeaderMap) -> Option<Response> {
    let limiter: Arc<dyn RateLimiter> = state.ctx.ports.rate_limiter.clone()?;
    let ip = client_ip(headers);
    for key in rate_limit_keys(ip.as_deref(), None) {
        match limiter.limit(&key).await {
            Ok(Decision { ok: true, .. }) => {}
            Ok(Decision {
                ok: false,
                retry_after,
            }) => {
                return Some(rate_limited(retry_after));
            }
            Err(err) => {
                tracing::warn!(error = %err, key = %key, "rate limiter unavailable; allowing");
            }
        }
    }
    None
}

/// The ingest route's body, read as raw bytes rather than through
/// `cratefield_core::Json`. That extractor is exactly right everywhere
/// else, but its rejection path copies axum's `body_text()` — serde's
/// parse error, prefixed with the client-chosen JSON key — into the
/// problem `detail`, which would make this route echo its caller (see
/// [`NOT_JSON_DETAIL`]). The bytes are parsed here instead, so the route
/// owns every word of its own rejections. The one guard axum's extractor
/// performed that a parse does not imply — the `Content-Type` header —
/// is made here too ([`json_content_type`]), so a body is only read from
/// a request that named JSON. A byte read that fails is the harness's
/// 64 KiB cap or a client that went away mid-body; either maps to the
/// same request-too-large slug core's `Json` uses.
struct RawBody(Bytes);

impl<S: Send + Sync> FromRequest<S> for RawBody {
    type Rejection = Problem;

    async fn from_request(
        request: axum::extract::Request,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let instance = request
            .extensions()
            .get::<Scope>()
            .map(|scope| scope.request_id.clone());
        // Axum checks the header before it reads the body; so does this.
        if !json_content_type(request.headers()) {
            let problem = Problem::new(&PAYLOAD_REJECTED).with_detail(NOT_JSON_CONTENT_TYPE_DETAIL);
            return Err(match instance {
                Some(request_id) => problem.instance(&request_id),
                None => problem,
            });
        }
        if let Ok(bytes) = Bytes::from_request(request, state).await {
            Ok(Self(bytes))
        } else {
            let mut problem = Problem::request_too_large();
            if let Some(instance) = instance {
                problem = problem.instance(&instance);
            }
            Err(problem)
        }
    }
}

/// Whether the request names a JSON content type, decided exactly as
/// axum's `Json` extractor decides it: `application/json` and any
/// `application/*+json` subtype, with parameters (`charset=utf-8`) and
/// case differences accepted — the same `mime` crate, so a correct
/// client cannot tell this restored check from the extractor's own.
fn json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<mime::Mime>().ok())
        .is_some_and(|mime| {
            mime.type_() == "application"
                && (mime.subtype() == "json" || mime.suffix().is_some_and(|name| name == "json"))
        })
}

/// `POST /v1/telemetry/events` — a batch of counted events (issue #413).
/// The body is parsed before anything else: a rejected batch costs
/// nothing and writes nothing. An accepted batch writes its aggregates in
/// one all-or-nothing call, then emits `telemetry.recorded` with counts
/// only.
async fn record(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    RawBody(bytes): RawBody,
) -> Result<Response, Problem> {
    if let Some(denied) = rate_limit(&state, &headers).await {
        return Ok(denied);
    }
    // Two different failures, two different sentences, neither of them
    // serde's: a body that is not JSON at all gets the fixed one, and a
    // body that parsed but broke the grammar gets `Rejection`'s.
    let body: Value = serde_json::from_slice(&bytes).map_err(|_| not_json_problem(&scope))?;
    let batch = Batch::parse(&body, &state.settings.vocabulary)
        .map_err(|rejection| rejection_problem(&scope, rejection))?;
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let now = now_of(&state.ctx);
    store::record_batch(&*db, &batch, &day_of(now), &rfc3339_seconds(now)).await?;
    state.ctx.events.emit_in(
        &scope,
        EVENT_RECORDED,
        json!({"events": batch.events.len(), "modules": batch.modules.len()}),
    );
    Ok(accepted())
}

/// `GET /v1/telemetry/notice` — the canonical machine-readable consent
/// notice (issue #413): the exact first-run text, the one-line opt-out and
/// status commands, both declared vocabularies, and every payload field
/// with its permitted grammar, generated from the schema so it cannot
/// drift from the parser. Unauthenticated and read-only, like the privacy
/// manifest: a notice a client must authenticate to read is not a notice,
/// and this route holds nothing the module does not publish in its own
/// binary anyway.
async fn notice(State(state): State<Arc<ModuleState>>) -> Json<Value> {
    Json(json!({
        "schema": crate::payload::SCHEMA,
        "notice": consent::notice(&state.settings),
        "opt_out_command": state.settings.opt_out_command,
        "status_command": state.settings.status_command,
        "events": state.settings.vocabulary.events,
        "modules": state.settings.vocabulary.modules,
        "fields": crate::payload::fields(&state.settings.vocabulary),
    }))
}

/// `GET /v1/telemetry/admin/usage` — the aggregate rows the collection is
/// for (issue #413). Admin-guarded exactly like the waitlist export; the
/// GROUP BY is the privacy control here, so the response has no per-install
/// row to leak.
async fn admin_usage(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
) -> Result<Response, Problem> {
    require_admin(&*state.ctx.config, &headers)
        .map_err(|problem| problem.instance(&scope.request_id))?;
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let rows = store::usage(&*db).await?;
    Ok(Json(json!({ "rows": rows })).into_response())
}
