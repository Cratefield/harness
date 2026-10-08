//! The signed receiver: `POST /v1/owlpost/events` (issue #673). A delivery
//! that does not prove itself gets the single [`UNVERIFIED`] `401` — a
//! missing header, a wrong secret and a stale timestamp are the same answer,
//! so a caller probing the endpoint learns nothing about how it is
//! configured. A verified but malformed body is a `400`.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use cratefield_adapter_owlpost::webhook::{self, OwlpostEvent};
use cratefield_core::{
    Action, Clock, DbError, Inbox, Json, ModuleContext, Problem, ProblemDef, RoutePolicy, Scope,
    Surface,
};
use serde_json::json;
use time::format_description::well_known::Rfc3339;

use crate::{InboundMail, SECRET_KEY};

/// The dedup ledger. The key is the envelope's id — from the signed body,
/// never the unauthenticated id header.
fn inbox() -> Inbox {
    Inbox::new("owlpost_inbox")
}

/// `owlpost.inbound`: mail that reached the venture, received or held. The
/// payload is an [`InboundMail`].
pub const EVENT_INBOUND: &str = "owlpost.inbound";

/// Every event this module emits: [`EVENT_INBOUND`] plus one per provider
/// delivery type, the wire's `email.<what>` as `owlpost.<what>`. A type
/// Owlpost adds later is claimed but emits nothing until it is named here.
pub const EVENTS: &[&str] = &[
    EVENT_INBOUND,
    "owlpost.sent",
    "owlpost.delivered",
    "owlpost.delivery_delayed",
    "owlpost.bounced",
    "owlpost.soft_bounced",
    "owlpost.complained",
    "owlpost.unsubscribed",
    "owlpost.rejected",
    "owlpost.opened",
    "owlpost.clicked",
    "owlpost.failed",
];

/// The one refusal for a delivery that does not prove itself.
const UNVERIFIED: ProblemDef = ProblemDef {
    slug: "owlpost-unverified",
    status: StatusCode::UNAUTHORIZED,
    title: "Unverified delivery",
    description: "The request carried no signature this deployment could verify, or one that \
                  did not hold.",
};

struct OwlpostState {
    ctx: Arc<ModuleContext>,
    hooks: crate::OwlpostEvents,
}

pub(crate) fn router(ctx: Arc<ModuleContext>, hooks: crate::OwlpostEvents) -> axum::Router {
    axum::Router::new()
        .route("/events", post(receive))
        .with_state(Arc::new(OwlpostState { ctx, hooks }))
}

pub(crate) fn surface() -> Surface {
    Surface::new().action(Action::post("event-receive", "/events").policy(RoutePolicy::Signature))
}

/// A database failure is ours and is logged, not described to the caller.
fn db_problem(error: &DbError, scope: &Scope) -> Problem {
    tracing::error!(error = %error, "owlpost: a database statement failed");
    Problem::internal().instance(&scope.request_id)
}

/// RFC 3339 UTC, second resolution — the `seen_at` the ledger stores.
fn rfc3339_now(clock: &dyn Clock) -> String {
    clock
        .now()
        .replace_nanosecond(0)
        .expect("truncation stays in range")
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// `POST /v1/owlpost/events` — one verified delivery in, events out. The
/// hook and the bus emission run **before** the [`inbox()`] claim commits:
/// a hook failure is a `5xx` with the key unclaimed, so Owlpost's retry
/// re-runs it — at-least-once (a crash between hook and claim can
/// double-run) beats at-most-once (a swallowed event).
async fn receive(
    State(state): State<Arc<OwlpostState>>,
    scope: Scope,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, Problem> {
    let Some(secret) = state
        .ctx
        .config
        .get(SECRET_KEY)
        .filter(|secret| !secret.trim().is_empty())
    else {
        // Fail closed: without a secret nothing can be verified, and
        // pretending otherwise would serve every forged delivery.
        tracing::error!("owlpost: no signing secret configured; every delivery is refused");
        return Err(
            Problem::not_ready("owlpost has no webhook signing secret configured")
                .instance(&scope.request_id),
        );
    };
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(Problem::internal().instance(&scope.request_id));
    };
    let Some(clock) = state.ctx.ports.clock.clone() else {
        return Err(Problem::internal().instance(&scope.request_id));
    };

    // Verify over the raw bytes before any JSON is read; the adapter owns
    // the scheme, the tolerance and the parse.
    let envelope = webhook::parse_verified(
        &webhook::verifier(),
        &secret,
        &headers,
        &body,
        clock.now().unix_timestamp(),
    )
    .map_err(|error| match error {
        webhook::WebhookError::Signature => Problem::new(&UNVERIFIED),
        _ => Problem::validation_failed("the body is not a well-formed owlpost delivery"),
    })?;

    if inbox()
        .seen(&*db, &envelope.id)
        .await
        .map_err(|error| db_problem(&error, &scope))?
    {
        return Ok(ok());
    }

    dispatch(&state, &scope, &envelope).await?;

    // Commits last: reaching here means every fallible step succeeded, so a
    // `false` (a concurrent delivery won the race) only means the same work
    // ran twice — still a `200`.
    inbox()
        .claim(&*db, &envelope.id, &rfc3339_now(&*clock))
        .await
        .map_err(|error| db_problem(&error, &scope))?;
    Ok(ok())
}

/// Runs the venture hook and emits the bus events for one verified delivery.
async fn dispatch(
    state: &OwlpostState,
    scope: &Scope,
    envelope: &webhook::Envelope,
) -> Result<(), Problem> {
    let mail = match &envelope.data {
        OwlpostEvent::MessageReceived(data) => InboundMail::received(data),
        OwlpostEvent::MessageHeld(data) => InboundMail::held(data),
        event => {
            if let Some(name) = delivery_event(&envelope.event_type) {
                let (message_id, to) = fields(event);
                state.ctx.events.emit_in(
                    scope,
                    name,
                    json!({
                        "event_id": envelope.id,
                        "message_id": message_id,
                        "to": to,
                        "occurred_at": envelope.created_at,
                    }),
                );
            }
            // An unknown type emits nothing; the delivery is still claimed
            // below, so its redelivery is a no-op.
            return Ok(());
        }
    };
    if let Some(hook) = state.hooks.inbound.as_ref() {
        hook(mail.clone()).await.map_err(|error| {
            tracing::warn!(error = %error, "owlpost: the inbound hook failed");
            Problem::internal().instance(&scope.request_id)
        })?;
    }
    state.ctx.events.emit_in(
        scope,
        EVENT_INBOUND,
        serde_json::to_value(mail).unwrap_or_default(),
    );
    Ok(())
}

/// The bus name for one delivery type, `email.<what>` as `owlpost.<what>`.
fn delivery_event(event_type: &str) -> Option<&'static str> {
    let suffix = event_type.strip_prefix("email.")?;
    EVENTS
        .iter()
        .copied()
        .find(|name| name.strip_prefix("owlpost.") == Some(suffix) && *name != EVENT_INBOUND)
}

/// The `message_id` and recipients of one delivery's `data`; `to` is empty
/// for the types that carry none.
fn fields(event: &OwlpostEvent) -> (&str, &[String]) {
    use OwlpostEvent as E;
    match event {
        E::EmailSent(d)
        | E::EmailDelivered(d)
        | E::EmailComplained(d)
        | E::EmailUnsubscribed(d) => (&d.message_id, &d.to),
        E::EmailDeliveryDelayed(d) | E::EmailRejected(d) | E::EmailFailed(d) => {
            (&d.message_id, &d.to)
        }
        E::EmailBounced(d) | E::EmailSoftBounced(d) => (&d.message_id, &d.to),
        E::MessageReceived(d) => (&d.message_id, &d.to),
        E::EmailOpened(d) => (&d.message_id, &[]),
        E::EmailClicked(d) => (&d.message_id, &[]),
        // Held never reaches here (it is inbound mail); the enum is
        // `#[non_exhaustive]`, so an addition arrives unknown.
        _ => ("", &[]),
    }
}

fn ok() -> Response {
    Json(json!({ "ok": true })).into_response()
}
