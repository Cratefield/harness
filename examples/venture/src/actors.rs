//! Actors, as Durable Objects (issue #583).
//!
//! This is the half of the `Actors` port that cannot live in a library: a
//! `#[durable_object]` class is a `wasm_bindgen` export and has to be
//! declared in the crate compiled into the Worker. So the venture writes the
//! class and forwards its two entry points to [`ActorDriver`], which owns
//! everything else — the signature check, the frame, and the store over
//! `state.storage()`.
//!
//! The handlers themselves are the venture's. They are registered twice
//! against one [`actor_handlers`]: once here, so the object that serves a
//! call can dispatch it, and once on the harness builder in `lib.rs`. The
//! builder registration is not yet served by an in-process host — the native
//! runtime wires no `Actor` port (#584), so only the Durable Object answers
//! today — but it is built from the same list the object serves, so the kinds
//! the object dispatches and the kinds the builder declares cannot drift.
//!
//! CI boots this under `wrangler dev --local` and drives `actors-smoke.mjs`:
//! a Durable Object is the one thing in this repository `cargo test` cannot
//! reach, the same reason the D1 and room paths have a `wrangler dev` job.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use cratefield::cloudflare::ActorDriver;
use cratefield::{
    ActorContext, ActorError, ActorHandler, ActorHandlers, Config, ConfigError, Json, Migrations,
    Module, ModuleContext, Port, Problem, Scope,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use worker::{DurableObject, Env, Request, Response, Result, State as WorkerState, durable_object};

/// The counter: `inc` bumps and returns the new total, `read` returns it
/// without writing. Nothing is staged on a `read`, so a read commits nothing
/// — which is the core's all-or-nothing rule doing its job rather than the
/// handler's.
///
/// Every write goes through the object's single-threaded message loop, so
/// fifty `inc`s arriving at once become fifty increments with no lock here.
struct Counter;

/// The message that bumps the counter.
const INC: &[u8] = b"inc";
/// The message that reads it.
const READ: &[u8] = b"read";

#[async_trait::async_trait]
impl ActorHandler for Counter {
    async fn on_message(
        &self,
        ctx: &mut dyn ActorContext,
        message: &[u8],
    ) -> Result<Vec<u8>, ActorError> {
        let count = |bytes: &[u8]| -> u64 {
            std::str::from_utf8(bytes)
                .ok()
                .and_then(|text| text.parse().ok())
                .unwrap_or(0)
        };
        let mut value = ctx.get("count").await?.as_deref().map_or(0, count);
        match message {
            INC => {
                value += 1;
                ctx.put("count", value.to_string().into_bytes()).await?;
            }
            READ => {}
            other => {
                return Err(ActorError::Handler(format!(
                    "a counter takes `inc` or `read`, not `{}`",
                    String::from_utf8_lossy(other)
                )));
            }
        }
        Ok(value.to_string().into_bytes())
    }

    async fn on_alarm(&self, _ctx: &mut dyn ActorContext) -> Result<(), ActorError> {
        // A counter never arms an alarm, so nothing fires one. A handler that
        // did somehow get woken stages nothing and leaves no alarm set.
        Ok(())
    }
}

/// The expiring value: `put` (a message of the form `<ttl_ms>:<value>`)
/// stores the value and arms the alarm `ttl_ms` out; the fired alarm calls
/// `delete_all`, emptying the actor; `get` reads the value, or the empty
/// string once it has expired.
///
/// This is the one demo kind that exercises the alarm at all — the counter
/// exercises the serialization — which is why the smoke waits out a real
/// one-second alarm rather than reading the value back immediately.
struct Expiring;

/// The message that reads the value.
const GET: &[u8] = b"get";

#[async_trait::async_trait]
impl ActorHandler for Expiring {
    async fn on_message(
        &self,
        ctx: &mut dyn ActorContext,
        message: &[u8],
    ) -> Result<Vec<u8>, ActorError> {
        if message == GET {
            return Ok(ctx.get("value").await?.unwrap_or_default());
        }
        let text = std::str::from_utf8(message)
            .map_err(|_| ActorError::Handler("an expiring message is not utf-8".to_owned()))?;
        let (ttl, value) = text.split_once(':').ok_or_else(|| {
            ActorError::Handler("an expiring put is `<ttl_ms>:<value>`".to_owned())
        })?;
        let ttl: i64 = ttl.parse().map_err(|_| {
            ActorError::Handler("the ttl is not a number of milliseconds".to_owned())
        })?;
        ctx.put("value", value.as_bytes().to_vec()).await?;
        ctx.set_alarm(ctx.now() + time::Duration::milliseconds(ttl))
            .await?;
        Ok(b"ok".to_vec())
    }

    async fn on_alarm(&self, ctx: &mut dyn ActorContext) -> Result<(), ActorError> {
        ctx.delete_all().await
    }
}

/// The handlers the object and the harness builder share, so a kind is
/// defined once wherever it is dispatched. On Cloudflare the object is the
/// only thing that actually serves a call — the native runtime wires no
/// `Actor` port yet (#584) — but the builder still receives the same list, so
/// the two cannot drift.
#[must_use]
pub fn actor_handlers() -> ActorHandlers {
    ActorHandlers::new()
        .with("counter", Arc::new(Counter))
        .with("expiring", Arc::new(Expiring))
}

/// Registers every kind against a harness builder, from the same
/// [`actor_handlers`] the object serves with — so the kinds the object
/// dispatches and the kinds the harness knows about are one list, and neither
/// can grow a kind the other lacks. Only the object serves a call today: the
/// native runtime wires no `Actor` port (#584), so a native build declares
/// the port and finds it unwired.
#[must_use]
pub fn register(builder: cratefield::HarnessBuilder) -> cratefield::HarnessBuilder {
    let handlers = actor_handlers();
    let mut builder = builder;
    for kind in handlers.kinds() {
        // `kinds()` yields exactly the keys `with` inserted, so the lookup
        // always finds one; `if let` rather than `expect` so a future edit
        // that breaks that pairing skips a kind instead of panicking at
        // cold start.
        if let Some(handler) = handlers.get(kind) {
            builder = builder.actor(kind, handler);
        }
    }
    builder
}

/// The object that serves every actor kind: one class, one binding, the kind
/// carried in the name (`"<kind>:<key>"`) rather than in the class.
#[durable_object]
pub struct Actors {
    driver: ActorDriver,
}

impl DurableObject for Actors {
    fn new(state: WorkerState, env: Env) -> Self {
        Self {
            driver: ActorDriver::new(state, &env, actor_handlers()),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        self.driver.fetch(req).await
    }

    async fn alarm(&self) -> Result<Response> {
        self.driver.alarm().await
    }
}

/// Forwards an **unsigned** `POST` straight to the `counter` object for `key`
/// and returns whatever the object answers — which is a `403`, because the
/// driver verifies the signature before it reads a byte of the frame. The
/// route exists so CI can watch the refusal on a real Workers request; a
/// signed call never reaches it, because the client signs inside the port.
///
/// **It is a Worker route, not a module route, and that is forced.** A
/// module is handed a [`ModuleContext`] — ports and config — and never the
/// `Env`, which is per-request state ADR 0007 keeps out of a module: a module
/// that could name a binding directly would be reaching past its ports. Naming
/// `env.durable_object("ACTORS")` can only happen where `env` is in hand, so
/// the raw-binding probe lives where the binding is, beside the `/rooms/`
/// upgrade the same reasoning puts in `lib.rs`.
///
/// # Errors
/// When the object cannot be reached. A missing binding is `503`, not a 500.
pub async fn route_unsigned(key: &str, req: Request, env: &Env) -> Result<Response> {
    // Bounded before the name is used: `id_from_name` takes whatever it is
    // given, so an unbounded key from a URL is an unbounded number of billable
    // Durable Objects for anyone who can write a loop. The kind is fixed here,
    // so only the key is attacker-reachable.
    if !is_a_counter_key(key) {
        return Response::error("not a counter key", 400);
    }
    let Ok(namespace) = env.durable_object("ACTORS") else {
        return Response::error("actors are not configured", 503);
    };
    let name = format!("counter:{key}");
    namespace
        .id_from_name(&name)?
        .get_stub()?
        .fetch_with_request(req)
        .await
}

/// Short, lowercase, and nothing that could be mistaken for a path.
fn is_a_counter_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 64
        && key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The demo module: two kinds, four routes, all reaching the `Actors` port.
///
/// It declares `counter` and `expiring` in `actor_kinds()`, so the harness
/// scopes its view to exactly those — a route that named another module's
/// kind would be refused before it reached the host.
pub struct ActorModule;

impl Module for ActorModule {
    fn name(&self) -> &'static str {
        "actors"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Actor]
    }

    fn actor_kinds(&self) -> &'static [&'static str] {
        &["counter", "expiring"]
    }

    fn migrations(&self) -> Migrations {
        Migrations {
            sqlite: &[],
            postgres: &[],
        }
    }

    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let state = Arc::new(ctx);
        axum::Router::new()
            .route(
                "/counter/{key}/inc",
                post(inc_counter).with_state(Arc::clone(&state)),
            )
            .route(
                "/counter/{key}",
                get(read_counter).with_state(Arc::clone(&state)),
            )
            .route(
                "/expiring/{key}",
                post(put_expiring).with_state(Arc::clone(&state)),
            )
            .route(
                "/expiring/{key}/read",
                get(read_expiring).with_state(Arc::clone(&state)),
            )
    }
}

/// Maps an actor failure onto a problem, the way the port's own errors read:
/// a missing host is `503`, an oversized call `413`, a timeout `503`, and a
/// handler or operation failure the generic `500`. Logged because on wasm32 a
/// module's `tracing` is dropped (issue #107) and on native it is not — the
/// answer is what CI reads either way.
fn actor_problem(scope: &Scope, error: &ActorError) -> Problem {
    tracing::error!(error = %error, "actor call failed");
    let problem = match error {
        ActorError::NotConfigured => Problem::not_ready("no actor host is configured"),
        ActorError::TooLarge(_) => Problem::request_too_large(),
        ActorError::Timeout => Problem::not_ready("the actor call timed out"),
        ActorError::Handler(_) | ActorError::Operation(_) => Problem::internal(),
    };
    problem.instance(&scope.request_id)
}

/// The port, or the `503` the module gives when the runtime wired none.
fn port(scope: &Scope, ctx: &ModuleContext) -> Result<Arc<dyn cratefield::Actors>, Problem> {
    ctx.ports
        .actors
        .clone()
        .ok_or_else(|| actor_problem(scope, &ActorError::NotConfigured))
}

async fn inc_counter(
    scope: Scope,
    Path(key): Path<String>,
    State(ctx): State<Arc<ModuleContext>>,
) -> Result<Json<serde_json::Value>, Problem> {
    let actors = port(&scope, &ctx)?;
    let reply = actors
        .call("counter", &key, INC)
        .await
        .map_err(|error| actor_problem(&scope, &error))?;
    Ok(Json(json!({ "value": as_u64(&reply) })))
}

async fn read_counter(
    scope: Scope,
    Path(key): Path<String>,
    State(ctx): State<Arc<ModuleContext>>,
) -> Result<Json<serde_json::Value>, Problem> {
    let actors = port(&scope, &ctx)?;
    let reply = actors
        .call("counter", &key, READ)
        .await
        .map_err(|error| actor_problem(&scope, &error))?;
    Ok(Json(json!({ "value": as_u64(&reply) })))
}

#[derive(Deserialize)]
struct PutExpiring {
    value: String,
    ttl_ms: u64,
}

async fn put_expiring(
    scope: Scope,
    Path(key): Path<String>,
    State(ctx): State<Arc<ModuleContext>>,
    Json(body): Json<PutExpiring>,
) -> Result<Json<serde_json::Value>, Problem> {
    let actors = port(&scope, &ctx)?;
    // The one message shape the handler parses: the ttl in milliseconds, a
    // colon, then the value verbatim.
    let message = format!("{}:{}", body.ttl_ms, body.value);
    actors
        .call("expiring", &key, message.as_bytes())
        .await
        .map_err(|error| actor_problem(&scope, &error))?;
    Ok(Json(json!({ "stored": body.value, "ttl_ms": body.ttl_ms })))
}

async fn read_expiring(
    scope: Scope,
    Path(key): Path<String>,
    State(ctx): State<Arc<ModuleContext>>,
) -> Result<Json<serde_json::Value>, Problem> {
    let actors = port(&scope, &ctx)?;
    let reply = actors
        .call("expiring", &key, GET)
        .await
        .map_err(|error| actor_problem(&scope, &error))?;
    // Empty once the alarm has fired, which is how the smoke tells a live
    // value from an expired one — the object itself is what forgot it.
    Ok(Json(json!({
        "value": String::from_utf8_lossy(&reply),
    })))
}

fn as_u64(reply: &[u8]) -> u64 {
    std::str::from_utf8(reply)
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(0)
}
