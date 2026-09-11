//! A together room, as a Durable Object (issue #103).
//!
//! This is the half of the `Realtime` port that cannot live in a library: a
//! `#[durable_object]` class is a `wasm_bindgen` export and has to be declared
//! in the crate compiled into the Worker. So the venture writes the class and
//! forwards its five entry points to [`RoomDriver`], which owns everything else.
//!
//! CI boots this under `wrangler dev --local` and opens two sockets against it,
//! because a Durable Object is the one thing in this repository `cargo test`
//! cannot reach — the same reason the D1 path has a `wrangler dev` job at all.

use cratefield::cloudflare::RoomDriver;
use cratefield::{Member, RealtimeError, RoomContext, RoomHandler};
use std::sync::Arc;
use std::time::Duration;
use worker::{
    DurableObject, Env, Request, Response, Result, State, WebSocket, WebSocketIncomingMessage,
    durable_object,
};

/// The protocol: everything said in the room is repeated to the room, prefixed
/// with who said it, and joining arms a one-shot alarm that announces the tick.
///
/// Deliberately the smallest thing that exercises all four callbacks — a real
/// module's protocol is its own business, which is the point of the split.
struct Echo;

#[async_trait::async_trait]
impl RoomHandler for Echo {
    async fn on_join(&self, ctx: &dyn RoomContext, member: &Member) -> Result2 {
        ctx.broadcast(format!("joined:{}", member.id).as_bytes())
            .await?;
        // **Armed on the first arrival only.** `set_alarm` replaces the pending
        // one, so re-arming on every join pushes the tick out by another second
        // each time somebody arrives: in a room people are still joining, the
        // shared clock never fires at all.
        if ctx.members().await.len() == 1 {
            ctx.set_alarm(Duration::from_secs(1)).await?;
        }
        Ok(())
    }

    async fn on_message(&self, ctx: &dyn RoomContext, member: &Member, message: &[u8]) -> Result2 {
        let said = String::from_utf8_lossy(message);
        // `who` and `where` answer on the two context methods nothing else here
        // touches. They are in the example because the smoke test is the only
        // thing that can reach this adapter at all, and a method it never calls
        // is a method with no coverage on the runtime that ships.
        if said == "who" {
            let names: Vec<String> = ctx.members().await.into_iter().map(|m| m.id).collect();
            return ctx
                .send(
                    &member.id,
                    format!("members:{}", names.join(",")).as_bytes(),
                )
                .await;
        }
        if said == "where" {
            return ctx
                .send(&member.id, format!("room:{}", ctx.room_id()).as_bytes())
                .await;
        }
        ctx.broadcast(format!("{}:{said}", member.id).as_bytes())
            .await
    }

    async fn on_leave(&self, ctx: &dyn RoomContext, member: &Member) -> Result2 {
        ctx.broadcast(format!("left:{}", member.id).as_bytes())
            .await
    }

    async fn on_alarm(&self, ctx: &dyn RoomContext) -> Result2 {
        ctx.broadcast(b"tick").await?;
        // **Re-armed, or it is not a clock.** An alarm is one-shot; a shared
        // clock that ticks once and stops is no use to twenty people moving
        // through a sequence together. An empty room stops waking up because the
        // driver clears the alarm when the last socket goes.
        if ctx.members().await.is_empty() {
            return Ok(());
        }
        ctx.set_alarm(Duration::from_secs(1)).await
    }
}

type Result2 = std::result::Result<(), RealtimeError>;

/// The prefix the room handler declares, which is where the venture mounts it.
#[must_use]
pub fn route() -> &'static str {
    RoomDriver::new(std::sync::Arc::new(Echo)).route()
}

/// Route an upgrade to the object that is this room.
///
/// **Three guards, and each of them is a thing that goes wrong without it.**
///
/// - **`Upgrade: websocket` is required.** Without it a plain `curl` is accepted
///   as a socket, fires `on_join`, and broadcasts a join to the real members of
///   a room it is not in.
/// - **The room id is bounded.** `id_from_name` takes whatever it is given, so
///   an unbounded id from a URL is an unbounded number of billable Durable
///   Objects for anyone who can write a loop.
/// - **A missing binding is not configured, not a 500.** The port has
///   `RealtimeError::NotConfigured` precisely so a caller can degrade.
///
/// It does **not** verify the member, and that is the one thing this example
/// gets to skip: it has no accounts. A real venture verifies the upgrade
/// request's bearer token through its signer or the auth client and passes the
/// id that comes out — see `docs/REALTIME.md`. The query parameter below is a
/// canary's shortcut and is labelled as one wherever it appears.
///
/// # Errors
/// When the object cannot be reached.
pub async fn route_upgrade(room: &str, req: Request, env: &Env) -> Result<Response> {
    // The name first: it is the cheaper check, it needs no headers, and it is
    // the one that stops an unbounded number of billable objects being minted —
    // which should not depend on the caller having sent an upgrade header.
    if !is_a_room_name(room) {
        return Response::error("not a room name", 400);
    }
    let upgrade = req
        .headers()
        .get("upgrade")
        .ok()
        .flatten()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if upgrade != "websocket" {
        return Response::error("this endpoint takes a websocket upgrade", 426);
    }
    let Ok(namespace) = env.durable_object("ROOMS") else {
        // `RealtimeError::NotConfigured` on the port; 503 here, so a venture
        // without the binding degrades rather than looking broken.
        return Response::error("realtime is not configured", 503);
    };
    namespace
        .id_from_name(room)?
        .get_stub()?
        .fetch_with_request(req)
        .await
}

/// Short, lowercase, and nothing that could be mistaken for a path.
fn is_a_room_name(room: &str) -> bool {
    !room.is_empty()
        && room.len() <= 64
        && room
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[durable_object]
pub struct Rooms {
    state: State,
    driver: RoomDriver,
}

impl DurableObject for Rooms {
    fn new(state: State, _env: Env) -> Self {
        Self {
            state,
            driver: RoomDriver::new(Arc::new(Echo)),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        // **The venture establishes the member, not the driver.** Here it is a
        // query parameter, because this is a canary with no accounts in it. A
        // real venture verifies the upgrade request's bearer token through its
        // signer or the auth client and passes the id that comes out; the driver
        // never sees a token, which is what keeps that decision the venture's.
        let url = req.url()?;
        let member = url
            .query_pairs()
            .find(|(key, _)| key == "member")
            .map(|(_, value)| Member::new(value.into_owned()))
            .ok_or_else(|| worker::Error::RustError("no member".to_owned()))?;
        self.driver.upgrade(&self.state, &member).await
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        self.driver.message(&self.state, &ws, message).await
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        self.driver.close(&self.state, &ws).await
    }

    async fn websocket_error(&self, ws: WebSocket, _error: worker::Error) -> Result<()> {
        // **Five entry points, not four.** The macro binds this one whether or
        // not it is written, and the trait's default body is `unimplemented!()`,
        // so leaving it out means one member's phone dropping off panics the
        // object and every other socket in the room dies with it.
        self.driver.error(&self.state, &ws).await
    }

    async fn alarm(&self) -> Result<Response> {
        self.driver.alarm(&self.state).await
    }
}
