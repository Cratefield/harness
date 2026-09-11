//! A together room, as a Durable Object (issue #103).
//!
//! This is the half of the `Realtime` port that cannot live in a library: a
//! `#[durable_object]` class is a `wasm_bindgen` export and has to be declared
//! in the crate compiled into the Worker. So the venture writes the class and
//! forwards its four entry points to [`RoomDriver`], which owns everything else.
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
        // The shared clock. One second is long enough that a test can prove it
        // fired once rather than on every event.
        ctx.set_alarm(Duration::from_secs(1)).await
    }

    async fn on_message(&self, ctx: &dyn RoomContext, member: &Member, message: &[u8]) -> Result2 {
        let said = String::from_utf8_lossy(message);
        ctx.broadcast(format!("{}:{said}", member.id).as_bytes())
            .await
    }

    async fn on_leave(&self, ctx: &dyn RoomContext, member: &Member) -> Result2 {
        ctx.broadcast(format!("left:{}", member.id).as_bytes())
            .await
    }

    async fn on_alarm(&self, ctx: &dyn RoomContext) -> Result2 {
        ctx.broadcast(b"tick").await
    }
}

type Result2 = std::result::Result<(), RealtimeError>;

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

    async fn alarm(&self) -> Result<Response> {
        self.driver.alarm(&self.state).await
    }
}
