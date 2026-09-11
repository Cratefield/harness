//! The `Realtime` port on Cloudflare: a Durable Object holds the sockets
//! (issue #103).
//!
//! **The Durable Object class lives in the venture, not here.** `#[durable_object]`
//! is a `wasm_bindgen` export, and a library crate cannot export one on a
//! venture's behalf — the class has to be declared in the crate that is compiled
//! into the Worker. So this ships the driver: a venture writes a small class and
//! forwards each of its four entry points to [`RoomDriver`], which owns the
//! protocol, the member identity and the calls into the module's
//! [`RoomHandler`].
//!
//! ```ignore
//! #[durable_object]
//! pub struct Rooms { state: State, driver: RoomDriver }
//!
//! impl DurableObject for Rooms {
//!     fn new(state: State, _env: Env) -> Self {
//!         Self { state, driver: RoomDriver::new(Arc::new(MyRooms)) }
//!     }
//!     async fn fetch(&self, req: Request) -> Result<Response> {
//!         let member = verify(&req)?;            // the venture's job, see below
//!         self.driver.upgrade(&self.state, &member).await
//!     }
//!     async fn websocket_message(&self, ws: WebSocket, message: WebSocketIncomingMessage)
//!         -> Result<()> { self.driver.message(&self.state, &ws, message).await }
//!     async fn websocket_close(&self, ws: WebSocket, _c: usize, _r: String, _w: bool)
//!         -> Result<()> { self.driver.close(&self.state, &ws).await }
//!     async fn alarm(&self) -> Result<Response> { self.driver.alarm(&self.state).await }
//! }
//! ```
//!
//! **Identity is a socket tag, and that is what makes hibernation work.** An
//! idle room costs nothing because the runtime evicts the object and keeps only
//! the sockets; anything the driver held in memory is gone by the next message.
//! Tags survive that, so the member a socket belongs to is stored as its tag
//! when it is accepted and read back out of the socket on every event. It is
//! also what `send(member_id)` uses, through `get_websockets_with_tag`.
//!
//! **The driver never verifies a token.** `upgrade` takes a [`Member`] the
//! venture has already established from the request, because verification is
//! the venture's — it holds the signer, and the auth client, and knows which of
//! the two this room trusts. A driver that accepted a raw token would be
//! guessing at that on the venture's behalf.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cratefield_core::{Member, RealtimeError, RoomContext, RoomHandler};
use worker::send::IntoSendFuture;
use worker::{
    Response, Result as WorkerResult, State, WebSocket, WebSocketIncomingMessage, WebSocketPair,
};

/// Forwards a Durable Object's four entry points to a module's [`RoomHandler`].
pub struct RoomDriver {
    handler: Arc<dyn RoomHandler>,
}

impl RoomDriver {
    #[must_use]
    pub fn new(handler: Arc<dyn RoomHandler>) -> Self {
        Self { handler }
    }

    /// Accept the upgrade and join `member` to the room.
    ///
    /// `accept_websocket_with_tags` rather than `accept_web_socket`: the tag is
    /// the member id, and it is the only thing that survives hibernation.
    ///
    /// # Errors
    /// When the socket pair cannot be created, or the handler refuses the join —
    /// in which case the socket is closed before the error is returned, because
    /// the client is already holding one end of an open pair.
    pub async fn upgrade(&self, state: &State, member: &Member) -> WorkerResult<Response> {
        let pair = WebSocketPair::new()?;
        state.accept_websocket_with_tags(&pair.server, &[member.id.as_str()]);

        let ctx = DurableRoomContext::new(state);
        if let Err(error) = self.handler.on_join(&ctx, member).await {
            // The socket is already accepted, so a handler that refuses the join
            // has to be answered by closing it rather than by failing the
            // upgrade: the client is holding one end of an open pair.
            let _ = pair.server.close(Some(1011), Some(error.to_string()));
            return Err(worker::Error::RustError(error.to_string()));
        }
        Response::from_websocket(pair.client)
    }

    /// A frame arrived. Text and binary both reach the handler as bytes; the
    /// module owns the protocol, so the framing distinction is not its business.
    ///
    /// # Errors
    /// When the module's handler returns one. A frame from a socket carrying no
    /// member tag is dropped rather than failed: it is one this driver never
    /// accepted.
    pub async fn message(
        &self,
        state: &State,
        ws: &WebSocket,
        message: WebSocketIncomingMessage,
    ) -> WorkerResult<()> {
        let Some(member) = member_of(state, ws) else {
            // A socket with no tag is one this driver never accepted. Dropping
            // the frame is `RealtimeError::NotAMember` by another name.
            return Ok(());
        };
        let bytes = match message {
            WebSocketIncomingMessage::String(text) => text.into_bytes(),
            WebSocketIncomingMessage::Binary(bytes) => bytes,
        };
        let ctx = DurableRoomContext::new(state);
        self.handler
            .on_message(&ctx, &member, &bytes)
            .await
            .map_err(|error| into_worker(&error))
    }

    /// The socket closed, by either end.
    ///
    /// # Errors
    /// When the module's handler returns one.
    pub async fn close(&self, state: &State, ws: &WebSocket) -> WorkerResult<()> {
        let Some(member) = member_of(state, ws) else {
            return Ok(());
        };
        let ctx = DurableRoomContext::new(state);
        self.handler
            .on_leave(&ctx, &member)
            .await
            .map_err(|error| into_worker(&error))
    }

    /// The shared clock ticked.
    ///
    /// # Errors
    /// When the module's handler returns one.
    pub async fn alarm(&self, state: &State) -> WorkerResult<Response> {
        let ctx = DurableRoomContext::new(state);
        self.handler
            .on_alarm(&ctx)
            .await
            .map_err(|error| into_worker(&error))?;
        Response::empty()
    }
}

/// The member a socket belongs to, from its tag.
fn member_of(state: &State, ws: &WebSocket) -> Option<Member> {
    state.get_tags(ws).into_iter().next().map(Member::new)
}

fn into_worker(error: &RealtimeError) -> worker::Error {
    worker::Error::RustError(error.to_string())
}

/// [`RoomContext`] over a Durable Object's live sockets.
///
/// Borrows the state rather than owning anything: every call reads the sockets
/// back out of the object, because between two events the object may have
/// hibernated and any list this held would name sockets that no longer exist.
struct DurableRoomContext<'a> {
    state: &'a State,
}

impl<'a> DurableRoomContext<'a> {
    fn new(state: &'a State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl RoomContext for DurableRoomContext<'_> {
    fn room_id(&self) -> &str {
        // The object *is* the room: a Durable Object id is the room id, and the
        // venture routed the request to this object by name. The driver is
        // inside one room and has no second one to confuse it with.
        self.state.id().name().unwrap_or_default().leak()
    }

    async fn members(&self) -> Vec<Member> {
        self.state
            .get_websockets()
            .iter()
            .filter_map(|ws| member_of(self.state, ws))
            .collect()
    }

    async fn broadcast(&self, message: &[u8]) -> Result<(), RealtimeError> {
        for ws in self.state.get_websockets() {
            // One socket that will not take a frame does not stop the others:
            // a broadcast to a room where one phone has gone into a tunnel has
            // still reached everybody it could.
            let _ = ws.send_with_bytes(message);
        }
        Ok(())
    }

    async fn send(&self, member_id: &str, message: &[u8]) -> Result<(), RealtimeError> {
        let sockets = self.state.get_websockets_with_tag(member_id);
        if sockets.is_empty() {
            return Err(RealtimeError::NotAMember);
        }
        for ws in sockets {
            ws.send_with_bytes(message)
                .map_err(|error| RealtimeError::Operation(error.to_string()))?;
        }
        Ok(())
    }

    async fn set_alarm(&self, delay: Duration) -> Result<(), RealtimeError> {
        // `set_alarm` returns a JS promise, whose future is `!Send`, and
        // `RoomContext` is `Send + Sync` because a module's handler is. Workers
        // is single-threaded, which is what makes the bridge sound rather than a
        // hole — the same `worker::send` helper `D1Database` uses, so this crate
        // still needs no `unsafe` under its `forbid(unsafe_code)`.
        self.state
            .storage()
            .set_alarm(delay)
            .into_send()
            .await
            .map_err(|error| RealtimeError::Operation(error.to_string()))
    }
}
