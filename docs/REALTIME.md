# Realtime: rooms of WebSocket clients

The `Realtime` port (issue #103). The harness is otherwise one stateless Worker
over ports, with no way to hold a connection or coordinate between two requests.
This port is the exception, and it is shaped by that: the port owns the sockets,
the module owns the protocol.

A module implements `RoomHandler` — `on_join`, `on_message`, `on_leave`,
`on_alarm` — and the runtime calls it as events arrive, handing it a
`RoomContext` to reach the sockets. A module's ordinary HTTP handlers poke a room
from outside a socket through `Realtime` (`broadcast`, `members`).

**The handler holds no socket.** It reaches them only through the context it is
handed, which is what lets a hibernating Durable Object drop the handler between
two events and rebuild it on the next.

## On Cloudflare

One Durable Object class per venture. `cratefield-runtime-cloudflare` ships
`RoomDriver`; the class itself lives in the venture, because `#[durable_object]`
is a `wasm_bindgen` export and a library crate cannot declare one on a venture's
behalf. `examples/venture/src/rooms.rs` is a complete one, and it is four
forwarding methods.

```rust
#[durable_object]
pub struct Rooms { state: State, driver: RoomDriver }

impl DurableObject for Rooms {
    fn new(state: State, _env: Env) -> Self {
        Self { state, driver: RoomDriver::new(Arc::new(MyRooms)) }
    }
    async fn fetch(&self, req: Request) -> Result<Response> {
        let member = verify(&req)?;                 // the venture's job
        self.driver.upgrade(&self.state, &member).await
    }
    async fn websocket_message(&self, ws: WebSocket, m: WebSocketIncomingMessage)
        -> Result<()> { self.driver.message(&self.state, &ws, m).await }
    async fn websocket_close(&self, ws: WebSocket, _c: usize, _r: String, _w: bool)
        -> Result<()> { self.driver.close(&self.state, &ws).await }
    async fn alarm(&self) -> Result<Response> { self.driver.alarm(&self.state).await }
}
```

The venture routes the upgrade to the object rather than to the harness router,
because the room id is the name that picks which object — two people asking for
`/rooms/sunrise` have to land in the same one.

**That route is in front of the harness router, so nothing the router does
applies to it**: not CORS, not the security headers, not the rate limiter, not
the request id. Whatever the venture needs on that path, the venture puts there.
At a minimum:

```rust
let prefix = format!("{}/", rooms::route());     // the handler says where, not you
if let Some(room) = req.path().strip_prefix(&prefix) {
    // 1. An upgrade, or a curl is accepted as a socket and broadcasts a join
    //    to the real members of a room it is not in.
    if header(&req, "upgrade") != "websocket" {
        return Response::error("this endpoint takes a websocket upgrade", 426);
    }
    // 2. A bounded name. `id_from_name` takes whatever it is given, so an
    //    unbounded id from a URL is an unbounded number of billable objects.
    if !is_a_room_name(room) {
        return Response::error("not a room name", 400);
    }
    // 3. The member, verified. This is the venture's: it holds the signer and
    //    the auth client and knows which issuer this room trusts. The driver
    //    never sees a token, and the handler only ever sees the id that came
    //    out of one.
    let Ok(namespace) = env.durable_object("ROOMS") else {
        return Response::error("realtime is not configured", 503);  // not a 500
    };
    return namespace.id_from_name(room)?.get_stub()?.fetch_with_request(req).await;
}
```

`examples/venture/src/rooms.rs` has all three. It reads the member from a query
parameter because it is a canary with no accounts in it, and it says so where it
does it — **do not copy that part.**

`wrangler.toml` needs the binding and a migration declaring the class:

```toml
[[durable_objects.bindings]]
name = "ROOMS"
class_name = "Rooms"

[[migrations]]
tag = "v1"
new_sqlite_classes = ["Rooms"]
```

### Identity is a socket tag

The member a socket belongs to is stored as the socket's tag when it is
accepted, and read back out of the socket on every event. That is not a
convenience: **an idle room costs nothing because the runtime evicts the object
and keeps only the sockets**, so anything the driver held in memory is gone by
the next message. Tags survive hibernation. `get_websockets_with_tag` is also
how `send(member_id)` finds one member's sockets.

### The driver never verifies a token

`upgrade` takes a `Member` the venture has already established. Verification is
the venture's: it holds the signer and the auth client and knows which of the two
a given room trusts. A driver that accepted a raw token would be making that
decision on the venture's behalf, and the handler would have to be trusted with
a credential it has no reason to see.

### The object is a coordinator, not the record

Anything that must survive the room — a chat transcript — is the module's job to
write to the database. Room state is ephemeral coordination, and a Durable
Object's storage is not a backup of your data.

### What is not built on Cloudflare

`Realtime` — `broadcast` and `members` called from an ordinary HTTP handler
rather than from inside a socket — has **no Workers adapter**. Reaching a room
from outside means fetching the object's stub with an internal request, and
that needs a protocol between the Worker and the object, and something to stop
anything else speaking it. `Cloudflare::provides()` therefore does not list
`Port::Realtime`, so a module that puts it in `optional()` — the notifications
module does, to push inbox updates into a room — gets `None` on Workers and
degrades, which is what `optional()` is for. The native runtime has both halves.

## On the native runtime

`InProcessRealtime` in `cratefield-runtime-native`: a registry of rooms over
tokio channels, good enough for self-hosting and for the tests.

## How each half is proven, and why they are proven differently

The native adapter is covered by ordinary Rust tests in
`crates/runtime-native/src/ports/realtime.rs`: join broadcasts to every member,
leaving runs `on_leave` and removes the member, an alarm fires exactly once, and
a message from a non-member is refused.

**The Cloudflare adapter cannot be covered that way, and that is the point of the
issue's second acceptance criterion.** A Durable Object is a runtime object, not
a Rust type you can construct: `cargo test` cannot reach one, and a test that
faked it would be testing the fake. So CI boots `examples/venture` under
`wrangler dev --local` and runs `examples/venture/rooms-smoke.mjs`, which opens
**two** sockets — because everything that matters here is what one socket sees
when the other one acts — and asserts that a join reaches the other member, that
a message arrives tagged with who sent it, that the alarm fires once rather than
once per join, and that a leave reaches whoever is left.

One thing that smoke test learned the hard way: the port carries bytes, so a
browser hands frames back as a `Blob` unless told otherwise, and reading
`String(event.data)` gives you `"[object Blob]"` — an assertion that passes
about nothing.

## Not in the port

Media. Audio and video belong to a provider; this port carries messages.
