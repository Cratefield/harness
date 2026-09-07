# Realtime

The `Realtime` port (issue #103) is the one place the harness holds a
connection and coordinates state between requests: **rooms** of WebSocket
clients that share a clock and a chat — Yoginini's "together rooms", 2-20 people
practising the same sequence.

Everywhere else the harness is one stateless Worker over ports. Realtime is the
exception, and it is deliberately narrow.

## The split: the port owns sockets, the module owns the protocol

- A module implements **`RoomHandler`** — `on_join`, `on_message`, `on_leave`,
  `on_alarm` — and the runtime calls it as events arrive, handing it a
  **`RoomContext`** (`broadcast`, `send`, `members`, `set_alarm`).
- A module's ordinary HTTP handlers poke a room from outside a socket through
  the **`Realtime`** port (`broadcast`, `members`) held via `Ports`.
- A `RoomHandler` holds no socket itself — it reaches them only through the
  context it is handed — so a hibernating Durable Object can drop the handler
  between events and reconstruct it on the next. **Implementations must be
  stateless**; durable state is the module's to write to the database (the room
  is a coordinator, not the record).

Members are identified only *after* the venture verifies the upgrade's bearer
token (through the `Signer` or the auth client); a handler sees a verified
`Member { id }`, never a raw token.

## Native runtime (self-hosting): `InProcessRealtime`

`cratefield_runtime_native::InProcessRealtime` keeps every room's connected
members and their outgoing channels in this process. `connect(room_id, member)`
registers a socket and returns a `Connection` the server pumps (`next_outgoing`
to the wire, `deliver` from it, `close` to leave); `set_alarm` is a `tokio`
timer. This is the adapter the conformance suite runs against — join, broadcast
to N, a message reaching the other members, leave runs `on_leave`, an alarm
fires exactly once, and a message from a departed member is refused
(`RealtimeError::NotAMember`).

## Cloudflare runtime: Durable Object (in progress)

On Workers a **Durable Object** holds the sockets, using the WebSocket
hibernation API so an idle room costs nothing, and DO alarms for the shared
clock. Because the harness forbids `unsafe` and a DO's `State`/`WebSocket`
handles are `!Send`, the `RoomContext: Send + Sync` bound needs a
`SendWrapper`-style bridge (as `worker` does internally); the DO class itself is
declared in the venture (the `#[durable_object]` macro needs a concrete type),
with the runtime providing the driver that walks a `RoomHandler` through the
hibernation callbacks.

**Status:** the DO adapter is being built; like every Workers adapter it must be
proven in `wrangler dev` with two live sockets before it is trusted (issue #103
acceptance — `cargo test` and `worker-build` cannot exercise a real socket).
Until then, `InProcessRealtime` is the working, tested adapter.

## Not in scope

Audio and video — a venture uses a media provider for those, outside the
harness.
