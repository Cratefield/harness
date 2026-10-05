# Actors: per-key serialized state with an alarm

The `Actors` port (issue #583). An **actor** is one `(kind, key)` — a name a
module picks — whose calls the host runs **one at a time** and whose writes the
host applies **all-or-nothing**. No two calls for one `(kind, key)` run at once,
so a handler keeps a counter, a cursor or a small state machine consistent with
no locking. Each actor has **one alarm**, a single time it asks to be woken at,
re-armed by a handler or cancelled by not re-arming. The host owns serialization
and durability; the module owns the handler — the `Realtime` split again, which
is why the trait sits behind the runtime.

## When to use one, and when not to

Use an actor when state must survive a **read-modify-write** and a lost update is
the bug: a counter, a cursor, a lease that expires, a small per-key state machine.

Often you do not need one. A **guarded `UPDATE`** is enough when the state is one
row reached by one idempotent statement: `SendCooldown` (a guarded `UPDATE` then
`INSERT ... ON CONFLICT DO NOTHING`) and `Inbox` (an exactly-once claim,
composable as the first statement of `db.batch_atomic`) each work in one round
trip, with no host and no object.

`KeyValue` is never the answer for single-use things: it is **eventually
consistent**, so a `get` may miss a `put` that already happened, and a dedup
ledger or single-use token kept there can be spent twice.

## The API

A module implements one `ActorHandler` per kind; `on_message` returns a reply and
`on_alarm` fires when the alarm passes. Both stage writes on the `ActorContext`
and commit nothing until they return `Ok`; `examples/venture/src/actors.rs` is a
worked pair. The context stages `put`, `delete`, `delete_all`, `set_alarm` and
`cancel_alarm` into one `ActorWrites`; reads (`get`, `list_prefix`, `alarm`)
merge that staged view over the store, and `run_actor_message`/`run_actor_alarm`
commit the whole set only once the handler returns `Ok`. A module declares the
kinds it owns in `Module::actor_kinds`, like `tables()`, and
`HarnessBuilder::actor` registers a handler. `Harness::build` refuses an invalid
kind, a duplicate registration, a kind two modules both declare, a declared kind
with no handler, or a module that declares actor kinds but lists `Port::Actor` in
neither `requires()` nor `optional()`; `ScopedActors` then scopes each module's
view to its own kinds.

## Bounds

Every limit is a `const` in `cratefield-core`, checked before a byte reaches the
host:

| Constant | Bound | Caps |
|---|---|---|
| `MAX_ACTOR_MESSAGE_BYTES` | 1 MiB | one message sent |
| `MAX_ACTOR_REPLY_BYTES` | 1 MiB | one reply returned |
| `MAX_ACTOR_VALUE_BYTES` | 1 MiB | one stored value |
| `MAX_ACTOR_KEY_BYTES` | 512 | one actor or storage key |
| `MAX_ACTOR_KIND_BYTES` | 64 | a kind name, `[a-z0-9_-]` |
| `ACTOR_CALL_TIMEOUT` | 30 s | how long one call may take |

Past these bounds the state belongs in the database through `Ports::db`. The
message, reply and key bounds are enforced in the runner and again in
`ScopedActors`, so an oversized message never reaches the host. On Cloudflare
the object also refuses a request body larger than the largest frame
(`1 + MAX_ACTOR_KIND_BYTES + 2 + MAX_ACTOR_KEY_BYTES + MAX_ACTOR_MESSAGE_BYTES`)
before it buffers one. When the module has a `Clock` wired, `ScopedActors`
wraps each call in `timeout` against it: past `ACTOR_CALL_TIMEOUT` the caller
gives up with `ActorError::Timeout`. With no clock there is nothing to measure
the wait with, so the call is made straight through — the host still
serializes it, the caller just cannot impose a deadline.

## On Cloudflare

Each `(kind, key)` is a Durable Object. The venture writes the
`#[durable_object]` class — a `wasm_bindgen` export a library crate cannot
declare, the same split as `RoomDriver` — and it is two forwarding methods onto
`ActorDriver`, which owns the protocol and the calls into the handlers.
`Cloudflare::actors("ACTORS")` names the binding. `wrangler.toml` needs a
`[[durable_objects.bindings]]` stanza (`name = "ACTORS"`, `class_name = "Actors"`)
and a `[[migrations]]` stanza declaring the class with `new_sqlite_classes`,
because a class the runtime has not migrated is not created.
`examples/venture/src/actors.rs` is a complete class.

### The protocol

The Worker names the object `<kind>:<key>` — one object per key, so the runtime
serializes its calls — and POSTs one frame:

```text
kind length (u8) | kind | key length (u16, big endian) | key | message
```

It signs the frame `HMAC-SHA256(k, frame)`, with `k` domain-separated from the
signer's tokens: `k = HMAC-SHA256(HARNESS_SECRET, "cratefield actor protocol
v1")`. The `base64url-nopad` HMAC rides in `x-cratefield-actor-signature`, and
the object recomputes it and compares in constant time, accepting the current
secret and `HARNESS_SECRET_PREVIOUS` when configured. Anything unsigned or
wrongly signed is **403**, refused before the frame is parsed or storage touched;
a deployment with no `HARNESS_SECRET` derives no key and refuses everything 403
rather than serving. The frame carries no nonce or timestamp, so a captured
frame could be replayed; that is acceptable because frames never leave
Cloudflare's internal network — the Worker signs and the Durable Object
verifies, both inside the same account.

Statuses map back to `ActorError`: 200 the reply bytes; 403 unsigned or wrongly
signed; 400 a malformed frame, an invalid kind/key, or a frame that names a
different actor; 404 no handler for the kind (`NotConfigured`); 413 `TooLarge`;
422 `Handler`; 500 `Operation`.

### Atomicity and serialization

Values *and the alarm* commit inside one `storage.transaction`: workerd applies
every put, delete and alarm change in the closure or none of them, so a commit
cannot land a value and then fail to set (or clear) its alarm. `deleteAll` is
refused inside a transaction, so a `clear_all` is an explicit delete of the
listed keys *inside* the same transaction. Reaching that took the driver keeping
the raw `DurableObjectState`: `worker::Storage::transaction` hands a
`worker::Transaction` whose inner JS object is private, and `worker-sys` 0.8.5
does not bind the transaction's `getAlarm`/`setAlarm`/`deleteAlarm` even though
Cloudflare's `DurableObjectTransaction` has them, so the driver reads them off
the transaction object with `Reflect`.

Before a frame's `(kind, key)` reaches storage, the object checks that the frame
names *this* object: the name `id_from_name` gave it (`state.id().name()`, when
workerd exposes one) and the identity a previous commit persisted under the
reserved keys must both agree, or the request is refused 400 with nothing
touched.

Serialization is more than the object's message loop: a handler that awaits lets
workerd interleave the next event's *read* of storage, so `ActorDriver` holds a
mutex for the whole of a message or alarm run. The object persists its kind and
key under reserved keys (`\0kind`, `\0key`) on the first commit, because an alarm
arrives with no frame and still has to name its actor; handler keys live under a
`u:` prefix and cannot collide with those.

## Testing

`cratefield-testing` ships `MemoryActors`, an in-process host over a
`ManualClock`: a call takes its actor's lock for the whole of `run_actor_message`,
and `MemoryActors::advance(by)` moves the clock then runs every alarm due.

`assert_actor_contract(host, advance)` drives one host through every promise the
port makes — 100 concurrent increments each see a distinct value, a failing
handler commits nothing, the three size bounds hold at the limit and are refused
one byte over, an alarm fires only at its time and re-arms once, an unknown kind
is `NotConfigured` — and `contract_actor_handlers()` is the handler it drives.
`crates/testing/tests/actor_contract.rs` holds `MemoryActors` to it.

A Durable Object is the one thing `cargo test` cannot reach: a runtime object,
not a Rust type you can construct. So CI boots `examples/venture` under
`wrangler dev --local` and runs `examples/venture/actors-smoke.mjs`, which proves
what only the object can: fifty concurrent increments serialize to 1..50 with no
lost update, a second key is its own actor, an expiring value is erased by a real
one-second alarm, and an unsigned POST to the raw ACTORS binding is refused 403
by the object rather than by a check in the caller.

## What is not built

- **A native adapter (#584).** `cratefield-runtime-native` carries no actor host;
  `MemoryActors` is a test fake, not a deployment host.
- **Realtime over this protocol.** Reaching a room from outside a socket still
  has no Workers adapter; the signed frame could carry it, and moving Realtime's
  `broadcast`/`members` onto it is a follow-up ([REALTIME.md](REALTIME.md):
  `Port::Realtime` is still not provided).
- **Cross-key transactions.** One call touches one actor; there is no atomic
  write across two keys. **Actor-to-actor calls** are out too: a handler reaches
  only its own actor through `ActorContext`, never another.
- **Durable workflows.** No orchestration, sagas or retries beyond workerd's own
  retry of a thrown alarm; an actor is state and one timer, not a job queue.
- **Location hints and jurisdictions.** The object's location is Cloudflare's
  default.
