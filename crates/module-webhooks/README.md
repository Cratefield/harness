# cratefield-module-webhooks

Outbound webhook delivery, as a module. A venture's customer registers one
endpoint per subject — their account id, their tenant id — with an optional
event-type filter, and receives a signed `POST` for every published event the
filter matches. Delivery rides the core `Outbox`: durable exactly when the
event that caused it is, retried with exponential backoff, dead-lettered
after repeated failures, and replayable by hand.

Delivery is **at-least-once** — the outbox contract, not an SMTP promise. A
receiver dedupes on the event id, which every delivery carries in its
payload and its headers.

## The Rust API is the surface

This module ships **no HTTP routes of its own**. `GET /v1/webhooks` answers
404 by design. Two reasons, both of the same shape:

- **Fan-out starts in the venture's own code.** What counts as an event is
  the venture's vocabulary, and enqueueing is a transaction join:
  `publish` returns outbox `INSERT` statements for the caller's own
  `batch_atomic`, so the event is durable exactly when the state change
  that caused it is. A JSON route could not offer that.
- **The signing secret is credential material.** It is handed back exactly
  once, at registration, and a management UI that could show it again
  would need an auth decision this crate does not make.

```rust,ignore
use cratefield_module_webhooks::Webhooks;

let webhooks = Webhooks::new().max_attempts(5);

// Registration — the secret crosses this boundary once, and never again.
let created = webhooks
    .create_endpoint(&db, &account_id, "https://example.com/hooks", &["order.paid"], &now)
    .await?;
let secret = created.secret; // the customer stores it; this module cannot retrieve it

// Fan-out — inside the venture's own transaction.
let published = webhooks.publish(&db, &account_id, "order.paid", &payload, &now).await?;
let mut statements = the_venture_own_statements();
statements.extend(published.into_statements());
db.batch_atomic(&statements).await?;

// Drain — from the venture's scheduled entry point, with the runtime's context.
let report = webhooks.drain_with(&ctx).await?;
```

An event no endpoint matches is `published.endpoints == 0` and nothing
else: "nobody subscribed to that" is an ordinary answer, not an error.

## The wire

Each delivery is one `POST` with a JSON envelope:

```json
{
  "id": "01JARK2EXAMPLE9EXAMPLE",
  "type": "order.paid",
  "subject": "acct_01J...",
  "created_at": "2026-09-27T12:00:00Z",
  "data": { ...the published payload, exactly as published... }
}
```

| Header | Meaning |
|---|---|
| `Cratefield-Signature` | `t=<unix seconds>,v1=<hex>`, HMAC-SHA256 over `{t}.{body}` with the endpoint's secret |
| `Cratefield-Event-Id` | The envelope's `id`; the dedupe key for at-least-once delivery |
| `Cratefield-Event-Type` | The envelope's `type` |

The timestamp is bound **into** the signature, so a captured delivery
cannot be replayed with a fresh timestamp: re-stamping invalidates the MAC.
A receiver verifies by recomputing it — the same scheme
`cratefield-adapter-webhook-tracker` signs with, so one verifier covers
both.

## Delivery policy

One outbox row per (event, endpoint), so each endpoint retries
independently. The drain leases what is due (a five-minute lease, 16 rows a
pass) and files each row:

| Outcome | What happens |
|---|---|
| 2xx | Logged with its status; the row completes |
| `410 Gone`, or the `HttpClient` port refusing the destination (loopback, private, metadata — the SSRF contract) | Logged; dead-lettered **immediately** as `rejected`. Neither is weather; retrying burns attempts on a certainty |
| Any other status, transport failure, deadline, oversize reply | Logged; the row is retried with backoff — 30s, doubling, 60m ceiling |
| Attempts exhausted (`MAX_ATTEMPTS`) | Logged; dead-lettered as `attempts_exhausted` |
| A payload that no longer parses | Dead-lettered as `malformed` — a bug, not weather |
| Endpoint deleted since the enqueue | The row is dropped; nobody is subscribed at the other end any more |

A per-row failure never aborts the pass. Every attempt lands in
`webhooks_deliveries` — the log a customer support conversation reads:
which endpoint, which event, which attempt, what status came back, and
when.

## Replay

A dead letter stays in `webhooks_dead_letters` until a human decides:

```rust,ignore
for letter in webhooks.dead_letters(&db, &account_id, 50).await? { /* show it */ }
webhooks.replay(&db, &account_id, &letter.id, &now).await?;
```

Replay re-enqueues the event with attempts reset to zero and removes the
dead letter, in one batch. The delivery log keeps the history. It refuses
— the letter left exactly where it was — when the letter's endpoint is
gone: the drain would drop the re-enqueued row, and the event would be
destroyed for good.

## Endpoints and secrets

- `create_endpoint` validates the URL (http/https, a non-empty host, no
  whitespace) and normalizes the filter; an empty filter stores `*` —
  everything. Everything else is an exact, comma-separated match, so
  `order.paid` never matches `order.paid.v2`.
- An event type must be 1..=128 bytes of visible ASCII, no whitespace —
  the characters an HTTP header value survives verbatim. It is validated
  at `publish` and at filter registration alike, so a type that could
  never ride the `Cratefield-Event-Type` header is refused at the door
  instead of burning a delivery's retry budget.
- The secret is 32 OS-random bytes, `whsec_`-prefixed hex, generated where
  it is stored. It is returned once; listing endpoints never includes it;
  it appears in no error and no log line; exports redact it.
- Deleting an endpoint deletes its queued deliveries on the next drain —
  there is nobody left to deliver them to.

## Configuration

Keys are `SCREAMING_SNAKE`, prefixed with the module name. All optional.

| Key | Default | Meaning |
|---|---|---|
| `WEBHOOKS_MAX_ATTEMPTS` | `5` | Dead-letter a delivery after this many failed attempts. Must be a whole number in `1..=1000` — the same range the builder's `max_attempts` clamps to |

## Data

Four tables, all keyed on the subject the event (or endpoint) belongs to,
so account erasure reaches all four:

| Table | Holds |
|---|---|
| `webhooks_endpoints` | One row per registered URL, with its signing secret |
| `webhooks_outbox` | The core outbox contract, one row per (event, endpoint) |
| `webhooks_deliveries` | One row per attempt actually made |
| `webhooks_dead_letters` | The events that gave up, kept replayable |

## Ports

Requires `Database`, `HttpClient` and `Clock`. The drain refuses to start
when one of them is missing from the context — a wiring bug, named as
such, not papered over. The signature timestamp and every stored
timestamp come from the `Clock` port, so a test can advance time; all
HTTP goes through the `HttpClient` port, which is where the SSRF vetting
lives. Wasm-safe: no sockets, no threads, no filesystem.
