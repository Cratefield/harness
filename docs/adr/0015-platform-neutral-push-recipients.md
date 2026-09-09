# ADR 0015: A push recipient is an enum, and the router sits above the adapters

Status: accepted, 2026-09-09. Issue #177, child of the notifications epic
#192. Extends ADR 0002 (ports and adapters) for the `Push` port.

## Context

`Push::send(&str, &Notification)` (issue #104) was written for the one
adapter that existed. Both halves are APNs-shaped:

- **The recipient is one opaque string.** That is exactly an APNs device
  token and exactly an FCM registration token, and it is not a Web Push
  subscription, which is `{ endpoint, p256dh, auth }` — a URL plus the two
  RFC 8291 keys, all three needed to encrypt the payload.
- **`Notification` mirrors the `aps` block.** `title`, `body`, `category`,
  `thread_id`, `data`, `collapse_id`, `priority`. A browser also wants an
  `icon`, a click `url`, a `TTL` and an `Urgency`; FCM wants
  `android.collapse_key`, `android.priority` and `notification.click_action`.

The cheap escape — keep the string and put JSON in it — makes every adapter
a parser and every mistake a runtime surprise: a Web Push subscription sent
to the APNs adapter would be a `BadDeviceToken` from Apple rather than a
compile error, and a venture would have no way to ask "which transport is
this?" without parsing too.

There is exactly one in-tree consumer of the port (the APNs adapter) and no
out-of-tree one yet, so the cost of changing it will never be lower.

## Decision

**A recipient is an enum, one variant per transport.**

```rust
pub enum Recipient {
    Apns { device_token: String },
    Fcm { registration_token: String },
    WebPush { endpoint: String, p256dh: String, auth: String },
}
```

Each variant carries exactly what its protocol needs, named as the protocol
names it. Adding a transport is a new variant, which makes every `match` in
the tree fail to compile until someone decides what it answers — the whole
point of choosing an enum over a string.

**`Recipient::platform()` is a transport fact, not a device fact.** A
UnifiedPush endpoint is `Platform::Web` on an Android phone; a PWA installed
on an iPhone is `Platform::Web` on Apple hardware. `Platform` names how the
notification travels, and nothing else. Anything that wants to know what
kind of *device* a token belongs to is asking the venture's registry, not
this port.

**`Notification` grows optional, transport-neutral fields**, all
`Option`/`skip_serializing_if` so an existing payload still deserialises:
`icon`, `url`, `ttl`, `badge`, `silent`, `loc`. Each adapter maps what its
protocol has and **documents what it drops** — APNs has no `icon` (the icon
comes from the app bundle), Web Push has no `badge`. The dropping is in the
adapter, not in the caller: a module writes one notification and every
transport does its best with it.

`ttl` is the field most easily got wrong, so the port states the shape in
one place: it is a **duration**, and `apns-expiration` is an **absolute UNIX
epoch**, so the APNs adapter sends `now + ttl`. `android.ttl` is `"<s>s"`,
Web Push `TTL` is seconds. Zero means "deliver now or drop" everywhere.

**The router lives above the adapters, in core.** `RoutingPush` dispatches
by variant to whichever adapters a venture configured, and is itself a
`Push`, so venture code holds one `Arc<dyn Push>` and never matches on a
transport. An adapter serves one transport and answers
`PushError::Rejected("unsupported recipient…")` for the rest.

A recipient whose transport has **no** adapter is `PushOutcome::NotConfigured`,
not `Rejected`. The distinction is the caller's action: `Rejected` means the
request was wrong and retrying will not help, `NotConfigured` means the
venture did not wire that leg and the caller may degrade — the same contract
`Mailer` already has. Nothing is wrong with the recipient, so nothing should
be pruned.

**`PushError::Transient` carries an optional `retry_after`.** APNs `429`,
FCM `RESOURCE_EXHAUSTED`/`UNAVAILABLE` and Web Push `429`/`503` all answer
with `Retry-After`; throwing it away means the outbox re-hammers a provider
that just asked it not to.

## Consequences

- `cratefield-core` is a **breaking** change (0.3.x → 0.4.0). The blast
  radius is the APNs adapter and `FakePush`; the notification module
  (yoginini-backend#12) has not started. Doing it later would cost more and
  buy nothing.
- `FakePush` records `(Recipient, Notification)` and takes per-recipient
  failure modes, so a fan-out test can make one device of five dead and
  assert that exactly that one is pruned — which a single global mode could
  not express.
- `cratefield-testing::push_recipient_conformance` walks every `Recipient`
  variant against an adapter and asserts the unsupported-transport contract,
  so the answer is the port's, not each adapter's improvisation.
- The alternatives rejected: a string recipient with a `platform` field
  beside it (nothing stops the two disagreeing); one trait per transport
  (a venture then wires and matches three ports); a `Box<dyn Any>` payload
  per transport (compiles, fails at runtime).

## References

Issue #177; `crates/core/src/ports/push.rs`; RFC 8030 §5.2–5.4 (TTL,
Urgency, Topic), RFC 8291 (payload encryption keys); ADR 0002, ADR 0007.
