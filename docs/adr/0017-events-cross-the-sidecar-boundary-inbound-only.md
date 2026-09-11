# ADR 0017: Events cross the sidecar boundary inbound only

Status: accepted, 2026-09-11. Issue #62, child of epic #56 (custom modules
without rebuilding the shared bundle). Extends ADR 0009 (sidecar modules
over service bindings); constrained by ADR 0007 (request scope carries no
principal).

## Context

`ctx.events.emit_in(&scope, "waitlist.confirmed", payload)` runs every
registered handler inside the emitting request's `wait_until`. The bus is
an in-process registry of trait objects — `Arc<Vec<(EventName,
EventHandler)>>` — built once in `Harness::build`, and it is exactly one
wasm instance wide.

A sidecar module (ADR 0009) is a different instance, reached over a service
binding. So a sidecar could neither hear an event the host emitted nor emit
one the host would hear. Nothing said so anywhere. The way a module author
would have discovered it is by writing a handler and watching it never run,
which is the worst available way to learn a boundary exists.

Two facts about the current types shaped the decision as much as the
design did.

**The bus has no ports.** It is built in `Harness::build`, which has no
`Env` and therefore no `Dispatcher` — the dispatcher is per-request, derived
from the runtime's environment, and reaches sidecars. A forwarder built
where the bus is built has nothing to forward *over*.

**`Scope` carries a request id, a defer and a span, and nothing else.**
Putting the dispatcher in `Scope` would reach every handler, but every
handler signature is `Fn(&Scope, Value)`, so the change is observable by
every module that has ever subscribed to anything — a `HARNESS_API` bump
and a coordinated update of every module in the catalogue.

## Decision

**Inbound only.** The host forwards every emission to each mounted
sidecar's `POST /__events`. A sidecar can react to a host event. A sidecar
does not emit back.

**The forwarder is attached where ports are resolved.** `Harness::router`
has the `Dispatcher` and the mount table, so it builds an `EventForwarder`
and hands the bus a copy of itself carrying it
(`EventBus::forwarding_to`). `Scope` is untouched, no handler signature
changes, and `HARNESS_API` is unbumped. The bus is cheap to clone — two
`Arc`s — so per-router construction costs nothing worth measuring.

**The delivery contract is the one the bus already had.** At-most-once, no
retry, no ordering guarantee, inside `wait_until`, failures logged and
never surfaced to the emitting request. This is stated deliberately: no
module gains a guarantee it did not have in process, so a subscription
written against the bus behaves the same compiled in or mounted out.

**`POST /__events` answers `202` and runs handlers in the sidecar's own
`wait_until`.** `202 Accepted` and not `200`: when the response is written
the handlers have *not* run. The host reads the status to learn whether the
forward was accepted, never whether it succeeded — there is no status that
could tell it the latter, because the work outlives the response on the
other side of the boundary. Running handlers before answering would hold
the *host's* deferred future open for as long as the sidecar's slowest
subscriber, which is the one thing forwarding must not do.

**The route is mounted only when a gateway secret exists**, and it is
inside the gateway guard's protected set alongside `/v1/*` and
`/__surface`. Without the shared secret there is no way to distinguish the
host's forward from any other `POST`, and an unauthenticated event trigger
lets a stranger forge the payloads in-process handlers act on. Absent is
safer than open.

**An emission nothing hears is warned about, on both sides.** The host
warns when an event had no local handler *and* was forwarded nowhere; the
sidecar's inbound route reports an event that arrived with no subscriber
and answers `{"accepted": false, "handlers": 0}`. Before this, a sidecar
emitting with no local subscriber logged nothing at all — precisely the
silent failure this issue exists to prevent.

## Rejected

**1. Sidecars are HTTP-only: no emit, no subscribe.** Cheapest and honest,
and it was genuinely tempting. Rejected because the common case for a
private module *is* reacting to a host event — a signup, a confirmation —
so the restriction bites immediately rather than eventually, and the
workaround (polling, or a webhook the venture wires by hand) is worse than
the forwarding it avoids.

**2. Bidirectional.** Symmetric and, on the surface, more principled.
Rejected on two counts. It introduces a cycle: a sidecar handler that emits
an event the host forwards back is a loop with no natural bound, and
nothing in the bus's design can detect one. And it forces an answer to a
delivery-guarantee question the in-process bus never had to face — a host
handler that fails is logged and forgotten, but a *sidecar's* emission
failing to reach the host is a lost cross-process message, which reads as a
durable-queue requirement. Issue #62 rules a durable queue out of scope.
Leaving the question unanswered is better than answering it badly, and
outbound forwarding can be added later without changing anything decided
here.

**3. Dispatcher in `Scope`, bus built once.** Rejected for the
`HARNESS_API` bump: every handler signature changes, every module in the
catalogue needs a coordinated release, and the benefit over building the
forwarder in `router()` is nil. If `Scope` ever grows a port for other
reasons, this becomes free and the forwarder can move.

## Consequences

- A sidecar module's subscriptions work exactly as they do compiled in.
  Which side of the boundary a subscriber sits on is the deployment's
  choice (`HARNESS_SIDECARS`), not the module's.
- A host emission now costs one dispatch per mounted sidecar, deferred.
  Mounts the dispatcher has no binding for are skipped, not dialled.
- Sidecar-to-host events remain impossible, and the failure is visible: a
  sidecar emitting an event no local handler takes is warned about rather
  than silently dropped.
- `/__events` is a harness route on every deployment with a gateway
  secret, host or sidecar. A host that mounts no sidecars still exposes it;
  it simply never receives a forward.
