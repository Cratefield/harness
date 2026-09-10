# ADR 0016: The notifications module dead-letters in its own table, and learns the account from the auth client

Status: accepted, 2026-09-10. Issue #182, child of the notifications epic
#192. Extends ADR 0002 (ports and adapters) and ADR 0007 (request scope);
builds on ADR 0015 (platform-neutral push recipients).

## Context

`cratefield-module-notifications` is the first module to need two things
the harness has never had to answer.

**A terminal state for undeliverable work.** Core's `Outbox` (#128) has
`enqueue_statement`, `claim_due`, `complete` and `retry_later`, and nothing
else. Every failure is therefore either "delete it" or "try again", and a
notification the provider has *rejected* is neither: retrying a bad payload
forever is a busy loop, and deleting it silently loses the only evidence
that the venture is producing payloads APNs will not take. The same is true
of `PushOutcome::NotConfigured`, which means the module is mounted without
the adapter it needs — the single most likely misconfiguration, and the one
that must never look like a delivery.

**Who the caller is.** `Scope` deliberately carries no principal (ADR
0007): a request id, a defer and a span. `crates/auth-client` verifies the
venture's access tokens and hands a handler `Authenticated(Claims)`, but no
module had ever used it — the modules shipped so far are a public signup, a
public waitlist and an admin-token CMS. A per-account subscription list is
none of those.

## Decision

**Dead letters are a module-owned table, not a new state in core.**
`notifications_dead_letters` holds the row's id, topic, payload and
attempt count, plus a `reason` (`rejected`, `not_configured`,
`attempts_exhausted`, `malformed`) and `last_error`. A row moves there and
out of `notifications_outbox` in **one** `db.batch`, so it can never be
both queued and dead.

The alternative — a terminal status and a `last_error` column on the core
outbox — was rejected on three counts:

1. *One user is not a pattern.* This module is core's first real `Outbox`
   consumer. Designing terminal-state semantics for every future consumer
   from a single case is exactly the generalisation that becomes a
   constraint later.
2. *The shape is different.* A dead letter wants a reason and an error
   string that a work-queue row has no use for, and it wants them to
   survive a retention purge of the queue. Adding them to the queue also
   puts a `status <> 'dead'` predicate on `claim_due`'s hot path, for every
   consumer, forever.
3. *Nothing is hidden either way.* The requirement that `fz data export`
   sees a dead letter is met because the module declares the table in
   `Module::tables()`, which is precisely what export reads.

What this costs: a second module that needs dead-lettering would duplicate
the table. That is the trigger to promote it to core — with two examples of
what the shape has to be, rather than none.

**The account comes from `factory0-auth-client`, and the module depends on
it.** Every route takes an `Account` extractor that delegates to
`Authenticated`: the module does not parse a header, does not look at
`alg`, and does not decide what a failure looks like. Consequences,
recorded because they are load-bearing:

- The module declares `Port::HttpClient` as **optional**, which the issue's
  port list does not mention: the JWKS fetch goes through it. A venture
  that only fans out from its own modules never needs it and gets a module
  whose HTTP routes answer 401.
- `factory0-auth-client` is `publish = false`, so
  `cratefield-module-notifications` is too. It cannot be published until
  the auth client is.
- Without `NOTIFICATIONS_AUTH_ISSUER` and `NOTIFICATIONS_AUTH_CLIENT_ID`
  there is no verifier, and every route answers 401 rather than guessing.
  `validate_config` refuses a production deployment that sets neither.

**The production "is any transport wired?" check is a probe the venture
passes in.** The push environment has exactly one reader,
`cratefield-push-wiring` (#191), enforced by a workspace guard, and
depending on that crate would pull all three push adapters into a module
that must compile the same whether a venture wires zero or three. So
`Notifications::transport_probe(..)` takes the answer:
`inspect_push(cfg).any_routed()` in a venture that assembles the port from
the environment. With no probe the module says nothing about transports
rather than guessing, and `fz doctor` remains the other half.

**Another account's subscription is `404`, not `403`.** The `DELETE` is
scoped to the account in the statement itself, so the route never learns
whether the row exists, and an id that belongs to someone else is
byte-identical to an id that never existed.

**The module declares no UI surface.** ADR 0010's audiences are visitor,
admin and signed link. These routes are none of the three — they are an app
holding an access token — and declaring them `Public` would put a form no
visitor can submit into `/__surface`'s public subset. The sibling that
needs a rendered inbox (#187) can propose an `Audience::Account` in core;
this child does not invent one on the way past.

**All three channel switches ship in the first migration.**
`notifications_preferences` creates `push`, `in_app` and `email` at once,
although only `push` has meaning until #187 and #189. Three sibling issues
adding a column each to one table in the same forward-only migration stream
would collide, and a collision in that stream is skipped and reported as
success (docs/MIGRATION-STREAMS.md §2).

## Consequences

- `cratefield-core` is unchanged by this child. No breaking release.
- The dead-letter table is the module's; ops reads it, `fz data export`
  moves it, and a distinct `not_configured` reason tells "the payload is
  wrong" from "you forgot the keys" without reading the message.
- A venture that mounts this module and an auth service now has one crate
  pair — module and auth client — whose versions must move together. That
  is already true of every module and core.
- The preference is read in the **drain**, immediately before
  `Push::send`, so an opt-out that lands after the row was written still
  wins. `notify` also skips enqueueing a category that is already off; that
  is an optimisation over rows the drain would drop anyway, and never the
  authority.

## References

Issue #182; `crates/module-notifications/`; `crates/core/src/outbox.rs`
(#128); `crates/auth-client/`; ADR 0002, ADR 0007, ADR 0010, ADR 0015;
docs/MIGRATION-STREAMS.md.
