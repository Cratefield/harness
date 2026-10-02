# ADR 0025: One provider-neutral billing lifecycle, entitlement model and revenue ledger

Status: proposed, 2026-10-02. Issue #592. Extends ADR 0002 (ports and
adapters) with the `InAppPurchases` port, and revises the "billing logic
is venture code" line in `docs/PAYMENTS.md` and
`crates/core/src/ports/payments.rs`. A second reviewer still has to sign
off the webhook-as-trigger rule (Decision 5), the Stripe-through-
RevenueCat rule (Decision 8) and the chargeback default (Decision 9).

## Context

`Payments` (issue #102, ADR 0002) moves a venture's money through hosted
Stripe flows: `create_checkout`, `create_subscription_checkout`,
`create_connect_account_link`, `charge_with_transfer`, `refund`, and a
verified `verify_webhook`. What a verified event *means* — a trial
started, a subscription lapsed, a charge succeeded — was left to a
billing module the venture writes. `docs/PAYMENTS.md` said so plainly:
trials, entitlements and payout schedules are venture code.

The first venture that takes money sells a web membership through Stripe
**and** app subscriptions through the App Store and Google Play. Both
must land in the same entitlement, and the store side does not go
through Stripe at all: Apple and Google bill the customer and move the
money. RevenueCat aggregates the store reports and answers a REST API,
but the backend never moves that money. The reconciliation
`docs/PAYMENTS.md` handed to venture code is now the reconciliation
**every** app-selling venture needs, and implementing it per venture is
how two ventures come to disagree about what a customer has paid for.

Three facts shape the decision.

- **`Payments` moves money; RevenueCat does not.** Every `Payments`
  method names a hosted Stripe flow or a Stripe object id. RevenueCat's
  server API reports purchases the stores already made, and its few
  writes (promotional grants, transfer, delete customer, Google
  refund/revoke) correct that record — they do not move money.
- **A webhook is a trigger, not the truth.** RevenueCat's own guidance
  is to call the REST API after every webhook; deliveries can be missed
  or arrive out of order, so state rebuilt from events alone drifts.
- **The shape is the same whatever billed.** The events, states and
  money lines that decide a customer's access do not depend on the
  store, so their shape belongs in core and the vendor's spelling
  belongs in an adapter (ADR 0002).

## Decision

**1. RevenueCat is not added to `Payments`; there is a second port.**
`Payments` stays Stripe-shaped (ADR 0002: an adapter translates a
vendor, it never becomes the vendor's shape). A new `InAppPurchases`
port — `Port::InAppPurchases` — names a store-billing aggregator: verify
and parse a webhook; read a customer's entitlements, subscriptions and
purchases; and the few write actions RevenueCat exposes (promotional
grants, transfer, delete customer, Google refund/revoke). The first
adapter is `cratefield-adapter-revenuecat`. Another aggregator, or a
direct App Store Server API or Play Developer API adapter, can implement
the same port later without the module changing.

**2. Core gains provider-neutral billing types, with no I/O.** A
`crates/core/src/billing/` module defines `LifecycleEvent` (what
happened), `SubscriptionState` (where a subscription now is) and the
pure transition function between states, `EntitlementGrant` (what a
customer is entitled to, and until when) and `LedgerEntry` (one revenue
line). Each adapter maps its vendor events onto these; the mapping table
is part of that adapter's docs. The module never parses a vendor payload
(ADR 0002).

The lifecycle event kinds, and the states they move between:

| Kind | Fires when | RevenueCat event(s) |
|---|---|---|
| Trial started | A free trial begins | INITIAL_PURCHASE (trial) |
| Trial converted | A trial becomes a paid period | RENEWAL |
| Initial purchase | The first paid period | INITIAL_PURCHASE |
| Renewal | A period renews | RENEWAL |
| Period extended | The current period's end is pushed back; no money | SUBSCRIPTION_EXTENDED |
| Invoice issued | An unpaid invoice is issued (RevenueCat Billing); an observation, no state change until it is paid | INVOICE_ISSUANCE |
| Billing issue / retry | A renewal charge fails; a grace period may run | BILLING_ISSUE |
| Cancellation | Auto-renew off; access continues to period end | CANCELLATION (not a refund) |
| Uncancellation | Auto-renew back on | UNCANCELLATION |
| Expiration | Access ends | EXPIRATION |
| Refund | A store refund revokes access at once | CANCELLATION (cancel_reason CUSTOMER_SUPPORT) |
| Chargeback / dispute | A dispute opens, is won, or is lost | (Stripe dispute events; stores report it as a CANCELLATION) |
| Transfer | A purchase moves between app user ids | TRANSFER |
| Pause | A subscription pauses, and resumes | SUBSCRIPTION_PAUSED |
| Product change | Upgrade, downgrade or crossgrade | PRODUCT_CHANGE |
| Non-renewing purchase | A consumable or lifetime purchase | NON_RENEWING_PURCHASE |

Out-of-order and duplicate deliveries are expected. Every event carries
the provider's event timestamp and its event id. Transitions are
**monotonic per subscription** — an event older than the state it would
move is ignored, not applied — and **idempotent per event id** through
the `Inbox` dedup ledger (`claim_with`, the claim and the effect in one
batch), so a redelivery applies its effect exactly once. The states the
sketch names are Trialing, Active, InGracePeriod (billing retry),
Canceled-but-active-until-period-end, Paused, Expired and Revoked. The
exact state set and the full transition table belong to the implementing
issues; recorded here is that the transition is pure, lives in core, and
is shared.

**3. One published module owns the state.**
`cratefield-module-billing` owns the subscriptions, purchases,
entitlement grants, provider customer mapping, disputes, account flags
and the ledger; the two webhook routes (Stripe and RevenueCat); the
scheduled reconciliation job; and the module-facing `Entitlements` API.
This is the part `docs/PAYMENTS.md` and
`crates/core/src/ports/payments.rs` called venture code. What stays
venture code is **policy**: what an entitlement key unlocks, its prices,
and what to do with a flagged account beyond the module's configured
default.

**4. Entitlement keys belong to the venture.** A RevenueCat entitlement
identifier is used as-is; a Stripe price is mapped to the same key in
the module builder. `has_entitlement(account, key)` is true when any
active grant from any source exists — the point of one model covering
both providers.

**5. Webhook as trigger, REST as truth.** A verified event is applied
optimistically and recorded — as a ledger row, or as an observation when
Decision 8 or Decision 10 says it carries no money — and for RevenueCat
it also schedules a **coalesced** snapshot refresh of that customer: a
burst of events becomes one REST call. The refresh is coalesced by the
per-subject window ledger (`SendCooldown`): the first event to claim a
customer's window enqueues one refresh `Outbox` row, and events inside
the window
add nothing. The scheduled tick drains due refresh rows with
`drain_within` under the tick's `ScheduledBudget` (ADR 0023), so the work
is durable across a crash and bounded per tick. A snapshot newer than
the deltas already applied wins; a snapshot older than them is
discarded.

**6. Identity.** The RevenueCat app user id is the harness `Subject.id`
(`crates/core/src/ports/auth.rs`). An id with the `$RCAnonymousID:`
prefix is never granted to an account by guessing: an anonymous purchase
is linked only by an explicit transfer or alias, never by a matching
email.

**7. Verification.** RevenueCat webhooks are verified with HMAC through the
existing `StripeStyle` scheme (header
`X-RevenueCat-Webhook-Signature`, `t=<unix>,v1=<hex>`, HMAC-SHA256 over
`<t>.<raw body>`), the shape `webhook_signature` already implements.
RevenueCat's static `Authorization` header is accepted only as an
**extra** check, never instead of HMAC, in production. To let one module
host both webhook routes — the Stripe route verifying through
`Payments`, the RevenueCat route through this scheme — core gains a
signature verifier **per route** (issue #595). Today the verifier is per
module, through `Module::signature_verification()` and
`SignatureVerification::{Payments, Hmac}`.

**8. Double counting when a venture connects Stripe to RevenueCat.**
RevenueCat can front a Stripe subscription, so the same purchase can
arrive on both routes. A RevenueCat event whose `store` is STRIPE is
recorded as an observation only — no ledger row, no grant — because the
Stripe adapter is the authority for Stripe money. Configurable, because
a venture that uses RevenueCat *instead of* a Stripe webhook may want
the opposite.

**9. Chargebacks and flags, by default.** When a dispute opens, the account
is flagged. When it is lost, the grants funded by the disputed payment
are revoked; when it is won, they are restored. A store refund — which
includes a store-side chargeback, indistinguishable through RevenueCat —
revokes immediately: the store reports a reversal, not a dispute with a
win path, so revoke-now is the safe default. A later REFUND_REVERSED
(App Store) restores the grant and writes a reversing ledger row. The flag
and the revocation are the module's default; a venture may configure
them (issue #612).

**10. Sandbox.** An event whose `environment` is SANDBOX is stored on every
environment and applied to state on non-production ones; in production
it is stored but never grants and is excluded from revenue. Test traffic
must not open access or inflate the ledger.

**11. The ledger is append-only and in minor units.** Every revenue line is
an amount in the purchase currency's minor units plus its USD value,
with tax and store commission (or the Stripe fee) recorded and **marked
estimated** when they come from RevenueCat, whose tax and commission
figures are its own estimates. A correction is a new line, never an
edit. The Stripe fee on the Stripe side is Stripe's actual, not an
estimate.

## Alternatives considered

- **Extend `Payments` with RevenueCat.** Lost on ADR 0002 and the port's
  own doc: `Payments` names only money-moving Stripe flows, and
  RevenueCat moves no money from the backend. A `verify_webhook` that
  sometimes parses a store report and sometimes a Stripe event makes
  every `Payments` method's meaning conditional on the vendor, and the
  port's "card data never crosses the harness" reasoning no longer
  covers store purchases. A second port keeps each trait honest.
- **Keep everything in venture code.** The status quo, and the reason two
  ventures disagree about the same customer. It also duplicates the state
  machine, the ledger and the webhook handling in every venture — the
  work this ADR moves into a module.
- **One `Entitlements` port with Stripe and RevenueCat adapters behind
  it.** Lost because the two providers are not interchangeable at the
  port boundary: Stripe *moves* money (checkout, refund, transfer);
  RevenueCat *reports* it (snapshots, entitlements, a handful of
  corrections). A trait wide enough to cover both is two traits wearing
  one name, and the webhook verification differs per route — #595's
  problem, not a reason to merge the ports.

## Consequences

- A new port (`Port::InAppPurchases`) added to `Port::ALL`, so the
  exhaustive match behind `Ports::provides` makes forgetting it a compile
  error, not a quietly wrong bundle.
- A new adapter crate (`cratefield-adapter-revenuecat`) and a new
  published module (`cratefield-module-billing`), each with its own
  contract suite (issue #597).
- Core gains the per-route signature verifier (issue #595). Until it
  lands, one module cannot honestly host two routes with different
  verifiers, because `Module::signature_verification()` returns a single
  answer for the whole module.
- `Payments` stays Stripe-shaped and gains disputes, subscription-cancel
  and balance-transaction lookup on the Stripe adapter (issue #602).
  Subscription lookup — `get_subscription`, `list_subscriptions`,
  customer portal sessions — is what the Stripe side of reconciliation
  reads (issue #589); reconciliation is not one provider's API alone.
- The module owns more than `Payments` did: state, ledger, flags and two
  routes. That is more surface than a venture's own billing code had,
  and the trade is deliberate — the surface is the same for every
  app-selling venture and is tested once.
- Entitlement keys and the account-flag response stay venture code on
  purpose; the module cannot know what a key unlocks, or what a flagged
  account should be denied beyond its configured default.
- RevenueCat's REST rate limits and the coalesced refresh shape the
  module's scheduled work; a burst of webhooks is bounded by the tick's
  `ScheduledBudget`, and unspent refresh work rolls to the next tick
  (ADR 0023).
- The chain of command is explicit: a RevenueCat event is a trigger, the
  RevenueCat REST API is the truth, and the Stripe adapter is the
  authority for Stripe money.

## Implementing issues

This ADR is #592. The rest of the billing set:

Core:
- #593 — provider-neutral lifecycle events and the subscription state
  machine.
- #594 — charge amounts, currency exponents and ledger entry types.
- #595 — per-route signature verifiers in core.
- #596 — the `InAppPurchases` port, `Port::InAppPurchases`, and wiring
  on both runtimes.
- #597 — `FakeInAppPurchases`, a scripted lifecycle builder and the
  adapter contract suite.

Adapters:
- #598 — `cratefield-adapter-revenuecat`: REST client, rate limits, typed
  models and customer snapshot.
- #599 — `cratefield-adapter-revenuecat`: promotional grants, transfer,
  customer deletion and Google refunds.
- #600 — `cratefield-adapter-revenuecat`: webhook verification and the
  event mapping table.
- #601 — Stripe adapter: map verified Stripe events to provider-neutral
  lifecycle events.
- #602 — `Payments`: disputes, subscription cancel and balance-transaction
  lookup on the Stripe adapter.
- #589 — `Payments`: customer portal sessions and subscription lookup on
  the Stripe adapter.

Module:
- #603 — `cratefield-module-billing`: crate, tables, migrations and
  personal-data declarations.
- #604 — apply events exactly once, survive reordering, let snapshots win.
- #605 — the Stripe and RevenueCat webhook routes.
- #606 — app user id to account mapping, anonymous ids, aliases, transfers
  and restore.
- #607 — `has_entitlement`, the entitlements routes and durable change
  listeners.
- #608 — scheduled reconciliation against RevenueCat and Stripe.

Lifecycle, money and policy:
- #609 — trials and intro offers, renewals, billing retry and grace,
  cancellation versus expiration.
- #610 — upgrades, downgrades and crossgrades per store; Play pauses and
  resumes; Stripe pauses.
- #611 — refunds: store refunds through RevenueCat, merchant refunds
  through Stripe, reversals and revocation.
- #612 — chargebacks and disputes: one dispute record, account flags,
  revocation policy.
- #613 — Stripe dispute evidence: assemble from billing records, add and
  submit on review.
- #614 — non-renewing and consumable purchases, promotional and temporary
  grants and family sharing.
- #615 — price changes: store consent events, expiry for declined
  increases and Stripe price migrations.
- #616 — revenue ledger: gross, tax/VAT, commission or fee and net, per
  currency, from both providers.
- #617 — reconciliation reports: RevenueCat versus the ledger versus
  Stripe.

Downstream:
- #618 — privacy: export and erasure for billing data, including deleting
  the RevenueCat customer.
- #619 — docs: `docs/BILLING.md` and a venture setup guide.
- #620 — example venture mounting billing on Workers and on the native
  runtime.
- #621 — facade features, `fz doctor` rules and the publish set.

Historical: #102 — the `Payments` port and Stripe adapter, which this ADR
builds on rather than revises.

## References

- Issue #592 (this ADR); `crates/core/src/ports/payments.rs`,
  `docs/PAYMENTS.md`, `crates/core/src/ports/mod.rs`,
  `crates/core/src/idempotency.rs`, `crates/core/src/outbox.rs`,
  `crates/core/src/webhook_signature.rs`, `crates/core/src/route_policy.rs`;
  ADR 0002 (ports and adapters), ADR 0023 (the scheduled budget the
  reconciliation drain runs under).
- RevenueCat webhooks: https://www.revenuecat.com/docs/integrations/webhooks
  and event types and fields:
  https://www.revenuecat.com/docs/integrations/webhooks/event-types-and-fields
- RevenueCat REST API v2: https://www.revenuecat.com/docs/api-v2
