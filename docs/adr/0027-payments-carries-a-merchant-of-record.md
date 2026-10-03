# ADR 0027: `Payments` carries a Merchant of Record, and disputes are read through the port

Status: proposed, 2026-10-03. Issue #690. Extends ADR 0002 (ports and
adapters) and ADR 0025 (the billing lifecycle). Builds on the port
shapes issues #589 and #602 set out, without implementing their Stripe
halves.

## Context

The Factory Zero ventures are run by an individual founder with no
company yet, outside Stripe's supported countries. A Merchant of Record
(MoR) is the legal seller: it collects the payment, handles VAT, GST and
sales tax, and pays the founder out. Polar is one, and it sells
subscriptions, one-off purchases and usage-based billing fed by
ingested events. A venture should be able to start on Polar and move to
`cratefield-adapter-stripe` once a company exists, without changing
module code.

`Payments` was written for Stripe (ADR 0025, Decision 1: it "stays
Stripe-shaped"). Polar fits most of it: hosted checkout, refunds, usage
reporting and verified webhooks map directly. Three things do not fit.

- **Disputes.** Polar exposes disputes through its API
  (`GET /v1/disputes/`, `GET /v1/disputes/{id}`,
  `POST /v1/disputes/{id}/accept`) but sends **no dispute webhook**. Its
  webhook catalogue has no `dispute.*` event. A venture that must flag
  an account when a chargeback opens has to read disputes, and the port
  has no way to do that. Issue #602 had already planned `get_dispute`,
  `close_dispute` and a `Dispute`/`DisputeStatus` shape, for Stripe.
- **The customer portal.** Plan changes, invoices and self-serve
  cancellation belong to the provider's hosted portal. Issue #589 had
  already planned `create_portal_session` with an exact shape, for
  Stripe.
- **Webhook headers.** Polar signs with Standard Webhooks: three headers
  (`webhook-id`, `webhook-timestamp`, `webhook-signature`), and the
  event id is a header, not part of the body. `verify_webhook` takes one
  `signature_header: &str`, which cannot carry three headers without a
  packing convention every caller has to know.

Issues #593 (provider-neutral `LifecycleEvent`) and #601 (Stripe's
`normalize`) set the direction for interpreting events: each adapter
maps its vendor's verified events in a **free function in the adapter
crate**, so `Payments` does not change for it. None of #589, #593, #601,
#602 is implemented, and `cratefield-module-billing` (#603, #605) does
not exist yet.

## Decision

**1. Polar is a `Payments` adapter, not a new port.** It moves money the
way the port means: hosted checkout, refunds, metered usage. Operations
a MoR does not offer (`create_connect_account_link`,
`charge_with_transfer`) return `PaymentsError::Unsupported`, never a
silent no-op.

**2. The port gains only additive methods with defaults**, so every
existing implementation compiles unchanged and `HARNESS_API` stays 1:

- `create_portal_session(&PortalSessionRequest { customer_ref,
  return_url, idempotency_key }) -> PortalSession { url }`, exactly the
  shape #589 specified.
- `get_dispute(dispute_ref) -> Dispute` and
  `close_dispute(dispute_ref, idempotency_key) -> Dispute`, as #602
  specified, plus `list_disputes(&DisputeListRequest) -> DisputePage`,
  which #602 did not have and Polar needs: without a webhook, a
  scheduled poll is the only way to see a dispute open.
- `verify_webhook_request(&HeaderMap, body)`, defaulting to reading
  `Stripe-Signature` and delegating to `verify_webhook`. A handler that
  calls it is the same for every adapter.

The defaults answer `Unsupported` (portal, disputes) or delegate
(`verify_webhook_request`).

**3. The dispute types follow #602, with three changes.** `Dispute` keeps
#602's fields (`id`, `charge_ref`, `payment_ref`, `amount`, `reason`,
`status`, `evidence_due_by`, `is_charge_refundable`,
`balance_transactions`). It adds `customer_ref`, because a venture
reacting to a dispute needs the account, and `provider_status`, the raw
string. `is_charge_refundable` is `Option<bool>`, because Polar does not
report it. `DisputeStatus` keeps #602's variants and adds `EarlyWarning`
and `Prevented`, the two states Polar reports around a dispute. It is
`#[non_exhaustive]`. `DisputeStatus::phase()` folds every status into
`DisputePhase::{Open, Won, Lost, Closed}`, the lifecycle a venture acts
on: flag on `Open`, restore on `Won`/`Closed`, revoke on `Lost` (ADR
0025, Decision 9). `Dispute::event_key()` (`dispute:{id}:{status}`) is
the `Inbox` key, so a transition seen by webhook and by poll is acted on
once.

**4. Event interpretation stays in the adapter**, as #601 shapes it for
Stripe: `cratefield_adapter_polar::normalize(&WebhookEvent)` returns
typed `PolarEvent`s, and no event type is added to `Payments`. Disputes
inside it are the port's own `Dispute`, so dispute handling is already
provider-neutral. When #593's `LifecycleEvent` lands, Polar's mapping
onto it goes in the same function.

**5. Refund reasons and usage batches are adapter methods**
(`Polar::refund_with_reason`, `Polar::report_usage_batch`), not port
methods. No issue has designed them for the port, and neither is needed
to switch providers.

## Alternatives considered

- **A `PaymentEvent` enum on the port, with a
  `payment_events(&WebhookEvent)` method.** It would let one handler
  interpret both providers' webhooks today. It lost because it is the
  parallel design to #593's `LifecycleEvent`. Two neutral event models
  would have to be reconciled, and #601 already decided interpretation
  is an adapter free function.
- **A second port for Merchants of Record.** It lost because the
  operations are the same ones `Payments` names (checkout, refund,
  usage). Splitting them would make a venture's code depend on which
  kind of seller it uses, which is the coupling this ADR removes.
- **Packing Polar's three headers into `signature_header`.** Kept only
  as a fallback (`signature_header(&headers)` builds the packing). As
  the primary path it pushes a vendor convention onto every caller.

## Consequences

- `cratefield-core` gains the dispute and portal types and four default
  methods. The change is additive (a minor bump; the next core release
  is already 0.7.0 for other reasons) and `HARNESS_API` is unchanged.
- #589 and #602 land smaller: the port shape exists, and they implement
  the Stripe side (`billing_portal/sessions`, `/v1/disputes`) and the
  rest of their scope (subscription lookup, evidence, balance
  transactions).
- With no dispute webhook from Polar, the module that owns disputes
  (#603, #612) must run a scheduled `list_disputes` poll for Polar.
  `Dispute::event_key` keeps it exactly-once alongside Stripe's
  webhooks.
- A Polar webhook route in `cratefield-module-billing` (#605) is a
  follow-up: the module does not exist yet.
- The live path against the Polar sandbox is needs-human: it needs an
  organization token, which does not live in the repo.

## References

- Issue #690 (this ADR); issues #589, #593, #601, #602, #603, #605,
  #612; ADR 0002, ADR 0025.
- `crates/core/src/ports/payments.rs`, `crates/adapter-polar/`,
  `docs/PAYMENTS.md`.
- Polar API 2026-04: https://polar.sh/docs/api-reference/2026-04/introduction,
  OpenAPI at https://polar.sh/docs/openapi/2026-04.openapi.json; webhook
  delivery and signing:
  https://polar.sh/docs/integrate/webhooks/delivery; dispute fees:
  https://polar.sh/docs/merchant-of-record/fees; chargeback management:
  https://polar.sh/docs/merchant-of-record/account-reviews.
