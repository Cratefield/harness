<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/banners/cratefield-adapter-polar.png" alt="cratefield-adapter-polar — Merchant of Record." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-adapter-polar"><img src="https://img.shields.io/crates/v/cratefield-adapter-polar.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-adapter-polar on crates.io"></a>
  <a href="https://docs.rs/cratefield-adapter-polar"><img src="https://img.shields.io/docsrs/cratefield-adapter-polar?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-adapter-polar documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-adapter-polar

The [`Payments`](https://docs.rs/cratefield-core) port over
[Polar](https://polar.sh), a **Merchant of Record**, for the Cratefield harness
(issue #690, ADR 0027).

Polar is the legal seller. It collects the payment, handles VAT, GST and sales
tax worldwide, and pays the founder out, so a venture run by an individual
with no company can sell from day one. When a company exists, switching to
`cratefield-adapter-stripe` is a change of composition: the venture's code
talks to `Payments`, never to Polar.

It talks to Polar through the runtime's `HttpClient` port, so the one adapter
runs unchanged on Cloudflare Workers and on the native runtime. No vendor SDK,
no `reqwest`.

## What it does

| `Payments` | Polar |
|---|---|
| `create_subscription_checkout` | `POST /v1/checkouts/` for one product. A Polar product has one interval, so monthly and annual are two products, and `price_ref` is the product id |
| `create_checkout` (one-off) | `POST /v1/checkouts/` with an ad-hoc fixed price on the product set with `with_one_off_product` |
| `create_portal_session` | `POST /v1/customer-sessions/` → `customer_portal_url` (plan changes, invoices, cancelling) |
| `refund` | `POST /v1/refunds/`, full (the order's `refundable_amount`) or partial, with a reason |
| `report_usage` | `POST /v1/events/ingest`, deduplicated on `external_id` = `UsageReport::identifier` |
| `get_dispute`, `list_disputes`, `close_dispute` | `GET /v1/disputes/{id}`, `GET /v1/disputes/`, `POST /v1/disputes/{id}/accept` |
| `verify_webhook_request`, `verify_webhook` | Standard Webhooks headers, with both of Polar's key derivations |
| `create_connect_account_link`, `charge_with_transfer` | `PaymentsError::Unsupported`. Polar pays the seller out itself and has no server-side charge API |

Checkout and subscription **metadata** (the venture's account id, say) goes to
Polar's `metadata`, which Polar copies onto the resulting order and
subscription, so it comes back on their webhooks. The customer's email goes
to `customer_email`.

**Customer ids.** By default a `customer_ref` is Polar's customer id. With
`.with_customer_ids(CustomerIds::External)` it is the venture's own id
(Polar's `external_customer_id`) for checkout, the portal, usage events and
disputes, so the venture never stores a Polar id at all.

**Refund amounts are net.** Polar refunds the amount before tax and refunds the
matching tax itself. Polar takes no `Idempotency-Key`, so the adapter stores
the request's key in the refund's metadata
(`cratefield_idempotency_key`) and looks it up before creating: a retried
refund returns the one already made. `refund` records the reason set with
`with_refund_reason` (default `customer_request`); `refund_with_reason` names
it per call.

**Usage** is ingested as one event per report: `name` is the meter event
name, the value goes under the metadata key `value` (or `with_usage_value_key`),
and `external_id` is the report's identifier. Re-sending an identifier Polar
has already ingested comes back as `already_reported: true`, so the hourly
`UsageReport::hourly` flush in `docs/PAYMENTS.md` works unchanged.
`report_usage_batch` sends many reports per request (up to `MAX_INGEST_BATCH`).

## Webhooks

Polar signs with [Standard Webhooks](https://www.standardwebhooks.com/):
headers `webhook-id`, `webhook-timestamp` and `webhook-signature`
(`v1,<base64>`, space-separated), HMAC-SHA256 over
`{id}.{timestamp}.{raw body}`. The key depends on the secret's age, and the
adapter tries both, as Polar's own SDKs do:

- secrets created on or after 2026-09-08: the Standard Webhooks key, the base64
  after `whsec_`;
- older secrets ("Polar HMAC"): the UTF-8 bytes of the whole `whsec_…` string.

A timestamp more than five minutes from now, either way, is refused. Use
`verify_webhook_request(&headers, body)`: it takes the headers directly. The
port's older `verify_webhook(header, body)` takes the three headers packed by
`signature_header(&headers)`.

The returned event's `id` is the `webhook-id`, which Polar keeps across
retries: claim it through `cratefield_core::Inbox` and a replayed delivery is
applied once. `normalize(&event)` maps it onto a typed `PolarEvent`:

| Polar event | `PolarEvent` |
|---|---|
| `checkout.created` / `.updated` / `.expired` | `Checkout` (`Created` / `Updated` / `Expired`) |
| `subscription.created` / `.active` / `.updated` / `.canceled` / `.uncanceled` / `.revoked` / `.past_due` / `.paused` / `.resumed` / `.cycled` / `.migrated` | `Subscription` with the matching `SubscriptionChange` |
| `order.created` / `.paid` / `.updated` / `.refunded` | `Order` (`Created` / `Paid` / `Updated` / `Refunded`) |
| `refund.created` / `.updated` | `Refund`, plus `Dispute` when the refund prevented one |
| `customer.created` / `.updated` / `.deleted` / `.state_changed` | `Customer` |
| `benefit*`, `product.*`, `member.*`, `customer_seat.*`, `discount.*`, `organization.*` | nothing (logged at debug) |
| anything else | nothing (logged), never an error |

## Disputes and chargebacks

Polar sends **no dispute webhook**. It exposes disputes through its API, and
records a `balance.dispute` (and, when won, `balance.dispute_reversal`) system
event. So a venture **polls**: a scheduled job calls
`list_disputes(&DisputeListRequest { open_only: true, .. })` and `get_dispute`
for the disputes it is tracking, and claims each `dispute.event_key()`
(`dispute:{id}:{status}`) through the `Inbox`, so each transition is acted on
once:

| Polar status | `DisputeStatus` | `phase()` | What a venture typically does |
|---|---|---|---|
| `early_warning` | `EarlyWarning` | `Open` | flag the account |
| `needs_response` | `NeedsResponse` | `Open` | flag; evidence goes in through the Polar dashboard |
| `under_review` | `UnderReview` | `Open` | keep flagged |
| `won` | `Won` | `Won` | restore |
| `lost` | `Lost` | `Lost` | revoke what the payment funded |
| `prevented` | `Prevented` | `Closed` | Polar refunded to head it off: nothing to restore |

A dispute costs **$15** whatever the outcome, deducted from the Polar balance.
To head off chargebacks, Polar may refund an order within 60 days at its own
discretion. When it does, the order is refunded, any related subscription is
cancelled and benefits are revoked. That refund arrives as `refund.created`
with reason `dispute_prevention`, and `normalize` yields both the `Refund` and
a `Dispute` in `Prevented`. Polar holds accounts to a 0.4% chargeback rate.
`close_dispute` accepts the chargeback (settles it as lost).

## Usage

```rust,ignore
use std::sync::Arc;
use cratefield_adapter_polar::{CustomerIds, Environment, Polar};

let http = Arc::new(cratefield_runtime_cloudflare::FetchClient);
let clock = Arc::new(cratefield_runtime_cloudflare::WorkersClock);

let payments: Arc<dyn cratefield_core::Payments> = Arc::new(
    Polar::new(
        http,
        clock,
        Environment::parse(env.var("POLAR_ENVIRONMENT").ok().map(|v| v.to_string()).as_deref()),
        env.secret("POLAR_ACCESS_TOKEN").map(|s| s.to_string()).unwrap_or_default(),
        env.secret("POLAR_WEBHOOK_SECRET").map(|s| s.to_string()).unwrap_or_default(),
    )
    .with_customer_ids(CustomerIds::External),
);

let runtime = cratefield_runtime_cloudflare::Cloudflare::new().payments_arc(payments);
```

Natively, `Polar::from_env(http, clock)` reads the same three variables, and
`Polar::from_config(http, clock, &config)` reads them from the harness config.
`POLAR_ENVIRONMENT` is `sandbox` (`https://sandbox-api.polar.sh`, the default,
so a missing setting cannot move real money) or `production`
(`https://api.polar.sh`). A blank token makes the adapter `NotConfigured`
with no network call. The token and the webhook secret are never logged,
printed by `Debug`, or put in an error.

## Verification

Request shaping for every call, error mapping, webhook verification (both key
derivations, a wrong secret, a stale and a future timestamp, a tampered body
and id), the event mapping for every webhook type, both dispute lifecycles,
refund and usage idempotency, `Unsupported`, and switching from Stripe by
composition are tested against a scripted `HttpClient`. The response fixtures
follow Polar's `OpenAPI` schemas (API 2026-04) field for field. The live path
against the Polar sandbox is **needs-human**: it needs an organization token,
which does not live in the repo.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
