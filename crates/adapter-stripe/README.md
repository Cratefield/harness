<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/banners/cratefield-adapter-stripe.png" alt="cratefield-adapter-stripe — Payments port." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-adapter-stripe"><img src="https://img.shields.io/crates/v/cratefield-adapter-stripe.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-adapter-stripe on crates.io"></a>
  <a href="https://docs.rs/cratefield-adapter-stripe"><img src="https://img.shields.io/docsrs/cratefield-adapter-stripe?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-adapter-stripe documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-adapter-stripe

The [`Payments`](https://docs.rs/cratefield-core) port over the Stripe REST API,
for the Cratefield harness (issue #102).

It talks to `api.stripe.com` through the runtime's `HttpClient` port, so the one
adapter runs unchanged on Cloudflare Workers and on the native runtime — no
vendor SDK.

## Card data never crosses this adapter

Every call creates or reads a Stripe object by id, or returns a **hosted Stripe
URL** the browser is redirected to (Checkout, Connect onboarding). Card numbers,
CVCs and expiries are entered on Stripe's own pages and never reach the harness;
it holds Stripe identifiers only. See `docs/PAYMENTS.md`.

## What it does

- `create_checkout` / `create_subscription_checkout` — hosted Checkout in
  `payment` / `subscription` mode; returns the URL to redirect to.
- `create_connect_account_link` — creates an Express Connect account (a coach)
  when needed and returns a hosted onboarding link.
- `charge_with_transfer` — a destination charge (`PaymentIntent` with
  `transfer_data[destination]` and `application_fee_amount`): the platform keeps
  its fee, the rest goes to the connected account.
- `refund` — a full or partial refund of a prior payment.
- `report_usage` — reports one metered usage amount to a Stripe Billing Meter
  (`POST /v1/billing/meter_events`). The `identifier` is the exactly-once key
  and also the `Idempotency-Key`, so a retry is safe; Stripe's
  `duplicate_meter_event` is returned as `already_reported: true`, not an error.
- `verify_webhook` — verifies the `Stripe-Signature` HMAC-SHA256 and its
  timestamp (5-minute tolerance) over the raw body, then returns the event.

Every mutating call sends an `Idempotency-Key`. When no key is configured the
adapter reports `NotConfigured` without any network call.

## Usage

```rust,ignore
use std::sync::Arc;
use cratefield_adapter_stripe::Stripe;

let http = Arc::new(cratefield_runtime_cloudflare::FetchClient);
let clock = Arc::new(cratefield_runtime_cloudflare::WorkersClock);

let payments: Arc<dyn cratefield_core::Payments> = match env.secret("STRIPE_SECRET_KEY").ok() {
    Some(key) => Arc::new(Stripe::new(
        http,
        clock,
        key.to_string(),
        env.secret("STRIPE_WEBHOOK_SECRET").map(|s| s.to_string()).unwrap_or_default(),
    )),
    None => Arc::new(Stripe::not_configured()),
};

let runtime = cratefield_runtime_cloudflare::Cloudflare::new().payments_arc(payments);
```

## Verification

Request shaping, error mapping, and webhook verification (a tampered signature
and a stale timestamp are both refused) are unit-tested against a scripted
`HttpClient`. The live path against Stripe is **needs-human**: it needs real
test-mode keys, which do not live in the repo.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
