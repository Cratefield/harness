# cratefield-adapter-stripe

The [`Payments`](https://docs.rs/cratefield-core) port over the Stripe REST API,
for the Factory Zero / Cratefield harness (issue #102).

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
