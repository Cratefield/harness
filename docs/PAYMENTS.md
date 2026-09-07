# Payments

The `Payments` port (issue #102) is how a venture moves money. Stripe is the
first and only adapter (`cratefield-adapter-stripe`); like every adapter it runs
over the runtime's `HttpClient` port, so the same code serves on Cloudflare
Workers and on the native runtime.

## Card data never reaches the harness

The harness holds **Stripe identifiers only** — a checkout session, a customer,
a Connect account, a payment-intent, a refund — never a card number, CVC, or
expiry. Buyers enter their card on Stripe's own hosted pages:

- `create_checkout` and `create_subscription_checkout` return a **hosted Stripe
  Checkout URL** the browser is redirected to. The card is entered there.
- `create_connect_account_link` returns a **hosted Stripe onboarding URL** for a
  coach's Connect account.
- `charge_with_transfer` and `refund` name existing Stripe objects by id.

Because no card data crosses a harness process, there is nothing in scope here
to store, encrypt, or audit as card data. The complementary rule — that a
venture must not build a card field or persist card-shaped data itself — is the
card-data non-goal in [CARD-DATA.md](CARD-DATA.md), enforced by the
`card_data` lint and `SecretStore` name check.

We use Stripe the ordinary way. This document makes no compliance claim and
defines no compliance program.

## The three money flows (Yoginini, the first venture that takes money)

1. **Web membership subscription** — Stripe Billing. `create_subscription_checkout`
   against a configured Stripe Price, with an optional free trial.
2. **Per-session payments to a coach** — Stripe Connect **destination charges**.
   `charge_with_transfer` creates a payment-intent with
   `transfer_data[destination]` (the coach's Connect account) and
   `application_fee_amount` (the platform's cut — an 80/20 split that a venture
   can shift to ~88/12 on repeat bookings by lowering the fee it passes).
3. **App Store subscriptions** — not Stripe at all. Apple's App Store Server
   Notifications are a separate inbound webhook a **venture module** verifies
   (JWS/ES256 against Apple's certificate chain); they are out of scope for this
   port and this adapter. They must land in the same entitlement the Stripe
   subscription does, but that reconciliation is venture code.

## Webhooks

`verify_webhook(signature_header, body)` verifies the `Stripe-Signature` header
before returning an event:

- HMAC-SHA256 over `{timestamp}.{raw body}` with the endpoint's `whsec_...`
  signing secret, compared in constant time against every `v1` signature the
  header carries.
- The timestamp must be within five minutes of now (`WEBHOOK_TOLERANCE`), so a
  captured request cannot be replayed later.

Only a verified event is returned; a bad signature or a stale timestamp is a
`PaymentsError::SignatureInvalid`, and the handler must answer `400` without
processing anything. A billing **module** subscribes to the verified event and
decides what it means (a trial started, a subscription lapsed, a charge
succeeded) — the adapter never interprets it.

## Configuration

Two secrets, through the secrets layer (never plain env in production):

- `STRIPE_SECRET_KEY` — the `sk_...` API key.
- `STRIPE_WEBHOOK_SECRET` — the `whsec_...` endpoint signing secret.

`fz doctor` fails a **production** venture that provides the `Payments` port
without `STRIPE_WEBHOOK_SECRET` set: without it, webhook signatures cannot be
verified and forged events would be trusted. When no key is set at all the
adapter reports `NotConfigured` and makes no network call, so a venture builds
and runs without Stripe.

## Not in scope

Billing-module logic — trials, entitlements, payout schedules, the 80/20 → 88/12
split policy — is venture code. Apple JWS verification is a venture module. This
port names only what a module needs to reach Stripe.
