# Card data

Cratefield uses Stripe the normal way. Card details go straight to Stripe —
through Checkout, Elements, or the mobile SDKs — and never reach a Cratefield
Worker, database, or log. A backend on the harness never sees a card number, so
there is nothing to store.

This is not a compliance posture, just how a normal Stripe integration works.
The harness keeps it that way with two small guardrails so a card number cannot
be stored by accident.

## What we keep, and what we never keep

Stripe hands back **identifiers**, and those are ordinary data:

| Kept as an ordinary column | What it is |
| :--- | :--- |
| `stripe_customer_id` (`cus_…`) | A handle to Stripe's customer record |
| `stripe_payment_method_id` (`pm_…`) | A handle to a saved payment method Stripe holds |
| `stripe_payment_intent_id` (`pi_…`) | A handle to one payment Stripe is processing |
| `stripe_subscription_id` (`sub_…`) | A handle to a Stripe subscription |
| Card **brand** and **last four** | Stripe's own display fields, not the number |

Never stored: the card number, its expiry (`exp_month`/`exp_year`), its
verification code (CVV/CVC), or magnetic-stripe/track data. Not in a column, not
in a secret, not in a log.

## Secrets

Stripe's **webhook signing secret** and **API keys** are secrets, so they live
in the secrets layer (`cratefield-secrets`): encrypted, AAD-bound, audited,
rotatable. They are named plainly (`stripe/webhook_signing_secret`,
`stripe/secret_key`) — never after card data.

## The guardrails

- **Migrations.** `fz doctor` fails on a column or table name that looks like
  card data (`card_number`, `cvv`, `cvc`, `exp_month`, `exp_year`,
  `card_expiry`, `track_data`, …), on either dialect. The predicate is
  `cratefield_core::lint_card_data`. It reads DDL only, so this document does not
  trip it, and it deliberately does not match the bare words `pan`, `track` or
  `expiry`, which collide with legitimate columns (an audio pan, a music track,
  a `session_expiry`).
- **Secrets.** `SecretStore::put` refuses a secret whose name looks like card
  data (`cratefield_core::card_data_hit`).
