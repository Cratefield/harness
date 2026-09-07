# PCI DSS scope

Cratefield's posture is **SAQ A**: we never store, process, or transmit
cardholder data. **Stripe owns the card data.** A customer's card number, its
expiry, and its verification code are entered into Stripe's own fields (Checkout,
Elements, or the mobile SDKs) and never touch a Cratefield Worker, database, or
log. This keeps the harness and every venture on it out of PCI DSS scope, and it
is a decision that erodes the moment someone stores a card number "just
temporarily" — so it is also mechanically enforced (below).

## What we never store

Primary account numbers (PANs), full or truncated beyond Stripe's own display
form; card expiry (`exp_month`/`exp_year`); verification codes (CVV/CVC); and
magnetic-stripe or chip track data. Not in a column, not in a secret, not in a
log line, not "temporarily".

## What we do store, and why it is not card data

Stripe hands back **identifiers**, and those are ordinary data:

| Kept as an ordinary column | What it is |
| :--- | :--- |
| `stripe_customer_id` (`cus_…`) | A handle to Stripe's customer record |
| `stripe_payment_method_id` (`pm_…`) | A handle to a saved payment method Stripe holds |
| `stripe_payment_intent_id` (`pi_…`) | A handle to one payment Stripe is processing |
| `stripe_subscription_id` (`sub_…`) | A handle to a Stripe subscription |
| Card **brand** and **last four** | Stripe's own display fields; not the PAN |

None of these can reconstruct a card, and none is in PCI scope. The rule is
"never store the card," not "never mention payments."

## Secrets

Stripe's **webhook signing secret** and **API keys** are secrets, so they live
in the secrets layer (`cratefield-secrets`): encrypted, AAD-bound, audited,
rotatable. They are named plainly (`stripe/webhook_signing_secret`,
`stripe/secret_key`) — never after card data.

## How it is enforced

- **Migrations.** `fz doctor` runs a card-data lint over every module migration
  (both dialects) and fails on a column or table name that looks like card data
  (`card_number`, `cvv`, `cvc`, `exp_month`, `exp_year`, `card_expiry`,
  `track_data`, …). The predicate is `cratefield_core::lint_card_data`. It reads
  DDL only, so this document does not trip it, and it deliberately does not
  match the bare words `pan`, `track` or `expiry`, which collide with legitimate
  columns (an audio pan, a music track, a `session_expiry`).
- **Secrets.** `SecretStore::put` refuses a secret whose name looks like card
  data, with the reason above (`cratefield_core::card_data_hit`).

## Not yet enforced

The nightly production-checksum comparison and the required CI status check are
part of the migration-CI issue (#34) and are not built here. This document and
the two runtime/CLI checks are the parts that stand alone.

_Referenced from the SOC 2 control mapping (#43) once that document exists._
