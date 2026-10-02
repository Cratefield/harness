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
3. **App Store subscriptions** — not Stripe at all, and not this port.
   Apple's App Store Server Notifications and Google Play's notifications are
   aggregated by RevenueCat and reach the harness through the separate
   `InAppPurchases` port and `cratefield-module-billing` (ADR 0025); they are
   out of scope for `Payments` and the Stripe adapter. They land in the same
   entitlement the Stripe subscription does, and that reconciliation is the
   module's job, not the venture's (ADR 0025).

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

### Idempotency

A verified signature authenticates a *delivery*, not a *first* delivery: Stripe
retries, and two workers can process the same event at once. Before applying an
effect, a handler claims the event id through `cratefield_core::Inbox` — a dedup
ledger over the `Database` port whose primary key lets exactly one caller win.
The claim goes in the **same atomic batch** as the effect's database writes
(grant the entitlement, extend the trial) — `claim_with`, or
`claim_statement(..)` first in your own `db.batch_atomic(..)`: the two commit
together or not at all, so a worker that dies mid-way leaves the key unclaimed
and Stripe's retry re-runs both (issue #534). An effect that leaves the process
(a receipt mail, a webhook onward) cannot go in the batch: enqueue it as an
`Outbox` row (`enqueue_statement(..)`) in the same batch, so it is durable
exactly when the claim is — a direct external call made after `claim_with`
returns `true` is lost with nothing to retry it if the worker dies after the
commit.

```rust,ignore
let inbox = Inbox::new("billing_inbox"); // the module ships create_table_sql() as a migration
let event = payments.verify_webhook(sig, body).await?;
if inbox.claim_with(db, &event.id, &now, &grant_entitlement_stmts).await? {
    // first time: the claim AND the effect just committed together
} // else: a duplicate/replayed/concurrent delivery — already handled
```

So a duplicate, replayed, concurrent or out-of-order delivery applies its effect
exactly once (issue #134), and a delivery that fails part-way is retried rather
than lost (issue #534).

## Configuration

Two secrets, through the secrets layer (never plain env in production):

- `STRIPE_SECRET_KEY` — the `sk_...` API key.
- `STRIPE_WEBHOOK_SECRET` — the `whsec_...` endpoint signing secret.

`fz doctor` fails a **production** venture that mounts a module with a
signature-guarded write — a webhook — without `STRIPE_WEBHOOK_SECRET` set:
without it, webhook signatures cannot be verified and forged events would be
trusted. The trigger is the webhook route, not the `Payments` port: a venture
that only opens checkouts and receives no webhook has nothing to verify and
needs no secret, and is not failed for missing one. More precisely, the
trigger is the webhook route *plus* the module verifying through
`Payments::verify_webhook` (the default): a module that declared
`SignatureVerification::Hmac` (issue #533) verifies with the core
`webhook_signature` scheme instead, gated on its own module-scoped secret
key rather than `STRIPE_WEBHOOK_SECRET` or the `Payments` port.
When no key is set at all the
adapter reports `NotConfigured` and makes no network call, so a venture builds
and runs without Stripe.

## Usage-based billing

`report_usage(report)` reports one metered amount to a Stripe Billing Meter
(`POST /v1/billing/meter_events`). The [`UsageReport`] carries the meter's
`event_name`, the Stripe customer id, the `value`, a `timestamp`, and an
`identifier`. The **identifier is the exactly-once key**: Stripe rejects a
second event with an identifier it has seen within a rolling ≥24-hour window
(`error.code: duplicate_meter_event`), and the adapter turns that refusal into
`UsageReported { already_reported: true }` — a duplicate is success, not an
error, so a retry never double-bills and never has to be special-cased. The
identifier is also sent as the `Idempotency-Key`, so an exact retry inside the
idempotency window returns the first response unchanged.

`UsageReport::hourly(subject, meter_event_name, customer_ref, value, at)` builds
one report per **UTC hour**: `timestamp` is the start of the hour containing
`at` and `identifier` is `{subject}:{meter_event_name}:{start unix}`, so every
report for the same subject, meter and hour collides on the same identifier.
The collision is only safe once the hour's value is **final** — report closed
windows, as below.

Stripe validates the event **synchronously** — a request with no meter for the
event name (`no_meter`), an archived meter, a bad payload, or a duplicate
identifier is a `400` on the call itself (the adapter maps those to
`PaymentsError::Rejected`, carrying Stripe's `code` and `message`). A
`409 too_many_concurrent_requests` — two events for the same customer and meter
at once — is a **retryable** race, mapped to `Transient` so the outbox backs
off and retries; `429`/`5xx` are `Transient` too. But **the customer is
resolved asynchronously**: a `stripe_customer_id` that does not exist is *not* a
synchronous error — Stripe accepts the event and reports the failure later
through the `v1.billing.meter.error_report_triggered` event. Subscribe to it (a
billing module's job) and reconcile; do not expect `report_usage` to fail for a
bad customer id.

### Dashboard setup (**needs-human**)

Meters, prices and the subscription are Stripe dashboard state, not code:

1. **Create a meter** — an event name (e.g. `extra_avatar_minutes`), `sum`
   aggregation, customer mapping on the payload key `stripe_customer_id`, and
   value on the payload key `value`.
2. **Create a metered price** on that meter — e.g. release.show's
   "extra avatar minute" at `$3/min` — with `usage_type: metered` and the same
   meter as its `meter`.
3. **Attach the price to the subscription** whose customer the reports name.

The adapter reports against the meter's event name; nothing here moves money
until Stripe rolls the reported usage into the subscription's invoice.

### Consuming and reporting, hourly

Reporting rests on **immutable, closed hourly buckets** — a module-owned
`usage_hourly(subject, meter, hour_start TEXT, used BIGINT, frozen_at TEXT,
enqueued_at TEXT)` table, keyed `(subject, meter, hour_start)`, written in the
same transaction as the consumption it counts. The tick **freezes** an hour once
it has closed, so its value can no longer change; a frozen bucket is then
enqueued exactly once, and every delivery carries the same value under the same
`UsageReport::hourly` identifier, which Stripe dedups. That is an exactly-once
effect with no compare-and-set on a moving total and no per-billing-period state
to roll over.

**Consume composition.** `consume_statement`, given the meter's `limit`, refuses
an over-limit spend by writing `NULL`, which violates the `NOT NULL` on `used`
and fails the statement; `batch_atomic` is all-or-nothing, so the bucket
increment beside it rolls back too. Refused usage never reaches a bucket, and
every admitted amount lands in exactly one. The **same NOT NULL trick guards the
increment's `CASE`**: a consume naming an already-frozen hour writes `NULL`,
fails, and rolls back, so the caller retries with a `now` in the live hour —
units can never land in a bucket the tick is about to read.

**Refunds** are guarded the same way (`... THEN used - ? ELSE NULL END`): they
decrement only an unfrozen bucket, and corrections to an already-reported window
are out of scope.

The outbox gives at-least-once delivery; the identifier gives the exactly-once
effect at Stripe. Not compiled (`rust,ignore`); the names are the real ones from
`usage.rs`, `outbox.rs` and the `Database` port — `db`, `clock`, `budget`,
`payments` and `customer_ref` are the module's own:

```rust,ignore
use cratefield_core::{
    Clock, Database, DbError, DrainOptions, Outbox, Payments, PaymentsError, Period, Processed,
    ScheduledBudget, Statement, Usage, UsageReport,
};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime, UtcOffset};

fn rfc3339(at: OffsetDateTime) -> String {
    at.to_offset(UtcOffset::UTC)
        .replace_nanosecond(0)
        .unwrap_or(at)
        .format(&Rfc3339)
        .unwrap_or_default()
}

fn hour_start(at: OffsetDateTime) -> OffsetDateTime {
    let at = at.to_offset(UtcOffset::UTC);
    at.replace_minute(0)
        .and_then(|t| t.replace_second(0))
        .and_then(|t| t.replace_nanosecond(0))
        .unwrap_or(at)
}

/// Spend against the meter (#588) and count the same amount into its hourly
/// bucket, in one transaction.
async fn consume(
    db: &dyn Database,
    usage: &Usage,
    subject: &str,
    meter: &str,
    now: OffsetDateTime,
    amount: u64,
    limit: Option<u64>,
) -> Result<(), DbError> {
    db.batch_atomic(&[
        usage.consume_statement(subject, meter, Period::CalendarMonthUtc, now, amount, limit),
        bucket_increment(subject, meter, hour_start(now), amount),
    ])
    .await
}

/// `+= amount`, but only into a bucket the tick has not frozen. Writing `NULL`
/// into `used` (NOT NULL) aborts the batch, so a late consume into a frozen
/// hour rolls back and the caller retries with a `now` in the live hour.
fn bucket_increment(
    subject: &str,
    meter: &str,
    hour_start: OffsetDateTime,
    amount: u64,
) -> Statement {
    Statement::with_values(
        "INSERT INTO release_usage_hourly (subject, meter, hour_start, used, frozen_at, enqueued_at)\n\
         VALUES (?, ?, ?, ?, NULL, NULL)\n\
         ON CONFLICT (subject, meter, hour_start) DO UPDATE\n\
         SET used = CASE WHEN release_usage_hourly.frozen_at IS NULL\n\
                         THEN release_usage_hourly.used + excluded.used\n\
                         ELSE NULL END",
        vec![
            subject.to_owned().into(),
            meter.to_owned().into(),
            rfc3339(hour_start).into(),
            i64::try_from(amount).unwrap_or(i64::MAX).into(),
        ],
    )
}

fn mark_enqueued(
    subject: &str,
    meter: &str,
    hour_start: OffsetDateTime,
    at: OffsetDateTime,
) -> Statement {
    Statement::with_values(
        "UPDATE release_usage_hourly SET enqueued_at = ?\n\
         WHERE subject = ? AND meter = ? AND hour_start = ? AND enqueued_at IS NULL",
        vec![
            rfc3339(at).into(),
            subject.to_owned().into(),
            meter.to_owned().into(),
            rfc3339(hour_start).into(),
        ],
    )
}

/// Freeze every closed hour, then enqueue one report per frozen bucket.
async fn report_closed(
    db: &dyn Database,
    outbox: &Outbox,
    customer_ref: &str,
    now: OffsetDateTime,
) -> Result<(), DbError> {
    // Phase 1: freeze. Idempotent, so it needs no batch. Once an hour is
    // frozen, no consume can add to it (its batch fails), so the value phase 2
    // reads is final.
    let grace = Duration::hours(1) + Duration::minutes(5);
    let closed_before = rfc3339(hour_start(now - grace));
    db.execute(&Statement::with_values(
        "UPDATE release_usage_hourly SET frozen_at = ?\n\
         WHERE hour_start <= ? AND frozen_at IS NULL",
        vec![rfc3339(now).into(), closed_before.into()],
    ))
    .await?;

    // Phase 2: enqueue. A crash between the phases is harmless — the next tick
    // rescans whatever is frozen but not enqueued. Buckets older than 35 days
    // stop being scanned (they can no longer be reported), so an operator must
    // act before then.
    let oldest = rfc3339(hour_start(now - Duration::days(35)));
    let rows = db
        .query(&Statement::with_values(
            "SELECT subject, meter, hour_start, used FROM release_usage_hourly\n\
             WHERE frozen_at IS NOT NULL AND enqueued_at IS NULL AND hour_start >= ?",
            vec![oldest.into()],
        ))
        .await?;

    for row in &rows.rows {
        let subject = row.get::<String>("subject").unwrap_or_default();
        let meter = row.get::<String>("meter").unwrap_or_default();
        let hour = row.get::<String>("hour_start").unwrap_or_default();
        let value = row.get::<u64>("used").unwrap_or(0);
        if value == 0 {
            continue;
        }
        let Ok(at) = OffsetDateTime::parse(&hour, &Rfc3339) else {
            continue;
        };
        let report = UsageReport::hourly(&subject, &meter, customer_ref, value, at);
        let payload = serde_json::json!({
            "subject": subject,
            "meter": meter,
            "customer_ref": customer_ref,
            "hour_start": report.timestamp.unix_timestamp(),
            "value": value,
        })
        .to_string();
        let id = format!("usage-report-{}", report.identifier);

        // One batch: mark the bucket enqueued (guarded) and write the report,
        // so a crash can neither queue twice nor leave the bucket half-moved.
        let batch = [
            mark_enqueued(&subject, &meter, at, now),
            outbox.enqueue_statement(&id, "usage.report", &payload, Some(&subject), &rfc3339(now)),
        ];
        if let Err(err) = db.batch_atomic(&batch).await {
            // A racing tick may have enqueued this bucket between our SELECT and
            // our write; its outbox row collides with ours on the primary key
            // and our batch rolls back. Re-read to tell that benign case (the
            // marker is now set) from a real failure.
            let settled = db
                .query(&Statement::with_values(
                    "SELECT enqueued_at FROM release_usage_hourly\n\
                     WHERE subject = ? AND meter = ? AND hour_start = ?",
                    vec![
                        subject.clone().into(),
                        meter.clone().into(),
                        rfc3339(at).into(),
                    ],
                ))
                .await?;
            let now_enqueued = settled
                .first()
                .and_then(|row| row.get::<Option<String>>("enqueued_at"))
                .flatten()
                .is_some();
            if now_enqueued {
                tracing::debug!("usage bucket already enqueued by a racing tick");
            } else {
                tracing::warn!("usage enqueue batch failed: {err}");
                return Err(err);
            }
        }
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct UsagePayload {
    subject: String,
    meter: String,
    customer_ref: String,
    hour_start: i64,
    value: u64,
}

/// The scheduled drain.
async fn drain(
    db: &dyn Database,
    outbox: &Outbox,
    payments: &dyn Payments,
    clock: &dyn Clock,
    budget: &ScheduledBudget,
) -> Result<(), DbError> {
    outbox
        .drain_within(
            db,
            clock,
            budget,
            DrainOptions {
                limit: 20,
                lease: Duration::minutes(1),
                subrequests_per_item: 1,
            },
            |record| async move {
                let Ok(payload) = serde_json::from_str::<UsagePayload>(&record.payload) else {
                    // Our own payload, but never drop data on a parse failure:
                    // log it and retry later.
                    tracing::error!("usage report payload did not parse: {}", record.id);
                    return Processed::RetryAt(clock.now() + Duration::hours(6));
                };
                let at = OffsetDateTime::from_unix_timestamp(payload.hour_start)
                    .unwrap_or(OffsetDateTime::UNIX_EPOCH);
                let report = UsageReport::hourly(
                    &payload.subject,
                    &payload.meter,
                    &payload.customer_ref,
                    payload.value,
                    at,
                );
                match payments.report_usage(&report).await {
                    Ok(_) => Processed::Done, // including already_reported
                    Err(PaymentsError::Transient(_)) => Processed::RetryAt(
                        clock.now() + Duration::minutes(record.attempts.clamp(1, 60)),
                    ),
                    // Degraded mode (no keys) or no meter yet: expected and
                    // recoverable, retry later rather than drop the usage.
                    Err(PaymentsError::NotConfigured | PaymentsError::Unsupported(_)) => {
                        Processed::RetryAt(clock.now() + Duration::hours(6))
                    }
                    // A refusal (e.g. `no_meter`, a needs-human setup step) is
                    // recoverable too, and the bucket is already marked, so
                    // `Done` would lose the usage for good. Retry on a long
                    // delay; an operator must act before Stripe's 35-day window
                    // closes, or the report can never be accepted.
                    Err(err) => {
                        tracing::error!("usage report refused, retrying later: {err}");
                        Processed::RetryAt(clock.now() + Duration::hours(6))
                    }
                }
            },
        )
        .await
        .map(|_| ())
}
```

The 5-minute grace is not Stripe clock skew: an hour-start `timestamp` is always
in the past. It exists so a consume for that hour either commits or fails and
retries before the tick freezes it. Buckets older than 35 days simply stop being
scanned — they can no longer be reported, so an operator must reconcile them.

## Not in scope

The billing *lifecycle* — trials, entitlements, renewals, disputes and the
revenue ledger — is not this port's; it lives in the published
`cratefield-module-billing` module (ADR 0025), which reads store purchases
through the `InAppPurchases` port. What stays venture code is policy: what an
entitlement unlocks, its prices, and the payout-split policy (the 80/20 →
88/12 example above). This port names only what a module needs to reach
Stripe.

Usage reporting is deliberately narrow: it is Billing **Meters** only. The
legacy `subscription_item` usage-record API (the deprecated
`POST /v1/subscription_items/{id}/usage_records`, driven by `usage_type:
metered` without a meter) and invoice **previews** (`POST /v1/invoices/create_preview`,
`upcoming`) are out of scope — a venture that needs them today uses the Stripe
API through a venture-owned HTTP client, not this port.
