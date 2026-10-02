# Usage metering

`cratefield_core::Usage` (issue #588) is a durable **allowance** counter: "this
account may send 1 000 mails this month". It answers one question — *has this
subject already spent its allowance for this period?* — from the database,
race-free, in the same statement that does the spending. A module owns a meter
the way it owns a cooldown (`SendCooldown`): it declares the table, ships the
DDL as a migration, and calls the counter.

```rust,ignore
use cratefield_core::{Period, Usage};

let usage = Usage::new("notifications_usage"); // create_table_sql() is the migration
let period = Period::CalendarMonthUtc;
let now = time::OffsetDateTime::now_utc();
```

`subject` is who the allowance belongs to (an account id, a tenant id); `meter`
is which resource is counted (`"mail_sent"`). One table holds every meter,
keyed by `(subject, meter, period_start)`.

## An allowance is not a rate limit

The `RateLimiter` throttles **attempts** over a short fixed window and, being a
transport, may fail open — the right trade for shedding abusive traffic, the
wrong one for a quota someone pays for. It counts tries, so a request that
fails still spends; it forgets history at the window edge; and its counter can
live in a cache that loses the count under load.

An allowance counts **the work**, resets on a billing period, and lives in the
venture's own database, so the count is as durable as the rows the work wrote.
Use the rate limiter to keep a burst out; use `Usage` to refuse the
two-thousandth mail.

## Spend in the same batch as the work

The rule is one line: **the allowance is spent in the same transaction as the
work it pays for — never before, never after.** Spending first charges for work
that may fail; doing the work first gives it away when the allowance is gone.

`consume_statement` returns a `Statement` for the module's own
`db.batch_atomic(..)`, beside the work:

```rust,ignore
use cratefield_core::{Exhausted, Period, Problem, Usage, allowance_exhausted};

let batch = [
    usage.consume_statement(&account, "mail_sent", period, now, 1, Some(limit)),
    // the work this spend pays for — an outbox row, a send record, …
    outbox.enqueue_statement(&id, "mail_sent", &payload, Some(&account), &now_text),
];

if db.batch_atomic(&batch).await.is_err() {
    // The batch rolled back. `consume_statement` FAILS (it does not affect
    // zero rows) when the allowance cannot carry the amount, so a spent
    // allowance arrives here as a failed batch like any other. Read the
    // meter back to tell the two apart.
    let used = usage.read(&*db, &account, "mail_sent", period, now).await?;
    if used >= limit {
        return Ok(allowance_exhausted(
            "mail_sent",
            &Exhausted::spent(used, limit, period, now),
        ));
    }
    return Err(Problem::internal());
}
// Committed: the spend and the work both stand.
```

Why it **fails** rather than affecting zero rows: `batch_atomic` reports no
per-statement counts, so a guard that silently affected nothing would let the
paid-for work commit for free. A `NOT NULL` violation on `used` aborts the
whole batch. With `limit` `None` the meter is counted but unbounded — the same
upsert without the guard, failing only on a genuine database error.

## The single-call shape

When the work cannot join a batch — an upstream API call, say — use `consume`.
It runs the guarded upsert alone (one row affected on admission, none when
spent) and answers a `Consumption`:

```rust,ignore
use cratefield_core::{Consumption, Period, Usage, allowance_exhausted};

match usage.consume(db, &account, "mail_sent", period, now, 1, Some(limit)).await? {
    Consumption::Consumed(_) => { /* the allowance is spent; now do the work */ }
    Consumption::Exhausted(ref spent) => return Ok(allowance_exhausted("mail_sent", spent)),
}
```

Admission and the increment are one statement, so concurrent callers cannot
overspend the last unit. An `amount` larger than the whole allowance is refused
as exhausted from the start (`used` `0`). `refund` returns an amount without
going below zero; `read` answers the current total (`0` when there is no row).

## Periods

A `Period` says how the window is cut; every variant converts to UTC first.
`CalendarMonthUtc` is the UTC calendar month, `Day` the UTC day, and
`Anchored { anchor, every }` a billing cycle anchored on a subscription's
start: period *k* starts at `anchor + k * every` months, **recomputed from the
anchor every time, never chained**.

The anchored rule is the only subtlety. The day is clamped to the target
month's last day and the anchor's time-of-day kept: an anchor on **Jan 31**
gives Feb 28 next (Feb 29 in a leap year), then Mar 31, then Apr 30 — each
clamp remembered only for the month that needs it, because the next start comes
from the anchor. An anchor on the 29th keeps the 29th outside February. A `now`
before the anchor uses floor division (a negative index), so a cycle that has
not started still has a window. `window_at(now)` gives the period containing
`now`; `index_at` and `window_for` step back n periods. Hand-rolled, no date
library beyond `time`, so core stays wasm-safe.

## History and retention

`history(db, subject, meter, period, now, last_n_periods)` returns the last n
windows with their spend, **most recent first**, the period containing `now`
first, periods with no row reported as `0` — a chart should not have holes.

The meter grows one row per `(subject, meter, period)` forever. `purge` deletes
every counter older than the `keep_periods` most recent windows (the one
containing `now` included). Core schedules nothing: the owning module calls it
from its `Module::scheduled` tick, the way `cratefield-module-waitlist` calls
`SendCooldown::prune` from its cron handler. Keep at least as many periods as
the longest report reads.

## The 429

An exhausted allowance is the `usage/allowance-exhausted` problem: 429 with
`Retry-After` set to the seconds until the period resets and the extension
members `meter`, `limit`, `used` and `period_end` (RFC 3339) in the body, so a
caller can show "You have used 1 000 of 1 000 mails; resets on 1 Mar" without a
second request. Build it with `cratefield_core::allowance_exhausted`; the slug
is in `docs/ERRORS.md` with every other problem.
