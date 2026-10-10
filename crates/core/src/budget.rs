//! Outbound HTTP budgets (issue #765): a per-upstream (and per-API-key)
//! token bucket shared across isolates, a per-provider daily quota, and a
//! `Retry-After`-aware retry policy — one [`HttpClient`] decorator an
//! adapter opts into by wrapping the client it already holds.
//!
//! An outbound request spends three budgets, in the order they can refuse
//! it:
//!
//! 1. **Pacing.** A [`Budget`] names a token bucket — `capacity` tokens of
//!    burst, refilled at `refill_per_sec` — and what one request costs. The
//!    bucket lives in the venture database, one row per key, so every
//!    isolate of every Worker instance spends the *same* bucket: admission
//!    and the refill-and-spend are **one statement** (the same guarded
//!    upsert shape [`Usage`] is built on, issue #588), so concurrent
//!    callers cannot both spend the last token. A shortfall that refills
//!    within [`RetryPolicy::max_delay`] is waited out in-process — that is
//!    pacing, not refusal, and it is bounded by `MAX_PACING_WAITS` — and
//!    anything longer comes back as [`HttpError::BudgetExhausted`] with the
//!    wait as `retry_after`.
//! 2. **Daily quota.** `Budget::daily_limit` caps requests per UTC day
//!    through [`Usage`] (`Period::Day`), so "10 000 calls a day" is a
//!    durable allowance, not a hope. Crossing the limit — or its 80%
//!    warning mark — emits [`EVENT_QUOTA_EXHAUSTED`] /
//!    [`EVENT_QUOTA_WARNING`] when [`BudgetedHttpClient::with_events`] is
//!    set. The alerts are at-most-once **by claim, not by arithmetic**:
//!    the increment is atomic but the read-back each caller sees is a
//!    separate statement, so concurrent callers can all observe the same
//!    crossing. What keeps the emission to one is a durable claim row —
//!    the first caller whose guarded insert reports one affected row owns
//!    the emission, every later observer's reports none and skips (the
//!    table: [`BudgetedHttpClient::create_alert_table_sql`]; the claim is
//!    keyed per UTC day, so a new day alerts afresh). The same rule trades
//!    the old exact-match arithmetic for an inequality: a burst that leaps
//!    the warning mark in one step — any limit of 4 or fewer, where
//!    `ceil(limit * 4 / 5)` is the limit itself — emits only
//!    [`EVENT_QUOTA_EXHAUSTED`]. A budget with `daily_limit: None` is
//!    untracked and pays no database round-trip.
//! 3. **Retries.** A 429/503 or a transport failure on an **idempotent**
//!    request (safe methods by default, a request-inserted [`Idempotent`]
//!    extension to override) is retried with exponential backoff, honouring
//!    the upstream's own `Retry-After` when it states one — both of its
//!    forms, through the one parser (issue #214). Delays clamp to
//!    `max_delay` each and to `max_total` for the whole exchange; a retry
//!    that no longer fits is not taken, and the last response or error
//!    passes through as-is. Bodies are never consumed to make this
//!    decision. Retries never re-pay the budget: pacing and the daily
//!    quota are spent once, before the first attempt, and the retries
//!    re-send through the inner client without touching either — one
//!    budget unit per logical call, across at most `max_retries + 1`
//!    upstream hits. Deliberate: the quota counts calls, not wire
//!    attempts.
//!
//! # The worst case, added up
//!
//! The budgets stack, and so do their waits: one `send()` may spend
//! `MAX_PACING_WAITS * max_delay` pacing (4 × 5 s = 20 s on the default
//! [`RetryPolicy`]), then up to `max_total` more in the retry exchange
//! (15 s), then whatever the inner client's own response timeout allows —
//! up to the 30 s `MAX_RESPONSE_TIMEOUT` ceiling `ports/http.rs` caps it
//! at. On the defaults that sum is 65 s, past the 30 s request bound a
//! Worker runs under, so a caller with a strict deadline lowers
//! [`RetryPolicy`] (and its router's numbers); the decorator does not
//! shorten the sum for it.
//!
//! Anything the budget layer does not govern — unrouted requests,
//! non-idempotent failures, other error variants — reaches the inner client
//! unchanged, exactly as
//! [`BoundedHttpClient`](crate::ports::BoundedHttpClient) passes through
//! what it does not bound.
//!
//! # Wiring
//!
//! ```ignore
//! let client = BudgetedHttpClient::new(inner, clock, db, router)
//!     .with_retry(RetryPolicy::default().with_max_retries(3))
//!     .with_events(ctx.events.clone())
//!     .with_defer(ctx.ports.defer.clone()?);
//! ```
//!
//! The decorator needs three tables, and the venture ships all three as
//! migrations: [`BudgetedHttpClient::create_bucket_table_sql`] for the
//! pacing buckets, [`Usage::create_table_sql`] for the daily quota, and
//! [`BudgetedHttpClient::create_alert_table_sql`] for the quota-alert
//! claims (default names [`DEFAULT_BUCKET_TABLE`], [`DEFAULT_QUOTA_TABLE`]
//! and [`DEFAULT_ALERT_TABLE`], overridable with `with_bucket_table` /
//! `with_quota_table` / `with_alert_table`). Only the alert path writes
//! the claim table, and it creates the table on demand if a claim ever
//! meets its absence — the migration is the contract, the auto-create the
//! safety net that keeps the alerts strict instead of dropping them. A
//! client with `with_events` unset never touches the claim table at all.
//!
//! Tokens are `f64` end to end — capacity, refill, cost — so a fractional
//! refill (0.5 tokens a second, a 2.5-token cost) needs no scaling. The
//! *read* is wider than the write: D1's JSON bridge hands a safe integral
//! JS number back as an integer, not a double, so the advisory read falls
//! back from the float shapes to the integral ones (`tokens_of` below) —
//! a bucket parked at exactly `9.0` must read as `9.0`, not as a fresh
//! bucket. All the arithmetic is pure functions below, unit-tested without
//! a database.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use serde_json::json;

use crate::events::EventBus;
use crate::ports::{
    ByteStream, Clock, Database, Defer, HttpClient, HttpError, IdGen, NoopDefer, Row, Statement,
    UlidIdGen,
};
use crate::retry_after;
use crate::scope::Scope;
use crate::usage::{Consumption, Period, Usage, rfc3339};

/// Emitted when a key's daily quota is crossed — the first budgeted send
/// whose read-back observes `used >= limit` and wins the day's durable
/// claim. Payload: `{"subject": <key>, "used": <used>, "limit": <limit>}`,
/// where `used` is the observed total and can pass `limit`. At most once
/// per key per UTC day: the claim row is keyed `(subject, period, kind)`
/// and the day is part of the key, so a new day can alert again.
pub const EVENT_QUOTA_EXHAUSTED: &str = "budget.quota_exhausted";

/// Emitted when a key lands past the daily quota's 80% warning mark
/// (`ceil(limit * 4 / 5)`) — the same durable claim under a different
/// `kind`, so the two never suppress each other within a day. The send
/// that crosses the limit in the same step emits [`EVENT_QUOTA_EXHAUSTED`]
/// instead, which is what happens for every limit of 4 or fewer (where the
/// mark *is* the limit) and for any burst that leaps the mark in one
/// increment.
pub const EVENT_QUOTA_WARNING: &str = "budget.quota_warning";

/// The meter name every daily-quota spend is counted under, so
/// [`Usage::history`] reads one meter across all budgeted keys.
const QUOTA_METER: &str = "http-requests";

/// The default pacing-bucket table [`BudgetedHttpClient`] spends from;
/// override with `with_bucket_table` when a venture renames it.
pub const DEFAULT_BUCKET_TABLE: &str = "http_bucket";

/// The default daily-quota table [`BudgetedHttpClient`] meters into;
/// override with `with_quota_table` when a venture renames it.
pub const DEFAULT_QUOTA_TABLE: &str = "http_usage";

/// The default quota-alert claim table [`BudgetedHttpClient`] gates its
/// [`EVENT_QUOTA_WARNING`] / [`EVENT_QUOTA_EXHAUSTED`] emissions with;
/// override with `with_alert_table` when a venture renames it.
pub const DEFAULT_ALERT_TABLE: &str = "budget_alerts";

/// How many times one send may wait out a token-bucket shortfall before
/// giving up and reporting [`HttpError::BudgetExhausted`]. Each wait is the
/// computed refill time, itself capped by [`RetryPolicy::max_delay`], so
/// pacing gives up after at most `MAX_PACING_WAITS * max_delay` — the bound
/// that keeps a permanently dry bucket from holding a request forever.
const MAX_PACING_WAITS: u32 = 4;

/// Fraction of the daily quota the warning event marks, as a numerator over
/// its denominator (`4 / 5 == 80%`), kept integral so the threshold is
/// exact.
const QUOTA_WARNING_NUMERATOR: u64 = 4;
const QUOTA_WARNING_DENOMINATOR: u64 = 5;

/// Request extension overriding the default method-based idempotency
/// classification. Safe methods (`GET`, `HEAD`, `OPTIONS`) are retried on a
/// 429/503 or a transport failure; a caller that knows better — a `POST`
/// the upstream de-duplicates by idempotency key, or a `GET` with side
/// effects — pins the answer with this extension, which never reaches the
/// wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Idempotent(pub bool);

/// The budget a single request spends against, as the router names it.
#[derive(Debug, Clone, PartialEq)]
pub struct Budget {
    /// Identifies the upstream (and the API key within it), e.g.
    /// `"dexscreener"` or `"rpc:3f9a…"`. The token-bucket row and the daily
    /// quota counter are keyed by exactly this string.
    pub key: String,
    /// Token-bucket size: the burst the key may spend at once, and the
    /// level every bucket refills toward.
    pub capacity: f64,
    /// Sustained refill rate, tokens per second.
    pub refill_per_sec: f64,
    /// Tokens this one request spends. `1.0` is a plain request; heavier
    /// endpoints can charge more. A cost above `capacity` can never be
    /// served and reports exhausted with the wait until a full bucket
    /// would cover it.
    pub cost: f64,
    /// Per-UTC-day request quota, counted through [`Usage`] with
    /// [`Period::Day`]. `None` is untracked: no quota, no database write.
    pub daily_limit: Option<u64>,
}

/// Routes a request to the budget it spends, or `None` to pass it through
/// un-budgeted. The key should name the upstream and, where credentials
/// rotate, the key they ride on — never the credential itself.
pub type BudgetRouter = Arc<dyn Fn(&http::Request<Bytes>) -> Option<Budget> + Send + Sync>;

/// How a failed exchange is retried: `max_retries` extra attempts at most,
/// exponential backoff from `base` (200 ms, 400 ms, 800 ms, …) clamped to
/// `max_delay` per wait and `max_total` across the whole exchange. An
/// upstream-stated `Retry-After` replaces the computed delay and clamps
/// only to what `max_total` still allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    max_retries: u32,
    base: Duration,
    max_delay: Duration,
    max_total: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 2,
            base: Duration::from_millis(200),
            max_delay: Duration::from_secs(5),
            max_total: Duration::from_secs(15),
        }
    }
}

impl RetryPolicy {
    /// Extra attempts after the first send.
    #[must_use]
    pub fn max_retries(self) -> u32 {
        self.max_retries
    }

    /// First computed backoff, doubled every attempt.
    #[must_use]
    pub fn base(self) -> Duration {
        self.base
    }

    /// Ceiling on one computed wait. An upstream-stated `Retry-After` may
    /// exceed this; only `max_total` caps it.
    #[must_use]
    pub fn max_delay(self) -> Duration {
        self.max_delay
    }

    /// Ceiling on everything the retries may wait, added up.
    #[must_use]
    pub fn max_total(self) -> Duration {
        self.max_total
    }

    /// Sets the retry count.
    #[must_use]
    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Sets the first computed backoff.
    #[must_use]
    pub fn with_base(mut self, base: Duration) -> Self {
        self.base = base;
        self
    }

    /// Sets the per-wait ceiling.
    #[must_use]
    pub fn with_max_delay(mut self, max_delay: Duration) -> Self {
        self.max_delay = max_delay;
        self
    }

    /// Sets the across-the-exchange ceiling.
    #[must_use]
    pub fn with_max_total(mut self, max_total: Duration) -> Self {
        self.max_total = max_total;
        self
    }
}

/// The async sleep pacing and backoff wait through. The default is a real
/// timer (`futures-timer`, no executor dependency). Runtimes with a native
/// timer of their own — Workers' `setTimeout`, a test's instant no-op —
/// install it here with [`BudgetedHttpClient::with_sleeper`]; on a wasm
/// target, whose std has no timer to borrow, a runtime sleeper is the
/// supported path (see `default_sleeper`).
pub type Sleeper = Arc<dyn Fn(Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// Wraps any [`HttpClient`] with the outbound budgets of issue #765:
/// a shared token bucket per upstream key, a daily quota with alerts, and
/// `Retry-After`-aware retries for idempotent calls. Adapters opt in by
/// wrapping the client they already hold — the runtime's
/// [`BoundedHttpClient`](crate::ports::BoundedHttpClient) stays the
/// innermost hop, so the port's own bounds
/// still apply underneath.
///
/// The streaming twin ([`HttpClient::send_streaming`]) spends the same
/// budget the same way before the head, then hands the body through
/// untouched: the retry loop covers the head only, because a body that
/// has started arriving can never be replayed.
pub struct BudgetedHttpClient {
    inner: Arc<dyn HttpClient>,
    clock: Arc<dyn Clock>,
    db: Arc<dyn Database>,
    router: BudgetRouter,
    retry: RetryPolicy,
    events: Option<EventBus>,
    defer: Arc<dyn Defer>,
    sleeper: Sleeper,
    bucket_table: String,
    quota_table: String,
    alert_table: String,
}

impl BudgetedHttpClient {
    /// Budgets `inner`'s sends through `router`, reading wall time from
    /// `clock` and spending buckets and quotas against `db`.
    #[must_use]
    pub fn new(
        inner: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
        db: Arc<dyn Database>,
        router: BudgetRouter,
    ) -> Self {
        Self {
            inner,
            clock,
            db,
            router,
            retry: RetryPolicy::default(),
            events: None,
            defer: Arc::new(NoopDefer),
            sleeper: default_sleeper(),
            bucket_table: DEFAULT_BUCKET_TABLE.to_owned(),
            quota_table: DEFAULT_QUOTA_TABLE.to_owned(),
            alert_table: DEFAULT_ALERT_TABLE.to_owned(),
        }
    }

    /// Replaces the retry policy.
    #[must_use]
    pub fn with_retry(mut self, policy: RetryPolicy) -> Self {
        self.retry = policy;
        self
    }

    /// Emits [`EVENT_QUOTA_WARNING`] / [`EVENT_QUOTA_EXHAUSTED`] to `bus`
    /// as the daily quotas are crossed.
    #[must_use]
    pub fn with_events(mut self, bus: EventBus) -> Self {
        self.events = Some(bus);
        self
    }

    /// Runs the alert events' handlers through this defer. Without it the
    /// default [`NoopDefer`] drops them (with a warning), so a deployment
    /// that subscribes to the quota events mounts the port's defer here.
    #[must_use]
    pub fn with_defer(mut self, defer: Arc<dyn Defer>) -> Self {
        self.defer = defer;
        self
    }

    /// Replaces the sleep pacing and backoff wait through — the hook a
    /// runtime with a native timer (or a test that asserts on delays)
    /// supplies.
    #[must_use]
    pub fn with_sleeper(mut self, sleeper: Sleeper) -> Self {
        self.sleeper = sleeper;
        self
    }

    /// Renames the pacing-bucket table.
    #[must_use]
    pub fn with_bucket_table(mut self, table: impl Into<String>) -> Self {
        self.bucket_table = table.into();
        self
    }

    /// Renames the daily-quota table.
    #[must_use]
    pub fn with_quota_table(mut self, table: impl Into<String>) -> Self {
        self.quota_table = table.into();
        self
    }

    /// Renames the quota-alert claim table.
    #[must_use]
    pub fn with_alert_table(mut self, table: impl Into<String>) -> Self {
        self.alert_table = table.into();
        self
    }

    /// The portable DDL for the pacing-bucket table. The daily-quota table
    /// is [`Usage::create_table_sql`] and the quota-alert claim table is
    /// [`create_alert_table_sql`](Self::create_alert_table_sql) — a venture
    /// budgets only when it has created **all three**.
    #[must_use]
    pub fn create_bucket_table_sql(table: &str) -> String {
        format!(
            "CREATE TABLE IF NOT EXISTS {table} (\n    \
             bucket TEXT NOT NULL,\n    \
             tokens DOUBLE PRECISION NOT NULL,\n    \
             updated_ms BIGINT NOT NULL,\n    \
             PRIMARY KEY (bucket)\n);"
        )
    }

    /// The portable DDL for the quota-alert claim table: one row per
    /// `(subject, day, kind)` emission already made, the at-most-once gate
    /// behind [`EVENT_QUOTA_WARNING`] / [`EVENT_QUOTA_EXHAUSTED`]. The
    /// claim's `subject` column names the quota table too, so two clients
    /// metering different tables never claim each other's alerts. A
    /// venture that wires `with_events` ships this as a migration beside
    /// the other two; a claim that meets its absence creates it on demand
    /// (the same DDL, `IF NOT EXISTS`) rather than dropping the alert.
    #[must_use]
    pub fn create_alert_table_sql(table: &str) -> String {
        format!(
            "CREATE TABLE IF NOT EXISTS {table} (\n    \
             subject TEXT NOT NULL,\n    \
             period TEXT NOT NULL,\n    \
             kind TEXT NOT NULL,\n    \
             claimed_ms BIGINT NOT NULL,\n    \
             PRIMARY KEY (subject, period, kind)\n);"
        )
    }

    /// Spends one request against the key's daily quota. `daily_limit:
    /// None` is untracked and skips the database entirely; with a limit,
    /// refusal carries the period's own `retry_after`.
    async fn spend_daily_quota(&self, budget: &Budget) -> Result<(), HttpError> {
        let Some(limit) = budget.daily_limit else {
            return Ok(());
        };
        // One clock reading for the spend and its alert alike, so the two
        // cannot disagree about which UTC day they landed in.
        let now = self.clock.now();
        let outcome = Usage::new(&self.quota_table)
            .consume(
                &*self.db,
                &budget.key,
                QUOTA_METER,
                Period::Day,
                now,
                1,
                Some(limit),
            )
            .await
            .map_err(|err| store_failed(&budget.key, &err))?;
        match outcome {
            Consumption::Consumed(consumed) => {
                self.emit_quota_alert(&budget.key, consumed.used, limit, now)
                    .await;
                Ok(())
            }
            Consumption::Exhausted(exhausted) => Err(HttpError::BudgetExhausted {
                what: budget.key.clone(),
                retry_after: exhausted.retry_after,
            }),
        }
    }

    /// The quota alerts, at-most-once **by claim**: the read-back total
    /// every concurrent caller sees can be the same number — `Usage`'s
    /// increment is atomic, its separate read-back is not — so the
    /// emission is gated on the durable claim row. The first caller whose
    /// guarded insert reports one affected row owns the emission; the rest
    /// report none and skip. The condition is read off the observed total
    /// as an inequality, `used >= limit` then `used >= warning mark` (kept
    /// as an else-if, so a burst that leaps the mark in one increment
    /// emits the exhaustion only).
    ///
    /// The scope is built here, not taken from a request — a budgeted send
    /// may serve no request at all — with a fresh traceable id, the same
    /// shape `module-connections` uses for its scheduled passes.
    async fn emit_quota_alert(&self, key: &str, used: u64, limit: u64, now: time::OffsetDateTime) {
        let Some(bus) = self.events.as_ref() else {
            return;
        };
        let (name, kind) = if used >= limit {
            (EVENT_QUOTA_EXHAUSTED, "exhausted")
        } else if used >= warning_threshold(limit) {
            (EVENT_QUOTA_WARNING, "warning")
        } else {
            return;
        };
        let claimant = format!("{}:{key}", self.quota_table);
        let period = rfc3339(Period::Day.window_at(now).start);
        if !self
            .claim_quota_alert(&claimant, kind, &period, epoch_millis(now))
            .await
        {
            return;
        }
        let scope = Scope {
            request_id: UlidIdGen.ulid(),
            defer: Arc::clone(&self.defer),
            span: tracing::info_span!("http.budget", budget = %key, outcome = kind),
        };
        bus.emit_in(
            &scope,
            name,
            json!({ "subject": key, "used": used, "limit": limit }),
        );
    }

    /// The durable emission claim: one guarded insert —
    /// [`SendCooldown`]'s conflict-insert arm (a claim is never renewed; a
    /// new day is a new row, so the update arm has nothing to renew) —
    /// answering `true` for the one caller that owns the emission.
    /// `rows-affected == 1` is the whole contract, and it is the only path
    /// to an emission.
    ///
    /// A claim that meets its missing table creates it (the same DDL a
    /// venture ships as its migration, `IF NOT EXISTS`) and claims once
    /// more; a claim that still cannot be written drops the alert with a
    /// warning. An alert never fails the send it observes — at-most-once
    /// means a lost alert stays lost, never a retried one.
    async fn claim_quota_alert(
        &self,
        claimant: &str,
        kind: &str,
        period: &str,
        now_ms: i64,
    ) -> bool {
        let insert = || claim_statement(&self.alert_table, claimant, kind, period, now_ms);
        match self.db.execute(&insert()).await {
            Ok(1) => true,
            Ok(_) => false,
            Err(_) => {
                let created = self
                    .db
                    .execute(&Statement::new(BudgetedHttpClient::create_alert_table_sql(
                        &self.alert_table,
                    )))
                    .await
                    .is_ok();
                if !created {
                    tracing::warn!(
                        budget = %claimant,
                        kind,
                        "quota alert dropped: the claim table is missing and could not be created"
                    );
                    return false;
                }
                matches!(self.db.execute(&insert()).await, Ok(1))
            }
        }
    }

    /// Refills and spends the key's token bucket, atomically. A shortfall
    /// that refills within `max_delay` is waited out (up to
    /// `MAX_PACING_WAITS`); anything longer refuses.
    async fn acquire(&self, budget: &Budget) -> Result<(), HttpError> {
        // The router's numbers are configuration: a negative or NaN value
        // collapses to zero here instead of poisoning the arithmetic, which
        // `f64::max` gives for free (NaN.max(0.0) is 0.0).
        let capacity = budget.capacity.max(0.0);
        let cost = budget.cost.max(0.0);
        let refill_per_sec = budget.refill_per_sec.max(0.0);
        let mut waits_left = MAX_PACING_WAITS;
        loop {
            let now_ms = epoch_millis(self.clock.now());
            let affected = self
                .db
                .execute(&acquire_statement(
                    &self.bucket_table,
                    &budget.key,
                    capacity,
                    cost,
                    refill_per_sec,
                    now_ms,
                ))
                .await
                .map_err(|err| store_failed(&budget.key, &err))?;
            if affected > 0 {
                return Ok(());
            }
            // Advisory read, no transaction: one row's level, to say *when*
            // the bucket could carry this request. Another isolate may
            // spend or refill before the answer lands; the number is a
            // quotation, not a promise.
            let (stored, updated_ms) = self.bucket_row(&budget.key, capacity, now_ms).await?;
            let refilled = refilled_tokens(stored, updated_ms, now_ms, refill_per_sec, capacity);
            let retry_in = pacing_retry_in(refilled, cost, refill_per_sec);
            if retry_in > self.retry.max_delay() || waits_left == 0 {
                return Err(HttpError::BudgetExhausted {
                    what: budget.key.clone(),
                    retry_after: retry_in,
                });
            }
            (self.sleeper)(retry_in).await;
            waits_left -= 1;
        }
    }

    /// The bucket row's `(tokens, updated_ms)`, or a full fresh bucket when
    /// the key has no row yet (its absence after a failed spend means the
    /// seed guard refused: `capacity < cost`).
    async fn bucket_row(
        &self,
        key: &str,
        capacity: f64,
        now_ms: i64,
    ) -> Result<(f64, i64), HttpError> {
        let rows = self
            .db
            .query(&Statement::with_values(
                bucket_read_sql(&self.bucket_table),
                vec![key.to_owned().into()],
            ))
            .await
            .map_err(|err| store_failed(key, &err))?;
        Ok(rows
            .first()
            .and_then(|row| Some((tokens_of(row)?, row.get::<i64>("updated_ms")?)))
            .unwrap_or((capacity, now_ms)))
    }

    /// The send-and-retry loop: pacing and the quota have already admitted
    /// this request, so what is left is the exchange itself. `send_one`
    /// produces one attempt's future — the buffered `send` retries the
    /// whole exchange, `send_streaming` retries only the **head** (a body
    /// that has started arriving can never be replayed, so once a
    /// streamed response is in hand it is returned as-is). Each attempt
    /// clones what it consumes — `Bytes` clones are refcounted, and the
    /// extensions (the [`Idempotent`] marker included) ride along.
    async fn exchange_with<B, F, Fut>(
        &self,
        idempotent: bool,
        send_one: F,
    ) -> Result<http::Response<B>, HttpError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<http::Response<B>, HttpError>>,
    {
        let policy = self.retry;
        let mut waited = Duration::ZERO;
        let mut retries_left = policy.max_retries();
        let mut attempt = 0_u32;
        loop {
            let outcome = send_one().await;
            match outcome {
                Ok(response) => {
                    let throttled = matches!(response.status().as_u16(), 429 | 503);
                    if !throttled || !idempotent || retries_left == 0 {
                        return Ok(response);
                    }
                    let stated = retry_after(response.headers(), &*self.clock);
                    let Some(delay) = next_delay(policy, waited, attempt, stated) else {
                        // The provider's pause (or the schedule) no longer
                        // fits the total: hand the caller the 429/503
                        // as-is, its `Retry-After` header intact.
                        return Ok(response);
                    };
                    (self.sleeper)(delay).await;
                    waited += delay;
                    retries_left -= 1;
                    attempt += 1;
                }
                Err(HttpError::Transport(detail)) if idempotent && retries_left > 0 => {
                    let Some(delay) = next_delay(policy, waited, attempt, None) else {
                        return Err(HttpError::Transport(detail));
                    };
                    (self.sleeper)(delay).await;
                    waited += delay;
                    retries_left -= 1;
                    attempt += 1;
                }
                // Deadline, size cap, a refused destination, our own
                // budget refusal, or weather on a request that may not be
                // retried: the caller hears it immediately.
                Err(err) => return Err(err),
            }
        }
    }
}

#[async_trait]
impl HttpClient for BudgetedHttpClient {
    async fn send(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        let Some(budget) = (self.router)(&request) else {
            // Unrouted requests are not free — they are simply not ours to
            // govern. The inner client's own bounds still apply.
            return self.inner.send(request).await;
        };
        let idempotent = request_is_idempotent(&request);
        self.acquire(&budget).await?;
        self.spend_daily_quota(&budget).await?;
        self.exchange_with(idempotent, || self.inner.send(request.clone()))
            .await
    }

    async fn send_streaming(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<ByteStream>, HttpError> {
        let Some(budget) = (self.router)(&request) else {
            // Unrouted requests are not free — they are simply not ours to
            // govern. The inner client's own bounds still apply.
            return self.inner.send_streaming(request).await;
        };
        let idempotent = request_is_idempotent(&request);
        self.acquire(&budget).await?;
        self.spend_daily_quota(&budget).await?;
        // The budget is spent once, up front, exactly as `send` spends it;
        // the retry loop covers the head only, so a stream never replays
        // bytes that are already in flight.
        self.exchange_with(idempotent, || self.inner.send_streaming(request.clone()))
            .await
    }
}

/// The timer the sleeps fall back to: `futures-timer`, which brings no
/// executor and no runtime dependency. Its `Delay` reads the platform's
/// monotonic clock, so on wasm32-unknown-unknown it still *compiles* (the
/// wasm-safety gate) but cannot *fire* — std has no timer there — which is
/// why a runtime on that target supplies its own sleeper.
fn default_sleeper() -> Sleeper {
    Arc::new(|after| Box::pin(async move { futures_timer::Delay::new(after).await }))
}

/// The safe-method default behind [`Idempotent`]'s absence. `Method`'s
/// names are its own constants, not enum variants, so the comparison goes
/// through `as_str` — the wire spelling is uppercase on every path here.
fn default_method_idempotent(method: &http::Method) -> bool {
    matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS")
}

/// The request's idempotency: the [`Idempotent`] extension when present,
/// the method's safety otherwise.
fn request_is_idempotent(request: &http::Request<Bytes>) -> bool {
    request.extensions().get::<Idempotent>().map_or_else(
        || default_method_idempotent(request.method()),
        |idempotent| idempotent.0,
    )
}

/// The epoch-millisecond reading the bucket table stores, floored so the
/// arithmetic stays integral (pre-1970 clocks included). Saturates at the
/// `i64` edge, the way a counter does in `usage.rs`.
fn epoch_millis(at: time::OffsetDateTime) -> i64 {
    i64::try_from(at.unix_timestamp_nanos().div_euclid(1_000_000)).unwrap_or(i64::MAX)
}

/// The bucket level as a read-back row holds it. The write binds a double
/// and rusqlite and Postgres answer with one, but D1's JSON bridge hands a
/// safe integral JS number back as an integer — serde-wasm-bindgen visits
/// whole numbers as `BigInt` — and `Row::get::<f64>` on an integer is
/// `None`. Without the integral fallback, a bucket parked at exactly
/// `9.0` or `0.0` reads as missing, and the advisory read treats a spent
/// bucket as fresh. The integer shapes `Row` carries are the signed ones
/// (`TinyInt` through `BigInt`), which one `i64` read covers; token
/// counts stay far below the `f64` exact-integer range, so the widening
/// cast loses nothing.
#[expect(
    clippy::cast_precision_loss,
    reason = "token counts stay far below 2^53, the exact f64 integer range"
)]
fn tokens_of(row: &Row) -> Option<f64> {
    row.get::<f64>("tokens")
        .or_else(|| row.get::<i64>("tokens").map(|tokens| tokens as f64))
}

/// Milliseconds between `from_ms` and `to_ms`, as seconds, never negative —
/// a clock that steps backwards must not *un*-refill a bucket.
#[expect(
    clippy::cast_precision_loss,
    reason = "millisecond deltas stay far below 2^53"
)]
fn elapsed_seconds(from_ms: i64, to_ms: i64) -> f64 {
    (to_ms - from_ms).max(0) as f64 / 1_000.0
}

/// The bucket level at `now_ms`: what was stored, plus the elapsed refill,
/// clamped to capacity. A backwards clock leaves the level where it was.
fn refilled_tokens(
    stored: f64,
    updated_ms: i64,
    now_ms: i64,
    refill_per_sec: f64,
    capacity: f64,
) -> f64 {
    (stored + refill_per_sec * elapsed_seconds(updated_ms, now_ms)).min(capacity)
}

/// How long until the bucket can carry `cost`: zero when it already can,
/// unrepresentable when it never will (`refill_per_sec` of zero), the
/// missing tokens over the refill rate otherwise.
fn pacing_retry_in(refilled: f64, cost: f64, refill_per_sec: f64) -> Duration {
    if cost <= refilled {
        return Duration::ZERO;
    }
    if refill_per_sec <= 0.0 {
        return Duration::MAX;
    }
    Duration::try_from_secs_f64((cost - refilled) / refill_per_sec).unwrap_or(Duration::MAX)
}

/// The computed backoff for `attempt` (0-based): `base` doubled each time,
/// clamped to `max_delay`. Saturating, so an absurd attempt count pins at
/// the clamp instead of panicking.
fn backoff_delay(base: Duration, max_delay: Duration, attempt: u32) -> Duration {
    base.saturating_mul(2_u32.saturating_pow(attempt))
        .min(max_delay)
}

/// The next wait: the upstream's stated `Retry-After` when it gave one
/// (honoured up to what the total still allows), the exponential schedule
/// otherwise, never past `max_total`. `None` — nothing left to wait with —
/// means the caller keeps the response it has.
fn next_delay(
    policy: RetryPolicy,
    waited: Duration,
    attempt: u32,
    stated: Option<Duration>,
) -> Option<Duration> {
    let remaining = policy.max_total().checked_sub(waited)?;
    if remaining.is_zero() {
        return None;
    }
    Some(match stated {
        Some(stated) => stated.min(remaining),
        None => backoff_delay(policy.base(), policy.max_delay(), attempt).min(remaining),
    })
}

/// `ceil(limit * 80 / 100)` in integers, exact for every `u64` limit
/// (saturating, for the limits no day will ever reach).
#[must_use]
fn warning_threshold(limit: u64) -> u64 {
    limit
        .saturating_mul(QUOTA_WARNING_NUMERATOR)
        .div_ceil(QUOTA_WARNING_DENOMINATOR)
}

/// A budget-store failure as a transport error. `DbError`'s `Display` is
/// already scrubbed (issue #135), so the key and the driver's words ride
/// safely.
fn store_failed(what: &str, err: &crate::DbError) -> HttpError {
    HttpError::Transport(format!("budget store for {what} failed: {err}"))
}

/// The atomic refill-and-spend: one guarded upsert, one row changed on
/// admission, none when the bucket cannot carry `cost` — the same
/// rows-affected contract [`Usage::consume`] is built on, which is what
/// SQLite, D1 and Postgres all report identically. The fresh-key arm seeds
/// a full bucket minus this request's spend, guarded so a cost above
/// capacity seeds nothing at all; the conflict arm refills from
/// `updated_ms`, clamps to capacity with `CASE` (never `MIN`/`LEAST`),
/// spends, and re-checks the guard against the refilled level, so two
/// concurrent callers cannot both take the last token. The elapsed
/// milliseconds pass through their own `CASE` — the SQL twin of
/// [`elapsed_seconds`]: an isolate whose clock runs ahead writes a future
/// `updated_ms`, and without the clamp every other isolate's negative
/// elapsed would both shrink the guard (a refusal could pass) and burn
/// `rate × skew` tokens off the level.
fn acquire_sql(table: &str) -> String {
    // `CASE WHEN`, never a `GREATEST`: the engines disagree on the
    // spelling, and the scalar `max(a, b)` is SQLite-only.
    let elapsed =
        format!("CASE WHEN ? >= {table}.updated_ms THEN (? - {table}.updated_ms) ELSE 0 END");
    format!(
        "INSERT INTO {table} (bucket, tokens, updated_ms)\n\
         SELECT ?, ? - ?, ? WHERE ? >= ?\n\
         ON CONFLICT (bucket) DO UPDATE\n\
         SET tokens = CASE\n\
             WHEN {table}.tokens + ? * {elapsed} / 1000.0 > ?\n\
             THEN ? - ?\n\
             ELSE {table}.tokens + ? * {elapsed} / 1000.0 - ?\n\
         END,\n\
         updated_ms = ?\n\
         WHERE {table}.tokens + ? * {elapsed} / 1000.0 >= ?"
    )
}

/// The advisory read behind a failed spend: one key's level and stamp.
fn bucket_read_sql(table: &str) -> String {
    format!("SELECT tokens, updated_ms FROM {table} WHERE bucket = ?")
}

/// The quota-alert emission claim: one guarded insert, conflict-do-nothing,
/// whose rows-affected answer is the whole at-most-once contract — `1` the
/// caller owns the emission, `0` someone else already made it.
fn claim_statement(
    table: &str,
    claimant: &str,
    kind: &str,
    period: &str,
    claimed_ms: i64,
) -> Statement {
    Statement::with_values(
        format!(
            "INSERT INTO {table} (subject, period, kind, claimed_ms)\n\
             VALUES (?, ?, ?, ?)\n\
             ON CONFLICT (subject, period, kind) DO NOTHING"
        ),
        vec![
            claimant.to_owned().into(),
            period.to_owned().into(),
            kind.to_owned().into(),
            claimed_ms.into(),
        ],
    )
}

/// [`acquire_sql`]'s twenty-one binds, in the order the statement reads
/// them: the seed row (key, capacity − cost, now, guarded by
/// capacity ≥ cost), then the refill-and-spend three times over — the
/// clamp, the spend, and the guard — each refill term reading the elapsed
/// milliseconds through a two-bind `CASE` that clamps a backwards clock to
/// zero, because no dialect here has a cheaper way to say "refilled,
/// clamped, minus cost" without repeating it.
fn acquire_statement(
    table: &str,
    key: &str,
    capacity: f64,
    cost: f64,
    refill_per_sec: f64,
    now_ms: i64,
) -> Statement {
    Statement::with_values(
        acquire_sql(table),
        vec![
            key.to_owned().into(), // seed: bucket
            capacity.into(),       // seed: capacity - cost
            cost.into(),           //
            now_ms.into(),         // seed: updated_ms
            capacity.into(),       // seed guard: capacity >= cost
            cost.into(),           //
            refill_per_sec.into(), // clamp: rate
            now_ms.into(),         // clamp: elapsed CASE, the `when`
            now_ms.into(),         // clamp: elapsed CASE, the `then`
            capacity.into(),       // clamp: refilled > capacity
            capacity.into(),       // spend: THEN capacity - cost
            cost.into(),           //
            refill_per_sec.into(), // spend: ELSE rate
            now_ms.into(),         // spend: elapsed CASE, the `when`
            now_ms.into(),         // spend: elapsed CASE, the `then`
            cost.into(),           // spend: - cost
            now_ms.into(),         // stamp: updated_ms
            refill_per_sec.into(), // guard: rate
            now_ms.into(),         // guard: elapsed CASE, the `when`
            now_ms.into(),         // guard: elapsed CASE, the `then`
            cost.into(),           // guard: >= cost
        ],
    )
}

#[cfg(test)]
mod tests {
    // Every float compared below is exactly representable (halves, wholes,
    // tenths the arithmetic constructs by scaling by 1000), so `==` is the
    // precise assertion, not a rounded one.
    #![allow(clippy::float_cmp)]

    use super::*;
    use crate::lint_portable_sql;

    // --- pure helpers ---------------------------------------------------

    /// `elapsed_seconds` drives every refill; a backwards clock must read
    /// as "no time passed", never as negative refill.
    #[test]
    fn elapsed_seconds_is_the_ms_delta_never_negative() {
        assert_eq!(elapsed_seconds(1_000, 4_500), 3.5);
        assert_eq!(elapsed_seconds(1_000, 1_000), 0.0);
        assert_eq!(elapsed_seconds(5_000, 1_000), 0.0, "backwards clock");
    }

    /// The bucket level: stored plus refill, clamped at capacity, and a
    /// backwards clock leaves the level where the row left it.
    #[test]
    fn refilled_tokens_clamps_at_capacity_and_ignores_backwards_clocks() {
        assert_eq!(refilled_tokens(0.5, 0, 1_000, 1.0, 10.0), 1.5);
        assert_eq!(
            refilled_tokens(9.0, 0, 10_000, 1.0, 10.0),
            10.0,
            "the clamp, not 19"
        );
        assert_eq!(
            refilled_tokens(4.0, 5_000, 1_000, 1.0, 10.0),
            4.0,
            "backwards clock: no un-refill"
        );
    }

    /// `pacing_retry_in` is what a refusal reports as `retry_after`: zero
    /// when the request fits, unrepresentable when nothing will ever
    /// refill, the missing tokens over the rate otherwise.
    #[test]
    fn pacing_retry_in_scales_with_the_missing_tokens() {
        assert_eq!(pacing_retry_in(5.0, 1.0, 1.0), Duration::ZERO);
        assert_eq!(pacing_retry_in(0.0, 1.0, 0.0), Duration::MAX);
        assert_eq!(pacing_retry_in(1.0, 2.0, 0.5), Duration::from_secs(2));
        assert_eq!(pacing_retry_in(9.0, 10.0, 4.0), Duration::from_millis(250));
    }

    /// The backoff schedule: doubles from base, clamped at `max_delay`,
    /// saturating on absurd attempt counts.
    #[test]
    fn backoff_doubles_then_clamps() {
        let (base, max) = (Duration::from_millis(200), Duration::from_secs(5));
        assert_eq!(backoff_delay(base, max, 0), Duration::from_millis(200));
        assert_eq!(backoff_delay(base, max, 1), Duration::from_millis(400));
        assert_eq!(backoff_delay(base, max, 2), Duration::from_millis(800));
        assert_eq!(backoff_delay(base, max, 3), Duration::from_millis(1_600));
        assert_eq!(
            backoff_delay(base, max, 4),
            Duration::from_millis(3_200),
            "still under the clamp"
        );
        assert_eq!(
            backoff_delay(base, max, 5),
            Duration::from_secs(5),
            "clamped"
        );
        assert_eq!(backoff_delay(base, max, u32::MAX), Duration::from_secs(5));
    }

    /// `next_delay` is the exchange's whole sense of time: stated
    /// `Retry-After` wins over the schedule, everything clamps to what the
    /// total still allows, and an exhausted total is `None` — no retry.
    #[test]
    fn next_delay_honours_the_stated_pause_within_the_total() {
        let policy = RetryPolicy::default();
        assert_eq!(
            next_delay(policy, Duration::ZERO, 0, None),
            Some(Duration::from_millis(200))
        );
        // Stated beats schedule; over max_delay but under max_total, so it
        // is honoured anyway.
        assert_eq!(
            next_delay(policy, Duration::ZERO, 0, Some(Duration::from_secs(9))),
            Some(Duration::from_secs(9))
        );
        // Stated clamps to the remaining total.
        assert_eq!(
            next_delay(
                policy,
                Duration::from_secs(10),
                0,
                Some(Duration::from_secs(9))
            ),
            Some(Duration::from_secs(5))
        );
        // The schedule never spends more than the remaining total: with
        // 1 s left, its 200 ms wait fits and is what comes back.
        assert_eq!(
            next_delay(policy, Duration::from_secs(14), 0, None),
            Some(Duration::from_millis(200))
        );
        // A schedule longer than what is left is cut to it.
        assert_eq!(
            next_delay(policy, Duration::from_secs(14), 4, None),
            Some(Duration::from_secs(1))
        );
        // Exactly at the total, and past it: nothing left to wait with.
        assert_eq!(next_delay(policy, Duration::from_secs(15), 0, None), None);
        assert_eq!(
            next_delay(policy, Duration::from_secs(16), 0, Some(Duration::ZERO)),
            None
        );
        // A total with headroom and a stated "now": retry immediately.
        assert_eq!(
            next_delay(policy, Duration::ZERO, 0, Some(Duration::ZERO)),
            Some(Duration::ZERO)
        );
    }

    /// The 80% mark, exact in integers: `ceil(limit * 4 / 5)`, saturating.
    #[test]
    fn warning_threshold_is_the_exact_eighty_percent_mark() {
        assert_eq!(warning_threshold(10), 8);
        assert_eq!(warning_threshold(5), 4);
        assert_eq!(
            warning_threshold(3),
            3,
            "ceil(2.4) is 3 — the small-quota case"
        );
        assert_eq!(warning_threshold(1), 1);
        assert_eq!(warning_threshold(10_000), 8_000);
        // At the edge, the multiply saturates and the ceil-divide lands a
        // fifth of the range up — monotone and panic-free, which is all a
        // quota no day will reach owes anyone.
        assert_eq!(warning_threshold(u64::MAX), u64::MAX.div_ceil(5));
    }

    /// Idempotency: safe methods by default, the [`Idempotent`] extension
    /// overrides either way.
    #[test]
    fn idempotency_defaults_to_safe_methods_and_the_extension_overrides() {
        let request = |method: http::Method| {
            http::Request::builder()
                .method(method)
                .body(Bytes::new())
                .expect("test request")
        };
        assert!(request_is_idempotent(&request(http::Method::GET)));
        assert!(request_is_idempotent(&request(http::Method::HEAD)));
        assert!(request_is_idempotent(&request(http::Method::OPTIONS)));
        assert!(!request_is_idempotent(&request(http::Method::POST)));
        assert!(!request_is_idempotent(&request(http::Method::DELETE)));

        let mut vouched = request(http::Method::POST);
        vouched.extensions_mut().insert(Idempotent(true));
        assert!(request_is_idempotent(&vouched), "the caller vouches");

        let mut withheld = request(http::Method::GET);
        withheld.extensions_mut().insert(Idempotent(false));
        assert!(!request_is_idempotent(&withheld), "the caller withholds");
    }

    /// The DDL: names the table and passes the portable-SQL lint, like
    /// `Usage`'s quota DDL beside it and the alert-claim DDL beside that.
    #[test]
    fn the_bucket_ddl_is_portable_and_names_the_table() {
        let sql = BudgetedHttpClient::create_bucket_table_sql("http_bucket");
        assert!(sql.contains("CREATE TABLE IF NOT EXISTS http_bucket"));
        assert!(sql.contains("tokens DOUBLE PRECISION NOT NULL"));
        assert!(sql.contains("PRIMARY KEY (bucket)"));
        assert_eq!(lint_portable_sql(&sql), vec![], "DDL must be portable");
        let usage = Usage::new("http_usage").create_table_sql();
        assert_eq!(
            lint_portable_sql(&usage),
            vec![],
            "the quota DDL already is"
        );
        let alerts = BudgetedHttpClient::create_alert_table_sql("budget_alerts");
        assert!(alerts.contains("CREATE TABLE IF NOT EXISTS budget_alerts"));
        assert!(alerts.contains("PRIMARY KEY (subject, period, kind)"));
        assert_eq!(
            lint_portable_sql(&alerts),
            vec![],
            "the claim DDL must be portable too"
        );
    }

    /// The alert-claim insert: four binds, conflict-do-nothing, the same
    /// rows-affected contract `SendCooldown`'s first-send arm is built on.
    #[test]
    fn the_alert_claim_inserts_one_guarded_row() {
        let statement = claim_statement(
            "budget_alerts",
            "http_usage:dexscreener",
            "exhausted",
            "2026-10-09T00:00:00Z",
            1_000,
        );
        assert!(
            statement
                .sql
                .contains("ON CONFLICT (subject, period, kind) DO NOTHING")
        );
        assert_eq!(statement.values.0.len(), 4);
        assert!(
            matches!(&statement.values.0[0], sea_query::Value::String(Some(who)) if who.as_str() == "http_usage:dexscreener"),
            "the claimant (quota table and key) is the first bind"
        );
        assert!(
            matches!(&statement.values.0[2], sea_query::Value::String(Some(kind)) if kind.as_str() == "exhausted"),
            "the kind is the third bind"
        );
        assert!(
            matches!(statement.values.0[3], sea_query::Value::BigInt(Some(v)) if v == 1_000),
            "the stamp binds as a big integer"
        );
    }

    /// The acquire statement: twenty-one binds in the order the SQL reads
    /// them, doubles where the table says so and the stamp as a big
    /// integer, with `CASE` doing the clamp (never `MIN`/`LEAST`) — both
    /// the capacity clamp and, twice per refill term, the backwards-clock
    /// clamp on the elapsed milliseconds. The count is the SQL's, pinned
    /// here so a reordered clause fails this test before it fails a
    /// venture's request.
    #[test]
    fn the_acquire_statement_binds_the_seed_and_three_refill_passes() {
        let statement = acquire_statement("http_bucket", "dexscreener", 60.0, 1.0, 2.0, 1_000);
        assert!(statement.sql.contains("ON CONFLICT (bucket) DO UPDATE"));
        assert!(statement.sql.contains("CASE"));
        assert!(!statement.sql.contains("MIN("));
        assert!(!statement.sql.contains("LEAST("));
        // The backwards-clock clamp, once per refill term: the SQL twin of
        // `elapsed_seconds`, present in the clamp, the spend and the guard.
        assert_eq!(
            statement
                .sql
                .matches("CASE WHEN ? >= http_bucket.updated_ms")
                .count(),
            3,
            "each of the three refill terms clamps the elapsed time"
        );
        assert_eq!(statement.values.0.len(), 21);
        assert!(
            matches!(statement.values.0[1], sea_query::Value::Double(Some(v)) if v == 60.0),
            "capacity binds as a double"
        );
        assert!(
            matches!(statement.values.0[3], sea_query::Value::BigInt(Some(v)) if v == 1_000),
            "the stamp binds as a big integer"
        );
        assert!(
            matches!(&statement.values.0[0], sea_query::Value::String(Some(key)) if key.as_str() == "dexscreener"),
            "the key is the first bind"
        );
        // The first refill term's elapsed CASE reads the clock twice (the
        // `when` and the `then`), both as the big integer the column is.
        assert!(
            matches!(statement.values.0[7], sea_query::Value::BigInt(Some(v)) if v == 1_000),
            "the clamp's `when` binds the clock"
        );
        assert!(
            matches!(statement.values.0[8], sea_query::Value::BigInt(Some(v)) if v == 1_000),
            "the clamp's `then` binds the clock again"
        );
    }

    /// The advisory read's level: the doubles the row carries natively,
    /// and the integral fallback D1 needs — its JSON bridge hands a safe
    /// integral JS number back as an integer, on which `Row::get::<f64>`
    /// is `None`, reading a bucket parked at exactly `9.0` as missing.
    #[test]
    fn the_bucket_level_reads_as_doubles_and_as_the_integral_shapes_d1_hands_back() {
        let row = |value: sea_query::Value| Row::new(vec![("tokens".to_owned(), value)]);
        assert_eq!(tokens_of(&row(9.5.into())), Some(9.5), "double, as bound");
        assert_eq!(
            tokens_of(&row(sea_query::Value::Float(Some(9.5)))),
            Some(9.5),
            "the single-precision shape some drivers answer with"
        );
        assert_eq!(
            tokens_of(&row(9_i64.into())),
            Some(9.0),
            "D1's integral numbers: the fallback, not `None`"
        );
        assert_eq!(
            tokens_of(&row(0_i64.into())),
            Some(0.0),
            "the spent bucket, exactly zero, reads as zero"
        );
        assert_eq!(
            tokens_of(&row(sea_query::Value::Double(None))),
            None,
            "NULL is still missing"
        );
        assert_eq!(
            tokens_of(&row("9".to_owned().into())),
            None,
            "a non-numeric column is unrepresentable, as ever"
        );
    }

    /// The advisory read: one key's row, nothing else.
    #[test]
    fn the_bucket_read_targets_one_key() {
        assert_eq!(
            bucket_read_sql("http_bucket"),
            "SELECT tokens, updated_ms FROM http_bucket WHERE bucket = ?"
        );
    }

    /// The policy's defaults are the ones the issue names, and the
    /// builders change exactly what they name.
    #[test]
    fn the_retry_policy_defaults_and_builds() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_retries(), 2);
        assert_eq!(policy.base(), Duration::from_millis(200));
        assert_eq!(policy.max_delay(), Duration::from_secs(5));
        assert_eq!(policy.max_total(), Duration::from_secs(15));
        let tuned = policy
            .with_max_retries(5)
            .with_base(Duration::from_millis(50))
            .with_max_delay(Duration::from_secs(2))
            .with_max_total(Duration::from_secs(30));
        assert_eq!(tuned.max_retries(), 5);
        assert_eq!(tuned.base(), Duration::from_millis(50));
        assert_eq!(tuned.max_delay(), Duration::from_secs(2));
        assert_eq!(tuned.max_total(), Duration::from_secs(30));
        // `Copy` semantics: the default was not disturbed.
        assert_eq!(policy.max_retries(), 2);
    }

    /// The epoch stamp: whole milliseconds since the epoch, floored, far
    /// from the `i64` edge the saturating cast guards.
    #[test]
    fn epoch_millis_floors_to_whole_milliseconds() {
        let at = |nanos: i64| time::OffsetDateTime::UNIX_EPOCH + time::Duration::nanoseconds(nanos);
        assert_eq!(epoch_millis(at(1_500_000)), 1, "1.5 ms floors, not rounds");
        assert_eq!(epoch_millis(at(1_999_999)), 1);
        assert_eq!(epoch_millis(at(2_000_000)), 2);
        assert_eq!(epoch_millis(at(0)), 0);
        assert_eq!(
            epoch_millis(at(-1_500_000)),
            -2,
            "floors below the epoch too"
        );
    }
}
