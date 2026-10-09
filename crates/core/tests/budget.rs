//! Behaviour tests for `cratefield_core::BudgetedHttpClient` (issue #765)
//! against a real SQLite database — the same engine the guarded-upsert
//! rows-affected contract was built on, the way `tests/api_keys.rs` does
//! for `ApiKeys`. The bucket's atomic refill-and-spend is exercised, not
//! assumed; the retry loop runs against a scripted inner client with an
//! instant sleeper, so the delays are asserted, never awaited.

// Test support: connection-guarding Mutexes for the recorded sends,
// sleeps and events (the exception `adapter-sqlite` documents); exact
// floats (every compared value is exactly representable); and the
// epoch-day pause spelled in milliseconds because that is the unit the
// arithmetic reads in.
#![allow(clippy::disallowed_types, clippy::float_cmp)]
#![allow(clippy::duration_suboptimal_units)]

use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_core::{
    Budget, BudgetRouter, BudgetedHttpClient, Clock, DEFAULT_ALERT_TABLE, DEFAULT_BUCKET_TABLE,
    DEFAULT_QUOTA_TABLE, Database, Defer, EVENT_QUOTA_EXHAUSTED, EVENT_QUOTA_WARNING, EventBus,
    HttpClient, HttpError, Idempotent, RetryPolicy, Statement, Usage,
};
use futures_core::future::BoxFuture;

// Connection guarding for the recorded sends, sleeps and events — test
// support, not request state; the same exception `adapter-sqlite` documents
// in `clippy.toml`.
#[allow(clippy::disallowed_types)]
type Log<T> = StdMutex<T>;

/// A `Clock` the test steps by hand, in whole milliseconds — the only time
/// the client under test reads.
struct StepClock(Log<i64>);

impl StepClock {
    fn advance(&self, millis: i64) {
        *self.0.lock().expect("clock lock") += millis;
    }
}

#[async_trait]
impl Clock for StepClock {
    fn now(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::UNIX_EPOCH
            + time::Duration::milliseconds(*self.0.lock().expect("clock lock"))
    }
}

/// The scripted inner client: records every request that arrives and pops
/// one outcome per send. An exhausted script answers a bare `200` — the
/// tests that care about outcomes script them; the rest only need the pipe
/// open.
struct ScriptedClient {
    sent: Log<Vec<http::Request<Bytes>>>,
    script: Log<Vec<Result<http::Response<Bytes>, HttpError>>>,
}

impl ScriptedClient {
    fn new() -> Self {
        Self {
            sent: Log::new(Vec::new()),
            script: Log::new(Vec::new()),
        }
    }

    fn push(&self, outcome: Result<http::Response<Bytes>, HttpError>) {
        self.script.lock().expect("script lock").push(outcome);
    }

    fn sends(&self) -> usize {
        self.sent.lock().expect("sent lock").len()
    }
}

#[async_trait]
impl HttpClient for ScriptedClient {
    async fn send(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        self.sent.lock().expect("sent lock").push(request);
        let mut script = self.script.lock().expect("script lock");
        if script.is_empty() {
            Ok(http::Response::new(Bytes::new()))
        } else {
            script.remove(0)
        }
    }
}

/// A `Defer` that collects the deferred futures instead of running them:
/// `EventBus::emit_in` schedules handlers through it, and the test drains
/// and completes them explicitly, so an event's arrival is observable and
/// ordered relative to the send that emitted it.
#[derive(Default, Clone)]
struct CollectedDefer(Arc<Log<Vec<BoxFuture<'static, ()>>>>);

impl Defer for CollectedDefer {
    fn wait_until(&self, fut: BoxFuture<'static, ()>) {
        self.0.lock().expect("defer lock").push(fut);
    }
}

impl CollectedDefer {
    /// Runs every collected future to completion, in arrival order.
    fn drain(&self) {
        for fut in self.0.lock().expect("defer lock").drain(..) {
            pollster::block_on(fut);
        }
    }
}

/// Everything one test needs. The router budgets every request the same
/// way; the sleeper records and returns immediately. The client sits in an
/// `Arc` so a test that wants genuine concurrency can carry clones onto
/// threads.
struct Fixture {
    db: Arc<SqliteDatabase>,
    clock: Arc<StepClock>,
    inner: Arc<ScriptedClient>,
    sleeps: Arc<Log<Vec<Duration>>>,
    events: Arc<Log<Vec<(String, serde_json::Value)>>>,
    defer: CollectedDefer,
    client: Arc<BudgetedHttpClient>,
}

impl Fixture {
    /// Builds a fixture whose router always answers with `budget`, over
    /// `policy`, with an instant sleeper and a bus recording the quota
    /// events through this fixture.
    fn new(budget: &Budget, policy: RetryPolicy) -> Self {
        let db = Arc::new(SqliteDatabase::in_memory().expect("in-memory sqlite opens"));
        let clock = Arc::new(StepClock(Log::new(1_000)));
        let inner = Arc::new(ScriptedClient::new());
        let sleeps: Arc<Log<Vec<Duration>>> = Arc::new(Log::new(Vec::new()));
        let events: Arc<Log<Vec<(String, serde_json::Value)>>> = Arc::new(Log::new(Vec::new()));
        let warnings = Arc::clone(&events);
        let exhaustions = Arc::clone(&events);
        let bus = EventBus::new()
            .on(
                EVENT_QUOTA_WARNING,
                Arc::new(move |_scope, payload| {
                    warnings
                        .lock()
                        .expect("event record")
                        .push((EVENT_QUOTA_WARNING.to_owned(), payload));
                    Box::pin(std::future::ready(Ok(())))
                }),
            )
            .on(
                EVENT_QUOTA_EXHAUSTED,
                Arc::new(move |_scope, payload| {
                    exhaustions
                        .lock()
                        .expect("event record")
                        .push((EVENT_QUOTA_EXHAUSTED.to_owned(), payload));
                    Box::pin(std::future::ready(Ok(())))
                }),
            );
        let router: BudgetRouter = {
            let budget = budget.clone();
            Arc::new(move |_request| Some(budget.clone()))
        };
        let defer = CollectedDefer::default();
        let sleeper_sleeps = Arc::clone(&sleeps);
        let sleeper_clock = Arc::clone(&clock);
        let client = BudgetedHttpClient::new(
            Arc::clone(&inner) as Arc<dyn HttpClient>,
            clock.clone(),
            db.clone(),
            router,
        )
        .with_retry(policy)
        .with_events(bus)
        .with_defer(Arc::new(defer.clone()) as Arc<dyn Defer>)
        .with_sleeper(Arc::new(move |after| {
            sleeper_sleeps.lock().expect("sleeps lock").push(after);
            // Sleeping is time passing: the manual clock advances by what
            // was slept, so a paced acquire finds its refill on the next
            // attempt, exactly as it would against a real timer.
            sleeper_clock.advance(i64::try_from(after.as_millis()).unwrap_or(i64::MAX));
            Box::pin(std::future::ready(()))
        }));
        Self {
            db,
            clock,
            inner,
            sleeps,
            events,
            defer,
            client: Arc::new(client),
        }
    }

    fn sends(&self) -> usize {
        self.inner.sends()
    }

    fn sleep_log(&self) -> Vec<Duration> {
        self.sleeps.lock().expect("sleeps lock").clone()
    }

    /// The recorded quota events, with their deferred handlers completed.
    fn event_log(&self) -> Vec<(String, serde_json::Value)> {
        self.defer.drain();
        self.events.lock().expect("event record").clone()
    }

    /// The stored bucket row, through the same SQL the client reads with.
    async fn bucket_row(&self, key: &str) -> (f64, i64) {
        let rows = self
            .db
            .query(&Statement::with_values(
                format!("SELECT tokens, updated_ms FROM {DEFAULT_BUCKET_TABLE} WHERE bucket = ?"),
                vec![key.to_owned().into()],
            ))
            .await
            .expect("bucket row reads");
        let row = rows.first().expect("a row exists");
        (
            row.get::<f64>("tokens").expect("tokens"),
            row.get::<i64>("updated_ms").expect("updated_ms"),
        )
    }
}

fn budget(capacity: f64, refill_per_sec: f64) -> Budget {
    Budget {
        key: "dexscreener".to_owned(),
        capacity,
        refill_per_sec,
        cost: 1.0,
        daily_limit: None,
    }
}

fn get_request() -> http::Request<Bytes> {
    http::Request::builder()
        .method(http::Method::GET)
        .uri("https://api.example.com/pairs")
        .body(Bytes::new())
        .expect("test request")
}

fn throttled(status: http::StatusCode, retry_after: Option<&str>) -> http::Response<Bytes> {
    let mut builder = http::Response::builder().status(status);
    if let Some(value) = retry_after {
        builder = builder.header(http::header::RETRY_AFTER, value);
    }
    builder.body(Bytes::new()).expect("test response")
}

/// The migrations the way a venture ships them: all three tables.
async fn create_tables(db: &dyn Database) {
    db.execute(&Statement::new(
        BudgetedHttpClient::create_bucket_table_sql(DEFAULT_BUCKET_TABLE),
    ))
    .await
    .expect("bucket DDL");
    db.execute(&Statement::new(
        Usage::new(DEFAULT_QUOTA_TABLE).create_table_sql(),
    ))
    .await
    .expect("quota DDL");
    db.execute(&Statement::new(BudgetedHttpClient::create_alert_table_sql(
        DEFAULT_ALERT_TABLE,
    )))
    .await
    .expect("alert-claim DDL");
}

/// Writes a bucket row directly, the way another isolate — or another
/// deployment with a skewed clock — would have left it.
async fn seed_bucket(db: &dyn Database, key: &str, tokens: f64, updated_ms: i64) {
    db.execute(&Statement::with_values(
        format!(
            "INSERT INTO {DEFAULT_BUCKET_TABLE} (bucket, tokens, updated_ms)\n\
             VALUES (?, ?, ?)\n\
             ON CONFLICT (bucket) DO UPDATE SET tokens = ?, updated_ms = ?"
        ),
        vec![
            key.to_owned().into(),
            tokens.into(),
            updated_ms.into(),
            tokens.into(),
            updated_ms.into(),
        ],
    ))
    .await
    .expect("bucket row seeds");
}

#[pollster::test]
async fn a_send_spends_the_bucket_and_reaches_the_inner_client() {
    let fixture = Fixture::new(&budget(10.0, 0.0), RetryPolicy::default());
    create_tables(&*fixture.db).await;
    let response = fixture
        .client
        .send(get_request())
        .await
        .expect("a fresh bucket carries the request");
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(fixture.sends(), 1);
    let (tokens, updated_ms) = fixture.bucket_row("dexscreener").await;
    assert_eq!(tokens, 9.0, "capacity minus cost");
    assert_eq!(updated_ms, 1_000, "the clock's reading when it was spent");
}

#[pollster::test]
async fn the_bucket_exhausts_and_refills_with_the_clock() {
    // max_delay below the 1 s refill, so the dry bucket is *reported*
    // rather than paced out — this test is about the refusal and the
    // refill, not the pacing (covered below).
    let fixture = Fixture::new(
        &budget(2.0, 1.0),
        RetryPolicy::default().with_max_delay(Duration::from_millis(500)),
    );
    create_tables(&*fixture.db).await;
    fixture.client.send(get_request()).await.expect("first");
    fixture.client.send(get_request()).await.expect("second");
    // The bucket is dry: capacity 2, both spent, no refill yet.
    let err = fixture
        .client
        .send(get_request())
        .await
        .expect_err("a dry bucket refuses");
    assert!(
        matches!(&err, HttpError::BudgetExhausted { what, retry_after }
            if what == "dexscreener" && *retry_after == Duration::from_secs(1)),
        "one token at 1/s: got {err}"
    );
    assert_eq!(fixture.sends(), 2, "the refused request never went out");
    // One second of refill is one token: the request goes through.
    fixture.clock.advance(1_000);
    fixture.client.send(get_request()).await.expect("refilled");
}

#[pollster::test]
async fn keys_do_not_share_a_bucket() {
    let fixture = Fixture::new(&budget(1.0, 0.0), RetryPolicy::default());
    create_tables(&*fixture.db).await;
    fixture.client.send(get_request()).await.expect("spent");
    // A different key has no row of its own yet — its first send would
    // seed a full fresh bucket, not inherit this one's emptiness.
    let rows = fixture
        .db
        .query(&Statement::with_values(
            format!("SELECT tokens FROM {DEFAULT_BUCKET_TABLE} WHERE bucket = ?"),
            vec!["other".to_owned().into()],
        ))
        .await
        .expect("the other key reads");
    assert!(rows.is_empty(), "no cross-key row");
}

#[pollster::test]
async fn a_shortfall_within_the_pacing_bound_is_waited_out_not_reported() {
    let fixture = Fixture::new(&budget(1.0, 10.0), RetryPolicy::default());
    create_tables(&*fixture.db).await;
    fixture.client.send(get_request()).await.expect("first");
    // Dry, but one token at 10/s refills in 100 ms — pacing, not a 429.
    fixture.client.send(get_request()).await.expect("paced");
    assert_eq!(
        fixture.sleep_log(),
        vec![Duration::from_millis(100)],
        "the one computed wait, no more"
    );
    assert_eq!(fixture.sends(), 2);
}

#[pollster::test]
async fn a_long_shortfall_is_reported_with_the_wait() {
    let fixture = Fixture::new(
        &budget(1.0, 0.01),
        RetryPolicy::default().with_max_delay(Duration::from_secs(1)),
    );
    create_tables(&*fixture.db).await;
    fixture.client.send(get_request()).await.expect("first");
    // One token at 0.01/s is 100 s: beyond max_delay, so it refuses with
    // the wait instead of pacing.
    let err = fixture
        .client
        .send(get_request())
        .await
        .expect_err("beyond the pacing bound");
    assert!(
        matches!(&err, HttpError::BudgetExhausted { retry_after, .. }
            if *retry_after == Duration::from_secs(100)),
        "got {err}"
    );
    assert_eq!(fixture.sends(), 1);
}

#[pollster::test]
async fn the_daily_quota_exhausts_with_the_period_end_as_retry_after() {
    let fixture = Fixture::new(
        &Budget {
            daily_limit: Some(2),
            ..budget(10.0, 0.0)
        },
        RetryPolicy::default(),
    );
    create_tables(&*fixture.db).await;
    fixture.client.send(get_request()).await.expect("first");
    fixture.client.send(get_request()).await.expect("second");
    let err = fixture
        .client
        .send(get_request())
        .await
        .expect_err("the day is spent");
    // 1 000 ms into the epoch day: the rest of it is the pause.
    assert!(
        matches!(&err, HttpError::BudgetExhausted { what, retry_after }
            if what == "dexscreener"
                && *retry_after == Duration::from_millis(86_400_000 - 1_000)),
        "got {err}"
    );
    assert_eq!(fixture.sends(), 2);
}

#[pollster::test]
async fn an_untracked_budget_pays_no_quota_round_trip() {
    let fixture = Fixture::new(&budget(10.0, 0.0), RetryPolicy::default());
    // Only the bucket table exists — and nothing errors: `daily_limit:
    // None` never touches the quota table.
    fixture
        .db
        .execute(&Statement::new(
            BudgetedHttpClient::create_bucket_table_sql(DEFAULT_BUCKET_TABLE),
        ))
        .await
        .expect("bucket DDL only");
    fixture.client.send(get_request()).await.expect("untracked");
}

#[pollster::test]
async fn the_quota_alerts_fire_once_each_at_the_marks() {
    let fixture = Fixture::new(
        &Budget {
            daily_limit: Some(10),
            ..budget(100.0, 0.0)
        },
        RetryPolicy::default(),
    );
    create_tables(&*fixture.db).await;
    for _ in 0..10 {
        fixture
            .client
            .send(get_request())
            .await
            .expect("within quota");
    }
    // The ninth spend observed `used = 9`, past the warning mark but short
    // of the limit: its warning claim reports a row already claimed, and
    // the log stays at the eighth send's emission.
    let log = fixture.event_log();
    assert_eq!(
        log.first().map(|(name, _)| name.as_str()),
        Some(EVENT_QUOTA_WARNING),
        "the eighth spend is the warning"
    );
    assert_eq!(
        log.last().map(|(name, _)| name.as_str()),
        Some(EVENT_QUOTA_EXHAUSTED),
        "the tenth is the exhaustion"
    );
    assert_eq!(log.len(), 2, "at-most-once, no bookkeeping");
    let (_, payload) = log.last().expect("exhausted payload");
    assert_eq!(payload["subject"], "dexscreener");
    assert_eq!(payload["used"], 10);
    assert_eq!(payload["limit"], 10);
    // The eleventh spend is refused at the quota outright — the alert
    // fired at the crossing, and refusals emit nothing.
    fixture
        .client
        .send(get_request())
        .await
        .expect_err("the day is spent");
    assert_eq!(fixture.event_log().len(), 2, "still exactly the two");
}

#[pollster::test]
async fn concurrent_sends_across_the_limit_alert_exactly_once() {
    // The claim, not the arithmetic: `Usage`'s increment is atomic but its
    // read-back is a separate statement, so eight sends released together
    // can all observe the same post-increment total. Only the caller whose
    // guarded insert lands first may emit — the rest lose the claim and
    // stay silent.
    let limit = 8_u64;
    let senders = usize::try_from(limit).expect("a day quota of eight fits a thread count");
    let fixture = Fixture::new(
        &Budget {
            daily_limit: Some(limit),
            ..budget(100.0, 0.0)
        },
        RetryPolicy::default(),
    );
    create_tables(&*fixture.db).await;
    let gate = Arc::new(std::sync::Barrier::new(senders));
    let handles: Vec<_> = (0..senders)
        .map(|_| {
            let client = Arc::clone(&fixture.client);
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || {
                gate.wait();
                pollster::block_on(client.send(get_request()))
                    .expect("each of the eight sends fits the day's quota")
                    .status()
                    .as_u16()
            })
        })
        .collect();
    let statuses: Vec<u16> = handles
        .into_iter()
        .map(|handle| handle.join().expect("send thread"))
        .collect();
    assert_eq!(statuses, vec![200; senders], "every send went out");
    assert_eq!(fixture.sends(), senders);
    let log = fixture.event_log();
    assert_eq!(
        log.iter()
            .filter(|(name, _)| name.as_str() == EVENT_QUOTA_EXHAUSTED)
            .count(),
        1,
        "exactly one exhausted emission, whatever the interleaving: got {log:?}"
    );
    assert!(
        log.iter()
            .filter(|(name, _)| name.as_str() == EVENT_QUOTA_WARNING)
            .count()
            <= 1,
        "the warning's claim is at-most-once too"
    );
    // The exhausted claimant observed the full day: every send counted.
    let (_, payload) = log
        .iter()
        .find(|(name, _)| name.as_str() == EVENT_QUOTA_EXHAUSTED)
        .expect("the exhausted event");
    assert_eq!(payload["used"], 8);
    assert_eq!(payload["limit"], 8);
}

#[pollster::test]
async fn the_smallest_limit_shadows_the_warning_with_the_exhaustion() {
    // Limit 2: the warning mark `ceil(2 * 4 / 5)` is 2 — the limit itself —
    // so the send that crosses the mark is the send that crosses the limit,
    // and the else-if rule emits the exhaustion only. The warning mark can
    // never fire for a limit of 4 or fewer.
    let fixture = Fixture::new(
        &Budget {
            daily_limit: Some(2),
            ..budget(100.0, 0.0)
        },
        RetryPolicy::default(),
    );
    create_tables(&*fixture.db).await;
    fixture.client.send(get_request()).await.expect("first");
    fixture.client.send(get_request()).await.expect("second");
    fixture
        .client
        .send(get_request())
        .await
        .expect_err("the day is spent");
    let log = fixture.event_log();
    assert_eq!(
        log.len(),
        1,
        "one claim: the exhaustion, never a shadowed warning"
    );
    assert_eq!(
        log.first().map(|(name, _)| name.as_str()),
        Some(EVENT_QUOTA_EXHAUSTED)
    );
    let (_, payload) = log.first().expect("exhausted payload");
    assert_eq!(payload["used"], 2);
    assert_eq!(payload["limit"], 2);
}

#[pollster::test]
async fn the_alert_claim_is_per_day_so_a_new_day_alerts_again() {
    let fixture = Fixture::new(
        &Budget {
            daily_limit: Some(2),
            ..budget(100.0, 0.0)
        },
        RetryPolicy::default(),
    );
    create_tables(&*fixture.db).await;
    fixture
        .client
        .send(get_request())
        .await
        .expect("day one, first");
    fixture
        .client
        .send(get_request())
        .await
        .expect("day one, second");
    assert_eq!(
        fixture.event_log().len(),
        1,
        "day one: one exhausted emission"
    );
    // Midnight passes: a new period is a new quota and a new claim row, so
    // the crossing can be observed — and alerted — again.
    fixture.clock.advance(86_400_000);
    fixture
        .client
        .send(get_request())
        .await
        .expect("day two, first");
    fixture
        .client
        .send(get_request())
        .await
        .expect("day two, second");
    let log = fixture.event_log();
    assert_eq!(
        log.len(),
        2,
        "day two claims its own exhaustion, not day one's"
    );
    assert!(
        log.iter()
            .all(|(name, _)| name.as_str() == EVENT_QUOTA_EXHAUSTED),
        "two days, two exhaustions, never a warning"
    );
}

#[pollster::test]
async fn a_missing_claim_table_self_heals_and_still_alerts_once() {
    // A venture that wired `with_events` but shipped only the two original
    // migrations: the first claim meets the missing table, creates it (the
    // same DDL, `IF NOT EXISTS`) and claims again — the alert stays strict,
    // at-most-once, rather than silently dropped.
    let fixture = Fixture::new(
        &Budget {
            daily_limit: Some(2),
            ..budget(100.0, 0.0)
        },
        RetryPolicy::default(),
    );
    fixture
        .db
        .execute(&Statement::new(
            BudgetedHttpClient::create_bucket_table_sql(DEFAULT_BUCKET_TABLE),
        ))
        .await
        .expect("bucket DDL");
    fixture
        .db
        .execute(&Statement::new(
            Usage::new(DEFAULT_QUOTA_TABLE).create_table_sql(),
        ))
        .await
        .expect("quota DDL");
    fixture.client.send(get_request()).await.expect("first");
    fixture.client.send(get_request()).await.expect("second");
    let log = fixture.event_log();
    assert_eq!(log.len(), 1, "the self-healed claim emitted exactly once");
    assert_eq!(
        log.first().map(|(name, _)| name.as_str()),
        Some(EVENT_QUOTA_EXHAUSTED)
    );
    // The healed table is a real claim table: a third send is refused and
    // emits nothing, the same as a migrated deployment.
    fixture
        .client
        .send(get_request())
        .await
        .expect_err("the day is spent");
    assert_eq!(fixture.event_log().len(), 1);
}

#[pollster::test]
async fn a_transport_failure_on_an_idempotent_get_is_retried() {
    let fixture = Fixture::new(&budget(10.0, 0.0), RetryPolicy::default());
    create_tables(&*fixture.db).await;
    fixture
        .inner
        .push(Err(HttpError::Transport("reset".to_owned())));
    fixture
        .inner
        .push(Ok(http::Response::new(Bytes::from_static(b"ok"))));
    let response = fixture
        .client
        .send(get_request())
        .await
        .expect("the retry lands");
    assert_eq!(response.body().as_ref(), b"ok");
    assert_eq!(fixture.sends(), 2);
    assert_eq!(
        fixture.sleep_log(),
        vec![Duration::from_millis(200)],
        "the first computed backoff"
    );
}

#[pollster::test]
async fn a_transport_failure_on_a_post_is_not_retried() {
    let fixture = Fixture::new(&budget(10.0, 0.0), RetryPolicy::default());
    create_tables(&*fixture.db).await;
    fixture
        .inner
        .push(Err(HttpError::Transport("reset".to_owned())));
    let post = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://api.example.com/pairs")
        .body(Bytes::new())
        .expect("test request");
    let err = fixture
        .client
        .send(post)
        .await
        .expect_err("a POST owns its weather");
    assert!(matches!(err, HttpError::Transport(_)), "got {err}");
    assert_eq!(fixture.sends(), 1, "no second attempt");
    assert!(fixture.sleep_log().is_empty());
}

#[pollster::test]
async fn the_idempotent_extension_overrides_the_method() {
    let fixture = Fixture::new(&budget(10.0, 0.0), RetryPolicy::default());
    create_tables(&*fixture.db).await;
    // A POST the caller vouches for IS retried.
    let mut vouched = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://api.example.com/pairs")
        .body(Bytes::new())
        .expect("test request");
    vouched.extensions_mut().insert(Idempotent(true));
    fixture
        .inner
        .push(Err(HttpError::Transport("reset".to_owned())));
    fixture.inner.push(Ok(http::Response::new(Bytes::new())));
    fixture
        .client
        .send(vouched)
        .await
        .expect("the vouched retry");
    assert_eq!(fixture.sends(), 2);
    // And a GET the caller withholds is NOT.
    fixture
        .inner
        .push(Err(HttpError::Transport("reset".to_owned())));
    let mut withheld = get_request();
    withheld.extensions_mut().insert(Idempotent(false));
    let err = fixture
        .client
        .send(withheld)
        .await
        .expect_err("withheld is weather");
    assert!(matches!(err, HttpError::Transport(_)));
    assert_eq!(fixture.sends(), 3, "one attempt, no retry");
}

#[pollster::test]
async fn a_429_with_a_retry_after_header_is_honoured_verbatim() {
    let fixture = Fixture::new(&budget(10.0, 0.0), RetryPolicy::default());
    create_tables(&*fixture.db).await;
    fixture.inner.push(Ok(throttled(
        http::StatusCode::TOO_MANY_REQUESTS,
        Some("7"),
    )));
    fixture
        .inner
        .push(Ok(http::Response::new(Bytes::from_static(b"ok"))));
    let response = fixture
        .client
        .send(get_request())
        .await
        .expect("the retry after the stated pause");
    assert_eq!(response.body().as_ref(), b"ok");
    assert_eq!(
        fixture.sleep_log(),
        vec![Duration::from_secs(7)],
        "the header, verbatim"
    );
    assert_eq!(fixture.sends(), 2);
}

#[pollster::test]
async fn a_429_without_a_header_falls_back_to_the_schedule() {
    let fixture = Fixture::new(&budget(10.0, 0.0), RetryPolicy::default());
    create_tables(&*fixture.db).await;
    fixture
        .inner
        .push(Ok(throttled(http::StatusCode::TOO_MANY_REQUESTS, None)));
    fixture.inner.push(Ok(http::Response::new(Bytes::new())));
    fixture
        .client
        .send(get_request())
        .await
        .expect("the scheduled retry");
    assert_eq!(fixture.sleep_log(), vec![Duration::from_millis(200)]);
}

#[pollster::test]
async fn retries_stop_when_the_total_is_spent() {
    let policy = RetryPolicy::default()
        .with_max_retries(10)
        .with_max_total(Duration::from_millis(500));
    let fixture = Fixture::new(&budget(10.0, 0.0), policy);
    create_tables(&*fixture.db).await;
    // Always throttled, each stating a 10 s pause: the first wait is the
    // total's own 500 ms, after which no retry fits and the last response
    // is handed back as-is.
    for _ in 0..20 {
        fixture.inner.push(Ok(throttled(
            http::StatusCode::SERVICE_UNAVAILABLE,
            Some("10"),
        )));
    }
    let response = fixture
        .client
        .send(get_request())
        .await
        .expect("the 503 itself is the answer once the total is spent");
    assert_eq!(response.status(), http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        fixture.sleep_log(),
        vec![Duration::from_millis(500)],
        "one clamped wait, then nothing fits"
    );
    assert_eq!(fixture.sends(), 2);
}

#[pollster::test]
async fn max_retries_bounds_the_attempts() {
    let policy = RetryPolicy::default().with_max_retries(2);
    let fixture = Fixture::new(&budget(10.0, 0.0), policy);
    create_tables(&*fixture.db).await;
    for _ in 0..5 {
        fixture
            .inner
            .push(Err(HttpError::Transport("reset".to_owned())));
    }
    let err = fixture
        .client
        .send(get_request())
        .await
        .expect_err("weather all the way down");
    assert!(matches!(err, HttpError::Transport(_)));
    assert_eq!(
        fixture.sends(),
        3,
        "the first send plus exactly max_retries"
    );
    assert_eq!(
        fixture.sleep_log(),
        vec![Duration::from_millis(200), Duration::from_millis(400)]
    );
}

#[pollster::test]
async fn the_body_passes_through_untouched() {
    let fixture = Fixture::new(&budget(10.0, 0.0), RetryPolicy::default());
    create_tables(&*fixture.db).await;
    let body = Bytes::from(vec![7_u8; 64]);
    fixture.inner.push(Ok(http::Response::new(body.clone())));
    let response = fixture
        .client
        .send(get_request())
        .await
        .expect("passthrough");
    assert_eq!(response.body(), &body);
}

#[pollster::test]
async fn an_unrouted_request_skips_the_budget_entirely() {
    // No tables exist — the router answering `None` must not touch the
    // store at all.
    let db = Arc::new(SqliteDatabase::in_memory().expect("in-memory sqlite opens"));
    let inner = Arc::new(ScriptedClient::new());
    let clock: Arc<dyn Clock> = Arc::new(StepClock(Log::new(0)));
    let router: BudgetRouter = Arc::new(|_request| None);
    let client =
        BudgetedHttpClient::new(Arc::clone(&inner) as Arc<dyn HttpClient>, clock, db, router);
    let response = client
        .send(get_request())
        .await
        .expect("unrouted passes through");
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(inner.sends(), 1);
}

#[pollster::test]
async fn two_back_to_back_sends_cannot_overspend_a_dry_bucket() {
    // Capacity 1, two spends at the same clock instant: exactly one of them
    // wins the token, the other is refused with the refill wait — the
    // guarded upsert's rows-affected contract, read through the port's own
    // client. max_delay below the 1 s refill keeps the loser a refusal,
    // not a pace. (The genuinely concurrent race is the alert test's
    // eight threads above; the bucket itself has no second driver here.)
    let fixture = Fixture::new(
        &budget(1.0, 1.0),
        RetryPolicy::default().with_max_delay(Duration::from_millis(100)),
    );
    create_tables(&*fixture.db).await;
    fixture
        .client
        .send(get_request())
        .await
        .expect("the winner");
    let err = fixture
        .client
        .send(get_request())
        .await
        .expect_err("the loser, same clock instant");
    assert!(
        matches!(&err, HttpError::BudgetExhausted { retry_after, .. }
            if *retry_after == Duration::from_secs(1)),
        "got {err}"
    );
    let (tokens, _) = fixture.bucket_row("dexscreener").await;
    assert_eq!(tokens, 0.0, "nothing went negative");
}

#[pollster::test]
async fn a_clock_ahead_stamp_cannot_burn_tokens_from_a_send() {
    // An isolate whose clock runs two seconds ahead spent this bucket
    // last: its `updated_ms` is in this clock's future. The clamped
    // refill reads "no time passed" — the send costs exactly its cost,
    // and the stamp heals to this clock's now. Unclamped, the negative
    // elapsed would destroy `rate x skew` tokens on top of the spend.
    let fixture = Fixture::new(&budget(10.0, 1.0), RetryPolicy::default());
    create_tables(&*fixture.db).await;
    seed_bucket(&*fixture.db, "dexscreener", 9.0, 3_000).await;
    let response = fixture
        .client
        .send(get_request())
        .await
        .expect("the refilled level carries the request");
    assert_eq!(response.status(), http::StatusCode::OK);
    let (tokens, updated_ms) = fixture.bucket_row("dexscreener").await;
    assert_eq!(
        tokens, 8.0,
        "exactly the cost — not 9 minus the two phantom seconds"
    );
    assert_eq!(updated_ms, 1_000, "the stamp heals to this clock's now");
}

#[pollster::test]
async fn a_clock_ahead_stamp_reports_the_true_refill_wait_not_a_free_one() {
    // The same skew against a dry bucket: the refusal's `retry_after` is
    // the true refill wait for the level that is really there (one token
    // at 1/s), never the negative-elapsed arithmetic's free zero.
    let fixture = Fixture::new(
        &budget(10.0, 1.0),
        RetryPolicy::default().with_max_delay(Duration::from_millis(100)),
    );
    create_tables(&*fixture.db).await;
    seed_bucket(&*fixture.db, "dexscreener", 0.0, 3_000).await;
    let err = fixture
        .client
        .send(get_request())
        .await
        .expect_err("a dry bucket refuses");
    assert!(
        matches!(&err, HttpError::BudgetExhausted { what, retry_after }
            if what == "dexscreener" && *retry_after == Duration::from_secs(1)),
        "the true wait, one token at 1/s: got {err}"
    );
    // Immediate, and bounded: no pacing loop, no second statement, and a
    // refusal never moves the row.
    assert_eq!(fixture.sends(), 0, "the refused request never went out");
    assert!(
        fixture.sleep_log().is_empty(),
        "below the pacing bound: no waits at all"
    );
    let (tokens, updated_ms) = fixture.bucket_row("dexscreener").await;
    assert_eq!(tokens, 0.0, "the refusal overspends nothing");
    assert_eq!(updated_ms, 3_000, "a refused spend does not move the row");
}
