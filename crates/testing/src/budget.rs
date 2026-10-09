//! The outbound-budget contract (issue #765), asserted against a live
//! adapter rather than trusted from its docs. A token bucket that lets two
//! isolates both spend the last token, a daily quota that fires its alert
//! twice, or a retry loop that swallows a provider's `Retry-After` would
//! pass a hand-written spot check and then spend a venture's quota behind
//! its back.
//!
//! [`assert_budget_pacing`], [`assert_budget_daily_quota`],
//! [`assert_budget_retries`] and [`assert_budget_passthrough`] each build
//! a [`BudgetedHttpClient`] themselves — over a caller-provided database,
//! a [`ManualClock`] the recorded sleeper advances, and a scripted inner
//! client — so a runtime or venture holds its own store to the same
//! standard by calling any subset, the way
//! `assert_blob_round_trips(&db)` does for the blob port. The sleeps are
//! recorded, never awaited: the delays are asserted, never slept.
//!
//! Each function runs its own probe tables
//! (`budget_probe_*_buckets` / `budget_probe_*_usage`, the DDL the
//! decorator ships: [`BudgetedHttpClient::create_bucket_table_sql`] and
//! [`Usage::create_table_sql`]), cleared before and after, so the checks
//! re-run against a database a previous run left behind.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures_core::future::BoxFuture;
use http::StatusCode;
use time::OffsetDateTime;

use cratefield_core::{
    Budget, BudgetRouter, BudgetedHttpClient, Database, Defer, EVENT_QUOTA_EXHAUSTED,
    EVENT_QUOTA_WARNING, EventBus, HttpClient, HttpError, Idempotent, RetryPolicy, Statement,
    Usage,
};

use crate::fakes::ManualClock;

// Connection-guarding `Mutex` for the recorded sends, sleeps and events —
// test support, not request state (ADR 0007); the exception the workspace
// `clippy.toml` documents for this crate's recording fakes.
#[allow(clippy::disallowed_types)]
use std::sync::Mutex as StdMutex;

#[allow(clippy::disallowed_types)]
type Log<T> = StdMutex<T>;

/// The instant the probe clocks start at: one second into the Unix epoch,
/// so the UTC day a daily quota counts against ends exactly 86 399 s later
/// and the day-quota's `retry_after` is exact.
fn clock_start() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1)
}

/// The scripted inner client: records every request that arrives — whole,
/// so a passthrough check can compare method, URI, headers and body — and
/// pops one outcome per send. An exhausted script answers a bare `200`:
/// the checks that care about outcomes script them, the rest only need the
/// pipe open.
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

    fn captured(&self) -> Vec<http::Request<Bytes>> {
        self.sent.lock().expect("sent lock").clone()
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
/// the bus's quota alerts ride the scope's defer, and draining it is what
/// makes an event's arrival observable and ordered relative to the send
/// that emitted it.
#[derive(Clone, Default)]
struct RecordingDefer(Arc<Log<Vec<BoxFuture<'static, ()>>>>);

impl Defer for RecordingDefer {
    fn wait_until(&self, fut: BoxFuture<'static, ()>) {
        self.0.lock().expect("defer lock").push(fut);
    }
}

impl RecordingDefer {
    /// Runs every deferred future to completion, in deferral order.
    async fn drain(&self) {
        loop {
            let next = {
                let mut pending = self.0.lock().expect("defer lock");
                (!pending.is_empty()).then(|| pending.remove(0))
            };
            let Some(fut) = next else { break };
            fut.await;
        }
    }
}

/// Everything one check needs: the budgeted client over the caller's
/// database, the manual clock its sleeper advances, and the recordings —
/// inner sends, sleeps and quota events.
struct Fixture {
    db: Arc<dyn Database>,
    clock: ManualClock,
    inner: Arc<ScriptedClient>,
    sleeps: Arc<Log<Vec<Duration>>>,
    events: Arc<Log<Vec<(String, serde_json::Value)>>>,
    defer: RecordingDefer,
    client: BudgetedHttpClient,
}

impl Fixture {
    /// Builds a fixture whose router hands out the budgets, over `policy`,
    /// with an instant sleeper and a bus recording the quota events.
    fn new(
        db: &Arc<dyn Database>,
        buckets: &str,
        usage: &str,
        policy: RetryPolicy,
        router: BudgetRouter,
    ) -> Self {
        let clock = ManualClock::new(clock_start());
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
        let defer = RecordingDefer::default();
        let sleeper_sleeps = Arc::clone(&sleeps);
        let sleeper_clock = clock.clone();
        let client = BudgetedHttpClient::new(
            Arc::clone(&inner) as Arc<dyn HttpClient>,
            Arc::new(clock.clone()),
            Arc::clone(db),
            router,
        )
        .with_retry(policy)
        .with_events(bus)
        .with_defer(Arc::new(defer.clone()) as Arc<dyn Defer>)
        .with_bucket_table(buckets)
        .with_quota_table(usage)
        .with_sleeper(Arc::new(move |after| {
            sleeper_sleeps.lock().expect("sleeps lock").push(after);
            // Sleeping is time passing: the manual clock advances by what
            // was slept, so a paced acquire finds its refill on the next
            // attempt, exactly as it would against a real timer.
            sleeper_clock.advance(after);
            Box::pin(std::future::ready(()))
        }));
        Self {
            db: Arc::clone(db),
            clock,
            inner,
            sleeps,
            events,
            defer,
            client,
        }
    }

    fn sends(&self) -> usize {
        self.inner.sends()
    }

    fn sleep_log(&self) -> Vec<Duration> {
        self.sleeps.lock().expect("sleeps lock").clone()
    }

    /// The recorded quota events, with their deferred handlers completed,
    /// draining the record so the next assertion starts empty.
    async fn drain_events(&self) -> Vec<(String, serde_json::Value)> {
        self.defer.drain().await;
        std::mem::take(&mut *self.events.lock().expect("event record"))
    }

    /// The bucket keys holding a row, sorted — one row per budget key, no
    /// cross-key row.
    async fn bucket_keys(&self, buckets: &str) -> Vec<String> {
        let rows = self
            .db
            .query(&Statement::new(format!(
                "SELECT bucket FROM {buckets} ORDER BY bucket"
            )))
            .await
            .expect("bucket rows read");
        rows.rows
            .iter()
            .filter_map(|row| row.get::<String>("bucket"))
            .collect()
    }
}

/// A router that sends every request to the same budget.
fn fixed_router(budget: &Budget) -> BudgetRouter {
    let budget = budget.clone();
    Arc::new(move |_request| Some(budget.clone()))
}

/// A `GET` against the probe upstream.
fn get_request(path: &str) -> http::Request<Bytes> {
    http::Request::builder()
        .method(http::Method::GET)
        .uri(format!("https://upstream.example.test{path}"))
        .body(Bytes::new())
        .expect("test request")
}

/// A `POST` against the probe upstream.
fn post_request(path: &str) -> http::Request<Bytes> {
    http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("https://upstream.example.test{path}"))
        .body(Bytes::new())
        .expect("test request")
}

/// A throttled response with an optional `Retry-After` in delta-seconds.
fn throttled(status: StatusCode, retry_after: Option<&str>) -> http::Response<Bytes> {
    let mut builder = http::Response::builder().status(status);
    if let Some(value) = retry_after {
        builder = builder.header(http::header::RETRY_AFTER, value);
    }
    builder.body(Bytes::new()).expect("test response")
}

/// A `200` carrying a body a retry check can recognise.
fn ok_response(body: &[u8]) -> http::Response<Bytes> {
    http::Response::builder()
        .status(StatusCode::OK)
        .body(Bytes::copy_from_slice(body))
        .expect("test response")
}

/// Creates the probe tables the decorator spends from and clears whatever a
/// previous run left in them.
async fn create_probe_tables(db: &Arc<dyn Database>, buckets: &str, usage: &str) {
    db.execute(&Statement::new(
        BudgetedHttpClient::create_bucket_table_sql(buckets),
    ))
    .await
    .expect("bucket probe table");
    db.execute(&Statement::new(Usage::new(usage).create_table_sql()))
        .await
        .expect("quota probe table");
    clear_probe_tables(db, buckets, usage).await;
}

/// Leaves the probe tables empty, so a re-run starts where the first began.
async fn clear_probe_tables(db: &Arc<dyn Database>, buckets: &str, usage: &str) {
    for table in [buckets, usage] {
        db.execute(&Statement::new(format!("DELETE FROM {table}")))
            .await
            .expect("clear probe");
    }
}

/// Proves `db` can carry the pacing half of the outbound budgets (issue
/// #765): capacity 2 refilled at 1 token per second, cost 1 per request —
/// two sends spend the whole bucket, the third paces (the recorded sleeper
/// waits no longer than the policy's `max_delay`) or refuses with
/// [`HttpError::BudgetExhausted`] naming a positive `retry_after`, and one
/// refill window later the request goes through. A second key spends its
/// own full bucket and holds its own row: keys do not share a bucket.
///
/// Runs its own probe tables, so it can be called against any adapter with
/// a writable connection.
///
/// # Panics
///
/// Panics when the pacing contract is violated: a dry bucket answers with
/// anything but a paced send or a budget refusal, the recorded wait passes
/// `max_delay`, a refusal names no wait, a refill window does not carry the
/// next request, the second key inherits the first's emptiness, or the
/// probe tables cannot be created on the given connection.
pub async fn assert_budget_pacing(db: &Arc<dyn Database>) {
    let buckets = "budget_probe_pacing_buckets";
    let usage = "budget_probe_pacing_usage";
    create_probe_tables(db, buckets, usage).await;

    let budget = |key: &str| Budget {
        key: key.to_owned(),
        capacity: 2.0,
        refill_per_sec: 1.0,
        cost: 1.0,
        daily_limit: None,
    };
    let router: BudgetRouter = {
        let (a, b) = (budget("budget-probe:a"), budget("budget-probe:b"));
        Arc::new(move |request| match request.uri().path() {
            "/a" => Some(a.clone()),
            "/b" => Some(b.clone()),
            _ => None,
        })
    };
    let policy = RetryPolicy::default();
    let fixture = Fixture::new(db, buckets, usage, policy, router);

    fixture
        .client
        .send(get_request("/a"))
        .await
        .expect("the first send is within the fresh bucket");
    fixture
        .client
        .send(get_request("/a"))
        .await
        .expect("the second send spends the last token");
    // The bucket is dry. A shortfall that refills within the policy's bound
    // is pacing; anything longer is a refusal carrying the wait.
    match fixture.client.send(get_request("/a")).await {
        Ok(_) => {
            let waits = fixture.sleep_log();
            assert!(!waits.is_empty(), "a paced send records the waits it made");
            assert!(
                waits.iter().all(|wait| *wait <= policy.max_delay()),
                "pacing never waits past max_delay: {waits:?}"
            );
        }
        Err(HttpError::BudgetExhausted { what, retry_after }) => {
            assert_eq!(what, "budget-probe:a");
            assert!(
                retry_after > Duration::ZERO,
                "a refusal carries the refill wait, got {retry_after:?}"
            );
        }
        Err(other) => panic!("a dry bucket paces or refuses, nothing else: {other}"),
    }
    // One refill window is one token: the request goes through.
    fixture.clock.advance(Duration::from_secs(1));
    fixture
        .client
        .send(get_request("/a"))
        .await
        .expect("the refilled bucket carries the request");

    // The second key's first send succeeds even though the first key's
    // bucket is dry right now — its own full bucket, not a shared one — and
    // the store holds one row per key, never a cross-key row.
    fixture
        .client
        .send(get_request("/b"))
        .await
        .expect("a second key has its own full bucket");
    assert_eq!(
        fixture.bucket_keys(buckets).await,
        vec!["budget-probe:a", "budget-probe:b"],
        "one bucket row per key"
    );

    clear_probe_tables(db, buckets, usage).await;
}

/// Proves `db` can carry the daily-quota half of the outbound budgets
/// (issue #765): a `daily_limit` of 10 at cost 1 fires
/// [`EVENT_QUOTA_WARNING`] exactly once on the eighth send (the 80% mark)
/// and [`EVENT_QUOTA_EXHAUSTED`] exactly once on the tenth — at-most-once,
/// with no bookkeeping — and the eleventh send is refused with
/// [`HttpError::BudgetExhausted`] whose `retry_after` reaches the UTC day
/// boundary, past which the quota is fresh again. A budget with
/// `daily_limit: None` never refuses on quota and never alerts.
///
/// Runs its own probe tables, so it can be called against any adapter with
/// a writable connection.
///
/// # Panics
///
/// Panics when the quota contract is violated: an alert fires twice or not
/// at all, a refusal names anything but the day boundary, the next day's
/// quota is not fresh, an untracked budget refuses, or the probe tables
/// cannot be created on the given connection.
pub async fn assert_budget_daily_quota(db: &Arc<dyn Database>) {
    let buckets = "budget_probe_quota_buckets";
    let usage = "budget_probe_quota_usage";
    create_probe_tables(db, buckets, usage).await;

    let budget = Budget {
        key: "budget-probe:quota".to_owned(),
        capacity: 100.0,
        refill_per_sec: 0.0,
        cost: 1.0,
        daily_limit: Some(10),
    };
    let fixture = Fixture::new(
        db,
        buckets,
        usage,
        RetryPolicy::default(),
        fixed_router(&budget),
    );

    check_quota_alerts(&fixture).await;
    check_untracked_quota(db, buckets, usage).await;

    clear_probe_tables(db, buckets, usage).await;
}

/// Eight sends land exactly on the 80% warning, the tenth on the
/// exhaustion, the eleventh on a refusal pointing at the day boundary —
/// and once the boundary passes, the day resets.
async fn check_quota_alerts(fixture: &Fixture) {
    for spent in 1..=8 {
        fixture
            .client
            .send(get_request("/quota"))
            .await
            .expect("within quota");
        assert_eq!(
            fixture.sends(),
            spent,
            "every send within the quota goes out"
        );
    }
    let events = fixture.drain_events().await;
    let [(name, payload)] = events.as_slice() else {
        panic!("exactly one alert by the eighth send, got {events:?}");
    };
    assert_eq!(name, EVENT_QUOTA_WARNING, "the eighth spend is the warning");
    assert_eq!(payload["subject"], "budget-probe:quota");
    assert_eq!(payload["used"], 8);
    assert_eq!(payload["limit"], 10);

    fixture
        .client
        .send(get_request("/quota"))
        .await
        .expect("the ninth send is under the limit");
    fixture
        .client
        .send(get_request("/quota"))
        .await
        .expect("the tenth send spends the day");
    let events = fixture.drain_events().await;
    let [(name, payload)] = events.as_slice() else {
        panic!("exactly one alert for the tenth send, got {events:?}");
    };
    assert_eq!(
        name, EVENT_QUOTA_EXHAUSTED,
        "the tenth spend is the exhaustion"
    );
    assert_eq!(payload["used"], 10);

    // The day is spent: the next send is refused, pointing at the boundary
    // — one second into the epoch day, the rest of that day.
    let err = fixture
        .client
        .send(get_request("/quota"))
        .await
        .expect_err("the day is spent");
    assert!(
        matches!(
            &err,
            HttpError::BudgetExhausted { what, retry_after }
                if what == "budget-probe:quota"
                    && *retry_after == Duration::from_secs(86_400 - 1)
        ),
        "the retry_after reaches the UTC day boundary: got {err}"
    );
    assert_eq!(fixture.sends(), 10, "the refused request never went out");

    // The boundary is a promise: when it passes, the new day is fresh.
    fixture.clock.advance(Duration::from_secs(86_400 - 1));
    fixture
        .client
        .send(get_request("/quota"))
        .await
        .expect("the next day's quota is fresh");
}

/// A budget with `daily_limit: None` is untracked: however many sends go
/// out, none refuses and none alerts.
async fn check_untracked_quota(db: &Arc<dyn Database>, buckets: &str, usage: &str) {
    let budget = Budget {
        key: "budget-probe:untracked".to_owned(),
        daily_limit: None,
        ..budget_shape()
    };
    let fixture = Fixture::new(
        db,
        buckets,
        usage,
        RetryPolicy::default(),
        fixed_router(&budget),
    );
    for _ in 0..12 {
        fixture
            .client
            .send(get_request("/quota"))
            .await
            .expect("an untracked budget never refuses on quota");
    }
    let events = fixture.drain_events().await;
    assert!(events.is_empty(), "no limit, no alerts: {events:?}");
}

/// The shape every probe budget shares: a wide idle bucket and cost 1, so
/// only the field a check names is doing any work.
fn budget_shape() -> Budget {
    Budget {
        key: String::new(),
        capacity: 100.0,
        refill_per_sec: 0.0,
        cost: 1.0,
        daily_limit: None,
    }
}

/// Proves the retry half of the outbound budgets (issue #765): a 429
/// stating `Retry-After: 7` on an idempotent `GET` is honoured verbatim —
/// the recorded sleeper waits exactly 7 s and the exchange lands on the
/// second attempt — the same script on a `POST` is *not* a retry (the 429
/// itself is the answer), a `POST` the caller vouches for with the
/// [`Idempotent`] extension set to `true` retries, and a transport failure
/// on a `GET` retries on the policy's exponential schedule (its own
/// `base`, doubled).
///
/// Runs its own probe tables, so it can be called against any adapter with
/// a writable connection.
///
/// # Panics
///
/// Panics when the retry contract is violated: a stated `Retry-After` is
/// not waited out verbatim, a `POST` is retried without the extension, a
/// vouched `POST` is not, a transport failure is not retried or retries
/// off the schedule, or the probe tables cannot be created on the given
/// connection.
pub async fn assert_budget_retries(db: &Arc<dyn Database>) {
    let buckets = "budget_probe_retry_buckets";
    let usage = "budget_probe_retry_usage";
    create_probe_tables(db, buckets, usage).await;

    check_stated_retry_after_is_honoured(db, buckets, usage).await;
    check_a_post_is_not_retried(db, buckets, usage).await;
    check_the_idempotent_extension_vouches(db, buckets, usage).await;
    check_transport_retries_on_the_schedule(db, buckets, usage).await;

    clear_probe_tables(db, buckets, usage).await;
}

/// A budget for one retry check: a wide idle bucket, so only the exchange
/// under test is doing any work.
fn retry_fixture(db: &Arc<dyn Database>, buckets: &str, usage: &str, key: &str) -> Fixture {
    let budget = Budget {
        key: key.to_owned(),
        ..budget_shape()
    };
    let router = fixed_router(&budget);
    Fixture::new(db, buckets, usage, RetryPolicy::default(), router)
}

/// A 429 with `Retry-After: 7` on a `GET`: one wait of exactly the stated
/// pause, then the retried send's own answer.
async fn check_stated_retry_after_is_honoured(db: &Arc<dyn Database>, buckets: &str, usage: &str) {
    let fixture = retry_fixture(db, buckets, usage, "budget-probe:retry-stated");
    fixture
        .inner
        .push(Ok(throttled(StatusCode::TOO_MANY_REQUESTS, Some("7"))));
    fixture.inner.push(Ok(ok_response(b"ok")));
    let response = fixture
        .client
        .send(get_request("/retry"))
        .await
        .expect("the retry lands after the stated pause");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body().as_ref(), b"ok");
    assert_eq!(fixture.sends(), 2, "one throttled attempt, one retry");
    assert_eq!(
        fixture.sleep_log(),
        vec![Duration::from_secs(7)],
        "the header's pause, verbatim"
    );
}

/// The same script on a `POST` is not a retry: the 429 itself is the
/// answer, with no wait and no second attempt.
async fn check_a_post_is_not_retried(db: &Arc<dyn Database>, buckets: &str, usage: &str) {
    let fixture = retry_fixture(db, buckets, usage, "budget-probe:retry-post");
    fixture
        .inner
        .push(Ok(throttled(StatusCode::TOO_MANY_REQUESTS, Some("7"))));
    let response = fixture
        .client
        .send(post_request("/retry"))
        .await
        .expect("a throttled POST is a response, not an error");
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(fixture.sends(), 1, "a POST owns its weather");
    assert!(fixture.sleep_log().is_empty(), "no wait was made");
}

/// A `POST` the caller vouches for with the [`Idempotent`] extension
/// retries like a `GET`; with no header stated, the wait is the schedule's
/// own base.
async fn check_the_idempotent_extension_vouches(
    db: &Arc<dyn Database>,
    buckets: &str,
    usage: &str,
) {
    let fixture = retry_fixture(db, buckets, usage, "budget-probe:retry-vouched");
    fixture
        .inner
        .push(Ok(throttled(StatusCode::TOO_MANY_REQUESTS, None)));
    fixture.inner.push(Ok(ok_response(b"ok")));
    let mut vouched = post_request("/retry");
    vouched.extensions_mut().insert(Idempotent(true));
    let response = fixture
        .client
        .send(vouched)
        .await
        .expect("the vouched retry lands");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(fixture.sends(), 2, "the vouch makes the POST retryable");
    assert_eq!(
        fixture.sleep_log(),
        vec![RetryPolicy::default().base()],
        "no header stated: the schedule's first backoff"
    );
}

/// A transport failure on a `GET` retries on the exponential schedule: the
/// policy's `base`, then its double.
async fn check_transport_retries_on_the_schedule(
    db: &Arc<dyn Database>,
    buckets: &str,
    usage: &str,
) {
    let fixture = retry_fixture(db, buckets, usage, "budget-probe:retry-weather");
    fixture
        .inner
        .push(Err(HttpError::Transport("reset".to_owned())));
    fixture
        .inner
        .push(Err(HttpError::Transport("reset".to_owned())));
    fixture.inner.push(Ok(ok_response(b"ok")));
    let response = fixture
        .client
        .send(get_request("/retry"))
        .await
        .expect("the weather clears on the third attempt");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        fixture.sends(),
        3,
        "the first send plus exactly the two retries"
    );
    let policy = RetryPolicy::default();
    assert_eq!(
        fixture.sleep_log(),
        vec![policy.base(), policy.base() * 2],
        "exponential: base, then double"
    );
}

/// Proves the pass-through half of the outbound budgets (issue #765): a
/// router that answers `None` governs nothing — the request reaches the
/// inner client verbatim (method, URI, headers, body and the request
/// extensions an [`Idempotent`] marker rides in), the response passes back
/// untouched, and the budget store stays empty because nothing was spent:
/// no bucket row, no quota row, no sleeper wait.
///
/// Runs its own probe tables, so it can be called against any adapter with
/// a writable connection.
///
/// # Panics
///
/// Panics when the pass-through contract is violated: the inner client sees
/// a request other than the one sent, the response is rewritten, a budget
/// row or a sleeper wait appears, or the probe tables cannot be created on
/// the given connection.
pub async fn assert_budget_passthrough(db: &Arc<dyn Database>) {
    let buckets = "budget_probe_passthrough_buckets";
    let usage = "budget_probe_passthrough_usage";
    create_probe_tables(db, buckets, usage).await;

    // A router that answers None: nothing here is ours to govern, however
    // tight the budgets a deployment configured might be.
    let router: BudgetRouter = Arc::new(|_request| None);
    let fixture = Fixture::new(db, buckets, usage, RetryPolicy::default(), router);

    let mut request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://upstream.example.test/v1/things?x=1")
        .header("x-probe", "yes")
        .body(Bytes::from_static(b"payload"))
        .expect("test request");
    request.extensions_mut().insert(Idempotent(true));
    fixture.inner.push(Ok(http::Response::builder()
        .status(StatusCode::ACCEPTED)
        .header("x-probe-echo", "same")
        .body(Bytes::from_static(b"untouched"))
        .expect("test response")));

    let response = fixture
        .client
        .send(request)
        .await
        .expect("an unrouted request passes through");
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(response.body().as_ref(), b"untouched");
    assert_eq!(
        response
            .headers()
            .get("x-probe-echo")
            .map(http::HeaderValue::as_bytes),
        Some(b"same".as_slice()),
        "the response's own headers survive"
    );

    let captured = fixture.inner.captured();
    let [sent] = captured.as_slice() else {
        panic!(
            "the inner client saw exactly one request, got {}",
            captured.len()
        );
    };
    assert_eq!(sent.method(), http::Method::POST);
    assert_eq!(sent.uri(), "https://upstream.example.test/v1/things?x=1");
    assert_eq!(
        sent.headers()
            .get("x-probe")
            .map(http::HeaderValue::as_bytes),
        Some(b"yes".as_slice())
    );
    assert_eq!(sent.body().as_ref(), b"payload");
    assert_eq!(
        sent.extensions().get::<Idempotent>(),
        Some(&Idempotent(true)),
        "the extensions ride along"
    );

    assert!(fixture.sleep_log().is_empty(), "no budget, no waits");
    assert_eq!(row_count(db, buckets).await, 0, "no bucket rows written");
    assert_eq!(row_count(db, usage).await, 0, "no quota rows written");

    clear_probe_tables(db, buckets, usage).await;
}

/// The number of rows in a probe table.
async fn row_count(db: &Arc<dyn Database>, table: &str) -> i64 {
    let rows = db
        .query(&Statement::new(format!(
            "SELECT COUNT(*) AS n FROM {table}"
        )))
        .await
        .expect("count probe rows");
    rows.first()
        .and_then(|row| row.get::<i64>("n"))
        .expect("one count row")
}
