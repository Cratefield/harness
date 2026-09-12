//! Shared fixtures for the module's tests: a real ES256 access token, the
//! JWKS the verifier fetches to check it, a kit with the `Push` port wired
//! to a [`FakePush`], and a probe module that records the events this one
//! emits.
//!
//! The tokens are minted the way the auth service does, and verified by
//! `cratefield-auth-client` itself — no bypass, no test-only extractor. A
//! route test that could not produce a valid token would not be testing
//! the route this module ships.

#![allow(dead_code)]
// Interior mutability here records test observations — a clock a test can
// move, a scripted provider's queue, the events the bus delivered. It is
// not request state (ADR 0007); the scoped allow follows the policy in the
// workspace `clippy.toml`, as `cratefield-testing`'s own fakes do.
#![allow(clippy::disallowed_types)]
// Every accessor locks an unpoisoned fixture mutex; per-method `# Panics`
// sections would add noise without information.
#![allow(clippy::missing_panics_doc)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64ct::{Base64UrlUnpadded, Encoding};
use bytes::Bytes;
use cratefield_core::{
    AnyError, BoxFuture, Clock, Config, ConfigError, Defer, EventHandler, EventName, HttpClient,
    HttpError, MapConfig, Migrations, Module, ModuleContext, Notification, PersonalDataCatalog,
    Port, Ports, Push, PushError, PushOutcome, Recipient, Scope, Statement, TemplateRegistry,
    UlidIdGen, Venture,
};
use cratefield_module_notifications::{Category, Notifications, Notifier, Transport};
use cratefield_testing::{FakePush, PushMode, TestHarness};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{self, Signature};
use serde_json::{Value, json};
use time::OffsetDateTime;

/// The issuer the kit configures and every token claims.
pub const ISSUER: &str = "https://auth.test.example";
/// The client id the kit configures and every token's `aud` equals.
pub const CLIENT: &str = "client-notifications";
/// `TestHarness`'s `FixedClock`, so `exp` and `iat` line up with the clock
/// the verifier reads.
pub const NOW: i64 = 1_800_000_000;

pub const ALICE: &str = "acct-alice";
pub const BOB: &str = "acct-bob";

pub const BOOKING: &str = "booking";
pub const COACH_NOTES: &str = "coach_notes";
pub const ROOM_STARTING: &str = "room_starting";

/// A fixed P-256 keypair and its JWK. Deterministic so a failing test is
/// reproducible.
fn signing_key() -> (ecdsa::SigningKey, Value) {
    let secret = p256::SecretKey::from_slice(&[7u8; 32]).expect("a valid scalar");
    let signing = ecdsa::SigningKey::from(&secret);
    let point = signing.verifying_key().to_sec1_point(false);
    let sec1 = point.as_bytes();
    assert_eq!(sec1.len(), 65, "uncompressed point");
    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "kid": "test-key-1",
        "x": Base64UrlUnpadded::encode_string(&sec1[1..33]),
        "y": Base64UrlUnpadded::encode_string(&sec1[33..65]),
    });
    (signing, jwk)
}

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// An access token for `sub`, signed the way the auth service signs.
pub fn token_for(sub: &str) -> String {
    token_with(&json!({
        "sub": sub,
        "aud": CLIENT,
        "iss": ISSUER,
        "sid": "session-1",
        "exp": NOW + 3_600,
        "iat": NOW - 10,
    }))
}

/// [`token_for`] plus a verified email claim, the way an issuer that has
/// confirmed the address presents it.
pub fn token_for_verified_email(sub: &str, email: &str) -> String {
    token_with(&json!({
        "sub": sub,
        "aud": CLIENT,
        "iss": ISSUER,
        "sid": "session-1",
        "exp": NOW + 3_600,
        "iat": NOW - 10,
        "email": email,
        "email_verified": true,
    }))
}

/// A token with arbitrary claims, for the refusals.
pub fn token_with(claims: &Value) -> String {
    let (signing, _) = signing_key();
    let header = json!({ "alg": "ES256", "kid": "test-key-1", "typ": "JWT" });
    let input = format!(
        "{}.{}",
        b64(serde_json::to_string(&header).expect("header").as_bytes()),
        b64(serde_json::to_string(claims).expect("claims").as_bytes())
    );
    let signature: Signature = signing.sign(input.as_bytes());
    format!("{input}.{}", b64(&signature.to_bytes()))
}

/// An `HttpClient` that answers every request with the issuer's key set,
/// and counts how many times it was asked.
///
/// Deliberately not `FakeHttpClient`, whose scripted responses run out:
/// the verifier refetches on an unknown `kid`, and a test that failed
/// because the script was exhausted would look like a verification bug.
///
/// The count is what makes "the token verifier is built once, not once per
/// request" observable: a verifier rebuilt per request starts with an
/// empty JWKS cache and fetches again.
pub struct StaticJwks {
    body: String,
    fetches: Arc<AtomicUsize>,
}

impl StaticJwks {
    /// A key set server over the fixture's own signing key.
    pub fn new() -> Self {
        let (_, jwk) = signing_key();
        Self {
            body: json!({ "keys": [jwk] }).to_string(),
            fetches: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// How many times the key set has been fetched.
    pub fn fetches(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.fetches)
    }
}

#[async_trait]
impl HttpClient for StaticJwks {
    async fn send(
        &self,
        _request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        http::Response::builder()
            .status(200)
            .body(Bytes::from(self.body.clone()))
            .map_err(|err| HttpError::Transport(err.to_string()))
    }
}

// ---------------------------------------------------------------------------
// An event subscriber, so the bus can be asserted on

#[derive(Default)]
pub struct EventLog(Mutex<Vec<(String, Value)>>);

impl EventLog {
    pub fn all(&self) -> Vec<(String, Value)> {
        self.0.lock().expect("event log").clone()
    }

    /// Every payload seen for one event name.
    pub fn payloads(&self, event: &str) -> Vec<Value> {
        self.0
            .lock()
            .expect("event log")
            .iter()
            .filter(|(name, _)| name == event)
            .map(|(_, payload)| payload.clone())
            .collect()
    }
}

/// A module that subscribes to this module's events and records them.
pub struct EventProbe {
    pub log: Arc<EventLog>,
}

impl Module for EventProbe {
    fn name(&self) -> &'static str {
        "event-probe"
    }
    fn version(&self) -> &'static str {
        "0.0.0"
    }
    fn requires(&self) -> &'static [Port] {
        &[]
    }
    fn migrations(&self) -> Migrations {
        Migrations::EMPTY
    }
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        axum::Router::new()
    }
    fn events(&self) -> Vec<(EventName, EventHandler)> {
        [
            cratefield_module_notifications::EVENT_SUBSCRIPTION_PRUNED,
            cratefield_module_notifications::EVENT_SUBSCRIPTION_REHOMED,
            cratefield_module_notifications::EVENT_MISSING_TRANSLATION,
        ]
        .into_iter()
        .map(|event| {
            let log = Arc::clone(&self.log);
            let handler: EventHandler = Arc::new(move |_scope, payload| {
                let log = Arc::clone(&log);
                Box::pin(async move {
                    log.0
                        .lock()
                        .expect("event log")
                        .push((event.to_owned(), payload));
                    Ok::<(), AnyError>(())
                }) as BoxFuture<'static, Result<(), AnyError>>
            });
            (event.to_owned(), handler)
        })
        .collect()
    }
}

// ---------------------------------------------------------------------------
// A clock the test moves

/// A `Clock` a test can advance, so a retried row can actually become due
/// again. `FixedClock` cannot: a bounded-retry test against a frozen clock
/// would claim each row exactly once and prove nothing about the second
/// attempt.
#[derive(Clone)]
pub struct TestClock(Arc<Mutex<OffsetDateTime>>);

impl TestClock {
    pub fn at(unix: i64) -> Self {
        Self(Arc::new(Mutex::new(
            OffsetDateTime::from_unix_timestamp(unix).expect("in range"),
        )))
    }

    pub fn advance(&self, seconds: i64) {
        let mut now = self.0.lock().expect("clock");
        *now = now.saturating_add(time::Duration::seconds(seconds));
    }

    pub fn now_unix(&self) -> i64 {
        self.0.lock().expect("clock").unix_timestamp()
    }
}

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().expect("clock")
    }
}

// ---------------------------------------------------------------------------
// A Push whose answers are scripted

/// The one thing `FakePush` cannot express: a provider that names a
/// `Retry-After`. Answers from a queue, then `Delivered`, and records
/// **every** call — including the failures, which `FakePush` does not.
#[derive(Clone, Default)]
pub struct ScriptedPush {
    inner: Arc<ScriptedInner>,
}

#[derive(Default)]
struct ScriptedInner {
    queue: Mutex<Vec<Result<PushOutcome, PushError>>>,
    calls: Mutex<Vec<(Recipient, Notification)>>,
}

impl ScriptedPush {
    pub fn new(results: Vec<Result<PushOutcome, PushError>>) -> Self {
        let mut queue = results;
        queue.reverse();
        Self {
            inner: Arc::new(ScriptedInner {
                queue: Mutex::new(queue),
                calls: Mutex::new(Vec::new()),
            }),
        }
    }

    pub fn calls(&self) -> Vec<(Recipient, Notification)> {
        self.inner.calls.lock().expect("script").clone()
    }
}

#[async_trait]
impl Push for ScriptedPush {
    async fn send(
        &self,
        to: &Recipient,
        notification: &Notification,
    ) -> Result<PushOutcome, PushError> {
        self.inner
            .calls
            .lock()
            .expect("script")
            .push((to.clone(), notification.clone()));
        self.inner
            .queue
            .lock()
            .expect("script")
            .pop()
            .unwrap_or(Ok(PushOutcome::Delivered { id: None }))
    }
}

// ---------------------------------------------------------------------------
// A database that lets another request win a race

/// The kit's database with one interleaving hook: the first statement
/// whose SQL contains `when` has `run` committed **immediately before**
/// it, on the same database.
///
/// That is what a concurrent request looks like from inside a handler
/// that read the table a moment ago — the read is stale by the time the
/// write lands. Two `PUT`s arriving together is ordinary traffic (an app
/// registers on every launch; a client retries), so the interleaving has
/// to be reproducible rather than hoped for.
#[derive(Clone)]
pub struct RacingDb {
    inner: Arc<dyn cratefield_core::Database>,
    interloper: Arc<Mutex<Option<(String, Statement)>>>,
}

impl RacingDb {
    pub fn new(inner: Arc<dyn cratefield_core::Database>) -> Self {
        Self {
            inner,
            interloper: Arc::new(Mutex::new(None)),
        }
    }

    /// Arms the hook: `run` commits just before the first statement whose
    /// SQL contains `when`. One shot.
    pub fn interleave(&self, when: &str, run: Statement) {
        *self.interloper.lock().expect("interloper") = Some((when.to_owned(), run));
    }

    /// Whether the armed statement has fired.
    pub fn fired(&self) -> bool {
        self.interloper.lock().expect("interloper").is_none()
    }

    async fn maybe_race(&self, sql: &str) {
        let armed = {
            let mut slot = self.interloper.lock().expect("interloper");
            match slot.as_ref() {
                Some((when, _)) if sql.contains(when.as_str()) => slot.take().map(|(_, run)| run),
                _ => None,
            }
        };
        if let Some(statement) = armed {
            self.inner
                .execute(&statement)
                .await
                .expect("the concurrent write commits");
        }
    }
}

#[async_trait]
impl cratefield_core::Database for RacingDb {
    async fn execute(&self, stmt: &Statement) -> Result<u64, cratefield_core::DbError> {
        self.maybe_race(&stmt.sql).await;
        self.inner.execute(stmt).await
    }

    async fn query(
        &self,
        stmt: &Statement,
    ) -> Result<cratefield_core::Rows, cratefield_core::DbError> {
        self.inner.query(stmt).await
    }

    async fn batch_atomic(&self, stmts: &[Statement]) -> Result<(), cratefield_core::DbError> {
        for stmt in stmts {
            self.maybe_race(&stmt.sql).await;
        }
        self.inner.batch_atomic(stmts).await
    }
}

// ---------------------------------------------------------------------------
// A Push that reports how many sends were in flight at once

/// Records the high-water mark of concurrent `send` calls.
///
/// Every send suspends once before answering, which is what a real
/// provider round-trip does and what a synchronous fake cannot: a drain
/// that awaits its rows one after another never has two in flight, and
/// nothing else about the report would tell the two apart.
#[derive(Clone, Default)]
pub struct ConcurrentPush {
    inner: Arc<ConcurrentInner>,
}

#[derive(Default)]
struct ConcurrentInner {
    in_flight: AtomicUsize,
    peak: AtomicUsize,
    calls: AtomicUsize,
}

impl ConcurrentPush {
    /// The most sends that were ever in flight at the same moment.
    pub fn peak_in_flight(&self) -> usize {
        self.inner.peak.load(Ordering::SeqCst)
    }

    pub fn calls(&self) -> usize {
        self.inner.calls.load(Ordering::SeqCst)
    }
}

/// A future that is not ready the first time it is polled — one
/// suspension point, so a caller that awaits sequentially can be told
/// apart from one that does not.
struct YieldOnce(bool);

impl std::future::Future for YieldOnce {
    type Output = ();

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        if self.0 {
            std::task::Poll::Ready(())
        } else {
            self.0 = true;
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    }
}

#[async_trait]
impl Push for ConcurrentPush {
    async fn send(
        &self,
        _to: &Recipient,
        _notification: &Notification,
    ) -> Result<PushOutcome, PushError> {
        let now = self.inner.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.inner.peak.fetch_max(now, Ordering::SeqCst);
        YieldOnce(false).await;
        self.inner.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.in_flight.fetch_sub(1, Ordering::SeqCst);
        Ok(PushOutcome::Delivered { id: None })
    }
}

// ---------------------------------------------------------------------------
// The kit

pub struct Kit {
    pub harness: TestHarness,
    pub notifier: Notifier,
    pub events: Arc<EventLog>,
    pub clock: TestClock,
    /// The `Push` reached only through [`Kit::scheduled_context`], never
    /// through the router. A send that lands here came from the context
    /// the scheduled entry point was handed.
    pub scheduled_push: FakePush,
    /// How many times the verifier fetched the issuer's key set.
    pub jwks_fetches: Arc<AtomicUsize>,
    config: Arc<dyn Config>,
}

/// The categories the tests use: one on by default, one off, and one that
/// opted into badge counts.
pub fn categories() -> Vec<Category> {
    vec![
        Category::new(BOOKING),
        Category::new(COACH_NOTES).default_enabled(false),
        Category::new(ROOM_STARTING).badge(true),
    ]
}

/// The kit the route tests use: everything delivers.
pub fn kit() -> Kit {
    kit_with(
        Arc::new(cratefield_testing::FakePush::new(
            cratefield_testing::PushMode::DeliverOk,
        )),
        categories(),
        &[],
    )
}

/// A kit over the caller's `Push`, with `categories` declared and `config`
/// merged over the module's keys.
pub fn kit_with(push: Arc<dyn Push>, categories: Vec<Category>, config: &[(&str, &str)]) -> Kit {
    build_kit(
        push,
        categories,
        config,
        Wiring::default(),
        |module| module,
        |db| db,
    )
}

/// [`kit_with`], with one more turn of the builder — a catalog, a default
/// locale, the message ids a venture promises (issue #190).
pub fn kit_customised(
    push: Arc<dyn Push>,
    categories: Vec<Category>,
    config: &[(&str, &str)],
    customise: impl FnOnce(Notifications) -> Notifications,
) -> Kit {
    build_kit(
        push,
        categories,
        config,
        Wiring::default(),
        customise,
        |db| db,
    )
}

/// [`kit_with`] with **no `Signer` port**, the way a venture that never
/// set `HARNESS_SECRET` is wired.
///
/// `Signer` is optional on this module, so this is a real deployment
/// shape rather than a hypothetical one — and the arm no test covered
/// (issue #234).
pub fn kit_without_signer(
    push: Arc<dyn Push>,
    categories: Vec<Category>,
    config: &[(&str, &str)],
) -> Kit {
    build_kit(
        push,
        categories,
        config,
        Wiring {
            no_signer: true,
            ..Wiring::default()
        },
        |module| module,
        |db| db,
    )
}

/// The config key [`kit_serving_vapid`]'s probe reads.
///
/// The probe reads it rather than closing over the key, so a test proves
/// the module hands its venture's own config to the probe — the whole
/// point of the seam (issue #183). A probe that ignored what it was
/// given would still answer, and nothing else would notice.
pub const VAPID_KEY_CONFIG: &str = "TEST_APPLICATION_SERVER_KEY";

/// A kit whose `Notifications` serves `key` at
/// `GET /vapid-public-key`, through a probe reading it from config.
pub fn kit_serving_vapid(key: &str) -> Kit {
    build_kit(
        Arc::new(cratefield_testing::FakePush::new(
            cratefield_testing::PushMode::DeliverOk,
        )),
        categories(),
        &[(VAPID_KEY_CONFIG, key)],
        Wiring {
            vapid_key_probe: true,
            ..Wiring::default()
        },
        |module| module,
        |db| db,
    )
}

/// [`kit_with`], plus the database the router runs against — wrapped by
/// `wrap`, so a test can interleave a concurrent write into a handler.
pub fn kit_racing(
    push: Arc<dyn Push>,
    categories: Vec<Category>,
    config: &[(&str, &str)],
) -> (Kit, RacingDb) {
    let racing: Arc<Mutex<Option<RacingDb>>> = Arc::new(Mutex::new(None));
    let captured = Arc::clone(&racing);
    let kit = build_kit(
        push,
        categories,
        config,
        Wiring::default(),
        |module| module,
        move |db| {
            let wrapper = RacingDb::new(db);
            *captured.lock().expect("racing db") = Some(wrapper.clone());
            Arc::new(wrapper)
        },
    );
    let wrapper = racing.lock().expect("racing db").clone().expect("wrapped");
    (kit, wrapper)
}

/// The wirings a kit can ask for that the default does not have.
#[derive(Default, Clone, Copy)]
struct Wiring {
    /// Serve `GET /vapid-public-key` through the venture's own probe.
    vapid_key_probe: bool,
    /// Leave `Ports::signer` unset.
    no_signer: bool,
}

fn build_kit(
    push: Arc<dyn Push>,
    categories: Vec<Category>,
    config: &[(&str, &str)],
    wiring: Wiring,
    customise: impl FnOnce(Notifications) -> Notifications,
    wrap_db: impl FnOnce(Arc<dyn cratefield_core::Database>) -> Arc<dyn cratefield_core::Database>,
) -> Kit {
    let jwks = StaticJwks::new();
    let jwks_fetches = jwks.fetches();

    let mut module = Notifications::new();
    // Taken **before** a single category is declared, on purpose. That is
    // the composition order that used to fork the settings — `.category(..)`
    // mutates an `Arc<Vec<_>>` through `make_mut`, so a handle cloned from
    // it kept the vector as it was — and it is legal Rust that no test
    // covered. Every kit test now sends through a handle taken first.
    let notifier = module.notifier();
    for category in categories {
        module = module.category(category);
    }
    if wiring.vapid_key_probe {
        module = module.vapid_public_key(|cfg| cfg.get(VAPID_KEY_CONFIG));
    }
    // After the categories, so a test can reach the finished set — and
    // after the handle above was taken, which is the composition order
    // that used to fork the settings.
    let module = customise(module);
    let events = Arc::new(EventLog::default());
    let clock = TestClock::at(NOW);
    let scheduled_push = FakePush::new(PushMode::DeliverOk);

    let mut pairs: Vec<(String, String)> = vec![
        ("HARNESS_SECRET".to_owned(), TEST_SECRET.to_owned()),
        ("NOTIFICATIONS_AUTH_ISSUER".to_owned(), ISSUER.to_owned()),
        ("NOTIFICATIONS_AUTH_CLIENT_ID".to_owned(), CLIENT.to_owned()),
    ];
    for (key, value) in config {
        pairs.push(((*key).to_owned(), (*value).to_owned()));
    }
    let map: Arc<dyn Config> = Arc::new(MapConfig::from_pairs(pairs));

    let probe = EventProbe {
        log: Arc::clone(&events),
    };
    let ports_config = Arc::clone(&map);
    let ports_clock = clock.clone();
    let harness = TestHarness::with_ports(vec![Box::new(module), Box::new(probe)], move |ports| {
        ports.push = Some(push);
        ports.http = Some(Arc::new(jwks));
        ports.clock = Some(Arc::new(ports_clock));
        ports.config = ports_config;
        if wiring.no_signer {
            ports.signer = None;
        }
        if let Some(db) = ports.db.take() {
            ports.db = Some(wrap_db(db));
        }
    });

    Kit {
        harness,
        notifier,
        events,
        clock,
        scheduled_push,
        jwks_fetches,
        config: map,
    }
}

const TEST_SECRET: &str = "cratefield-testing-dummy-secret-0123456789";

impl Kit {
    /// A scope whose defer is the kit's, so deferred work is observable.
    pub fn scope(&self) -> Scope {
        let defer: Arc<dyn Defer> = Arc::new(self.harness.defer.clone());
        Scope {
            request_id: "test-request-0123".to_owned(),
            defer,
            span: tracing::Span::none(),
        }
    }

    /// The context the venture's scheduled entry point hands the module —
    /// a **whole** context, the way `serve_scheduled` builds one, with
    /// this deployment's database and its own `Push` handle.
    ///
    /// It used to carry neither, and documented that only its `Defer` was
    /// read because the module drained through the context parked at
    /// router-build time. That made the recovery test pass over a path
    /// that cannot exist in production: Cloudflare's scheduled invocation
    /// builds no router, so on a cold isolate there is nothing parked and
    /// the whole recovery half of the outbox contract never ran. A
    /// fixture that hands in less than the runtime does cannot notice.
    ///
    /// [`Kit::scheduled_push`] is deliberately a **different** `Push` from
    /// the one the router holds, so a test can tell which context a drain
    /// actually used.
    pub fn scheduled_context(&self) -> ModuleContext {
        self.context_over(Arc::new(self.scheduled_push.clone()), None)
    }

    /// A `ModuleContext` over this kit's database and clock, with the
    /// `Push` and `HttpClient` the caller names — one request's worth of
    /// ports, the way a runtime assembles them per invocation.
    pub fn context_over(
        &self,
        push: Arc<dyn Push>,
        http: Option<Arc<dyn HttpClient>>,
    ) -> ModuleContext {
        let mut ports = Ports::with_config(Arc::clone(&self.config));
        ports.db = Some(Arc::clone(&self.harness.db));
        ports.push = Some(push);
        ports.http = http;
        ports.clock = Some(Arc::new(self.clock.clone()));
        ports.defer = Some(Arc::new(self.harness.defer.clone()));
        ports.id_gen = Some(Arc::new(UlidIdGen));
        ModuleContext {
            ports,
            config: Arc::clone(&self.config),
            // The kit's own bus, so work done through this context is as
            // observable as work done through a request's.
            events: self.harness.harness.events().clone(),
            templates: Arc::new(TemplateRegistry::default()),
            venture: Arc::new(Venture::new("test-venture", "test.example")),
            unprotected_writes_accepted: false,
            ui_mounted: false,
            personal_data: Arc::new(PersonalDataCatalog::default()),
        }
    }

    /// The mounted module, for the entry points a venture calls on it.
    pub fn module(&self) -> Arc<dyn Module> {
        Arc::clone(
            self.harness
                .modules
                .iter()
                .find(|module| module.name() == "notifications")
                .expect("the notifications module is mounted"),
        )
    }

    pub fn db(&self) -> Arc<dyn cratefield_core::Database> {
        Arc::clone(&self.harness.db)
    }

    /// Rows in one of the module's tables.
    pub async fn count(&self, table: &str) -> i64 {
        let rows = self
            .harness
            .db
            .query(&Statement::new(format!(
                "SELECT COUNT(*) AS n FROM {table}"
            )))
            .await
            .expect("count");
        rows.first()
            .and_then(|row| row.get::<i64>("n"))
            .unwrap_or(-1)
    }

    /// Every row of a table, for assertions.
    pub async fn rows(&self, table: &str) -> Vec<cratefield_core::Row> {
        self.harness
            .db
            .query(&Statement::new(format!("SELECT * FROM {table}")))
            .await
            .expect("select")
            .rows
    }
}

// ---------------------------------------------------------------------------
// Requests

pub struct Answer {
    pub status: http::StatusCode,
    pub body: Bytes,
}

impl Answer {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|err| panic!("body is not JSON ({err}): {:?}", self.text()))
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// A request with a bearer token.
pub async fn send(
    router: &axum::Router,
    method: http::Method,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> Answer {
    use tower::ServiceExt as _;

    let mut builder = http::Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header(http::header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let payload = match body {
        Some(value) => {
            builder = builder.header(http::header::CONTENT_TYPE, "application/json");
            axum::body::Body::from(value.to_string())
        }
        None => axum::body::Body::empty(),
    };
    let response = router
        .clone()
        .oneshot(builder.body(payload).expect("request builds"))
        .await
        .expect("router answers");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body reads");
    Answer { status, body }
}

/// A request straight at a module's own router, without the harness
/// around it: paths are the module's (`/subscriptions`, not
/// `/v1/notifications/subscriptions`), and the `Scope` the request-id
/// layer would have inserted is supplied here instead.
pub async fn send_unmounted(
    router: &axum::Router,
    method: http::Method,
    path: &str,
    token: Option<&str>,
) -> Answer {
    use tower::ServiceExt as _;

    let mut builder = http::Request::builder()
        .method(method)
        .uri(path)
        .extension(Scope {
            request_id: "test-request-direct".to_owned(),
            defer: Arc::new(cratefield_core::NoopDefer),
            span: tracing::Span::none(),
        });
    if let Some(token) = token {
        builder = builder.header(http::header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = router
        .clone()
        .oneshot(
            builder
                .body(axum::body::Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router answers");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body reads");
    Answer { status, body }
}

/// A request with arbitrary headers and an exact body, for a caller that
/// signs bytes rather than presenting a token.
///
/// The body goes on the wire exactly as given: a webhook signature covers
/// the bytes the provider sent, so a helper that re-serialised a `Value`
/// would sign one string and send another.
pub async fn send_raw(
    router: &axum::Router,
    method: http::Method,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Answer {
    use tower::ServiceExt as _;

    let mut builder = http::Request::builder()
        .method(method)
        .uri(path)
        .header(http::header::CONTENT_TYPE, "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = router
        .clone()
        .oneshot(
            builder
                .body(axum::body::Body::from(body.to_owned()))
                .expect("request builds"),
        )
        .await
        .expect("router answers");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body reads");
    Answer { status, body }
}

/// [`send`] with extra request headers — `Accept-Language`, for the
/// registration that has nothing else to go on (issue #190).
pub async fn send_with_headers(
    router: &axum::Router,
    method: http::Method,
    path: &str,
    token: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> Answer {
    use tower::ServiceExt as _;

    let mut builder = http::Request::builder()
        .method(method)
        .uri(path)
        .header(http::header::AUTHORIZATION, format!("Bearer {token}"));
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let payload = match body {
        Some(value) => {
            builder = builder.header(http::header::CONTENT_TYPE, "application/json");
            axum::body::Body::from(value.to_string())
        }
        None => axum::body::Body::empty(),
    };
    let response = router
        .clone()
        .oneshot(builder.body(payload).expect("request builds"))
        .await
        .expect("router answers");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body reads");
    Answer { status, body }
}

/// The `PUT /subscriptions` body for one recipient.
pub fn register_body(transport: Transport, recipient: &cratefield_core::Recipient) -> Value {
    json!({
        "transport": transport,
        "recipient": recipient,
    })
}
