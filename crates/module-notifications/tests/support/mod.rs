//! Shared fixtures for the module's tests: a real ES256 access token, the
//! JWKS the verifier fetches to check it, a kit with the `Push` port wired
//! to a [`FakePush`], and a probe module that records the events this one
//! emits.
//!
//! The tokens are minted the way the auth service does, and verified by
//! `factory0-auth-client` itself — no bypass, no test-only extractor. A
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

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64ct::{Base64UrlUnpadded, Encoding};
use bytes::Bytes;
use cratefield_core::{
    AnyError, BoxFuture, Clock, Config, ConfigError, Defer, EventBus, EventHandler, EventName,
    HttpClient, HttpError, MapConfig, Migrations, Module, ModuleContext, Notification,
    PersonalDataCatalog, Port, Ports, Push, PushError, PushOutcome, Recipient, Scope, Statement,
    TemplateRegistry, UlidIdGen, Venture,
};
use cratefield_module_notifications::{Category, Notifications, Notifier, Transport};
use cratefield_testing::TestHarness;
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

/// An `HttpClient` that answers every request with the issuer's key set.
///
/// Deliberately not `FakeHttpClient`, whose scripted responses run out:
/// the verifier refetches on an unknown `kid`, and a test that failed
/// because the script was exhausted would look like a verification bug.
struct StaticJwks {
    body: String,
}

#[async_trait]
impl HttpClient for StaticJwks {
    async fn send(
        &self,
        _request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
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
        let log = Arc::clone(&self.log);
        let event = cratefield_module_notifications::EVENT_SUBSCRIPTION_PRUNED;
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
        vec![(event.to_owned(), handler)]
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
// The kit

pub struct Kit {
    pub harness: TestHarness,
    pub notifier: Notifier,
    pub events: Arc<EventLog>,
    pub clock: TestClock,
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
    let (_, jwk) = signing_key();
    let jwks = StaticJwks {
        body: json!({ "keys": [jwk] }).to_string(),
    };

    let mut module = Notifications::new();
    for category in categories {
        module = module.category(category);
    }
    let notifier = module.notifier();
    let events = Arc::new(EventLog::default());
    let clock = TestClock::at(NOW);

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
    });

    Kit {
        harness,
        notifier,
        events,
        clock,
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

    /// The context the venture's scheduled entry point would hand the
    /// module. Only its `Defer` is read: the module drains through the
    /// context it parked when its router was built.
    pub fn scheduled_context(&self) -> ModuleContext {
        let mut ports = Ports::with_config(Arc::clone(&self.config));
        ports.defer = Some(Arc::new(self.harness.defer.clone()));
        ports.id_gen = Some(Arc::new(UlidIdGen));
        ModuleContext {
            ports,
            config: Arc::clone(&self.config),
            events: EventBus::new(),
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

/// The `PUT /subscriptions` body for one recipient.
pub fn register_body(transport: Transport, recipient: &cratefield_core::Recipient) -> Value {
    json!({
        "transport": transport,
        "recipient": recipient,
    })
}
