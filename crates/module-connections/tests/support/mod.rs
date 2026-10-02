//! Doubles and helpers for the connections suite: a scripted token endpoint,
//! a clock a test can move, and somewhere emitted events land. All three are
//! `Arc` newtypes, so the module and the test share one.

// Included with `mod support;` into every test binary here, so `pub` is how a
// helper reads; the recording fixtures carry the same `disallowed_types`
// allowance as the fakes in `cratefield-testing` (ADR 0007).
#![allow(unreachable_pub)]
#![allow(dead_code)]
#![allow(clippy::disallowed_types)]

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, Request, Response, StatusCode};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

use cratefield_core::{
    AnyError, BoxFuture, Clock, Config, ConfigError, EventHandler, EventName, HttpClient,
    HttpError, MapConfig, Migrations, Module, ModuleContext, Port, Ports,
};
use cratefield_module_connections::{AuthorizeUrl, Connections, ConnectionsApi, Provider, presets};
use cratefield_testing::TestHarness;

/// A valid 32-byte sealing key, base64. Obvious test material.
pub const TOKEN_KEY: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
pub const CLIENT_ID: &str = "test-client-id";
pub const CLIENT_SECRET: &str = "test-client-secret";
pub const OTHER_SECRET: &str = "other-secret";

/// An origin the venture vouches for, and a `return_to` on it.
pub const ALLOWED_ORIGIN: &str = "https://app.example.com";
pub const RETURN_TO: &str = "https://app.example.com/settings";

/// The admin bearer the privacy suite authenticates its erasure calls with.
pub const ADMIN: &str = "test-admin-token-0123456789abcdef";

/// The instant the test clock starts from — the harness's own fixed epoch.
const BASE_EPOCH: i64 = 1_800_000_000;

/// A first connect: an hour of access, a refresh token.
pub const CONNECTED_BODY: &str = r#"{"token_type":"Bearer","access_token":"AT-connected-1",
    "refresh_token":"RT-connected-1","expires_in":3600,"scope":"read write"}"#;

/// A refresh: new access, rotated refresh.
pub const REFRESHED_BODY: &str = r#"{"token_type":"Bearer","access_token":"AT-refreshed-2",
    "refresh_token":"RT-refreshed-2","expires_in":3600,"scope":"read write"}"#;

/// A refresh that did not rotate: new access, refresh unchanged.
pub const REFRESHED_NO_ROTATION: &str = r#"{"token_type":"Bearer","access_token":"AT-refreshed-2",
    "expires_in":3600,"scope":"read write"}"#;

/// A refresh whose response states no lifetime at all.
pub const REFRESHED_NO_EXPIRY: &str = r#"{"token_type":"Bearer","access_token":"AT-refreshed-2",
    "refresh_token":"RT-refreshed-2"}"#;

/// RFC 6749 §5.2's one code that means "a human must authorize again".
pub const INVALID_GRANT: &str = r#"{"error":"invalid_grant",
    "error_description":"the refresh token is no longer valid"}"#;

// ---------------------------------------------------------------------------
// The clock

/// A clock a test can move: expiry and the refresh lead only mean something
/// if time can pass.
#[derive(Clone)]
pub struct TestClock(Arc<AtomicI64>);

impl TestClock {
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(AtomicI64::new(BASE_EPOCH)))
    }

    pub fn advance_secs(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }

    /// Back to the start, so the next dialect of a `for kit` loop begins
    /// where this one did.
    pub fn reset(&self) {
        self.0.store(BASE_EPOCH, Ordering::SeqCst);
    }

    #[must_use]
    pub fn read(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::SeqCst)).expect("in range")
    }
}

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        self.read()
    }
}

// ---------------------------------------------------------------------------
// The provider's token endpoint

/// One request the module sent to the provider, verbatim.
#[derive(Debug, Clone)]
pub struct Call {
    pub uri: String,
    pub body: String,
    pub authorization: Option<String>,
    pub content_type: Option<String>,
}

impl Call {
    /// The form fields, parsed the way the provider would.
    #[must_use]
    pub fn fields(&self) -> Vec<(String, String)> {
        serde_urlencoded::from_str(&self.body).unwrap_or_default()
    }

    #[must_use]
    pub fn field(&self, name: &str) -> Option<String> {
        self.fields()
            .into_iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
    }
}

struct HttpState {
    calls: Vec<Call>,
    status: u16,
    body: String,
    transport: Option<String>,
    barrier: Option<Gate>,
}

/// A one-shot rendezvous for the two concurrent-refresh tests.
///
/// `futures::join` runs one future to completion before touching the next, and
/// every step here completes in a single poll, so two calls never race on
/// their own. A gate is the one await point that returns `Pending`, so both
/// refreshes park at the provider until each has read the same stored row —
/// the interleaving the guarded update exists for.
#[derive(Clone)]
pub struct Gate(Arc<Mutex<GateState>>);

struct GateState {
    expected: usize,
    arrived: usize,
    waiting: Vec<std::task::Waker>,
}

impl Gate {
    fn new(expected: usize) -> Self {
        Self(Arc::new(Mutex::new(GateState {
            expected,
            arrived: 0,
            waiting: Vec::new(),
        })))
    }

    /// A future that completes once `expected` passes have arrived.
    fn pass(&self) -> Pass {
        Pass {
            gate: Arc::clone(&self.0),
        }
    }
}

struct Pass {
    gate: Arc<Mutex<GateState>>,
}

impl std::future::Future for Pass {
    type Output = ();

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        use std::task::Poll;
        let mut state = self.gate.lock().expect("gate lock");
        if state.arrived >= state.expected {
            // Released: this is a woken waiter being re-polled.
            return Poll::Ready(());
        }
        state.arrived += 1;
        if state.arrived >= state.expected {
            // The last arrival releases everyone, itself included.
            for waker in state.waiting.drain(..) {
                waker.wake();
            }
            Poll::Ready(())
        } else {
            state.waiting.push(cx.waker().clone());
            Poll::Pending
        }
    }
}

/// A scripted [`HttpClient`]: it answers every token call with whatever body
/// the test set, and records every request so a test can assert the shape the
/// provider would have seen.
#[derive(Clone)]
pub struct FakeHttp(Arc<Mutex<HttpState>>);

impl FakeHttp {
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(HttpState {
            calls: Vec::new(),
            status: 200,
            body: CONNECTED_BODY.to_owned(),
            transport: None,
            barrier: None,
        })))
    }

    /// Arms a rendezvous: the next `expected` requests all wait until the last
    /// arrives, then proceed together. Used by the concurrent-refresh tests.
    pub fn rendezvous(&self, expected: usize) {
        self.0.lock().expect("http lock").barrier = Some(Gate::new(expected));
    }

    /// The body (and status) the token endpoint answers with from now on.
    pub fn set_response(&self, status: u16, body: &str) {
        let mut state = self.0.lock().expect("http lock");
        state.status = status;
        body.clone_into(&mut state.body);
        state.transport = None;
    }

    /// The token endpoint fails at the transport, the way a timeout does.
    pub fn fail_transport(&self, message: &str) {
        let mut state = self.0.lock().expect("http lock");
        state.transport = Some(message.to_owned());
    }

    /// Forgets every recorded call. The double is shared by every dialect's
    /// kit, so a loop resets before each one.
    pub fn reset(&self) {
        let mut state = self.0.lock().expect("http lock");
        state.calls.clear();
        state.status = 200;
        CONNECTED_BODY.clone_into(&mut state.body);
        state.transport = None;
        state.barrier = None;
    }

    #[must_use]
    pub fn calls(&self) -> Vec<Call> {
        self.0.lock().expect("http lock").calls.clone()
    }

    /// The calls that went to a token endpoint.
    #[must_use]
    pub fn token_calls(&self) -> Vec<Call> {
        self.calls()
            .into_iter()
            .filter(|call| call.uri.contains("token") || call.uri.contains("accessToken"))
            .collect()
    }

    /// The calls that went to a revocation endpoint.
    #[must_use]
    pub fn revoke_calls(&self) -> Vec<Call> {
        self.calls()
            .into_iter()
            .filter(|call| call.uri.contains("revoke"))
            .collect()
    }

    #[must_use]
    pub fn last_token_call(&self) -> Option<Call> {
        self.token_calls().pop()
    }
}

#[async_trait]
impl HttpClient for FakeHttp {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let (parts, body) = request.into_parts();
        let (barrier, transport) = {
            let mut state = self.0.lock().expect("http lock");
            state.calls.push(Call {
                uri: parts.uri.to_string(),
                body: String::from_utf8_lossy(&body).to_string(),
                authorization: parts
                    .headers
                    .get(http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned),
                content_type: parts
                    .headers
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned),
            });
            (state.barrier.clone(), state.transport.clone())
        };
        // Parked here (never while holding the lock), the first refresh waits
        // for the second so both write against the same stored row.
        if let Some(barrier) = barrier {
            barrier.pass().await;
        }
        if let Some(message) = transport {
            // The fake's own flag, not the provider's words: an error body
            // must never be able to name a token.
            return Err(HttpError::Transport(message));
        }
        let (status, body) = {
            let state = self.0.lock().expect("http lock");
            (state.status, state.body.clone())
        };
        let response = Response::builder()
            .status(StatusCode::from_u16(status).expect("valid status"))
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Bytes::from(body))
            .map_err(|err| HttpError::Transport(err.to_string()))?;
        Ok(response)
    }
}

// ---------------------------------------------------------------------------
// Events

/// Every event the module emitted, in order.
#[derive(Clone, Default)]
pub struct EventLog(Arc<Mutex<Vec<(String, Value)>>>);

impl EventLog {
    pub fn reset(&self) {
        self.0.lock().expect("event log").clear();
    }

    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.0
            .lock()
            .expect("event log")
            .iter()
            .map(|(name, _)| name.clone())
            .collect()
    }

    #[must_use]
    pub fn count(&self, name: &str) -> usize {
        self.names()
            .iter()
            .filter(|emitted| *emitted == name)
            .count()
    }

    #[must_use]
    pub fn has(&self, name: &str) -> bool {
        self.count(name) > 0
    }
}

/// A module that subscribes to all four of this module's events.
pub struct EventProbe {
    pub log: EventLog,
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
            "connections.connected",
            "connections.refreshed",
            "connections.revoked",
            "connections.needs_reconnect",
        ]
        .into_iter()
        .map(|event| {
            let log = self.log.clone();
            let handler: EventHandler = Arc::new(move |_scope, payload| {
                let log = log.clone();
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
// The fixture

/// What to build the module with. One instance per test, one module per
/// dialect.
#[derive(Clone)]
pub struct Spec {
    pub providers: Vec<Provider>,
    pub allowed_origins: Vec<String>,
    pub refresh_lead_secs: i64,
}

impl Default for Spec {
    fn default() -> Self {
        Self {
            providers: vec![presets::x()],
            allowed_origins: vec![ALLOWED_ORIGIN.to_owned()],
            refresh_lead_secs: 60,
        }
    }
}

impl Spec {
    /// A spec mounting exactly one provider, on the one allowed origin — so
    /// the request shape a provider sees is unambiguous.
    #[must_use]
    pub fn only(provider: Provider) -> Self {
        Self {
            providers: vec![provider],
            allowed_origins: vec![ALLOWED_ORIGIN.to_owned()],
            refresh_lead_secs: 60,
        }
    }
}

/// A built kit plus the doubles a test reads after the fact.
pub struct Fixture {
    pub kits: Vec<Kit>,
    pub clock: TestClock,
    pub http: FakeHttp,
    pub events: EventLog,
}

/// One dialect's harness with its shared doubles.
pub struct Kit {
    pub harness: TestHarness,
    pub api: ConnectionsApi,
    pub clock: TestClock,
    pub http: FakeHttp,
    pub events: EventLog,
    /// The config the fixture built the module with, so a scheduled pass can
    /// be run later against the same secrets.
    pub config: Arc<dyn Config>,
}

impl Kit {
    /// The database the module writes through.
    #[must_use]
    pub fn db(&self) -> Arc<dyn cratefield_core::Database> {
        Arc::clone(&self.harness.db)
    }

    /// Back to the start for the next dialect: clock at its epoch, the fake's
    /// call log and response cleared, the event log empty.
    pub fn fresh(&self) {
        self.clock.reset();
        self.http.reset();
        self.events.reset();
    }

    /// A `GET` through the harness router.
    pub async fn get(&self, path: &str) -> Res {
        send_router(self.harness.router.clone(), path).await
    }

    /// Runs the event handlers the module deferred during the calls so far.
    /// `EventBus::emit_in` hands every handler to the scope's defer rather
    /// than awaiting it inline, so an assertion on an event drains first.
    pub async fn drain(&self) {
        self.harness.defer.drain().await;
    }

    /// Runs the module's scheduled pass the way the runtime's cron does — a
    /// full `ModuleContext` over the shared doubles, so the pass purges and
    /// refreshes exactly what the test set up. Panics if the pass itself
    /// fails; an individual refresh failing is the module's business.
    pub async fn run_scheduled(&self) {
        let mut ports = Ports::with_config(Arc::clone(&self.config));
        ports.db = Some(self.db());
        ports.http = Some(Arc::new(self.http.clone()));
        ports.clock = Some(Arc::new(self.clock.clone()));
        ports.id_gen = Some(Arc::new(cratefield_core::UlidIdGen));
        ports.defer = Some(Arc::new(self.harness.defer.clone()));
        let module = self.harness.modules[0].clone();
        let ctx = self.harness.harness.module_context(module.as_ref(), &ports);
        module
            .scheduled(&ctx, "0 3 * * *")
            .await
            .expect("the scheduled pass runs");
    }

    /// One text column of one connection row, read straight from storage.
    pub async fn connection_column(&self, id: &str, column: &str) -> Option<String> {
        self.harness
            .db
            .query(&cratefield_core::Statement::with_values(
                format!("SELECT {column} FROM connection WHERE id = ?"),
                vec![id.into()],
            ))
            .await
            .expect("reads the connection row")
            .first()
            .and_then(|row| row.get::<String>(column))
    }

    /// How many rows a table holds, read directly rather than through the
    /// module, so a test can prove the module wrote exactly one.
    pub async fn rows(&self, table: &str) -> usize {
        self.harness
            .db
            .query(&cratefield_core::Statement::new(format!(
                "SELECT * FROM {table}"
            )))
            .await
            .expect("counts the rows")
            .len()
    }
}

/// Builds one kit per available dialect, each with a fresh module and a
/// config carrying the sealing key and one client credential per provider.
/// Panics like the harness does when a migration or the build fails.
#[must_use]
pub fn fixture(spec: &Spec) -> Fixture {
    fixture_with(spec, Vec::new)
}

/// [`fixture`] with `extra` modules mounted alongside Connections — the
/// privacy suite composes the Privacy module this way. `extra` is a factory,
/// so every dialect gets fresh instances too.
///
/// # Panics
/// Panics like `fixture`.
#[must_use]
pub fn fixture_with(spec: &Spec, extra: impl Fn() -> Vec<Box<dyn Module>>) -> Fixture {
    let clock = TestClock::new();
    let http = FakeHttp::new();
    let events = EventLog::default();
    let apis: Arc<Mutex<Vec<ConnectionsApi>>> = Arc::new(Mutex::new(Vec::new()));

    let mut pairs = vec![("CONNECTIONS_TOKEN_KEY".to_owned(), TOKEN_KEY.to_owned())];
    // The privacy suite authenticates its erasure calls with an admin token.
    pairs.push(("ADMIN_TOKEN".to_owned(), ADMIN.to_owned()));
    for provider in &spec.providers {
        let prefix = env_key(provider.key());
        pairs.push((
            format!("CONNECTIONS_{prefix}_CLIENT_ID"),
            CLIENT_ID.to_owned(),
        ));
        pairs.push((
            format!("CONNECTIONS_{prefix}_CLIENT_SECRET"),
            CLIENT_SECRET.to_owned(),
        ));
    }
    let config: Arc<dyn Config> = Arc::new(MapConfig::from_pairs(pairs));

    let spec_for_modules = spec.clone();
    let events_for_modules = events.clone();
    let apis_for_modules = Arc::clone(&apis);
    let make = move || {
        let mut builder = Connections::builder()
            .refresh_lead(Duration::seconds(spec_for_modules.refresh_lead_secs));
        for provider in &spec_for_modules.providers {
            builder = builder.provider(provider.clone());
        }
        for origin in &spec_for_modules.allowed_origins {
            builder = builder.allowed_origin(origin);
        }
        let module = builder.build();
        apis_for_modules
            .lock()
            .expect("api list")
            .push(module.api());
        let mut modules = vec![
            Box::new(module) as Box<dyn Module>,
            Box::new(EventProbe {
                log: events_for_modules.clone(),
            }),
        ];
        modules.extend(extra());
        modules
    };

    let clock_for_ports = clock.clone();
    let http_for_ports = http.clone();
    let config_for_ports = Arc::clone(&config);
    let harnesses = TestHarness::all_dialects_with_ports(make, move |ports: &mut Ports| {
        ports.clock = Some(Arc::new(clock_for_ports.clone()));
        ports.http = Some(Arc::new(http_for_ports.clone()));
        ports.config = Arc::clone(&config_for_ports);
    });

    let apis = apis.lock().expect("api list").clone();
    let kits = harnesses
        .into_iter()
        .zip(apis)
        .map(|(harness, api)| Kit {
            harness,
            api,
            clock: clock.clone(),
            http: http.clone(),
            events: events.clone(),
            config: Arc::clone(&config),
        })
        .collect();

    Fixture {
        kits,
        clock,
        http,
        events,
    }
}

/// The standard module the guards build: two providers, one allowed origin.
#[must_use]
pub fn module() -> Connections {
    Connections::builder()
        .provider(presets::x())
        .provider(presets::gitlab())
        .allowed_origin(ALLOWED_ORIGIN)
        .build()
}

/// The `CONNECTIONS_<KEY>` prefix a provider's secrets live under.
#[must_use]
pub fn env_key(key: &str) -> String {
    key.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The flow

/// Runs `start` and returns the pairing a browser would carry: the URL the
/// person is sent to, and the `state` inside it. Panics when the module
/// refuses to start, which is the failure a caller of this helper wants
/// reported at the call site.
pub async fn begin(
    kit: &Kit,
    subject: &str,
    provider: &str,
    return_to: &str,
) -> (AuthorizeUrl, String) {
    let authorize = kit
        .api
        .start(subject, provider, return_to)
        .await
        .expect("the module starts a connection");
    let state = query_of(&authorize.url, "state").expect("the authorize URL carries a state");
    (authorize, state)
}

/// Runs the whole connect flow: start, then the callback.
pub async fn connect(
    kit: &Kit,
    subject: &str,
    provider: &str,
) -> cratefield_module_connections::Connection {
    let (_authorize, state) = begin(kit, subject, provider, RETURN_TO).await;
    kit.api
        .complete(&state, "test-authorization-code")
        .await
        .expect("the code exchanges")
}

/// One value out of a URL's query string.
#[must_use]
pub fn query_of(url: &str, name: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    let fields: std::collections::HashMap<String, String> =
        serde_urlencoded::from_str(query).ok()?;
    fields.get(name).cloned()
}

/// The URL a callback carried, percent-encoded the way a browser would send
/// it.
#[must_use]
pub fn callback_url(provider: &str, state: &str, code: &str) -> String {
    format!(
        "/v1/connections/callback/{provider}?state={}&code={}",
        encode(state),
        encode(code)
    )
}

/// Percent-encodes one value.
#[must_use]
pub fn encode(value: &str) -> String {
    #[derive(serde::Serialize)]
    struct One<'a> {
        v: &'a str,
    }
    serde_urlencoded::to_string(One { v: value })
        .expect("a pair encodes")
        .trim_start_matches("v=")
        .to_owned()
}

// ---------------------------------------------------------------------------
// Requests

/// A fully-buffered response.
pub struct Res {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Res {
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    #[must_use]
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|err| panic!("body is not JSON ({err}): {}", self.text()))
    }

    /// The `Location` header, when present.
    #[must_use]
    pub fn location(&self) -> Option<String> {
        self.headers
            .get(http::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    }

    /// The problem's `type` slug, for an error response.
    #[must_use]
    pub fn problem_slug(&self) -> String {
        self.json()["type"].as_str().map_or_else(
            || panic!("no problem type: {}", self.text()),
            |uri| uri.rsplit('/').next().unwrap_or(uri).to_owned(),
        )
    }
}

/// A `GET` through a router the caller owns. Panics when the router itself
/// fails (never for ordinary responses).
pub async fn send_router(router: axum::Router, path: &str) -> Res {
    use tower::ServiceExt;
    let request = Request::builder()
        .method(http::Method::GET)
        .uri(path)
        .body(axum::body::Body::empty())
        .expect("request builds");
    let response = router.oneshot(request).await.expect("router answers");
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, 1024 * 1024)
        .await
        .expect("body reads");
    Res {
        status: parts.status,
        headers: parts.headers,
        body: bytes.to_vec(),
    }
}
