//! Events crossing the sidecar boundary (issue #62, ADR 0017).
//!
//! The host forwards every emission to `POST /__events` on each mounted
//! sidecar, inside the emitting request's `wait_until`. The sidecar answers
//! `202` and runs its own handlers in its *own* `wait_until`. At-most-once,
//! no retry, no ordering, failures logged and never surfaced to the caller.
//!
//! Two of these tests exist because the issue's own acceptance criterion was
//! amended as vacuous: `wait_until` never delays a response, so "the slow
//! handler did not delay the response" holds however the code is written.
//! What is actually worth asserting is that the response is produced while
//! the deferred work is still *unrun* — which a `Defer` that parks its
//! futures can see and an inline one cannot.

// Test fixtures recording what crossed the boundary are not request state
// (ADR 0007); the scoped allow follows the workspace clippy.toml policy, as
// the fakes in `cratefield-testing` do.
#![allow(clippy::disallowed_types)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use axum::http::{Method, StatusCode};
use bytes::Bytes;
use common::{body_json, request};
use cratefield_core::{
    AnyError, BoxFuture, Config, ConfigError, DispatchError, Dispatcher, EventHandler, EventName,
    GATEWAY_PURPOSE, HARNESS_SIDECARS, Harness, HmacSigner, KeyRing, Kid, MapConfig, Migrations,
    Module, ModuleContext, Payload, Port, Ports, Runtime, SIDECAR_GATEWAY_SECRET, Scope, Signer,
    X_HARNESS_GATEWAY, X_REQUEST_ID,
};
use futures_core::future::BoxFuture as CoreBoxFuture;

const GATEWAY_SECRET: &str = "a-gateway-secret-long-enough-for-the-ring";

// ------------------------------------------------------------------ fixtures

/// A defer that **parks** the futures handed to it instead of running them.
/// That is the whole point: with an inline defer every assertion about
/// "before the deferred work ran" is unfalsifiable, because there is no
/// moment at which the work is pending.
#[derive(Default)]
struct ParkingDefer(std::sync::Mutex<Vec<CoreBoxFuture<'static, ()>>>);

impl cratefield_core::Defer for ParkingDefer {
    fn wait_until(&self, fut: CoreBoxFuture<'static, ()>) {
        self.0.lock().expect("defer lock").push(fut);
    }
}

impl ParkingDefer {
    fn pending(&self) -> usize {
        self.0.lock().expect("defer lock").len()
    }

    /// Runs everything parked so far, including anything those futures park
    /// in turn.
    async fn drain(&self) {
        loop {
            let batch: Vec<CoreBoxFuture<'static, ()>> =
                self.0.lock().expect("defer lock").drain(..).collect();
            if batch.is_empty() {
                return;
            }
            for fut in batch {
                fut.await;
            }
        }
    }
}

/// Records every request dispatched over a binding and answers `/__events`
/// however the test asks.
struct EventDispatcher {
    events_status: StatusCode,
    unreachable: bool,
    bindings: Vec<String>,
    seen: std::sync::Mutex<Vec<http::Request<Bytes>>>,
}

impl EventDispatcher {
    fn answering(status: StatusCode) -> Self {
        Self {
            events_status: status,
            unreachable: false,
            bindings: vec!["ACME".to_owned()],
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn unreachable() -> Self {
        Self {
            unreachable: true,
            ..Self::answering(StatusCode::ACCEPTED)
        }
    }

    fn with_bindings(bindings: &[&str]) -> Self {
        Self {
            bindings: bindings.iter().map(|b| (*b).to_owned()).collect(),
            ..Self::answering(StatusCode::ACCEPTED)
        }
    }

    fn events_posts(&self) -> Vec<http::Request<Bytes>> {
        self.seen
            .lock()
            .expect("seen lock")
            .iter()
            .filter(|request| request.uri().path() == "/__events")
            .map(clone_request)
            .collect()
    }
}

/// `http::Request` is not `Clone`; the parts a test reads are.
fn clone_request(request: &http::Request<Bytes>) -> http::Request<Bytes> {
    let mut builder = http::Request::builder()
        .method(request.method().clone())
        .uri(request.uri().clone());
    for (name, value) in request.headers() {
        builder = builder.header(name, value);
    }
    builder
        .body(request.body().clone())
        .expect("a request rebuilds from its own parts")
}

#[async_trait]
impl Dispatcher for EventDispatcher {
    fn has(&self, binding: &str) -> bool {
        self.bindings.iter().any(|known| known == binding)
    }

    async fn dispatch(
        &self,
        binding: &str,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, DispatchError> {
        self.seen.lock().expect("seen lock").push(request);
        if self.unreachable {
            return Err(DispatchError::Unavailable {
                binding: binding.to_owned(),
                reason: "sidecar unreachable".to_owned(),
            });
        }
        http::Response::builder()
            .status(self.events_status)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Bytes::from_static(b"{}"))
            .map_err(|err| DispatchError::Unavailable {
                binding: binding.to_owned(),
                reason: err.to_string(),
            })
    }
}

/// Emits `waitlist.confirmed` from `POST /v1/waitlist/emit` and answers its
/// own normal response regardless of what the bus did with it.
struct EmitRouteModule {
    /// The event this module emits. Configurable so a test that asserts
    /// on the process-global report sink can name something only it
    /// produces.
    event: &'static str,
}

impl Default for EmitRouteModule {
    fn default() -> Self {
        Self {
            event: "waitlist.confirmed",
        }
    }
}

impl EmitRouteModule {
    fn named(event: &'static str) -> Self {
        Self { event }
    }
}

impl Module for EmitRouteModule {
    fn name(&self) -> &'static str {
        "waitlist"
    }
    fn version(&self) -> &'static str {
        "0.0.0"
    }
    fn requires(&self) -> &'static [Port] {
        &[]
    }
    fn migrations(&self) -> Migrations {
        Migrations::default()
    }
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let events = ctx.events.clone();
        let name = self.event;
        axum::Router::new().route(
            "/emit",
            axum::routing::post(move |scope: Scope| {
                let events = events.clone();
                async move {
                    events.emit_in(
                        &scope,
                        name,
                        serde_json::json!({ "email": "a@example.test" }),
                    );
                    axum::Json(serde_json::json!({ "ok": true }))
                }
            }),
        )
    }
}

/// Subscribes to `waitlist.confirmed` and records what it was handed.
struct SubscriberModule {
    runs: Arc<AtomicUsize>,
    seen: Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
}

impl SubscriberModule {
    fn new() -> (
        Self,
        Arc<AtomicUsize>,
        Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    ) {
        let runs = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        (
            Self {
                runs: Arc::clone(&runs),
                seen: Arc::clone(&seen),
            },
            runs,
            seen,
        )
    }
}

impl Module for SubscriberModule {
    fn name(&self) -> &'static str {
        "email-signup"
    }
    fn version(&self) -> &'static str {
        "0.0.0"
    }
    fn requires(&self) -> &'static [Port] {
        &[]
    }
    fn migrations(&self) -> Migrations {
        Migrations::default()
    }
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        axum::Router::new()
    }
    fn events(&self) -> Vec<(EventName, EventHandler)> {
        let runs = Arc::clone(&self.runs);
        let seen = Arc::clone(&self.seen);
        vec![(
            "waitlist.confirmed".to_owned(),
            Arc::new(
                move |_scope: &Scope,
                      value: serde_json::Value|
                      -> BoxFuture<'static, Result<(), AnyError>> {
                    let runs = Arc::clone(&runs);
                    let seen = Arc::clone(&seen);
                    Box::pin(async move {
                        seen.lock().expect("seen lock").push(value);
                        runs.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    })
                },
            ),
        )]
    }
}

struct AllPorts;

impl Runtime for AllPorts {
    fn provides(&self) -> Vec<Port> {
        Port::ALL.to_vec()
    }
}

fn harness_of(modules: Vec<Arc<dyn Module>>) -> Harness {
    let mut builder = Harness::builder()
        .venture(
            cratefield_core::Venture::new("test-venture", "test.example")
                .cors_origins(["https://test.example"]),
        )
        .runtime(AllPorts);
    for module in modules {
        builder = builder.module_arc(module);
    }
    builder.build().expect("harness builds")
}

fn ports_for(
    table: Option<&str>,
    dispatcher: Option<Arc<dyn Dispatcher>>,
    defer: Option<Arc<ParkingDefer>>,
) -> Ports {
    let mut pairs: Vec<(String, String)> =
        vec![(SIDECAR_GATEWAY_SECRET.to_owned(), GATEWAY_SECRET.to_owned())];
    if let Some(table) = table {
        pairs.push((HARNESS_SIDECARS.to_owned(), table.to_owned()));
    }
    let mut ports = Ports::with_config(Arc::new(MapConfig::from_pairs(pairs)));
    ports.dispatcher = dispatcher;
    ports.defer = defer.map(|d| d as Arc<dyn cratefield_core::Defer>);
    ports
}

/// The stamp `mint_gateway` produces for an ordinary (non-admin) forward.
fn gateway_stamp(mount: &str) -> String {
    let mut ring = KeyRing::new();
    ring.rotate_signing(Kid::Cur, GATEWAY_SECRET.as_bytes().to_vec())
        .expect("test secret is long enough");
    HmacSigner::from_ring(ring).sign(&Payload {
        purpose: GATEWAY_PURPOSE.to_owned(),
        subject: mount.to_owned(),
        exp: None,
        kid: Kid::Cur,
    })
}

fn envelope(body: &http::Request<Bytes>) -> serde_json::Value {
    serde_json::from_slice(body.body()).expect("the forward carries JSON")
}

/// Collects the reports the harness forwards to its internal-error sink.
///
/// **Process-global on purpose.** The first version of this captured
/// `tracing` through `with_default`, which is *thread-local*: it held
/// locally and failed on CI, because a report emitted on any thread but
/// the one running the closure is simply not seen. The sink
/// `set_error_forwarder` installs is global and `Mutex`-guarded, so it
/// cannot miss a line for scheduling reasons.
///
/// Being global means every test writes into one buffer, so an assertion
/// has to name something only its own test produces — hence the unique
/// event name per test below, rather than counting a shared phrase.
static REPORTS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
static INSTALL: std::sync::Once = std::sync::Once::new();

fn record(line: &str) {
    REPORTS.lock().expect("report lock").push(line.to_owned());
}

/// Installs the sink once per test binary — `set_error_forwarder` keeps
/// the first installation and ignores later ones, so this must not race.
fn reports() -> impl Fn(&str) -> usize {
    INSTALL.call_once(|| cratefield_core::set_error_forwarder(record));
    |needle: &str| {
        REPORTS
            .lock()
            .expect("report lock")
            .iter()
            .filter(|line| line.contains(needle))
            .count()
    }
}

// ------------------------------------------------------- the host's forward

#[pollster::test]
async fn an_emission_is_forwarded_to_every_mounted_sidecar() {
    let dispatcher = Arc::new(EventDispatcher::with_bindings(&["ACME", "BETA"]));
    let defer = Arc::new(ParkingDefer::default());
    let router = harness_of(vec![Arc::new(EmitRouteModule::default())]).router(ports_for(
        Some(r#"{"acme-pricing":"ACME","beta-billing":"BETA"}"#),
        Some(dispatcher.clone()),
        Some(Arc::clone(&defer)),
    ));

    let response = request(
        &router,
        Method::POST,
        "/v1/waitlist/emit",
        &[(X_REQUEST_ID, "req-abcdefgh")],
        Some(b"{}".to_vec()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    defer.drain().await;

    let posts = dispatcher.events_posts();
    assert_eq!(posts.len(), 2, "one forward per mount, at most once each");
    for post in &posts {
        assert_eq!(post.method(), Method::POST);
        let body = envelope(post);
        assert_eq!(body["event"], "waitlist.confirmed");
        assert_eq!(body["payload"]["email"], "a@example.test");
        assert_eq!(
            post.headers().get(X_REQUEST_ID).expect("stamped"),
            "req-abcdefgh",
            "one trail across both Workers"
        );
        assert!(
            post.headers().contains_key(X_HARNESS_GATEWAY),
            "the forward carries the host's stamp, as any forwarded request does"
        );
    }
}

#[pollster::test]
async fn a_mount_the_dispatcher_cannot_reach_is_skipped_not_dialled() {
    // Only ACME is bound; the table also names a mount the deployment has
    // no binding for. Forwarding to it would be a dial into nothing.
    let dispatcher = Arc::new(EventDispatcher::with_bindings(&["ACME"]));
    let defer = Arc::new(ParkingDefer::default());
    let router = harness_of(vec![Arc::new(EmitRouteModule::default())]).router(ports_for(
        Some(r#"{"acme-pricing":"ACME","ghost":"MISSING"}"#),
        Some(dispatcher.clone()),
        Some(Arc::clone(&defer)),
    ));

    let response = request(&router, Method::POST, "/v1/waitlist/emit", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    defer.drain().await;

    assert_eq!(dispatcher.events_posts().len(), 1, "only the bound mount");
}

#[pollster::test]
async fn the_response_is_produced_before_the_forward_runs() {
    // The amended criterion, made falsifiable: at the moment the caller has
    // its response, the forward is still parked and the sidecar has not been
    // dialled. An inline defer could not tell these apart.
    let dispatcher = Arc::new(EventDispatcher::answering(StatusCode::ACCEPTED));
    let defer = Arc::new(ParkingDefer::default());
    let router = harness_of(vec![Arc::new(EmitRouteModule::default())]).router(ports_for(
        Some(r#"{"acme-pricing":"ACME"}"#),
        Some(dispatcher.clone()),
        Some(Arc::clone(&defer)),
    ));

    let response = request(&router, Method::POST, "/v1/waitlist/emit", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["ok"], true);
    assert_eq!(
        dispatcher.events_posts().len(),
        0,
        "the caller was answered without waiting on the sidecar"
    );
    assert!(
        defer.pending() > 0,
        "and the forward is pending, not skipped"
    );

    defer.drain().await;
    assert_eq!(dispatcher.events_posts().len(), 1);
}

#[pollster::test]
async fn a_sidecar_that_answers_500_does_not_fail_the_originating_request() {
    let dispatcher = Arc::new(EventDispatcher::answering(
        StatusCode::INTERNAL_SERVER_ERROR,
    ));
    let defer = Arc::new(ParkingDefer::default());
    let router = harness_of(vec![Arc::new(EmitRouteModule::default())]).router(ports_for(
        Some(r#"{"acme-pricing":"ACME"}"#),
        Some(dispatcher.clone()),
        Some(Arc::clone(&defer)),
    ));

    let response = request(&router, Method::POST, "/v1/waitlist/emit", &[], None).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the emitting request keeps its own answer"
    );
    assert_eq!(body_json(response).await["ok"], true);

    // And the failure surfaces where failures go, not into the response.
    defer.drain().await;
    assert_eq!(
        dispatcher.events_posts().len(),
        1,
        "tried once, never retried"
    );
}

#[pollster::test]
async fn a_sidecar_that_cannot_be_reached_does_not_fail_the_originating_request() {
    let dispatcher = Arc::new(EventDispatcher::unreachable());
    let defer = Arc::new(ParkingDefer::default());
    let router = harness_of(vec![Arc::new(EmitRouteModule::default())]).router(ports_for(
        Some(r#"{"acme-pricing":"ACME"}"#),
        Some(dispatcher.clone()),
        Some(Arc::clone(&defer)),
    ));

    let response = request(&router, Method::POST, "/v1/waitlist/emit", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    defer.drain().await;
    assert_eq!(
        dispatcher.events_posts().len(),
        1,
        "tried once, never retried"
    );
}

// ------------------------------------------------------ the sidecar's half

#[pollster::test]
async fn an_inbound_event_is_accepted_with_202_before_its_handlers_run() {
    let (module, runs, seen) = SubscriberModule::new();
    let defer = Arc::new(ParkingDefer::default());
    // No mount table: this harness *is* the sidecar.
    let router =
        harness_of(vec![Arc::new(module)]).router(ports_for(None, None, Some(Arc::clone(&defer))));

    let response = request(
        &router,
        Method::POST,
        "/__events",
        &[(X_HARNESS_GATEWAY, &gateway_stamp("email-signup"))],
        Some(br#"{"event":"waitlist.confirmed","payload":{"email":"a@example.test"}}"#.to_vec()),
    )
    .await;

    assert_eq!(
        response.status(),
        StatusCode::ACCEPTED,
        "202: accepted for processing, not processed"
    );
    let body = body_json(response).await;
    assert_eq!(body["accepted"], true);
    assert_eq!(body["handlers"], 1);
    assert_eq!(
        runs.load(Ordering::SeqCst),
        0,
        "the handler runs in the sidecar's own wait_until, after the answer"
    );

    defer.drain().await;
    assert_eq!(runs.load(Ordering::SeqCst), 1);
    assert_eq!(
        seen.lock().expect("seen lock")[0]["email"],
        "a@example.test",
        "and it receives the payload the host emitted, verbatim"
    );
}

#[pollster::test]
async fn an_inbound_event_with_no_subscriber_says_so_rather_than_accepting_silently() {
    // The silent delivery this issue exists to prevent: an event arrives
    // over the boundary, nothing is listening, and nobody is told.
    let defer = Arc::new(ParkingDefer::default());
    let router = harness_of(vec![Arc::new(EmitRouteModule::default())]).router(ports_for(
        None,
        None,
        Some(Arc::clone(&defer)),
    ));

    let response = request(
        &router,
        Method::POST,
        "/__events",
        &[(X_HARNESS_GATEWAY, &gateway_stamp("waitlist"))],
        Some(br#"{"event":"nobody.listens","payload":{}}"#.to_vec()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = body_json(response).await;
    assert_eq!(body["accepted"], false, "the host is told nothing heard it");
    assert_eq!(body["handlers"], 0);
}

#[pollster::test]
async fn an_inbound_event_is_not_forwarded_on() {
    // A deployment can be both: a host with its own mounts and, to someone
    // above it, a sidecar. If the inbound route delivered through the
    // *forwarding* bus, an event would be re-posted to its own mounts, and
    // two deployments that mount each other would loop with nothing in the
    // bus able to detect it. The route delivers locally only.
    let (module, runs, _) = SubscriberModule::new();
    let dispatcher = Arc::new(EventDispatcher::answering(StatusCode::ACCEPTED));
    let defer = Arc::new(ParkingDefer::default());
    let router = harness_of(vec![Arc::new(module)]).router(ports_for(
        Some(r#"{"acme-pricing":"ACME"}"#),
        Some(dispatcher.clone()),
        Some(Arc::clone(&defer)),
    ));

    let response = request(
        &router,
        Method::POST,
        "/__events",
        &[(X_HARNESS_GATEWAY, &gateway_stamp("email-signup"))],
        Some(br#"{"event":"waitlist.confirmed","payload":{}}"#.to_vec()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    defer.drain().await;
    assert_eq!(runs.load(Ordering::SeqCst), 1, "the local handler ran");
    assert_eq!(
        dispatcher.events_posts().len(),
        0,
        "and nothing was posted onward to this deployment's own mounts"
    );
}

#[pollster::test]
async fn an_unstamped_post_to_events_is_refused() {
    let (module, runs, _) = SubscriberModule::new();
    let defer = Arc::new(ParkingDefer::default());
    let router =
        harness_of(vec![Arc::new(module)]).router(ports_for(None, None, Some(Arc::clone(&defer))));

    let body = br#"{"event":"waitlist.confirmed","payload":{}}"#.to_vec();

    let response = request(&router, Method::POST, "/__events", &[], Some(body.clone())).await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "an unauthenticated trigger could forge the payloads handlers act on"
    );

    let response = request(
        &router,
        Method::POST,
        "/__events",
        &[(X_HARNESS_GATEWAY, "not-a-token")],
        Some(body),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    defer.drain().await;
    assert_eq!(
        runs.load(Ordering::SeqCst),
        0,
        "and neither refusal ran a handler"
    );
}

#[pollster::test]
async fn a_malformed_envelope_is_a_validation_problem_not_a_panic() {
    let defer = Arc::new(ParkingDefer::default());
    let router = harness_of(vec![Arc::new(EmitRouteModule::default())]).router(ports_for(
        None,
        None,
        Some(Arc::clone(&defer)),
    ));

    let response = request(
        &router,
        Method::POST,
        "/__events",
        &[(X_HARNESS_GATEWAY, &gateway_stamp("waitlist"))],
        Some(br#"{"not":"an envelope"}"#.to_vec()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[pollster::test]
async fn a_deployment_with_no_gateway_secret_does_not_mount_the_route_at_all() {
    // Without the shared secret there is no way to tell the host's forward
    // from anyone else's POST, so the route is absent rather than open.
    let (module, runs, _) = SubscriberModule::new();
    let defer = Arc::new(ParkingDefer::default());
    let mut ports = Ports::with_config(Arc::new(MapConfig::from_pairs(
        Vec::<(String, String)>::new(),
    )));
    ports.defer = Some(Arc::clone(&defer) as Arc<dyn cratefield_core::Defer>);
    let router = harness_of(vec![Arc::new(module)]).router(ports);

    let response = request(
        &router,
        Method::POST,
        "/__events",
        &[],
        Some(br#"{"event":"waitlist.confirmed","payload":{}}"#.to_vec()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    defer.drain().await;
    assert_eq!(runs.load(Ordering::SeqCst), 0);
}

// ------------------------------------------------- nobody heard it (reports)
//
// Each test uses an event name only it emits, because the sink is
// process-global and the suite runs in parallel. Counting a shared phrase
// would make these tests depend on each other's scheduling, which is the
// bug the previous version of this file had.

#[pollster::test]
async fn an_emission_nothing_hears_is_reported() {
    // No subscriber in process and no mount to forward to. Before #62
    // this was silent, which is how a module author learns the hard way
    // that a handler never ran.
    let reports = reports();
    let defer = Arc::new(ParkingDefer::default());
    let router = harness_of(vec![Arc::new(EmitRouteModule::named("unheard.emission"))])
        .router(ports_for(None, None, Some(Arc::clone(&defer))));
    let response = request(&router, Method::POST, "/v1/waitlist/emit", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    defer.drain().await;

    assert_eq!(
        reports("emitted event `unheard.emission` has no registered handler"),
        1,
        "an emission nothing heard must be reported, exactly once"
    );
}

#[pollster::test]
async fn an_emission_that_is_forwarded_is_not_reported_as_unheard() {
    // The other half: a host with no local subscriber but a mount *has*
    // been heard by something, and warning there would train operators to
    // ignore the warning that matters.
    let reports = reports();
    let dispatcher = Arc::new(EventDispatcher::answering(StatusCode::ACCEPTED));
    let defer = Arc::new(ParkingDefer::default());
    let router =
        harness_of(vec![Arc::new(EmitRouteModule::named("forwarded.emission"))]).router(ports_for(
            Some(r#"{"acme-pricing":"ACME"}"#),
            Some(dispatcher.clone()),
            Some(Arc::clone(&defer)),
        ));
    let response = request(&router, Method::POST, "/v1/waitlist/emit", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    defer.drain().await;
    assert_eq!(dispatcher.events_posts().len(), 1, "it was forwarded");

    assert_eq!(
        reports("emitted event `forwarded.emission` has no registered handler"),
        0,
        "a forwarded emission was heard, so reporting it would be noise"
    );
}

#[pollster::test]
async fn an_inbound_event_with_no_subscriber_is_reported_once() {
    let reports = reports();
    let defer = Arc::new(ParkingDefer::default());
    let router = harness_of(vec![Arc::new(EmitRouteModule::default())]).router(ports_for(
        None,
        None,
        Some(Arc::clone(&defer)),
    ));
    let response = request(
        &router,
        Method::POST,
        "/__events",
        &[(X_HARNESS_GATEWAY, &gateway_stamp("waitlist"))],
        Some(br#"{"event":"inbound.unheard","payload":{}}"#.to_vec()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    defer.drain().await;

    assert_eq!(
        reports("event `inbound.unheard` arrived over the boundary with no subscriber"),
        1,
        "reported, and exactly once"
    );
}

#[pollster::test]
async fn a_sidecar_that_answers_500_is_reported_exactly_once() {
    // The issue's verification: the failure appears exactly once in logs,
    // and never in the response.
    let reports = reports();
    let dispatcher = Arc::new(EventDispatcher::answering(
        StatusCode::INTERNAL_SERVER_ERROR,
    ));
    let defer = Arc::new(ParkingDefer::default());
    // Its own mount name, not just its own event name: the report line
    // names the *mount*, and `a_sidecar_that_answers_500_does_not_fail_
    // the_originating_request` emits the identical line for
    // `acme-pricing`. One shared buffer means uniqueness has to cover
    // every part of the string being counted.
    let router = harness_of(vec![Arc::new(EmitRouteModule::default())]).router(ports_for(
        Some(r#"{"five-hundred-report":"ACME"}"#),
        Some(dispatcher.clone()),
        Some(Arc::clone(&defer)),
    ));
    let response = request(&router, Method::POST, "/v1/waitlist/emit", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    defer.drain().await;

    assert_eq!(
        reports("event forward to `five-hundred-report` answered 500"),
        1,
        "once, not once per retry"
    );
}
