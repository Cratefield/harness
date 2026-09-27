//! The delivery contract, end to end against a real SQLite database: the
//! event-type filter and subject isolation, the 2xx path, the 5xx
//! retry-then-dead-letter path, replay (including its refusal when the
//! endpoint is gone), the event types no header could carry, and the
//! signature a receiver verifies.
//!
//! The ports are the same ones a deployment gets: a `Clock` the test can
//! move forward (so a retried row actually becomes due again — a frozen
//! clock would claim each row exactly once and prove nothing about the
//! second attempt), and an `HttpClient` that records the full request —
//! headers included, because the signature lives in one — and answers from
//! a script.

#![allow(clippy::missing_panics_doc)]
// Interior mutability here records test observations — a clock a test can
// move, a scripted provider's queue, the requests a delivery made. It is
// not request state (ADR 0007); the scoped allow follows the policy in the
// workspace `clippy.toml`, as `cratefield-testing`'s own fakes do.
#![allow(clippy::disallowed_types)]

use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{
    Clock, Config, Database, HttpClient, HttpError, MapConfig, Module, ModuleContext,
    PersonalDataCatalog, Port, Ports, TemplateRegistry, Venture,
};
use cratefield_module_webhooks::{
    Delivery, DrainReport, EndpointError, PublishError, Published, Webhooks,
};
use cratefield_testing::TestHarness;
use hmac::{Hmac, KeyInit, Mac};
use http::{Request, Response};
use serde_json::{Value, json};
use sha2::Sha256;
use time::OffsetDateTime;

const NOW_UNIX: i64 = 1_800_000_000;
/// The same instant as [`NOW_UNIX`], in the stored spelling: every stored
/// timestamp should read as a time, never as an epoch, and the two must
/// agree or a queued row sits in the future of the clock reading it.
const NOW_ISO: &str = "2027-01-15T08:00:00Z";

const ALICE: &str = "acct-alice";
const BOB: &str = "acct-bob";

// ---------------------------------------------------------------------------
// The kit

struct Kit {
    harness: TestHarness,
    module: Webhooks,
    clock: TestClock,
    http: CaptureClient,
}

impl Kit {
    /// A harness with the webhooks module mounted, its `Clock` port the
    /// movable [`TestClock`] and its `HttpClient` port the recording
    /// [`CaptureClient`], which answers from `script` (statuses, in
    /// order) and then always 200.
    fn mount(max_attempts: u32, script: &[u16]) -> Self {
        let clock = TestClock::at(NOW_UNIX);
        let http = CaptureClient::scripted(script);
        let module = Webhooks::new().max_attempts(max_attempts);
        let harness = TestHarness::with_ports(vec![Box::new(module.clone())], |ports| {
            ports.clock = Some(Arc::new(clock.clone()));
            ports.http = Some(Arc::new(http.clone()));
        });
        Self {
            harness,
            module,
            clock,
            http,
        }
    }

    fn db(&self) -> Arc<dyn Database> {
        Arc::clone(&self.harness.db)
    }

    /// Every port a scheduled invocation would carry, wired to this kit —
    /// before a test pokes a hole in one to prove the drain refuses.
    fn wired_ports(&self, config: &Arc<dyn Config>) -> Ports {
        let mut ports = Ports::with_config(Arc::clone(config));
        ports.db = Some(Arc::clone(&self.harness.db));
        ports.clock = Some(Arc::new(self.clock.clone()));
        ports.http = Some(Arc::new(self.http.clone()));
        ports
    }

    /// The context a scheduled invocation would carry: this kit's
    /// database, movable clock and recording client.
    fn context(&self, config: Arc<dyn Config>) -> ModuleContext {
        let ports = self.wired_ports(&config);
        self.context_over(ports, config)
    }

    /// A context over given ports — the escape hatch the port-hole tests
    /// use to hand the drain a context with one port gone.
    fn context_over(&self, ports: Ports, config: Arc<dyn Config>) -> ModuleContext {
        ModuleContext {
            ports,
            config,
            events: self.harness.harness.events().clone(),
            templates: Arc::new(TemplateRegistry::default()),
            venture: Arc::new(Venture::new("test-venture", "test.example")),
            unprotected_writes_accepted: false,
            ui_mounted: false,
            personal_data: Arc::new(PersonalDataCatalog::default()),
        }
    }

    fn config() -> Arc<dyn Config> {
        Arc::new(MapConfig::default())
    }

    async fn create_endpoint(&self, subject: &str, url: &str, filters: &[&str]) -> String {
        self.module
            .create_endpoint(&*self.db(), subject, url, filters, NOW_ISO)
            .await
            .expect("the endpoint registers")
            .endpoint_id
    }

    /// `publish` + commit, the way a caller with its own transaction does
    /// it: the statements go into the caller's batch, never their own.
    async fn publish(&self, subject: &str, event_type: &str, data: Value) -> Published {
        let published = self
            .module
            .publish(&*self.db(), subject, event_type, &data, NOW_ISO)
            .await
            .expect("the event fans out");
        self.harness
            .db
            .batch_atomic(&published.clone().into_statements())
            .await
            .expect("the batch commits");
        published
    }

    async fn drain(&self) -> DrainReport {
        self.module
            .drain_with(&self.context(Kit::config()))
            .await
            .expect("the drain runs")
    }

    async fn deliveries(&self, subject: &str) -> Vec<Delivery> {
        self.module
            .deliveries(&*self.db(), subject, 100)
            .await
            .expect("the log reads")
    }
}

// ---------------------------------------------------------------------------
// A clock the test moves

#[derive(Clone)]
struct TestClock(Arc<Mutex<OffsetDateTime>>);

impl TestClock {
    fn at(unix: i64) -> Self {
        Self(Arc::new(Mutex::new(
            OffsetDateTime::from_unix_timestamp(unix).expect("in range"),
        )))
    }

    fn advance(&self, seconds: i64) {
        let mut now = self.0.lock().expect("clock");
        *now = now.saturating_add(time::Duration::seconds(seconds));
    }
}

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().expect("clock")
    }
}

// ---------------------------------------------------------------------------
// An HttpClient that records the whole request and answers from a script

#[derive(Clone, Default)]
struct CaptureClient {
    inner: Arc<Mutex<CaptureInner>>,
}

#[derive(Default)]
struct CaptureInner {
    script: Vec<u16>,
    answered: usize,
    captured: Vec<Captured>,
}

#[derive(Clone)]
struct Captured {
    uri: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl CaptureClient {
    fn scripted(statuses: &[u16]) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CaptureInner {
                script: statuses.to_vec(),
                ..CaptureInner::default()
            })),
        }
    }

    fn captured(&self) -> Vec<Captured> {
        self.inner.lock().expect("http lock").captured.clone()
    }
}

#[async_trait]
impl HttpClient for CaptureClient {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let (parts, body) = request.into_parts();
        let mut inner = self.inner.lock().expect("http lock");
        inner.captured.push(Captured {
            uri: parts.uri.to_string(),
            headers: parts
                .headers
                .iter()
                .map(|(name, value)| {
                    (
                        name.as_str().to_owned(),
                        value.to_str().unwrap_or_default().to_owned(),
                    )
                })
                .collect(),
            body: body.to_vec(),
        });
        // The script, then a 200 forever: the tests that care about
        // failures script every answer they expect to see.
        let status = if inner.answered < inner.script.len() {
            let status = inner.script[inner.answered];
            inner.answered += 1;
            status
        } else {
            200
        };
        Ok(Response::builder()
            .status(status)
            .body(Bytes::new())
            .expect("a bare status is a valid response"))
    }
}

// ---------------------------------------------------------------------------
// Assertion helpers

fn header<'a>(captured: &'a Captured, name: &str) -> &'a str {
    match captured
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
    {
        Some((_, value)) => value.as_str(),
        None => panic!("no {name} header on the delivery"),
    }
}

fn envelope(captured: &Captured) -> Value {
    serde_json::from_slice(&captured.body).expect("the body is the JSON envelope")
}

/// One delivery per URL, in the order they were made.
fn captures_to<'a>(captured: &'a [Captured], uri: &str) -> Vec<&'a Captured> {
    captured.iter().filter(|c| c.uri == uri).collect()
}

const URL_A: &str = "https://alice-a.test/hooks";
const URL_B: &str = "https://alice-b.test/hooks";
const URL_C: &str = "https://bob.test/hooks";

// ---------------------------------------------------------------------------

#[pollster::test]
async fn the_filter_decides_who_hears_an_event_and_no_subject_hears_anothers() {
    let kit = Kit::mount(5, &[]);
    let filtered = kit.create_endpoint(ALICE, URL_A, &["order.paid"]).await;
    // A second later, so the two creations carry distinct timestamps and
    // "creation order" is a property of the rows, not of the id tiebreak
    // that only decides rows stored in the same second.
    let catch_all = kit
        .module
        .create_endpoint(&*kit.db(), ALICE, URL_B, &[], "2027-01-15T08:00:01Z")
        .await
        .expect("the endpoint registers")
        .endpoint_id;
    kit.create_endpoint(BOB, URL_C, &[]).await;

    // The list never hands secrets back: the type carries none, and both
    // of Alice's endpoints are hers, in creation order.
    let endpoints = kit
        .module
        .endpoints(&*kit.db(), ALICE)
        .await
        .expect("the list reads");
    assert_eq!(
        endpoints.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
        [filtered.as_str(), catch_all.as_str()]
    );

    // A refunded order passes only the catch-all: the filtered endpoint
    // said `order.paid` and this is not one.
    assert_eq!(
        kit.publish(ALICE, "order.refunded", json!({ "n": 1 }))
            .await
            .endpoints,
        1
    );
    // A paid order reaches both of Alice's endpoints — and only hers.
    assert_eq!(
        kit.publish(ALICE, "order.paid", json!({ "n": 2 }))
            .await
            .endpoints,
        2
    );
    // Bob's event fans out to exactly one endpoint: his own.
    assert_eq!(
        kit.publish(BOB, "order.paid", json!({ "n": 3 }))
            .await
            .endpoints,
        1
    );

    let report = kit.drain().await;
    assert_eq!(report.claimed, 4);
    assert_eq!(report.delivered, 4);
    assert_eq!(report.retried, 0);
    assert_eq!(report.dead_lettered, 0);

    // Per endpoint, per subject: the filtered endpoint saw one delivery,
    // Alice's catch-all two, and every envelope's subject is its own
    // endpoint's subject — Bob's event never touched Alice's URL.
    let captured = kit.http.captured();
    assert_eq!(captures_to(&captured, URL_A).len(), 1);
    assert_eq!(captures_to(&captured, URL_B).len(), 2);
    assert_eq!(captures_to(&captured, URL_C).len(), 1);
    for c in &captured {
        let body = envelope(c);
        let expected_subject = if c.uri == URL_C { BOB } else { ALICE };
        assert_eq!(body["subject"], expected_subject, "{}", c.uri);
    }

    // And each subject's log is its own.
    assert_eq!(kit.deliveries(ALICE).await.len(), 3);
    assert_eq!(kit.deliveries(BOB).await.len(), 1);
}

#[pollster::test]
async fn a_2xx_delivery_is_logged_with_its_status_and_completes() {
    let kit = Kit::mount(5, &[]);
    kit.create_endpoint(ALICE, URL_A, &[]).await;
    let published = kit
        .publish(ALICE, "order.paid", json!({ "invoice": "in_1" }))
        .await;

    let report = kit.drain().await;
    assert_eq!(report.claimed, 1);
    assert_eq!(report.delivered, 1);

    let log = kit.deliveries(ALICE).await;
    assert_eq!(log.len(), 1, "one attempt, logged once");
    let entry = &log[0];
    assert_eq!(entry.endpoint_id.len(), 26, "an endpoint was named");
    assert_eq!(entry.event_id, published.event_id);
    assert_eq!(entry.event_type, "order.paid");
    assert_eq!(entry.attempt, 1);
    assert_eq!(entry.status_code, Some(200));
    assert_eq!(entry.error, None);

    // Completed: a second pass claims nothing.
    assert_eq!(kit.drain().await.claimed, 0);
}

#[pollster::test]
async fn a_5xx_retries_with_backoff_then_dead_letters_after_max_attempts() {
    // Three attempts allowed, three 500s scripted: the delivery exhausts
    // exactly its budget.
    let kit = Kit::mount(3, &[500, 500, 500]);
    kit.create_endpoint(ALICE, URL_A, &[]).await;
    let published = kit
        .publish(ALICE, "order.paid", json!({ "invoice": "in_2" }))
        .await;

    // First pass: one attempt, logged with the status, put back with the
    // first backoff.
    let report = kit.drain().await;
    assert_eq!(report.claimed, 1);
    assert_eq!(report.retried, 1);
    assert_eq!(kit.deliveries(ALICE).await.len(), 1);

    // The backoff holds: with the clock unmoved the row is not due, so
    // the second pass claims nothing — a 30s-old failure is not retried
    // 0s later.
    assert_eq!(kit.drain().await.claimed, 0);

    // +30s, the first backoff: attempt two, another 500, another backoff —
    // the doubling means this one is 60s out.
    kit.clock.advance(30);
    assert_eq!(kit.drain().await.retried, 1);
    assert_eq!(kit.deliveries(ALICE).await.len(), 2);

    kit.clock.advance(59);
    assert_eq!(kit.drain().await.claimed, 0, "59s into a 60s backoff");

    // +60s total: the last allowed attempt fails and the row dead-letters.
    kit.clock.advance(1);
    let report = kit.drain().await;
    assert_eq!(report.claimed, 1);
    assert_eq!(report.dead_lettered, 1);

    // The log holds every attempt, in order, all with the status.
    let log = kit.deliveries(ALICE).await;
    assert_eq!(log.len(), 3);
    assert_eq!(
        log.iter().map(|d| d.attempt).collect::<Vec<_>>(),
        [3, 2, 1],
        "newest attempt first"
    );
    assert!(log.iter().all(|d| d.status_code == Some(500)));

    // The dead letter is the event, not a summary of it.
    let letters = kit
        .module
        .dead_letters(&*kit.db(), ALICE, 10)
        .await
        .expect("the dead letters read");
    assert_eq!(letters.len(), 1);
    let letter = &letters[0];
    assert_eq!(letter.event_id, published.event_id);
    assert_eq!(letter.attempts, 3);
    assert_eq!(letter.reason, "attempts_exhausted");
    assert_eq!(letter.status_code, Some(500));
    assert!(
        letter.last_error.contains("500"),
        "the receiver's answer is preserved: {}",
        letter.last_error
    );

    // Given up means out of the queue: nothing left to claim.
    assert_eq!(kit.drain().await.claimed, 0);
}

#[pollster::test]
async fn replay_sends_a_dead_letter_again_and_resets_the_attempts() {
    let kit = Kit::mount(2, &[500, 500]);
    kit.create_endpoint(ALICE, URL_A, &[]).await;
    let published = kit.publish(ALICE, "order.paid", json!({ "n": 7 })).await;
    kit.drain().await;
    kit.clock.advance(30);
    kit.drain().await;
    assert_eq!(
        kit.module
            .dead_letters(&*kit.db(), ALICE, 10)
            .await
            .expect("read")
            .len(),
        1
    );

    // Replay re-enqueues the event — attempts reset to zero — and removes
    // the letter, in one batch. The receiver now answers 200 (the script
    // is exhausted), so the drain delivers. The clock moves first, so the
    // replayed attempt is logged strictly after the two it follows.
    kit.clock.advance(1);
    let letter_id = kit
        .module
        .dead_letters(&*kit.db(), ALICE, 10)
        .await
        .expect("read")[0]
        .id
        .clone();
    assert!(
        kit.module
            .replay(&*kit.db(), ALICE, &letter_id, NOW_ISO)
            .await
            .expect("the replay commits")
    );
    assert!(
        !kit.module
            .replay(&*kit.db(), ALICE, &letter_id, NOW_ISO)
            .await
            .expect("the second replay is an ordinary no"),
        "a replayed letter is gone; replaying it again is false, not an error"
    );
    assert_eq!(
        kit.module
            .dead_letters(&*kit.db(), ALICE, 10)
            .await
            .expect("read")
            .len(),
        0
    );

    let report = kit.drain().await;
    assert_eq!(report.claimed, 1);
    assert_eq!(report.delivered, 1);

    // The log keeps the whole history: the two failed attempts, then the
    // replayed delivery as attempt one of its (new) life.
    let log = kit.deliveries(ALICE).await;
    assert_eq!(log.len(), 3);
    assert_eq!(log[0].attempt, 1, "the replayed delivery restarts at one");
    assert_eq!(log[0].status_code, Some(200));

    // And it is the same event, not a copy with a new identity.
    let captured = kit.http.captured();
    let last = captured.last().expect("a delivery was made");
    let body = envelope(last);
    assert_eq!(body["id"], published.event_id.as_str());
    assert_eq!(body["data"]["n"], 7);

    // A replay names a letter of *this subject*: another subject's id (or
    // any invented one) is an ordinary `false`.
    assert!(
        !kit.module
            .replay(&*kit.db(), BOB, &letter_id, NOW_ISO)
            .await
            .expect("read")
    );
}

/// A replay whose endpoint is gone must refuse and leave the letter in
/// place: consuming it would hand the event to a drain that drops
/// undeliverable rows, destroying the event for good.
#[pollster::test]
async fn a_replay_into_a_deleted_endpoint_refuses_and_keeps_the_letter() {
    let kit = Kit::mount(1, &[500]);
    let endpoint_id = kit.create_endpoint(ALICE, URL_A, &[]).await;
    kit.publish(ALICE, "order.paid", json!({ "n": 1 })).await;
    // One attempt allowed, one 500 scripted: the row dead-letters.
    assert_eq!(kit.drain().await.dead_lettered, 1);

    assert!(
        kit.module
            .delete_endpoint(&*kit.db(), ALICE, &endpoint_id)
            .await
            .expect("the delete commits")
    );

    let letter_id = kit
        .module
        .dead_letters(&*kit.db(), ALICE, 10)
        .await
        .expect("read")[0]
        .id
        .clone();
    assert!(
        !kit.module
            .replay(&*kit.db(), ALICE, &letter_id, NOW_ISO)
            .await
            .expect("the replay commits"),
        "no endpoint to deliver to, so the replay refuses"
    );
    assert_eq!(
        kit.module
            .dead_letters(&*kit.db(), ALICE, 10)
            .await
            .expect("read")
            .len(),
        1,
        "the letter stays put"
    );
    assert_eq!(
        kit.drain().await.claimed,
        0,
        "and nothing was enqueued behind the refusal"
    );
}

/// A type no HTTP header could carry is refused at the door — publish and
/// filter registration alike — so nothing undeliverable is ever enqueued
/// to burn its retry budget.
#[pollster::test]
async fn unusable_event_types_are_refused_at_publish_and_at_registration() {
    let kit = Kit::mount(5, &[]);
    kit.create_endpoint(ALICE, URL_A, &[]).await;

    let error = kit
        .module
        .publish(&*kit.db(), ALICE, "two tokens", &json!({}), NOW_ISO)
        .await
        .expect_err("whitespace makes the type undeliverable");
    assert!(
        matches!(error, PublishError::InvalidEventType(ref t) if t == "two tokens"),
        "{error}"
    );

    let error = kit
        .module
        .create_endpoint(
            &*kit.db(),
            ALICE,
            URL_B,
            &["order.paid", "bad type"],
            NOW_ISO,
        )
        .await
        .expect_err("a filter naming an undeliverable type is refused");
    assert!(
        matches!(error, EndpointError::InvalidEventType(ref t) if t == "bad type"),
        "{error}"
    );
    // The refused endpoint was not inserted: only the catch-all is listed.
    assert_eq!(
        kit.module
            .endpoints(&*kit.db(), ALICE)
            .await
            .expect("read")
            .len(),
        1
    );
}

#[pollster::test]
async fn the_signature_header_verifies_against_the_endpoints_secret() {
    let kit = Kit::mount(5, &[]);
    let secret = kit
        .module
        .create_endpoint(&*kit.db(), ALICE, URL_A, &["order.paid"], NOW_ISO)
        .await
        .expect("the endpoint registers")
        .secret;
    let published = kit
        .publish(ALICE, "order.paid", json!({ "invoice": "in_3" }))
        .await;
    kit.drain().await;

    let captured = kit.http.captured();
    assert_eq!(captured.len(), 1);
    let delivery = &captured[0];

    // The delivery names the event twice over: in the envelope and in the
    // headers, so a receiver can dedupe without parsing the body.
    assert_eq!(header(delivery, "Cratefield-Event-Id"), published.event_id);
    assert_eq!(header(delivery, "Cratefield-Event-Type"), "order.paid");
    assert_eq!(header(delivery, "Content-Type"), "application/json");

    // The receiver's side of the contract: split the header, recompute the
    // MAC over `{t}.{body}` with the secret from registration, compare.
    let signature = header(delivery, "Cratefield-Signature");
    let (t, v1) = signature
        .split_once(",v1=")
        .map(|(t, v1)| (t.trim_start_matches("t="), v1))
        .expect("the header shape");
    let expected = {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("any key length");
        mac.update(t.as_bytes());
        mac.update(b".");
        mac.update(&delivery.body);
        mac.finalize().into_bytes()
    };
    assert_eq!(hex(&expected), v1, "the delivery is authentic");

    // ...and the binding is real: a tampered body (or a re-stamped one)
    // does not verify.
    let tampered = {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("any key length");
        mac.update(t.as_bytes());
        mac.update(b".");
        mac.update(b"{\"invoice\":\"in_4\"}");
        mac.finalize().into_bytes()
    };
    assert_ne!(hex(&tampered), v1);
}

/// Lowercase hex, the encoding the signature header carries.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[pollster::test]
async fn a_410_gone_never_retries() {
    let kit = Kit::mount(5, &[410]);
    kit.create_endpoint(ALICE, URL_A, &[]).await;
    kit.publish(ALICE, "order.paid", json!({ "n": 1 })).await;

    let report = kit.drain().await;
    assert_eq!(report.claimed, 1);
    assert_eq!(report.dead_lettered, 1);
    assert_eq!(report.retried, 0, "the endpoint said never again");

    let letters = kit
        .module
        .dead_letters(&*kit.db(), ALICE, 10)
        .await
        .expect("read");
    assert_eq!(letters.len(), 1);
    assert_eq!(letters[0].reason, "rejected");
    assert_eq!(letters[0].status_code, Some(410));
    assert_eq!(letters[0].attempts, 1, "one attempt, no budget burned");
}

#[pollster::test]
async fn the_config_override_tightens_the_attempt_budget() {
    // The compiled setting is 3; the deployment says 1. One 500 is then a
    // dead letter, not a retry — `WEBHOOKS_MAX_ATTEMPTS` is read by the
    // drain, through the context a scheduled invocation carries.
    let kit = Kit::mount(3, &[500]);
    kit.create_endpoint(ALICE, URL_A, &[]).await;
    kit.publish(ALICE, "order.paid", json!({ "n": 1 })).await;

    let config = Arc::new(MapConfig::from_pairs([("WEBHOOKS_MAX_ATTEMPTS", "1")]));
    let report = kit
        .module
        .drain_with(&kit.context(config))
        .await
        .expect("the drain runs");
    assert_eq!(report.dead_lettered, 1);
    assert_eq!(report.retried, 0);

    let letters = kit
        .module
        .dead_letters(&*kit.db(), ALICE, 10)
        .await
        .expect("read");
    assert_eq!(letters[0].attempts, 1);
}

/// The module needs a database, an HTTP client and a clock; a context
/// without one cannot start a drain, and says so rather than panicking —
/// or, for the clock, rather than silently falling back to the wall clock
/// a test never pinned.
async fn drain_without(kit: &Kit, absent: &str) -> String {
    let config: Arc<dyn Config> = Arc::new(MapConfig::default());
    let mut ports = kit.wired_ports(&config);
    match absent {
        "db" => ports.db = None,
        "HttpClient" => ports.http = None,
        "Clock" => ports.clock = None,
        other => panic!("no such port: {other}"),
    }
    kit.module
        .drain_with(&kit.context_over(ports, config))
        .await
        .expect_err("a missing port refuses to start a drain")
        .to_string()
}

#[pollster::test]
async fn a_drain_without_the_http_port_refuses_to_start() {
    let kit = Kit::mount(5, &[]);
    let error = drain_without(&kit, "HttpClient").await;
    assert!(
        error.contains("HttpClient"),
        "the error names the missing port: {error}"
    );
}

#[pollster::test]
async fn a_drain_without_the_clock_port_refuses_to_start() {
    let kit = Kit::mount(5, &[]);
    let error = drain_without(&kit, "Clock").await;
    assert!(
        error.contains("Clock"),
        "the error names the missing port: {error}"
    );
}

#[pollster::test]
async fn a_drain_without_the_db_port_refuses_to_start() {
    let kit = Kit::mount(5, &[]);
    let error = drain_without(&kit, "db").await;
    assert!(error.contains("Database"), "{error}");
}

/// The port set a deployment must resolve for this module to build at all.
#[test]
fn the_module_declares_the_ports_it_needs() {
    assert_eq!(
        Webhooks::new().requires(),
        [Port::Db, Port::HttpClient, Port::Clock]
    );
}
