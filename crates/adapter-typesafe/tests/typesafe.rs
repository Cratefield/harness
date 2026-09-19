//! `TypeSafe` adapter acceptance tests (issue #456): the happy path carries
//! all three question kinds in one request, a missing or blank key is
//! `NotConfigured` without touching the network, every vendor failure maps
//! to the error the port names (including both `Retry-After` forms), an
//! over-long `state` is trimmed on the wire and logged, and the API key
//! never reaches a log line or an error.
//!
//! All through a local fake `HttpClient` — deliberately built here rather
//! than borrowed from `cratefield-testing`, so this crate's tests do not
//! depend on a crate that is free to change under them.

// Test-side recording fixture, not request state — the same category
// and allowance as the fakes in `cratefield-testing` (ADR 0007 policy).
#![allow(clippy::disallowed_types)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_adapter_typesafe::TypeSafe;
use cratefield_core::{
    AnswerValue, Calibration, Classifier, ClassifierError, ClassifierProfile, Clock,
    DEFAULT_MAX_STATE_CHARS, HttpClient, HttpError, Question,
};
use http::{HeaderMap, Request, Response, StatusCode};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, Once, OnceLock};
use std::time::Duration;

// Obvious dummy key, never real.
const DUMMY_KEY: &str = "ts_live_dummy_key_000000";

const CLASSIFY_URI: &str = "https://api.typesafe.ai/v1/classify";

/// A 200 carrying one answer per question, all three kinds.
const THREE_ANSWERS: &str = r#"{"answers":[
  {"id":"topic","value":"bugs","probabilities":{"billing":0.1,"bugs":0.9}},
  {"id":"severity","value":1,"probabilities":{"1":0.7,"5":0.3}},
  {"id":"angry","value":"false","probabilities":{"true":0.2,"false":0.8}}]}"#;

// ---------------------------------------------------------------- fixtures

struct CapturedRequest {
    method: String,
    uri: String,
    headers: HeaderMap,
    body: String,
}

struct FakeHttp {
    status: u16,
    body: &'static str,
    retry_after: Option<String>,
    /// When set, `send` fails with this transport message instead of
    /// answering.
    fail_with: Option<&'static str>,
    calls: AtomicUsize,
    tx: mpsc::Sender<CapturedRequest>,
}

#[async_trait]
impl HttpClient for FakeHttp {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let (parts, body) = request.into_parts();
        self.tx
            .send(CapturedRequest {
                method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                headers: parts.headers,
                body: String::from_utf8_lossy(&body).to_string(),
            })
            .expect("test channel open");
        if let Some(message) = self.fail_with {
            return Err(HttpError::Transport(message.to_owned()));
        }
        let mut builder =
            Response::builder().status(StatusCode::from_u16(self.status).expect("valid status"));
        if let Some(retry) = &self.retry_after {
            builder = builder.header("retry-after", retry.as_str());
        }
        builder
            .body(Bytes::from(self.body))
            .map_err(|err| HttpError::Transport(err.to_string()))
    }
}

fn fixture(
    status: u16,
    body: &'static str,
    retry_after: Option<&str>,
) -> (Arc<FakeHttp>, mpsc::Receiver<CapturedRequest>) {
    let (tx, rx) = mpsc::channel();
    (
        Arc::new(FakeHttp {
            status,
            body,
            retry_after: retry_after.map(str::to_owned),
            fail_with: None,
            calls: AtomicUsize::new(0),
            tx,
        }),
        rx,
    )
}

fn failing_fixture() -> (Arc<FakeHttp>, mpsc::Receiver<CapturedRequest>) {
    let (tx, rx) = mpsc::channel();
    (
        Arc::new(FakeHttp {
            status: 200,
            body: "",
            retry_after: None,
            fail_with: Some("network down"),
            calls: AtomicUsize::new(0),
            tx,
        }),
        rx,
    )
}

struct FixedClock(time::OffsetDateTime);

#[async_trait]
impl Clock for FixedClock {
    fn now(&self) -> time::OffsetDateTime {
        self.0
    }
}

fn clock_at(secs_past_epoch: i64) -> Arc<dyn Clock> {
    Arc::new(FixedClock(
        time::OffsetDateTime::from_unix_timestamp(secs_past_epoch).expect("valid timestamp"),
    ))
}

/// IMF-fixdate, the one date form RFC 9110 requires senders to emit.
fn http_date(at: time::OffsetDateTime) -> String {
    let format = time::format_description::parse_borrowed::<2>(
        "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT",
    )
    .expect("valid format");
    at.format(&format).expect("formats")
}

fn adapter(http: Arc<FakeHttp>) -> TypeSafe {
    TypeSafe::new(http, clock_at(0), Some(DUMMY_KEY.to_owned()))
}

fn questions() -> BTreeMap<String, Question> {
    BTreeMap::from([
        (
            "topic".to_owned(),
            Question::Choice {
                instructions: "Which topic does the note belong to?".to_owned(),
                criteria: BTreeMap::from([
                    ("billing".to_owned(), "money, invoices".to_owned()),
                    ("bugs".to_owned(), "something is broken".to_owned()),
                ]),
            },
        ),
        (
            "severity".to_owned(),
            Question::Score {
                instructions: "How severe is the note?".to_owned(),
                levels: vec![
                    ("1".to_owned(), "a typo".to_owned()),
                    ("5".to_owned(), "data loss".to_owned()),
                ],
            },
        ),
        (
            "angry".to_owned(),
            Question::Noul {
                instructions: "Is the writer angry?".to_owned(),
            },
        ),
    ])
}

// ------------------------------------------------------------------ happy path

#[pollster::test]
async fn one_call_answers_all_three_question_kinds() {
    let (http, _rx) = fixture(200, THREE_ANSWERS, None);
    let answers = adapter(Arc::clone(&http))
        .ask("a customer note about a broken invoice", &questions())
        .await
        .expect("answered");

    assert_eq!(answers.len(), 3);
    let topic = &answers["topic"];
    assert_eq!(topic.value, AnswerValue::Choice("bugs".to_owned()));
    assert!((topic.confidence - 0.9).abs() < f32::EPSILON, "{topic:?}");
    let severity = &answers["severity"];
    assert_eq!(severity.value, AnswerValue::Score(1.0));
    assert!(
        (severity.confidence - 0.7).abs() < f32::EPSILON,
        "{severity:?}"
    );
    let angry = &answers["angry"];
    assert_eq!(angry.value, AnswerValue::Noul(false));
    assert!((angry.confidence - 0.8).abs() < f32::EPSILON, "{angry:?}");
    // `confidence` agrees with `probabilities` on every answer.
    for (id, answer) in &answers {
        let label = match answer.value {
            AnswerValue::Choice(ref label) => label.clone(),
            AnswerValue::Score(score) => score.to_string(),
            AnswerValue::Noul(verdict) => {
                if verdict {
                    "true".to_owned()
                } else {
                    "false".to_owned()
                }
            }
        };
        let confidence = answer.probabilities.get(&label).copied().unwrap_or(0.0);
        assert!(
            (answer.confidence - confidence).abs() < f32::EPSILON,
            "{id} disagrees with its own probabilities: {answer:?}"
        );
    }
    assert_eq!(
        http.calls.load(Ordering::SeqCst),
        1,
        "one request, not a loop"
    );
}

#[pollster::test]
async fn the_one_request_carries_the_state_and_all_three_questions() {
    let (http, rx) = fixture(200, THREE_ANSWERS, None);
    adapter(http)
        .ask("a customer note", &questions())
        .await
        .expect("answered");
    let request = rx.try_recv().expect("one request captured");

    assert_eq!(request.method, "POST");
    assert_eq!(request.uri, CLASSIFY_URI);
    let header = |name: &str| {
        request
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
    };
    assert_eq!(header("content-type"), Some("application/json"));
    // Bearer auth: the operator's key rides the header, and only there.
    assert_eq!(
        header("authorization"),
        Some(format!("Bearer {DUMMY_KEY}").as_str())
    );

    let sent: Value = serde_json::from_str(&request.body).expect("json body");
    assert_eq!(sent["state"], "a customer note");
    let sent_questions = sent["questions"].as_array().expect("questions array");
    assert_eq!(sent_questions.len(), 3, "all questions in one request");

    let topic = sent_questions
        .iter()
        .find(|q| q["id"] == "topic")
        .expect("topic");
    assert_eq!(topic["kind"], "choice");
    assert_eq!(
        topic["instructions"],
        "Which topic does the note belong to?"
    );
    assert_eq!(topic["criteria"]["billing"], "money, invoices");
    assert_eq!(topic["criteria"]["bugs"], "something is broken");
    assert!(topic.get("levels").is_none(), "a choice carries no levels");

    let severity = sent_questions
        .iter()
        .find(|q| q["id"] == "severity")
        .expect("severity");
    assert_eq!(severity["kind"], "score");
    assert_eq!(
        severity["levels"],
        serde_json::json!([
            {"name": "1", "meaning": "a typo"},
            {"name": "5", "meaning": "data loss"},
        ])
    );
    assert!(
        severity.get("criteria").is_none(),
        "a score carries no criteria"
    );

    let angry = sent_questions
        .iter()
        .find(|q| q["id"] == "angry")
        .expect("angry");
    assert_eq!(angry["kind"], "noul");
    assert!(angry.get("criteria").is_none(), "a noul carries neither");
    assert!(angry.get("levels").is_none(), "a noul carries neither");
}

#[test]
fn the_profile_names_the_classifier_calibration_and_the_default_ceiling() {
    let (http, _rx) = fixture(200, THREE_ANSWERS, None);
    let profile: ClassifierProfile = adapter(http).profile();
    assert_eq!(profile.calibration, Calibration::Classifier);
    assert_eq!(profile.max_state_chars, DEFAULT_MAX_STATE_CHARS);
}

// ------------------------------------------------------------- not configured

#[pollster::test]
async fn no_key_is_not_configured_and_never_touches_the_network() {
    let (http, _rx) = fixture(200, THREE_ANSWERS, None);
    let error = TypeSafe::new(http.clone(), clock_at(0), None)
        .ask("state", &questions())
        .await
        .expect_err("unconfigured");
    assert_eq!(error, ClassifierError::NotConfigured);
    assert_eq!(http.calls.load(Ordering::SeqCst), 0, "no network call");
}

#[pollster::test]
async fn a_blank_key_is_not_configured_too() {
    let (http, _rx) = fixture(200, THREE_ANSWERS, None);
    for blank in ["", "   ", "\t\n"] {
        let error = TypeSafe::new(http.clone(), clock_at(0), Some(blank.to_owned()))
            .ask("state", &questions())
            .await
            .expect_err("blank key");
        assert_eq!(error, ClassifierError::NotConfigured, "blank key {blank:?}");
    }
    assert_eq!(http.calls.load(Ordering::SeqCst), 0, "no network call");
}

#[pollster::test]
async fn from_env_without_typesafe_api_key_provides_no_port() {
    // Env mutation is unsafe in edition 2024; the var is absent in clean
    // environments (CI). Skip only when a developer machine has it set.
    if std::env::var("TYPESAFE_API_KEY").is_ok() {
        return;
    }
    let (http, _rx) = fixture(200, THREE_ANSWERS, None);
    assert!(TypeSafe::from_env(http, clock_at(0)).is_none());
}

// -------------------------------------------------------------- error mapping

#[pollster::test]
async fn an_http_4xx_is_rejected_with_the_body() {
    let (http, _rx) = fixture(400, r#"{"error":"invalid api key"}"#, None);
    let error = adapter(http.clone())
        .ask("state", &questions())
        .await
        .expect_err("refused");
    assert!(
        matches!(error, ClassifierError::Rejected(ref body) if body.contains("invalid api key")),
        "{error:?}"
    );
    assert_eq!(http.calls.load(Ordering::SeqCst), 1);
}

#[pollster::test]
async fn a_429_is_transient_with_the_seconds_retry_after_parsed() {
    let (http, _rx) = fixture(429, "slow down", Some("30"));
    let error = adapter(http.clone())
        .ask("state", &questions())
        .await
        .expect_err("throttled");
    assert_eq!(
        error,
        ClassifierError::Transient {
            retry_after: Some(Duration::from_secs(30))
        }
    );
    assert_eq!(error.retry_after(), Some(Duration::from_secs(30)));
    assert_eq!(http.calls.load(Ordering::SeqCst), 1);
}

#[pollster::test]
async fn a_date_form_retry_after_is_parsed_against_the_clock() {
    // The clock reads epoch 0, so "come back at 00:01:00 GMT" is 60 s away.
    let at = time::OffsetDateTime::from_unix_timestamp(60).expect("valid timestamp");
    let date = http_date(at);
    let (http, _rx) = fixture(429, "slow down", Some(date.as_str()));
    let error = adapter(http.clone())
        .ask("state", &questions())
        .await
        .expect_err("throttled");
    assert_eq!(
        error.retry_after(),
        Some(Duration::from_secs(60)),
        "the date form needs the clock the adapter was built with"
    );
    // A date already in the past is "retry now", not "no delay stated".
    let (http, _rx) = fixture(503, "down", Some(&http_date(at)));
    let adapter = TypeSafe::new(http, clock_at(120), Some(DUMMY_KEY.to_owned()));
    let error = adapter.ask("state", &questions()).await.expect_err("down");
    assert_eq!(error.retry_after(), Some(Duration::ZERO));
}

#[pollster::test]
async fn a_429_without_a_retry_after_is_transient_with_no_back_off() {
    let (http, _rx) = fixture(429, "slow down", None);
    let error = adapter(http)
        .ask("state", &questions())
        .await
        .expect_err("throttled");
    assert_eq!(error, ClassifierError::Transient { retry_after: None });
}

#[pollster::test]
async fn a_5xx_is_transient() {
    for status in [500_u16, 503, 504] {
        let (http, _rx) = fixture(status, "server exploded", None);
        let error = adapter(http)
            .ask("state", &questions())
            .await
            .expect_err("server error");
        assert!(
            matches!(error, ClassifierError::Transient { .. }),
            "{error:?}"
        );
    }
}

#[pollster::test]
async fn an_unparseable_success_body_is_transport() {
    let (http, _rx) = fixture(200, "this is not json", None);
    let error = adapter(http.clone())
        .ask("state", &questions())
        .await
        .expect_err("did not survive the hop");
    assert!(matches!(error, ClassifierError::Transport(_)), "{error:?}");
    // A 200 without the answers array is the same hop failure.
    let (http, _rx) = fixture(200, r#"{"nope":true}"#, None);
    let error = adapter(http)
        .ask("state", &questions())
        .await
        .expect_err("did not survive the hop");
    assert!(matches!(error, ClassifierError::Transport(_)), "{error:?}");
}

#[pollster::test]
async fn a_transport_failure_is_transport() {
    let (http, _rx) = failing_fixture();
    let error = adapter(http.clone())
        .ask("state", &questions())
        .await
        .expect_err("network down");
    assert!(matches!(error, ClassifierError::Transport(_)), "{error:?}");
    assert_eq!(http.calls.load(Ordering::SeqCst), 1);
}

// ------------------------------------------------------------ refused answers

#[pollster::test]
async fn an_answer_naming_a_label_the_question_never_offered_is_rejected() {
    let (http, _rx) = fixture(
        200,
        r#"{"answers":[{"id":"topic","value":"shipping","probabilities":{"shipping":1.0}}]}"#,
        None,
    );
    let error = adapter(http.clone())
        .ask("state", &questions())
        .await
        .expect_err("invented answer");
    assert!(matches!(error, ClassifierError::Rejected(_)), "{error:?}");
    assert_eq!(
        http.calls.load(Ordering::SeqCst),
        1,
        "refused after the hop"
    );
}

#[pollster::test]
async fn a_response_missing_a_question_id_is_rejected_not_invented() {
    let (http, _rx) = fixture(
        200,
        r#"{"answers":[
          {"id":"topic","value":"bugs","probabilities":{"bugs":1.0}}]}"#,
        None,
    );
    let error = adapter(http)
        .ask("state", &questions())
        .await
        .expect_err("two questions went unanswered");
    assert!(matches!(error, ClassifierError::Rejected(_)), "{error:?}");
}

// --------------------------------------------------------- malformed question set

#[pollster::test]
async fn a_malformed_question_set_is_rejected_before_any_network_call() {
    let (http, _rx) = fixture(200, THREE_ANSWERS, None);
    let classifier = adapter(http.clone());

    let error = classifier
        .ask("state", &BTreeMap::new())
        .await
        .expect_err("empty set");
    assert!(matches!(error, ClassifierError::Rejected(_)), "{error:?}");

    let single_criterion = BTreeMap::from([(
        "solo".to_owned(),
        Question::Choice {
            instructions: "Pick one.".to_owned(),
            criteria: BTreeMap::from([("only".to_owned(), "the only one".to_owned())]),
        },
    )]);
    let error = classifier
        .ask("state", &single_criterion)
        .await
        .expect_err("one criterion is not a choice");
    assert!(matches!(error, ClassifierError::Rejected(_)), "{error:?}");

    let blank_instructions = BTreeMap::from([(
        "angry".to_owned(),
        Question::Noul {
            instructions: "   ".to_owned(),
        },
    )]);
    let error = classifier
        .ask("state", &blank_instructions)
        .await
        .expect_err("blank instructions");
    assert!(matches!(error, ClassifierError::Rejected(_)), "{error:?}");

    assert_eq!(
        http.calls.load(Ordering::SeqCst),
        0,
        "refused before the wire"
    );
}

// ------------------------------------------------------------------ truncation

#[pollster::test]
async fn an_over_long_state_is_trimmed_to_the_limit_and_the_warning_is_emitted() {
    let (http, rx) = fixture(200, THREE_ANSWERS, None);
    let state = "x".repeat(DEFAULT_MAX_STATE_CHARS + 1);
    let (lines, _) = captured(|| {
        pollster::block_on(async {
            adapter(http.clone())
                .ask(&state, &questions())
                .await
                .expect("answered")
        })
    });
    let request = rx.try_recv().expect("one request captured");
    let sent: Value = serde_json::from_str(&request.body).expect("json body");
    let sent_state = sent["state"].as_str().expect("state is a string");
    assert_eq!(
        sent_state.len(),
        DEFAULT_MAX_STATE_CHARS,
        "the request carries the trimmed state"
    );
    assert!(
        lines.iter().any(|line| line.contains("truncated")),
        "expected the truncation warn, got: {lines:?}"
    );
    let warned = lines
        .iter()
        .find(|line| line.contains("truncated"))
        .expect("positive capture asserted above");
    assert!(
        warned.contains(&format!("limit={DEFAULT_MAX_STATE_CHARS}")),
        "the warn records the limit: {warned}"
    );
}

#[pollster::test]
async fn a_state_within_the_limit_is_not_trimmed_and_not_warned() {
    let (http, rx) = fixture(200, THREE_ANSWERS, None);
    let (lines, _) = captured(|| {
        pollster::block_on(async {
            adapter(http.clone())
                .ask("a short state", &questions())
                .await
                .expect("answered")
        })
    });
    let request = rx.try_recv().expect("one request captured");
    let sent: Value = serde_json::from_str(&request.body).expect("json body");
    assert_eq!(sent["state"], "a short state");
    assert!(
        !lines.iter().any(|line| line.contains("truncated")),
        "no trim, no warn: {lines:?}"
    );
}

// ------------------------------- the API key is never logged, never returned

/// A distinctive stand-in key whose literal presence is easy to assert
/// against. Never a real key.
const SECRET_PROBE: &str = "SUPER_SECRET_VALUE_9x8y7z";

/// Process-global capture (see the shared memory note on flaky
/// thread-scoped subscribers): `tracing` caches `Interest::never` per
/// callsite process-wide, so a thread-scoped `with_default` loses events
/// to whichever thread hit the callsite first. A global subscriber means
/// concurrent tests only ever add lines to scan, never remove them.
///
/// The capture is native-only — `cargo test` never runs under wasm32 —
/// and the wasm dispatcher guard enforces exactly that marking: a global
/// dispatcher must never reach a Worker isolate.
#[cfg(not(target_arch = "wasm32"))]
static LOG_LINES: OnceLock<Arc<Mutex<Vec<String>>>> = OnceLock::new();

#[cfg(not(target_arch = "wasm32"))]
fn log_lines() -> &'static Arc<Mutex<Vec<String>>> {
    static INSTALL: Once = Once::new();
    let lines = LOG_LINES.get_or_init(|| Arc::new(Mutex::new(Vec::new())));
    INSTALL.call_once(|| {
        let _ = tracing::subscriber::set_global_default(CapturingSubscriber {
            lines: Arc::clone(lines),
        });
        // Callsites that already cached `never` (tests running before the
        // install) must re-evaluate, or the capture starts empty.
        tracing::callsite::rebuild_interest_cache();
    });
    lines
}

/// Hand-rolled test subscriber: every event becomes one plain line of raw
/// field values — deliberately not core's `RedactingVisitor`, which would
/// mask the very leak these tests hunt.
#[cfg(not(target_arch = "wasm32"))]
struct CapturingSubscriber {
    lines: Arc<Mutex<Vec<String>>>,
}

#[cfg(not(target_arch = "wasm32"))]
impl tracing::Subscriber for CapturingSubscriber {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = LineVisitor(String::new());
        event.record(&mut visitor);
        self.lines.lock().expect("log lock").push(visitor.0);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

#[cfg(not(target_arch = "wasm32"))]
struct LineVisitor(String);

#[cfg(not(target_arch = "wasm32"))]
impl tracing::field::Visit for LineVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.push(field.name(), value);
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.push(field.name(), &format!("{value:?}"));
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl LineVisitor {
    fn push(&mut self, name: &str, rendered: &str) {
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        if name == "message" {
            self.0.push_str(rendered);
        } else {
            self.0.push_str(name);
            self.0.push('=');
            self.0.push_str(rendered);
        }
    }
}

/// Runs `run`, then returns every log line emitted so far. Lines from
/// concurrent tests may be interleaved — absence assertions scan a
/// superset, which only makes them stronger.
#[cfg(not(target_arch = "wasm32"))]
fn captured<T>(run: impl FnOnce() -> T) -> (Vec<String>, T) {
    let lines = log_lines();
    let value = run();
    let captured = lines.lock().expect("log lock").clone();
    (captured, value)
}

/// Nothing in the captured lines, and nothing in any rendered form of the
/// error, may carry the key.
fn assert_key_absent(lines: &[String], rendered: &str) {
    assert!(
        !rendered.contains(SECRET_PROBE),
        "key leaked into a value: {rendered}"
    );
    for line in lines {
        assert!(
            !line.contains(SECRET_PROBE),
            "key leaked into a log line: {line}"
        );
    }
}

#[test]
fn a_transport_failure_never_logs_or_returns_the_key() {
    let (http, _rx) = failing_fixture();
    let classifier = TypeSafe::new(http, clock_at(0), Some(SECRET_PROBE.to_owned()));
    let (lines, error) =
        captured(|| pollster::block_on(async { classifier.ask("state", &questions()).await }));
    let error = error.expect_err("network down");
    assert!(
        lines.iter().any(|line| line.contains("transport failure")),
        "expected the transport warn, got: {lines:?}"
    );
    assert_key_absent(&lines, &error.to_string());
    assert_key_absent(&lines, &format!("{error:?}"));
}

#[test]
fn a_refusal_never_logs_or_returns_the_key() {
    let (http, _rx) = fixture(400, "provider refused", None);
    let classifier = TypeSafe::new(http, clock_at(0), Some(SECRET_PROBE.to_owned()));
    let (lines, error) =
        captured(|| pollster::block_on(async { classifier.ask("state", &questions()).await }));
    let error = error.expect_err("refused");
    assert!(
        lines.iter().any(|line| line.contains("outcome=rejected")),
        "expected the rejection warn, got: {lines:?}"
    );
    assert_key_absent(&lines, &error.to_string());
    assert_key_absent(&lines, &format!("{error:?}"));
}

#[test]
fn an_unparseable_success_body_never_logs_or_returns_the_key() {
    let (http, _rx) = fixture(200, "this is not json", None);
    let classifier = TypeSafe::new(http, clock_at(0), Some(SECRET_PROBE.to_owned()));
    let (lines, error) =
        captured(|| pollster::block_on(async { classifier.ask("state", &questions()).await }));
    let error = error.expect_err("did not survive the hop");
    assert!(
        lines
            .iter()
            .any(|line| line.contains("did not survive the hop")),
        "expected the unparseable-body warn, got: {lines:?}"
    );
    assert_key_absent(&lines, &error.to_string());
    assert_key_absent(&lines, &format!("{error:?}"));
}

#[test]
fn the_key_rides_the_authorization_header_and_nothing_else() {
    let (http, rx) = fixture(200, THREE_ANSWERS, None);
    let classifier = TypeSafe::new(http, clock_at(0), Some(SECRET_PROBE.to_owned()));
    let (lines, _) =
        captured(|| pollster::block_on(async { classifier.ask("state", &questions()).await }));
    let request = rx.try_recv().expect("one request captured");
    let authorization = request
        .headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    assert_eq!(
        authorization,
        Some(format!("Bearer {SECRET_PROBE}").as_str())
    );
    // The request body is state and questions — never the key.
    assert!(!request.body.contains(SECRET_PROBE), "key in the body");
    assert_key_absent(&lines, &request.body);
}
