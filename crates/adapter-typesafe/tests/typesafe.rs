//! `TypeSafe` adapter acceptance tests (issue #456, re-worked onto the
//! documented Jev API): the happy path carries all three question kinds in
//! one request against the recorded example bodies of
//! `docs.typesafe.ai/api.md`, a missing or blank key is `NotConfigured`
//! without touching the network, every vendor failure maps to the error
//! the port names (including both `Retry-After` forms and the vendor's
//! own 529), the vendor's question-size ceilings are refused pre-network,
//! an over-long `state` is trimmed on the wire and logged, and the API key
//! never reaches a log line, a debug render or an error.
//!
//! All through a local fake `HttpClient` — deliberately built here rather
//! than borrowed from `cratefield-testing`, so this crate's tests do not
//! depend on a crate that is free to change under them.

// Test-side recording fixture, not request state — the same category
// and allowance as the fakes in `cratefield-testing` (ADR 0007 policy).
#![allow(clippy::disallowed_types)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_adapter_typesafe::{DEFAULT_ENDPOINT, DEFAULT_MODEL, TypeSafe};
use cratefield_core::{
    AnswerValue, Calibration, Classifier, ClassifierError, ClassifierProfile, Clock,
    DEFAULT_MAX_STATE_CHARS, HttpClient, HttpError, HttpPolicy, MAX_RESPONSE_BYTES,
    MAX_RESPONSE_TIMEOUT, Question,
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

/// The documented example request/response pair, recorded verbatim from
/// `https://docs.typesafe.ai/api.md`.
const REQUEST_FIXTURE: &str = include_str!("fixtures/request.json");
const RESPONSE_FIXTURE: &str = include_str!("fixtures/response.json");

/// A 200 carrying one answer per question, all three kinds, in the
/// documented shape. The score answer is weighted over the level
/// *indices* Jev was sent (`"0"` = the port's `"1"`, `"1"` = its `"5"`),
/// at exactly index 1 — the port's `5`.
const THREE_ANSWERS: &str = r#"{"model":"jev-1.13.0","answers":{
  "topic":{"type":"choice","choice":"bugs","probabilities":{"billing":0.1,"bugs":0.9},"confidence":0.9},
  "severity":{"type":"score","score":1.0,"probabilities":{"0":0.7,"1":0.3},"confidence":0.7},
  "angry":{"type":"noul","noul":0.2}},
  "usage":{"input_tokens":296,"output_tokens":20}}"#;

// ---------------------------------------------------------------- fixtures

struct CapturedRequest {
    method: String,
    uri: String,
    headers: HeaderMap,
    body: String,
    /// The `HttpPolicy` the adapter attached, if it did.
    policy_timeout: Option<Duration>,
    policy_max_bytes: Option<usize>,
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
        let policy = parts.extensions.get::<HttpPolicy>();
        self.tx
            .send(CapturedRequest {
                method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                headers: parts.headers,
                body: String::from_utf8_lossy(&body).to_string(),
                policy_timeout: policy.map(|policy| policy.timeout),
                policy_max_bytes: policy.map(|policy| policy.max_response_bytes),
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
    // Jev's index 1 is the port's second level, named `5`.
    let severity = &answers["severity"];
    assert_eq!(severity.value, AnswerValue::Score(5.0));
    assert!((severity.probabilities["1"] - 0.7).abs() < f32::EPSILON);
    assert!((severity.probabilities["5"] - 0.3).abs() < f32::EPSILON);
    assert!(
        (severity.confidence - 0.7).abs() < f32::EPSILON,
        "{severity:?}"
    );
    // p(yes) = 0.2: verdict false, confidence the chosen side's 1 - p.
    let angry = &answers["angry"];
    assert_eq!(angry.value, AnswerValue::Noul(false));
    assert!((angry.confidence - 0.8).abs() < f32::EPSILON, "{angry:?}");
    // The vendor-reported model rides on every answer.
    for (id, answer) in &answers {
        assert_eq!(answer.model.as_deref(), Some("jev-1.13.0"), "{id}");
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
    assert_eq!(request.uri, DEFAULT_ENDPOINT);
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
    assert_eq!(sent["model"], DEFAULT_MODEL, "the pinned model is sent");
    let sent_questions = sent["questions"].as_object().expect("questions map");
    assert_eq!(sent_questions.len(), 3, "all questions in one request");

    let topic = &sent_questions["topic"];
    assert_eq!(topic["type"], "choice");
    assert_eq!(
        topic["instructions"],
        "Which topic does the note belong to?"
    );
    assert_eq!(topic["criteria"]["billing"], "money, invoices");
    assert_eq!(topic["criteria"]["bugs"], "something is broken");

    let severity = &sent_questions["severity"];
    assert_eq!(severity["type"], "score");
    assert_eq!(severity["instructions"], "How severe is the note?");
    // The ordered level descriptions travel; the port's level names do
    // not — Jev answers in index space and the adapter re-keys.
    assert_eq!(
        severity["criteria"],
        serde_json::json!(["a typo", "data loss"])
    );

    let angry = &sent_questions["angry"];
    assert_eq!(angry["type"], "noul");
    assert_eq!(angry["instructions"], "Is the writer angry?");
    assert!(
        angry.get("criteria").is_none(),
        "a noul carries no criteria the port does not have"
    );
}

#[pollster::test]
async fn the_wire_body_matches_the_documented_example() {
    // The docs' example asks by the `jev-latest` alias; the adapter pins
    // by default, so the alias is what the pin is overridden to here.
    let (http, rx) = fixture(200, RESPONSE_FIXTURE, None);
    let questions = BTreeMap::from([(
        "is_urgent".to_owned(),
        Question::Noul {
            instructions: "Does this convey urgency?".to_owned(),
        },
    )]);
    adapter(http)
        .with_model("jev-latest")
        .ask("Help! My payouts have been failing for 3 days.", &questions)
        .await
        .expect("answered");
    let request = rx.try_recv().expect("one request captured");
    let sent: Value = serde_json::from_str(&request.body).expect("json body");
    let recorded: Value = serde_json::from_str(REQUEST_FIXTURE).expect("recorded fixture");
    assert_eq!(
        sent, recorded,
        "the wire body is the documented example, verbatim"
    );
}

#[pollster::test]
async fn the_documented_example_response_maps_onto_the_port() {
    let (http, _rx) = fixture(200, RESPONSE_FIXTURE, None);
    let questions = BTreeMap::from([(
        "is_urgent".to_owned(),
        Question::Noul {
            instructions: "Does this convey urgency?".to_owned(),
        },
    )]);
    let answers = adapter(http)
        .ask("Help! My payouts have been failing for 3 days.", &questions)
        .await
        .expect("answered");
    let urgent = &answers["is_urgent"];
    // p(yes) = 0.95: verdict true, the other side derived as 1 - p, and
    // the confidence the chosen side's probability.
    assert_eq!(urgent.value, AnswerValue::Noul(true));
    assert!((urgent.probabilities["true"] - 0.95).abs() < f32::EPSILON);
    assert!((urgent.probabilities["false"] - 0.05).abs() < f32::EPSILON);
    assert!(
        (urgent.confidence - 0.95).abs() < f32::EPSILON,
        "{urgent:?}"
    );
    // The version the vendor reports it answered under, recorded.
    assert_eq!(urgent.model.as_deref(), Some("jev-1.13.0"));
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

// ---------------------------------------------------------------- model pinning

#[pollster::test]
async fn with_model_overrides_the_pin_in_the_request_body() {
    let (http, rx) = fixture(200, THREE_ANSWERS, None);
    adapter(http)
        .with_model("jev-1.14.0")
        .ask("a customer note", &questions())
        .await
        .expect("answered");
    let request = rx.try_recv().expect("one request captured");
    let sent: Value = serde_json::from_str(&request.body).expect("json body");
    assert_eq!(sent["model"], "jev-1.14.0");
}

#[pollster::test]
async fn the_resolved_model_is_what_the_vendor_said_it_answered_under() {
    // The body names a version different from the one asked: the answers
    // record what the vendor reported, not what was requested.
    let (http, _rx) = fixture(
        200,
        r#"{"model":"jev-1.14.0","answers":{
          "angry":{"type":"noul","noul":0.9}}}"#,
        None,
    );
    let questions = BTreeMap::from([(
        "angry".to_owned(),
        Question::Noul {
            instructions: "Is the writer angry?".to_owned(),
        },
    )]);
    let answers = adapter(http)
        .with_model("jev-latest")
        .ask("state", &questions)
        .await
        .expect("answered");
    assert_eq!(answers["angry"].model.as_deref(), Some("jev-1.14.0"));

    // A body without `model` falls back to the model that was asked.
    let (http, _rx) = fixture(
        200,
        r#"{"answers":{"angry":{"type":"noul","noul":0.9}}}"#,
        None,
    );
    let answers = adapter(http)
        .with_model("jev-latest")
        .ask("state", &questions)
        .await
        .expect("answered");
    assert_eq!(answers["angry"].model.as_deref(), Some("jev-latest"));
}

// -------------------------------------------------------------- endpoint override

#[pollster::test]
async fn the_endpoint_override_is_what_is_posted_to() {
    let (http, rx) = fixture(200, THREE_ANSWERS, None);
    adapter(http)
        .with_endpoint("http://127.0.0.1:9/v1/systemone")
        .ask("a customer note", &questions())
        .await
        .expect("answered");
    let request = rx.try_recv().expect("one request captured");
    assert_eq!(request.uri, "http://127.0.0.1:9/v1/systemone");
}

// ------------------------------------------------------------- vendor ceilings

#[pollster::test]
async fn a_choice_over_the_vendors_255_options_is_rejected_before_the_wire() {
    let (http, _rx) = fixture(200, THREE_ANSWERS, None);
    let criteria: BTreeMap<String, String> = (0..=255)
        .map(|n| (format!("option-{n}"), "an option".to_owned()))
        .collect();
    let questions = BTreeMap::from([(
        "big".to_owned(),
        Question::Choice {
            instructions: "Pick one.".to_owned(),
            criteria,
        },
    )]);
    let error = adapter(http.clone())
        .ask("state", &questions)
        .await
        .expect_err("over the vendor's ceiling");
    assert!(matches!(error, ClassifierError::Rejected(_)), "{error:?}");
    assert_eq!(http.calls.load(Ordering::SeqCst), 0, "no request spent");
}

#[pollster::test]
async fn a_score_over_the_vendors_10_levels_is_rejected_before_the_wire() {
    let (http, _rx) = fixture(200, THREE_ANSWERS, None);
    let levels: Vec<(String, String)> = (0..=10)
        .map(|n| (format!("level-{n}"), "a level".to_owned()))
        .collect();
    let questions = BTreeMap::from([(
        "long".to_owned(),
        Question::Score {
            instructions: "Rate it.".to_owned(),
            levels,
        },
    )]);
    let error = adapter(http.clone())
        .ask("state", &questions)
        .await
        .expect_err("over the vendor's ceiling");
    assert!(matches!(error, ClassifierError::Rejected(_)), "{error:?}");
    assert_eq!(http.calls.load(Ordering::SeqCst), 0, "no request spent");
}

// -------------------------------------------------------------- error mapping

#[pollster::test]
async fn an_http_4xx_is_rejected_with_the_body() {
    for status in [400_u16, 401, 422] {
        let (http, _rx) = fixture(status, r#"{"error":"invalid api key"}"#, None);
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
async fn the_vendors_529_overloaded_is_transient_with_the_back_off() {
    let (http, _rx) = fixture(529, "overloaded", Some("7"));
    let error = adapter(http.clone())
        .ask("state", &questions())
        .await
        .expect_err("overloaded");
    assert_eq!(
        error,
        ClassifierError::Transient {
            retry_after: Some(Duration::from_secs(7))
        },
        "529 is the vendor's own retryable status, not a refusal"
    );
    assert_eq!(error.retry_after(), Some(Duration::from_secs(7)));
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
    // A 200 without the answers map is the same hop failure.
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
        r#"{"answers":{
          "topic":{"type":"choice","choice":"shipping","probabilities":{"shipping":1.0},"confidence":1.0}}}"#,
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
async fn an_answer_of_the_wrong_shape_is_rejected() {
    // A noul question answered as a choice.
    let (http, _rx) = fixture(
        200,
        r#"{"answers":{
          "angry":{"type":"choice","choice":"true","probabilities":{"true":1.0},"confidence":1.0}}}"#,
        None,
    );
    let error = adapter(http)
        .ask("state", &questions())
        .await
        .expect_err("shape mismatch");
    assert!(matches!(error, ClassifierError::Rejected(_)), "{error:?}");
}

#[pollster::test]
async fn a_response_missing_a_question_id_is_rejected_not_invented() {
    let (http, _rx) = fixture(
        200,
        r#"{"answers":{
          "topic":{"type":"choice","choice":"bugs","probabilities":{"bugs":1.0},"confidence":1.0}}}"#,
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
    let _limit = STATE_LIMIT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
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
    let _limit = STATE_LIMIT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (http, rx) = fixture(200, THREE_ANSWERS, None);
    // This call's own lines, with the sibling that emits a truncation
    // warning held off: a superset scan would read its line as this one's.
    let (lines, _) = captured_own(|| {
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

// ------------------------------------------------------------------ the request policy

#[pollster::test]
async fn the_request_carries_a_deadline_well_under_the_port_ceiling() {
    let (http, rx) = fixture(200, THREE_ANSWERS, None);
    adapter(http)
        .ask("a customer note", &questions())
        .await
        .expect("answered");
    let request = rx.try_recv().expect("one request captured");
    let timeout = request.policy_timeout.expect("an HttpPolicy is attached");
    assert_eq!(timeout, Duration::from_secs(20));
    assert!(
        timeout < MAX_RESPONSE_TIMEOUT,
        "well under the port's own ceiling, not equal to it"
    );
    // The response cap is the port default, stated explicitly.
    assert_eq!(request.policy_max_bytes, Some(MAX_RESPONSE_BYTES));
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

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows_from: &tracing::span::Id) {}

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

/// Serialises the two state-limit tests against each other.
///
/// One of them emits the truncation warning and the other asserts nobody
/// did. The capture is one global list, so the sibling's line lands in
/// this one's window whenever they overlap — slicing by index does not
/// help, because the appends interleave inside the window too. No other
/// test in this file writes that word, so holding this for both is enough
/// and costs nothing anywhere else.
#[cfg(not(target_arch = "wasm32"))]
static STATE_LIMIT: Mutex<()> = Mutex::new(());

/// Runs `run` and returns only the lines IT emitted.
///
/// [`captured`]'s superset is the right shape for the key assertions — a
/// secret must appear in no line at all, whoever wrote it — but not for an
/// absence assertion about behaviour. "no line says truncated" scanned
/// over a superset fails whenever a truncation test happens to run
/// alongside, which is exactly what it did. Slicing from the pre-run
/// length keeps the claim about this test's own call.
#[cfg(not(target_arch = "wasm32"))]
fn captured_own<T>(run: impl FnOnce() -> T) -> (Vec<String>, T) {
    let lines = log_lines();
    let before = lines.lock().expect("log lock").len();
    let value = run();
    let after = lines.lock().expect("log lock").clone();
    (after[before.min(after.len())..].to_vec(), value)
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
fn debug_names_the_endpoint_and_model_never_the_key() {
    let (http, _rx) = fixture(200, THREE_ANSWERS, None);
    let adapter = TypeSafe::new(http, clock_at(0), Some(SECRET_PROBE.to_owned()));
    let rendered = format!("{adapter:?}");
    assert!(!rendered.contains(SECRET_PROBE), "{rendered}");
    assert!(rendered.contains(DEFAULT_ENDPOINT), "{rendered}");
    assert!(rendered.contains(DEFAULT_MODEL), "{rendered}");
    assert!(rendered.contains("api_key_configured"), "{rendered}");
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
