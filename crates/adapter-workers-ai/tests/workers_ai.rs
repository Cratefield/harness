//! The adapter's behaviour against a fake `AiRunner`: the binding cannot be
//! constructed off wasm, but every line around the call — request building,
//! the one-call-per-ask contract, truncation, parsing, refusals, error
//! pass-through — is exercised here, natively.

#![allow(clippy::disallowed_types)]

use async_trait::async_trait;
use cratefield_adapter_workers_ai::{
    AiRunner, DEFAULT_MODEL_ID, WORKERS_AI_CONTEXT_TOKENS, WorkersAi,
};
use cratefield_core::{
    Answer, AnswerValue, Calibration, Classifier, ClassifierError, ClassifierProfile,
    DEFAULT_MAX_STATE_CHARS, Question,
};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, Once, OnceLock};

/// A stand-in binding: records every call and plays back programmed
/// responses in order. Each test programs exactly the calls it expects; an
/// unprogrammed call fails loudly rather than inventing an answer.
///
/// Cheaply cloneable so a test keeps a handle to the calls after the fake
/// has been handed to the adapter.
#[derive(Clone)]
struct FakeRunner {
    inner: Arc<Inner>,
}

struct Inner {
    state: Mutex<FakeState>,
}

struct FakeState {
    calls: Vec<Call>,
    responses: VecDeque<Result<serde_json::Value, ClassifierError>>,
}

#[derive(Clone)]
struct Call {
    model: String,
    input: serde_json::Value,
}

impl FakeRunner {
    fn answering(response: serde_json::Value) -> Self {
        Self::with_responses(vec![Ok(response)])
    }

    fn failing(error: ClassifierError) -> Self {
        Self::with_responses(vec![Err(error)])
    }

    fn with_responses(responses: Vec<Result<serde_json::Value, ClassifierError>>) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(FakeState {
                    calls: Vec::new(),
                    responses: responses.into(),
                }),
            }),
        }
    }

    fn calls(&self) -> Vec<Call> {
        self.inner.state.lock().expect("fake lock").calls.clone()
    }
}

#[async_trait]
impl AiRunner for FakeRunner {
    async fn run(
        &self,
        model: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ClassifierError> {
        let mut state = self.inner.state.lock().expect("fake lock");
        state.calls.push(Call {
            model: model.to_owned(),
            input,
        });
        state
            .responses
            .pop_front()
            .expect("every call is programmed a response")
    }
}

fn question_set() -> BTreeMap<String, Question> {
    BTreeMap::from([
        (
            "topic".to_owned(),
            Question::Choice {
                instructions: "Which topic?".to_owned(),
                criteria: BTreeMap::from([
                    ("billing".to_owned(), "money, invoices".to_owned()),
                    ("bugs".to_owned(), "something is broken".to_owned()),
                ]),
            },
        ),
        (
            "severity".to_owned(),
            Question::Score {
                instructions: "How severe?".to_owned(),
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

fn classifier(runner: FakeRunner) -> WorkersAi<FakeRunner> {
    WorkersAi::with_runner(
        runner,
        DEFAULT_MODEL_ID,
        ClassifierProfile::new(Calibration::Classifier, DEFAULT_MAX_STATE_CHARS),
    )
}

fn label_answer(id: &str, label: &str, probabilities: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "id": id, "value": label, "probabilities": probabilities })
}

fn number_answer(id: &str, score: f64, probabilities: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "id": id, "value": score, "probabilities": probabilities })
}

fn run_output(answers: &[serde_json::Value]) -> serde_json::Value {
    serde_json::json!({ "answers": answers })
}

fn full_happy_output() -> serde_json::Value {
    run_output(&[
        label_answer(
            "topic",
            "bugs",
            &serde_json::json!({ "billing": 0.1, "bugs": 0.9 }),
        ),
        number_answer("severity", 5.0, &serde_json::json!({ "5": 1.0 })),
        label_answer(
            "angry",
            "false",
            &serde_json::json!({ "true": 0.2, "false": 0.8 }),
        ),
    ])
}

// --- Process-global log capture -------------------------------------------

/// Process-global capture: `tracing` caches `Interest::never` per callsite
/// process-wide, so a thread-scoped `with_default` loses events to whichever
/// thread hit the callsite first. A global subscriber means concurrent tests
/// only ever add lines to scan, never remove them.
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

// --- The call itself ------------------------------------------------------

#[test]
fn one_call_carries_the_state_and_every_question() {
    let runner = FakeRunner::answering(full_happy_output());
    let adapter = classifier(runner.clone());
    let answers =
        pollster::block_on(adapter.ask("the whole state", &question_set())).expect("answers");
    assert_eq!(answers.len(), 3);

    let calls = runner.calls();
    assert_eq!(calls.len(), 1, "one ask, one run() call");
    let call = &calls[0];
    assert_eq!(call.input["state"], "the whole state");
    let sent = call.input["questions"].as_array().expect("questions array");
    assert_eq!(sent.len(), 3);
    let mut ids: Vec<_> = sent
        .iter()
        .map(|question| question["id"].as_str().expect("id"))
        .collect();
    ids.sort_unstable();
    assert_eq!(ids, vec!["angry", "severity", "topic"]);
}

#[test]
fn the_default_model_is_typesafe_jev_and_an_override_is_honoured() {
    let runner = FakeRunner::answering(full_happy_output());
    let adapter = classifier(runner.clone());
    let _ = pollster::block_on(adapter.ask("state", &question_set()));
    assert_eq!(DEFAULT_MODEL_ID, "typesafe/jev");
    assert_eq!(runner.calls()[0].model, "typesafe/jev");

    let runner = FakeRunner::answering(full_happy_output());
    let adapter = WorkersAi::with_runner(
        runner.clone(),
        "typesafe/jev@2026-06",
        ClassifierProfile::new(Calibration::Classifier, DEFAULT_MAX_STATE_CHARS),
    );
    let _ = pollster::block_on(adapter.ask("state", &question_set()));
    assert_eq!(runner.calls()[0].model, "typesafe/jev@2026-06");
}

#[test]
fn the_profile_names_the_classifier_family_and_the_window() {
    let adapter = classifier(FakeRunner::answering(full_happy_output()));
    let profile = adapter.profile();
    assert_eq!(profile.calibration, Calibration::Classifier);
    assert_eq!(profile.max_state_chars, DEFAULT_MAX_STATE_CHARS);
    assert_eq!(WORKERS_AI_CONTEXT_TOKENS, 32_000);
    // Compile-time: the constants must keep this relationship, so the
    // default ceiling always leaves room for the questions in the window.
    const {
        assert!(DEFAULT_MAX_STATE_CHARS < WORKERS_AI_CONTEXT_TOKENS * 4);
    }
}

// --- Mapped answers -------------------------------------------------------

#[test]
fn every_kind_maps_with_confidence_agreeing_with_probabilities() {
    // `topic` deliberately arrives under-normalised (0.3 + 0.3): the model's
    // distribution is normalised, and `confidence` must agree with it.
    let runner = FakeRunner::answering(run_output(&[
        label_answer(
            "topic",
            "bugs",
            &serde_json::json!({ "billing": 0.3, "bugs": 0.3 }),
        ),
        number_answer("severity", 5.0, &serde_json::json!({ "5": 1.0 })),
        label_answer(
            "angry",
            "false",
            &serde_json::json!({ "true": 0.2, "false": 0.8 }),
        ),
    ]));
    let adapter = classifier(runner);
    let answers = pollster::block_on(adapter.ask("state", &question_set())).expect("answers");

    let topic = &answers["topic"];
    assert_eq!(topic.value, AnswerValue::Choice("bugs".to_owned()));
    assert!(
        (topic.probabilities["bugs"] - 0.5).abs() < 1.0e-6,
        "{topic:?}"
    );
    assert!(
        (topic.probabilities["billing"] - 0.5).abs() < 1.0e-6,
        "{topic:?}"
    );
    assert!((topic.confidence - 0.5).abs() < 1.0e-6, "{topic:?}");

    let severity = &answers["severity"];
    assert_eq!(severity.value, AnswerValue::Score(5.0));
    assert!((severity.confidence - 1.0).abs() < 1.0e-6, "{severity:?}");

    let angry = &answers["angry"];
    assert_eq!(angry.value, AnswerValue::Noul(false));
    assert!((angry.confidence - 0.8).abs() < 1.0e-6, "{angry:?}");
    let expected = Answer::noul(false, angry.probabilities.clone());
    assert_eq!(angry.value, expected.value);
    assert!((angry.confidence - expected.confidence).abs() < 1.0e-6);
}

#[test]
fn a_malformed_set_is_rejected_before_any_call() {
    let empty: BTreeMap<String, Question> = BTreeMap::new();
    let one_criterion = BTreeMap::from([(
        "topic".to_owned(),
        Question::Choice {
            instructions: "Which topic?".to_owned(),
            criteria: BTreeMap::from([("bugs".to_owned(), "broken".to_owned())]),
        },
    )]);
    for (what, questions) in [("empty set", &empty), ("one criterion", &one_criterion)] {
        let runner = FakeRunner::answering(full_happy_output());
        let adapter = classifier(runner.clone());
        let outcome = pollster::block_on(adapter.ask("state", questions));
        assert!(
            matches!(outcome, Err(ClassifierError::Rejected(_))),
            "{what}: {outcome:?}"
        );
        assert!(runner.calls().is_empty(), "{what}: no call may be made");
    }
}

#[test]
fn a_malformed_answer_set_is_rejected() {
    let cases: Vec<(&str, serde_json::Value)> = vec![
        // An id that was not asked.
        (
            "unasked id",
            run_output(&[label_answer(
                "offTopic",
                "bugs",
                &serde_json::json!({ "bugs": 1.0 }),
            )]),
        ),
        // A label the question never offered.
        (
            "unknown label",
            run_output(&[label_answer(
                "topic",
                "shipping",
                &serde_json::json!({ "shipping": 1.0 }),
            )]),
        ),
        // A distribution that cannot be normalised.
        (
            "empty distribution",
            run_output(&[label_answer("topic", "bugs", &serde_json::json!({}))]),
        ),
        // A probability outside [0, 1].
        (
            "probability above one",
            run_output(&[label_answer(
                "topic",
                "bugs",
                &serde_json::json!({ "bugs": 1.5 }),
            )]),
        ),
        // A score off its numeric scale.
        (
            "off-scale score",
            run_output(&[number_answer(
                "severity",
                3.5,
                &serde_json::json!({ "5": 1.0 }),
            )]),
        ),
        // A choice answered with a number.
        (
            "number for a choice",
            run_output(&[number_answer(
                "topic",
                1.0,
                &serde_json::json!({ "bugs": 1.0 }),
            )]),
        ),
        // A question the model skipped.
        (
            "skipped question",
            run_output(&[label_answer(
                "topic",
                "bugs",
                &serde_json::json!({ "bugs": 1.0 }),
            )]),
        ),
    ];
    for (what, output) in cases {
        let runner = FakeRunner::answering(output);
        let adapter = classifier(runner);
        let outcome = pollster::block_on(adapter.ask("state", &question_set()));
        assert!(
            matches!(outcome, Err(ClassifierError::Rejected(_))),
            "{what}: {outcome:?}"
        );
    }
}

// --- Error pass-through ---------------------------------------------------

#[test]
fn runner_errors_pass_through_verbatim() {
    let adapter = classifier(FakeRunner::failing(ClassifierError::NotConfigured));
    let outcome = pollster::block_on(adapter.ask("state", &question_set()));
    assert!(matches!(outcome, Err(ClassifierError::NotConfigured)));

    let adapter = classifier(FakeRunner::failing(ClassifierError::Transient {
        retry_after: None,
    }));
    let outcome = pollster::block_on(adapter.ask("state", &question_set()));
    match outcome {
        Err(err @ ClassifierError::Transient { retry_after }) => {
            // The binding offers no hint; the adapter must not invent one.
            assert!(retry_after.is_none());
            assert_eq!(err.retry_after(), None);
        }
        other => panic!("expected transient, got {other:?}"),
    }

    let adapter = classifier(FakeRunner::failing(ClassifierError::Transport(
        "workerd hiccup".to_owned(),
    )));
    let outcome = pollster::block_on(adapter.ask("state", &question_set()));
    assert!(matches!(outcome, Err(ClassifierError::Transport(_))));
}

#[test]
fn a_body_that_does_not_parse_is_transport() {
    let adapter = classifier(FakeRunner::answering(serde_json::json!({
        "something": "else"
    })));
    let outcome = pollster::block_on(adapter.ask("state", &question_set()));
    assert!(
        matches!(outcome, Err(ClassifierError::Transport(_))),
        "{outcome:?}"
    );
}

// --- Truncation -----------------------------------------------------------

#[test]
fn an_oversize_state_is_trimmed_on_the_wire_and_the_trim_is_loud() {
    let long_state = "a".repeat(40);
    let runner = FakeRunner::answering(full_happy_output());
    let adapter = WorkersAi::with_runner(
        runner.clone(),
        DEFAULT_MODEL_ID,
        ClassifierProfile::new(Calibration::Classifier, 16),
    );
    let questions = question_set();
    let (lines, outcome) = captured(|| pollster::block_on(adapter.ask(&long_state, &questions)));
    outcome.expect("answers");

    let calls = runner.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].input["state"], "a".repeat(16));
    assert!(
        lines
            .iter()
            .any(|line| line.contains("truncated") && line.contains("limit=16")),
        "the truncation warning must fire with its limit: {lines:?}"
    );
    assert!(
        lines.iter().all(|line| !line.contains(&long_state)),
        "the state text never belongs in a log line: {lines:?}"
    );
}
