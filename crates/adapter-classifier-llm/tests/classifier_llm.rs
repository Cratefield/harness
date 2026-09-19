//! The `ClassifierLlm` adapter, exercised end to end through the shared
//! `FakeTextModel`: one call per ask, the structured-output fallbacks,
//! the model-output validation, the error mapping, and the truncation
//! contract with its warning.

use cratefield_adapter_classifier_llm::ClassifierLlm;
use cratefield_core::{
    AnswerValue, Calibration, Classifier, ClassifierError, ClassifierProfile, Completion,
    DEFAULT_MAX_STATE_CHARS, ModelTier, Question,
};
use cratefield_testing::{FakeTextModel, TextModelMode};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Fixtures

/// One question of each shape: a choice, a score, a yes/no.
fn good_questions() -> BTreeMap<String, Question> {
    BTreeMap::from([
        (
            "topic".to_owned(),
            Question::Choice {
                instructions: "Which topic does the note belong to?".to_owned(),
                criteria: BTreeMap::from([
                    ("billing".to_owned(), "money and invoices".to_owned()),
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

/// One answer entry the way the schema pins it.
fn entry(value: &str, probabilities: serde_json::Value) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    object.insert("value".to_owned(), serde_json::Value::from(value));
    object.insert("probabilities".to_owned(), probabilities);
    serde_json::Value::Object(object)
}

/// A well-formed answer to all three fixture questions.
fn good_answers() -> serde_json::Value {
    serde_json::json!({
        "answers": {
            "topic": entry("billing", serde_json::json!({ "billing": 0.9, "bugs": 0.1 })),
            "severity": entry("5", serde_json::json!({ "1": 0.1, "5": 0.9 })),
            "angry": entry("true", serde_json::json!({ "true": 0.8, "false": 0.2 })),
        }
    })
}

/// A completion that carries the structured payload the schema asked for.
fn structured(json: serde_json::Value) -> TextModelMode {
    TextModelMode::Complete(Completion::new("ignored", "structured-vendor").json(json))
}

/// Asks the adapter through a fake in `mode`, returning the fake (for the
/// recorded prompts) and the outcome.
fn ask_with(
    mode: TextModelMode,
    questions: &BTreeMap<String, Question>,
) -> (
    FakeTextModel,
    Result<BTreeMap<String, cratefield_core::Answer>, ClassifierError>,
) {
    install_log_capture();
    let model = FakeTextModel::new(mode);
    let adapter = ClassifierLlm::new(Arc::new(model.clone()));
    let answers =
        pollster::block_on(adapter.ask("a customer note about a late invoice", questions));
    (model, answers)
}

fn close(a: f32, b: f32) -> bool {
    (a - b).abs() < 1e-6
}

// ---------------------------------------------------------------------------
// The truncation warning

// The whole capture below is native-only: `cargo test` never runs under
// wasm32, and a global dispatcher must never reach a Worker isolate (the
// wasm dispatcher guard enforces exactly that marking).
/// Every emitted event whose message says the state was truncated bumps
/// this counter. An atomic, not a `Mutex`: the only thing any test wants
/// to know about logging is that the warn fired.
#[cfg(not(target_arch = "wasm32"))]
static TRUNCATION_WARNS: AtomicUsize = AtomicUsize::new(0);

#[cfg(not(target_arch = "wasm32"))]
static INSTALL: std::sync::Once = std::sync::Once::new();

#[cfg(not(target_arch = "wasm32"))]
struct CountingSubscriber;

#[cfg(not(target_arch = "wasm32"))]
struct Line(String);

#[cfg(not(target_arch = "wasm32"))]
impl tracing::field::Visit for Line {
    fn record_debug(&mut self, _field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let _ = write!(self.0, " {value:?}");
    }

    fn record_u64(&mut self, _field: &tracing::field::Field, value: u64) {
        let _ = write!(self.0, " {value}");
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl tracing::Subscriber for CountingSubscriber {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut line = Line(String::new());
        event.record(&mut line);
        if line.0.contains("truncated") {
            TRUNCATION_WARNS.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

/// Installs the counting subscriber once, before any test can trip the
/// adapter's `warn!` — a callsite's interest is fixed at its first
/// execution, so the subscriber must be in place before the first.
#[cfg(not(target_arch = "wasm32"))]
fn install_log_capture() {
    INSTALL.call_once(|| {
        let _ = tracing::subscriber::set_global_default(CountingSubscriber);
    });
}

// ---------------------------------------------------------------------------
// The profile

#[test]
fn the_profile_reports_language_model_calibration_and_the_state_ceiling() {
    install_log_capture();
    let adapter = ClassifierLlm::new(Arc::new(FakeTextModel::default()));
    assert_eq!(
        adapter.profile(),
        ClassifierProfile::new(Calibration::LanguageModel, DEFAULT_MAX_STATE_CHARS)
    );
    // The state-ceiling override reports through the profile too — it is
    // what a caller can learn about the adapter, not a hidden knob.
    let tuned = ClassifierLlm::new(Arc::new(FakeTextModel::default())).max_state_chars(500);
    assert_eq!(
        tuned.profile(),
        ClassifierProfile::new(Calibration::LanguageModel, 500)
    );
}

// ---------------------------------------------------------------------------
// The happy path: one call, all three kinds

#[test]
fn all_three_kinds_are_answered_in_one_complete_call() {
    let (model, answers) = ask_with(structured(good_answers()), &good_questions());
    let answers = answers.expect("the happy path answers");

    let (topic, severity, angry) = (&answers["topic"], &answers["severity"], &answers["angry"]);
    assert_eq!(topic.value, AnswerValue::Choice("billing".to_owned()));
    assert!(close(topic.probabilities["billing"], 0.9), "{topic:?}");
    assert!(close(topic.probabilities["bugs"], 0.1), "{topic:?}");
    assert!(
        close(topic.confidence, 0.9),
        "confidence agrees with the chosen label"
    );

    assert_eq!(severity.value, AnswerValue::Score(5.0));
    assert!(close(severity.probabilities["5"], 0.9), "{severity:?}");
    assert!(close(severity.confidence, 0.9));

    assert_eq!(angry.value, AnswerValue::Noul(true));
    assert!(close(angry.probabilities["true"], 0.8), "{angry:?}");
    assert!(close(angry.confidence, 0.8));

    // Asking as a set is the port's whole point: exactly one completion.
    let prompts = model.prompts();
    assert_eq!(
        prompts.len(),
        1,
        "all questions travel in ONE complete call"
    );

    let prompt = &prompts[0];
    assert_eq!(
        prompt.tier,
        ModelTier::Strong,
        "a judging task defaults to Strong"
    );
    let schema = prompt
        .json_schema
        .as_ref()
        .expect("the prompt asks for structured output");
    assert_eq!(
        schema["properties"]["answers"]["required"],
        serde_json::json!(["angry", "severity", "topic"]),
        "the schema pins every question id"
    );
    let user = &prompt.messages[0].content;
    assert!(
        user.contains("a customer note about a late invoice"),
        "the state travels"
    );
    assert!(
        user.contains("data loss"),
        "the questions render with their meanings"
    );
    assert!(user.contains("billing"), "the labels travel");
}

#[test]
fn the_tier_builder_overrides_the_default() {
    install_log_capture();
    let model = FakeTextModel::new(structured(good_answers()));
    let adapter = ClassifierLlm::new(Arc::new(model.clone())).tier(ModelTier::Fast);
    let answers = pollster::block_on(adapter.ask("state", &good_questions()));
    answers.expect("answers");
    assert_eq!(model.prompts()[0].tier, ModelTier::Fast);
}

// ---------------------------------------------------------------------------
// Structured output is a request: the plain-text fallbacks

#[test]
fn a_markdown_fenced_text_answer_is_parsed() {
    let text = format!("```json\n{}\n```", good_answers());
    let (model, answers) = ask_with(TextModelMode::Reply(text), &good_questions());
    answers.expect("a fenced body parses");
    assert_eq!(model.prompts().len(), 1, "the fallback is still one call");
}

#[test]
fn a_bare_text_answer_is_parsed() {
    let (model, answers) = ask_with(
        TextModelMode::Reply(good_answers().to_string()),
        &good_questions(),
    );
    answers.expect("a bare JSON body parses");
    assert_eq!(model.prompts().len(), 1);
}

#[test]
fn no_json_and_unparseable_text_is_transport_without_echoing_the_completion() {
    // The documented shape of a provider that cannot honour structured
    // output: plain text, `json` left `None` — and the text is not JSON.
    let mode =
        TextModelMode::Complete(Completion::new("I cannot classify LEAK-ANCHOR-42", "plain"));
    let (_, answers) = ask_with(mode, &good_questions());
    let error = answers.expect_err("unparseable text is an error");
    assert!(matches!(error, ClassifierError::Transport(_)), "{error:?}");
    let rendered = error.to_string();
    assert!(!rendered.contains("LEAK-ANCHOR-42"), "{rendered}");
}

// ---------------------------------------------------------------------------
// TextModelError mapping

#[test]
fn an_unwired_tier_surfaces_as_not_configured() {
    // This is how "no classifier vendor wired" surfaces honestly: the
    // `TextModel` tier underneath is unwired, and the mapping keeps the
    // variant the caller can match and degrade on.
    let (_, answers) = ask_with(TextModelMode::NotConfigured, &good_questions());
    let error = answers.expect_err("unwired");
    assert_eq!(error, ClassifierError::NotConfigured);
    assert_eq!(error.retry_after(), None);
}

#[test]
fn a_provider_refusal_maps_to_rejected_with_its_text() {
    let (_, answers) = ask_with(
        TextModelMode::Rejected("provider 4xx refused the schema".to_owned()),
        &good_questions(),
    );
    assert_eq!(
        answers.expect_err("refused"),
        ClassifierError::Rejected("provider 4xx refused the schema".to_owned())
    );
}

#[test]
fn a_transient_failure_preserves_the_retry_after() {
    let (_, answers) = ask_with(
        TextModelMode::Transient {
            retry_after: Some(Duration::from_secs(30)),
        },
        &good_questions(),
    );
    let error = answers.expect_err("throttled");
    assert_eq!(
        error,
        ClassifierError::Transient {
            retry_after: Some(Duration::from_secs(30))
        }
    );
    assert_eq!(error.retry_after(), Some(Duration::from_secs(30)));

    let (_, answers) = ask_with(
        TextModelMode::Transient { retry_after: None },
        &good_questions(),
    );
    assert_eq!(
        answers.expect_err("transient"),
        ClassifierError::Transient { retry_after: None }
    );
}

#[test]
fn a_transport_failure_maps_to_transport_with_its_text() {
    let (_, answers) = ask_with(
        TextModelMode::Error(cratefield_core::TextModelError::Transport(
            "the hop broke".to_owned(),
        )),
        &good_questions(),
    );
    assert_eq!(
        answers.expect_err("broken"),
        ClassifierError::Transport("the hop broke".to_owned())
    );
}

// ---------------------------------------------------------------------------
// Model-output validation

#[test]
fn a_missing_question_id_is_rejected() {
    let mut answers = good_answers();
    answers["answers"]
        .as_object_mut()
        .expect("an object")
        .remove("angry");
    let (_, answers) = ask_with(structured(answers), &good_questions());
    let error = answers.expect_err("a dropped question is refused");
    assert!(matches!(error, ClassifierError::Rejected(_)), "{error:?}");
    assert!(format!("{error:?}").contains("angry"), "{error:?}");
}

#[test]
fn an_invented_question_id_is_rejected() {
    let mut answers = good_answers();
    answers["answers"]
        .as_object_mut()
        .expect("an object")
        .insert(
            "weather".to_owned(),
            entry("true", serde_json::json!({ "true": 1.0, "false": 0.0 })),
        );
    let (_, answers) = ask_with(structured(answers), &good_questions());
    let error = answers.expect_err("an invented question is refused");
    assert!(matches!(error, ClassifierError::Rejected(_)), "{error:?}");
}

#[test]
fn a_chosen_label_the_question_never_offered_is_rejected() {
    let mut answers = good_answers();
    answers["answers"]["topic"] = entry("spam", serde_json::json!({ "billing": 0.9, "bugs": 0.1 }));
    let (_, answers) = ask_with(structured(answers), &good_questions());
    let error = answers.expect_err("an unoffered choice is refused");
    assert!(matches!(error, ClassifierError::Rejected(_)), "{error:?}");
}

#[test]
fn a_probability_under_an_unoffered_label_is_rejected() {
    let mut answers = good_answers();
    answers["answers"]["topic"] = entry(
        "billing",
        serde_json::json!({ "billing": 0.9, "bugs": 0.1, "spam": 0.0 }),
    );
    let (_, answers) = ask_with(structured(answers), &good_questions());
    assert!(matches!(
        answers.expect_err("an unoffered probability key is refused"),
        ClassifierError::Rejected(_)
    ));
}

#[test]
fn a_probability_that_is_not_a_number_is_rejected() {
    // A NaN arrives as a null — JSON has no NaN literal, and a model that
    // emitted one upstream serialises it as null — and an overflowing
    // literal lands the same way.
    let mut answers = good_answers();
    answers["answers"]["topic"] = entry(
        "billing",
        serde_json::json!({ "billing": null, "bugs": 0.1 }),
    );
    let (_, answers) = ask_with(structured(answers), &good_questions());
    assert!(matches!(
        answers.expect_err("null is not a probability"),
        ClassifierError::Rejected(_)
    ));
}

#[test]
fn a_non_normalised_distribution_is_normalised_and_confidence_agrees() {
    let mut answers = good_answers();
    answers["answers"]["topic"] = entry(
        "billing",
        serde_json::json!({ "billing": 2.0, "bugs": 6.0 }),
    );
    let (_, answers) = ask_with(structured(answers), &good_questions());
    let answers = answers.expect("a distribution that sums to 8 is normalised");
    let topic = &answers["topic"];
    assert!(close(topic.probabilities["billing"], 0.25), "{topic:?}");
    assert!(close(topic.probabilities["bugs"], 0.75), "{topic:?}");
    assert!(
        close(topic.confidence, 0.25),
        "confidence is picked from the same map"
    );
}

#[test]
fn a_zero_sum_distribution_is_rejected() {
    let mut answers = good_answers();
    answers["answers"]["topic"] = entry(
        "billing",
        serde_json::json!({ "billing": 0.0, "bugs": 0.0 }),
    );
    let (_, answers) = ask_with(structured(answers), &good_questions());
    assert!(matches!(
        answers.expect_err("nothing to normalise"),
        ClassifierError::Rejected(_)
    ));
}

#[test]
fn a_negative_probability_is_rejected() {
    let mut answers = good_answers();
    answers["answers"]["topic"] = entry(
        "billing",
        serde_json::json!({ "billing": -0.5, "bugs": 1.5 }),
    );
    let (_, answers) = ask_with(structured(answers), &good_questions());
    assert!(matches!(
        answers.expect_err("a negative mass is not a probability"),
        ClassifierError::Rejected(_)
    ));
}

#[test]
fn a_score_level_off_the_canonical_numeric_form_still_agrees() {
    // Levels named "1.0"/"5.0": the parsed value displays as "5", which
    // is not the probability key — the answer must not let the confidence
    // decay to 0.0 over a formatting mismatch.
    let questions = BTreeMap::from([(
        "severity".to_owned(),
        Question::Score {
            instructions: "How severe?".to_owned(),
            levels: vec![
                ("1.0".to_owned(), "a typo".to_owned()),
                ("5.0".to_owned(), "data loss".to_owned()),
            ],
        },
    )]);
    let payload = serde_json::json!({
        "answers": { "severity": entry("5.0", serde_json::json!({ "1.0": 0.2, "5.0": 0.8 })) }
    });
    let (_, answers) = ask_with(structured(payload), &questions);
    let answers = answers.expect("a decimal level name still answers");
    let severity = &answers["severity"];
    assert_eq!(severity.value, AnswerValue::Score(5.0));
    assert!(close(severity.confidence, 0.8), "{severity:?}");
}

#[test]
fn a_score_pick_that_is_not_a_number_is_rejected() {
    let questions = BTreeMap::from([(
        "severity".to_owned(),
        Question::Score {
            instructions: "How severe?".to_owned(),
            levels: vec![
                ("low".to_owned(), "a typo".to_owned()),
                ("high".to_owned(), "data loss".to_owned()),
            ],
        },
    )]);
    let payload = serde_json::json!({
        "answers": { "severity": entry("high", serde_json::json!({ "low": 0.2, "high": 0.8 })) }
    });
    let (_, answers) = ask_with(structured(payload), &questions);
    assert!(matches!(
        answers.expect_err("a named level has no score value"),
        ClassifierError::Rejected(_)
    ));
}

// ---------------------------------------------------------------------------
// The question set is validated first

#[test]
fn a_malformed_question_set_is_rejected_without_calling_the_model() {
    let empty = BTreeMap::new();
    let (model, answers) = ask_with(structured(good_answers()), &empty);
    assert!(matches!(
        answers.expect_err("empty"),
        ClassifierError::Rejected(_)
    ));
    assert!(
        model.prompts().is_empty(),
        "a malformed set never reaches the model"
    );

    let one_criterion = BTreeMap::from([(
        "topic".to_owned(),
        Question::Choice {
            instructions: "Which?".to_owned(),
            criteria: BTreeMap::from([("billing".to_owned(), "money".to_owned())]),
        },
    )]);
    let (model, answers) = ask_with(structured(good_answers()), &one_criterion);
    assert!(matches!(
        answers.expect_err("one criterion"),
        ClassifierError::Rejected(_)
    ));
    assert!(model.prompts().is_empty());
}

// ---------------------------------------------------------------------------
// Truncation

#[test]
fn truncation_trims_the_state_carries_the_trim_and_warns() {
    install_log_capture();
    let state = format!("{}TAIL-MARKER-XYZ", "invoice line. ".repeat(40));
    assert!(state.len() > 64, "the fixture must be over the override");

    let model = FakeTextModel::new(structured(good_answers()));
    let adapter = ClassifierLlm::new(Arc::new(model.clone())).max_state_chars(64);
    assert_eq!(adapter.profile().max_state_chars, 64);
    let before = TRUNCATION_WARNS.load(Ordering::Relaxed);

    let answers = pollster::block_on(adapter.ask(&state, &good_questions()));
    answers.expect("a truncated state still answers");

    let prompt = &model.prompts()[0];
    let carried = &prompt.messages[0].content;
    assert!(
        carried.contains(&state[..64]),
        "the trimmed prefix travels: {carried}"
    );
    assert!(
        !carried.contains("TAIL-MARKER-XYZ"),
        "the dropped tail does not: {carried}"
    );
    assert!(
        TRUNCATION_WARNS.load(Ordering::Relaxed) > before,
        "the truncation warning fires"
    );
}

#[test]
fn a_state_under_the_ceiling_is_carried_whole() {
    let (model, answers) = ask_with(structured(good_answers()), &good_questions());
    answers.expect("answers");
    let carried = &model.prompts()[0].messages[0].content;
    assert!(carried.contains("a customer note about a late invoice"));
}
