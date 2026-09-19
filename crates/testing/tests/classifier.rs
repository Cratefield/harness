//! `FakeClassifier` and a module that declares the `Classifier` port
//! (issue #456).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use cratefield_core::{
    Answer, AnswerValue, Calibration, Classifier, ClassifierError, Migrations, Module,
    ModuleContext, Port, Question,
};
use cratefield_testing::{ClassifierMode, FakeClassifier, TestHarness, conformance, request};

/// The judge's note — the state the questions are asked about.
const ESCALATION_NOTE: &str = "the customer has been waiting nine days for a refund";

/// The escalation judge asks its five questions in ONE `ask` call: the
/// port takes a set, not a loop — the expensive part is carrying the
/// state, and the provider would have run these concurrently.
fn judge_questions() -> BTreeMap<String, Question> {
    ["billing", "urgent", "angry", "refund", "spam"]
        .into_iter()
        .map(|id| {
            (
                id.to_owned(),
                Question::Noul {
                    instructions: format!("Is the note about {id}?"),
                },
            )
        })
        .collect()
}

/// A module that judges through the `Classifier` port — the smallest
/// shape that declares it and really uses it: the route asks its five
/// questions as one set and answers with the verdicts (or the error's
/// scrubbed `Display`, which is what a module that degrades does).
pub struct Judge;

impl Module for Judge {
    fn name(&self) -> &'static str {
        "judge"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Classifier]
    }

    fn migrations(&self) -> Migrations {
        Migrations::default()
    }

    fn validate_config(
        &self,
        _cfg: &dyn cratefield_core::Config,
    ) -> Result<(), cratefield_core::ConfigError> {
        Ok(())
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let classifier = ctx.ports.classifier.expect("judge requires Classifier");
        axum::Router::new().route(
            "/judge",
            axum::routing::get(move || {
                let classifier = Arc::clone(&classifier);
                async move {
                    let questions = judge_questions();
                    match classifier.ask(ESCALATION_NOTE, &questions).await {
                        Ok(answers) => cratefield_core::Json(serde_json::json!({
                            "answers": answers
                                .iter()
                                .map(|(id, answer)| {
                                    (id.clone(), serde_json::json!({
                                        "verdict": matches!(answer.value, AnswerValue::Noul(true)),
                                        "confidence": answer.confidence,
                                    }))
                                })
                                .collect::<serde_json::Map<String, serde_json::Value>>()
                        })),
                        Err(error) => {
                            cratefield_core::Json(serde_json::json!({ "error": error.to_string() }))
                        }
                    }
                }
            }),
        )
    }
}

#[test]
fn a_module_that_requires_the_classifier_port_conforms() {
    // The port is additive to HARNESS_API = 1, so a module declaring it
    // passes the same eight checks every other module passes — including
    // check 4, which is only true when `full_fake_ports` fakes the port.
    conformance(Box::new(Judge));
}

#[test]
fn the_harness_fakes_the_port_a_module_declares() {
    // `TestHarness::new` fakes every port; this is the classifier leg of
    // that promise. One question is scripted with its own probabilities;
    // the other four stay deterministic.
    let kit = TestHarness::new(vec![Box::new(Judge)]);
    kit.classifier.set_answer_for(
        "urgent",
        Answer::noul(
            true,
            BTreeMap::from([("true".to_owned(), 0.9_f32), ("false".to_owned(), 0.1_f32)]),
        ),
    );

    let response = pollster::block_on(request(
        &kit.router,
        http::Method::GET,
        "/v1/judge/judge",
        None,
    ));
    assert_eq!(
        response.status,
        http::StatusCode::OK,
        "{}",
        String::from_utf8_lossy(response.body())
    );

    let urgent = &response.json()["answers"]["urgent"];
    assert_eq!(urgent["verdict"], true);
    assert!(
        (urgent["confidence"].as_f64().unwrap() - 0.9).abs() < 1e-6,
        "the scripted probability came back: {}",
        urgent["confidence"]
    );
    let billing = &response.json()["answers"]["billing"];
    assert_eq!(billing["verdict"], true, "a Noul defaults to true");
    assert!(
        (billing["confidence"].as_f64().unwrap() - 0.6).abs() < 1e-6,
        "an unscripted question stayed deterministic: {}",
        billing["confidence"]
    );

    // The five questions went over as one call — the shape the port
    // exists for.
    let last = kit.classifier.last().expect("the judge asked");
    assert_eq!(last.state, ESCALATION_NOTE);
    assert_eq!(
        last.question_ids,
        vec!["angry", "billing", "refund", "spam", "urgent"]
    );
}

#[test]
fn an_unwired_classifier_surfaces_as_the_error_path_not_a_panic() {
    let kit = TestHarness::new(vec![Box::new(Judge)]);
    kit.classifier.set_mode(ClassifierMode::NotConfigured);

    let response = pollster::block_on(request(
        &kit.router,
        http::Method::GET,
        "/v1/judge/judge",
        None,
    ));
    assert_eq!(
        response.status,
        http::StatusCode::OK,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    assert_eq!(
        response.json()["error"],
        "no classifier is wired for this venture"
    );
    assert!(
        kit.classifier.asks().is_empty(),
        "a failed ask is not recorded"
    );
}

// ---------------------------------------------------------------------------
// FakeClassifier

#[test]
fn deterministic_answers_pick_the_first_label_of_each_shape() {
    let classifier = FakeClassifier::default();
    let questions = BTreeMap::from([
        (
            "topic".to_owned(),
            Question::Choice {
                instructions: "Which topic?".to_owned(),
                criteria: BTreeMap::from([
                    ("bugs".to_owned(), "something is broken".to_owned()),
                    ("billing".to_owned(), "money and invoices".to_owned()),
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
    ]);

    let answers = pollster::block_on(classifier.ask("a note", &questions)).unwrap();
    assert_eq!(
        answers["topic"].value,
        AnswerValue::Choice("billing".to_owned()),
        "the first criterion, in map order"
    );
    assert_eq!(answers["severity"].value, AnswerValue::Score(1.0));
    assert_eq!(answers["angry"].value, AnswerValue::Noul(true));

    // The distribution is normalised and puts most of the mass on the
    // chosen label — compared with a tolerance, not `==`: these are
    // floats by nature.
    for answer in answers.values() {
        let total: f32 = answer.probabilities.values().sum();
        assert!((total - 1.0).abs() < 1e-5, "mass sums to one: {total}");
        assert!((answer.confidence - 0.6).abs() < 1e-6);
    }

    // Deterministic: the same set answers the same way twice.
    let again = pollster::block_on(classifier.ask("a note", &questions)).unwrap();
    assert_eq!(answers, again);
}

#[test]
fn an_answers_mode_answers_the_scripted_set_and_falls_back_deterministically() {
    let angry = Answer::noul(
        false,
        BTreeMap::from([
            ("true".to_owned(), 0.05_f32),
            ("false".to_owned(), 0.95_f32),
        ]),
    );
    let classifier = FakeClassifier::new(ClassifierMode::Answers(BTreeMap::from([(
        "angry".to_owned(),
        angry,
    )])));
    let questions = judge_questions();

    let answers = pollster::block_on(classifier.ask(ESCALATION_NOTE, &questions)).unwrap();
    assert_eq!(answers["angry"].value, AnswerValue::Noul(false));
    assert!((answers["angry"].confidence - 0.95).abs() < 1e-6);
    assert_eq!(
        answers["spam"].value,
        AnswerValue::Noul(true),
        "a question the map does not name stays deterministic"
    );
}

#[test]
fn a_transient_mode_carries_the_provider_back_off() {
    let classifier = FakeClassifier::new(ClassifierMode::Transient {
        retry_after: Some(Duration::from_secs(30)),
    });
    let questions = judge_questions();

    let error = pollster::block_on(classifier.ask("a note", &questions)).unwrap_err();
    assert_eq!(
        error,
        ClassifierError::Transient {
            retry_after: Some(Duration::from_secs(30))
        }
    );
    assert_eq!(error.retry_after(), Some(Duration::from_secs(30)));
    assert!(classifier.asks().is_empty(), "a failure is not recorded");

    // A retry that then gets answers is recorded; the failed attempt is not.
    classifier.set_mode(ClassifierMode::Deterministic);
    assert!(pollster::block_on(classifier.ask("a note", &questions)).is_ok());
    assert_eq!(classifier.asks().len(), 1);
}

#[test]
fn a_rejected_mode_carries_the_provider_text() {
    let classifier = FakeClassifier::new(ClassifierMode::Rejected(
        "provider 422: state too long".to_owned(),
    ));
    let questions = judge_questions();

    let error = pollster::block_on(classifier.ask("a note", &questions)).unwrap_err();
    assert_eq!(
        error,
        ClassifierError::Rejected("provider 422: state too long".to_owned())
    );
    assert_eq!(error.retry_after(), None, "a refusal is not a back-off");
    assert!(classifier.asks().is_empty());
}

#[test]
fn the_exact_error_mode_answers_with_that_error() {
    let error = ClassifierError::Transport("the answer did not survive the hop".to_owned());
    let classifier = FakeClassifier::new(ClassifierMode::Error(error.clone()));
    let questions = judge_questions();

    assert_eq!(
        pollster::block_on(classifier.ask("a note", &questions)).unwrap_err(),
        error
    );
    assert!(classifier.asks().is_empty());
}

#[test]
fn the_not_configured_mode_reports_an_unwired_port() {
    let classifier = FakeClassifier::new(ClassifierMode::NotConfigured);
    let questions = judge_questions();

    assert_eq!(
        pollster::block_on(classifier.ask("a note", &questions)).unwrap_err(),
        ClassifierError::NotConfigured
    );
    assert!(classifier.asks().is_empty());
}

#[test]
fn a_scripted_question_answers_with_its_probabilities_while_the_rest_stay_deterministic() {
    let classifier = FakeClassifier::default();
    classifier.set_answer_for(
        "spam",
        Answer::noul(
            false,
            BTreeMap::from([("true".to_owned(), 0.2_f32), ("false".to_owned(), 0.8_f32)]),
        ),
    );
    let questions = judge_questions();

    let answers = pollster::block_on(classifier.ask("a note", &questions)).unwrap();
    assert_eq!(answers["spam"].value, AnswerValue::Noul(false));
    assert!((answers["spam"].confidence - 0.8).abs() < 1e-6);
    assert_eq!(
        answers["urgent"].value,
        AnswerValue::Noul(true),
        "the unscripted questions keep the mode"
    );

    // Clearing puts the question back on the mode.
    classifier.clear_answer_for("spam");
    let answers = pollster::block_on(classifier.ask("a note", &questions)).unwrap();
    assert_eq!(answers["spam"].value, AnswerValue::Noul(true));
}

#[test]
fn a_malformed_set_is_rejected_not_panicked() {
    let classifier = FakeClassifier::default();

    let error = pollster::block_on(classifier.ask("a note", &BTreeMap::new())).unwrap_err();
    assert!(matches!(error, ClassifierError::Rejected(_)));
    assert!(
        classifier.asks().is_empty(),
        "a refused set is not an answered ask"
    );

    let questions = BTreeMap::from([(
        "solo".to_owned(),
        Question::Choice {
            instructions: "Pick one.".to_owned(),
            criteria: BTreeMap::from([("only".to_owned(), "the only one".to_owned())]),
        },
    )]);
    assert!(matches!(
        pollster::block_on(classifier.ask("a note", &questions)),
        Err(ClassifierError::Rejected(_))
    ));
}

#[test]
fn an_ask_is_recorded_with_its_state_and_question_ids() {
    let classifier = FakeClassifier::default();
    let questions = judge_questions();

    pollster::block_on(classifier.ask("first note", &questions)).unwrap();
    pollster::block_on(classifier.ask("second note", &questions)).unwrap();

    let asks = classifier.asks();
    assert_eq!(asks.len(), 2);
    assert_eq!(asks[0].state, "first note");
    assert_eq!(
        asks[1].question_ids,
        vec!["angry", "billing", "refund", "spam", "urgent"]
    );
    assert_eq!(classifier.last().unwrap().state, "second note");
}

#[test]
fn the_profile_is_configurable() {
    let classifier = FakeClassifier::default();
    let profile = classifier.profile();
    assert_eq!(profile.calibration, Calibration::Classifier);
    assert_eq!(
        profile.max_state_chars,
        cratefield_core::DEFAULT_MAX_STATE_CHARS
    );

    classifier.set_profile(Calibration::LanguageModel, 1_000);
    let profile = classifier.profile();
    assert_eq!(profile.calibration, Calibration::LanguageModel);
    assert_eq!(profile.max_state_chars, 1_000);
}
