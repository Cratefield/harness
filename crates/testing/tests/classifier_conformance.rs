//! `classifier_conformance` and friends (issue #456): the shared port
//! suite, proven both ways — it passes the well-behaved `FakeClassifier`
//! and **fails** a deliberately broken one, so no rule here passes
//! vacuously.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

use async_trait::async_trait;
use cratefield_core::{
    Answer, AnswerValue, Classifier, ClassifierError, ClassifierProfile, Question,
};
use cratefield_testing::{
    ClassifierMode, FakeClassifier, classifier_conformance, classifier_conformance_questions,
    classifier_conformance_state, classifier_not_configured,
    classifier_rejects_malformed_questions, classifier_truncates_long_state,
};

// ---------------------------------------------------------------------------
// The suite passes a well-behaved classifier

#[test]
fn the_suite_passes_a_well_behaved_classifier() {
    let classifier = FakeClassifier::default();
    pollster::block_on(classifier_conformance(&classifier));

    // The suite asked exactly its canonical set about exactly its
    // canonical state — the request an adapter's transport scripts.
    let last = classifier.last().expect("the suite asked once");
    assert_eq!(last.state, classifier_conformance_state());
    assert_eq!(last.question_ids, vec!["severity", "topic", "urgent"]);
}

#[test]
fn the_suite_makes_exactly_one_ask() {
    let classifier = FakeClassifier::default();
    pollster::block_on(classifier_conformance(&classifier));
    assert_eq!(
        classifier.asks().len(),
        1,
        "one scripted request must be enough to run the suite"
    );
}

#[test]
fn the_malformed_sets_are_rejected_not_panicked() {
    pollster::block_on(classifier_rejects_malformed_questions(
        &FakeClassifier::default(),
    ));
}

#[test]
fn an_unconfigured_classifier_answers_not_configured() {
    let classifier = FakeClassifier::new(ClassifierMode::NotConfigured);
    pollster::block_on(classifier_not_configured(&classifier));
}

#[test]
fn an_over_limit_state_still_gets_answers() {
    pollster::block_on(classifier_truncates_long_state(&FakeClassifier::default()));
}

// ---------------------------------------------------------------------------
// The suite fails a deliberately broken one

/// A `FakeClassifier` whose answers are sabotaged one rule at a time: the
/// harness around what an adapter gets wrong, so the suite can be shown
/// to catch each.
#[derive(Clone)]
struct Tampered {
    fake: FakeClassifier,
    tampering: Tampering,
}

#[derive(Clone, Copy)]
enum Tampering {
    /// Drops one answer: the map's keys are no longer the asked ids.
    DropsAnAnswer,
    /// Adds an answer to a question that was never asked.
    AddsAnExtraAnswer,
    /// Reports a probability under a label the question never offered.
    ReportsAForeignLabel,
    /// Reports a confidence the answer's own distribution contradicts.
    ConflictsConfidence,
}

impl Tampered {
    fn sabotage(&self, mut answers: BTreeMap<String, Answer>) -> BTreeMap<String, Answer> {
        match self.tampering {
            Tampering::DropsAnAnswer => {
                answers.remove("urgent");
            }
            Tampering::AddsAnExtraAnswer => {
                answers.insert(
                    "never-asked".to_owned(),
                    Answer::noul(true, BTreeMap::from([("true".to_owned(), 1.0_f32)])),
                );
            }
            Tampering::ReportsAForeignLabel => {
                answers
                    .get_mut("topic")
                    .expect("the deterministic topic answer")
                    .probabilities
                    .insert("neither".to_owned(), 0.5);
            }
            Tampering::ConflictsConfidence => {
                let topic = answers.remove("topic").expect("the topic answer");
                answers.insert(
                    "topic".to_owned(),
                    Answer::new(topic.value, topic.probabilities, 0.99),
                );
            }
        }
        answers
    }
}

#[async_trait]
impl Classifier for Tampered {
    fn profile(&self) -> ClassifierProfile {
        self.fake.profile()
    }

    async fn ask(
        &self,
        state: &str,
        questions: &BTreeMap<String, Question>,
    ) -> Result<BTreeMap<String, Answer>, ClassifierError> {
        Ok(self.sabotage(self.fake.ask(state, questions).await?))
    }
}

/// Runs the suite against `classifier` and returns the panic message —
/// the suite reports violations by panicking, the way
/// `push_recipient_conformance` does.
fn caught_message(classifier: &dyn Classifier) -> String {
    let result = catch_unwind(AssertUnwindSafe(|| {
        pollster::block_on(classifier_conformance(classifier));
    }));
    let payload = result.expect_err("the suite must catch the tampering, not pass it");
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap_or_else(|| "a non-string panic".to_owned())
}

#[test]
fn a_missing_answer_is_caught_as_rule_one() {
    let message = caught_message(&Tampered {
        fake: FakeClassifier::default(),
        tampering: Tampering::DropsAnAnswer,
    });
    assert!(message.contains("rule 1"), "{message}");
    assert!(message.contains("urgent"), "{message}");
}

#[test]
fn an_extra_answer_is_caught_as_rule_one() {
    let message = caught_message(&Tampered {
        fake: FakeClassifier::default(),
        tampering: Tampering::AddsAnExtraAnswer,
    });
    assert!(message.contains("rule 1"), "{message}");
    assert!(message.contains("never-asked"), "{message}");
}

#[test]
fn a_foreign_probability_label_is_caught_as_rule_four() {
    let message = caught_message(&Tampered {
        fake: FakeClassifier::default(),
        tampering: Tampering::ReportsAForeignLabel,
    });
    assert!(message.contains("rule 4"), "{message}");
    assert!(message.contains("neither"), "{message}");
}

#[test]
fn a_confidence_own_distribution_contradicts_is_caught_as_rule_five() {
    let message = caught_message(&Tampered {
        fake: FakeClassifier::default(),
        tampering: Tampering::ConflictsConfidence,
    });
    assert!(message.contains("rule 5"), "{message}");
    assert!(message.contains("topic"), "{message}");
}

// ---------------------------------------------------------------------------
// Sanity: the canonical set is one of every shape, and a Value-holding
// answer for it carries a confidence the distribution agrees with — what
// a scripted adapter has to reproduce.

#[test]
fn the_canonical_set_is_one_of_every_shape() {
    let questions = classifier_conformance_questions();
    let kinds: Vec<&str> = questions.values().map(Question::kind).collect();
    // `BTreeMap` order: "severity" (score), "topic" (choice), "urgent" (noul).
    assert_eq!(kinds, vec!["score", "choice", "noul"]);

    let state = classifier_conformance_state();
    assert!(!state.is_empty());
    assert_eq!(state, classifier_conformance_state(), "the state is fixed");
}

#[test]
fn the_deterministic_fake_answers_the_canonical_set_conformantly() {
    // What the two suite tests above rely on: an answer whose value is a
    // label the question offered carries that label's probability as its
    // confidence — the shape every scripted adapter answer needs.
    let classifier = FakeClassifier::default();
    let answers =
        pollster::block_on(classifier.ask("a state", &classifier_conformance_questions())).unwrap();
    let topic = &answers["topic"];
    assert_eq!(topic.value, AnswerValue::Choice("billing".to_owned()));
    let severity = &answers["severity"];
    assert_eq!(severity.value, AnswerValue::Score(1.0));
    let AnswerValue::Score(value) = severity.value else {
        panic!("the severity answer is a score");
    };
    assert_eq!(value.to_string(), "1", "the value names its level");
    let urgent = &answers["urgent"];
    assert_eq!(urgent.value, AnswerValue::Noul(true));
}
