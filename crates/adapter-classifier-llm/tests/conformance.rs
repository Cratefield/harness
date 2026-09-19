//! The shared `Classifier` conformance suite (issue #456) run against
//! `ClassifierLlm`: the same common contract every adapter answers, over
//! the harness's own `FakeTextModel` scripted with one well-formed
//! structured answer to `classifier_conformance_questions`.

use cratefield_adapter_classifier_llm::ClassifierLlm;
use cratefield_core::Completion;
use cratefield_testing::{
    FakeTextModel, TextModelMode, classifier_conformance, classifier_not_configured,
    classifier_rejects_malformed_questions, classifier_truncates_long_state,
};
use std::sync::Arc;

/// One answer entry the way the adapter's schema pins it.
fn entry(value: &str, probabilities: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "value": value, "probabilities": probabilities })
}

/// A well-formed answer to the canonical question set: every id asked,
/// every chosen label offered, a probability for every offered label, the
/// masses summing to one. The adapter normalises anyway — this is the
/// shape a conforming model sends.
fn conformance_payload() -> serde_json::Value {
    serde_json::json!({
        "answers": {
            "topic": entry("bugs", &serde_json::json!({ "billing": 0.1, "bugs": 0.9 })),
            "severity": entry("5", &serde_json::json!({ "1": 0.2, "5": 0.8 })),
            "urgent": entry("true", &serde_json::json!({ "true": 0.75, "false": 0.25 })),
        }
    })
}

/// The adapter over a model scripted to answer the canonical ask — and,
/// the `FakeTextModel` answering every completion the same way, the
/// suite's optional second ask too.
fn scripted() -> ClassifierLlm {
    let completion = Completion::new("ignored", "structured-vendor").json(conformance_payload());
    ClassifierLlm::new(Arc::new(FakeTextModel::new(TextModelMode::Complete(
        completion,
    ))))
}

#[test]
fn the_shared_conformance_suite_passes_over_the_llm_adapter() {
    pollster::block_on(classifier_conformance(&scripted()));
}

#[test]
fn the_shared_malformed_question_suite_passes() {
    pollster::block_on(classifier_rejects_malformed_questions(&scripted()));
}

#[test]
fn an_unwired_model_answers_not_configured() {
    let adapter = ClassifierLlm::new(Arc::new(FakeTextModel::new(TextModelMode::NotConfigured)));
    pollster::block_on(classifier_not_configured(&adapter));
}

#[test]
fn an_over_limit_state_still_answers() {
    pollster::block_on(classifier_truncates_long_state(&scripted()));
}
