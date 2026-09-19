//! The shared `Classifier` conformance suite (issue #456) run against the
//! `WorkersAi` adapter: the same common contract every adapter answers,
//! over the `AiRunner` seam faked with one well-formed run output for
//! `classifier_conformance_questions`.

use async_trait::async_trait;
use cratefield_adapter_workers_ai::{AiRunner, DEFAULT_MODEL_ID, WorkersAi};
use cratefield_core::{Calibration, ClassifierError, ClassifierProfile};
use cratefield_testing::{
    classifier_conformance, classifier_not_configured, classifier_rejects_malformed_questions,
    classifier_truncates_long_state,
};

/// A well-formed run output for the canonical question set: every id
/// asked, every chosen label offered, a probability for every offered
/// label, the masses summing to one. The score answer is a number on the
/// `"1"`/`"5"` scale. These are the same documents the direct
/// `adapter-typesafe` adapter sends, one transport further away.
fn conformance_output() -> serde_json::Value {
    serde_json::json!({
        "answers": [
            { "id": "topic", "value": "bugs", "probabilities": { "billing": 0.1, "bugs": 0.9 } },
            { "id": "severity", "value": 5, "probabilities": { "1": 0.2, "5": 0.8 } },
            { "id": "urgent", "value": "true", "probabilities": { "true": 0.75, "false": 0.25 } }
        ]
    })
}

/// A stand-in binding that answers every run with the same scripted
/// output — the suite asks at most twice, and the model answers each run
/// the same way.
struct CannedRunner;

#[async_trait]
impl AiRunner for CannedRunner {
    async fn run(
        &self,
        _model: &str,
        _input: serde_json::Value,
    ) -> Result<serde_json::Value, ClassifierError> {
        Ok(conformance_output())
    }
}

/// A stand-in for the absent-or-unusable binding (miniflare without the
/// `Ai` class, an `env.AI` that was never provisioned): the adapter maps
/// it to `NotConfigured` rather than panicking.
struct AbsentBinding;

#[async_trait]
impl AiRunner for AbsentBinding {
    async fn run(
        &self,
        _model: &str,
        _input: serde_json::Value,
    ) -> Result<serde_json::Value, ClassifierError> {
        Err(ClassifierError::NotConfigured)
    }
}

fn adapter<R: AiRunner>(runner: R) -> WorkersAi<R> {
    WorkersAi::with_runner(
        runner,
        DEFAULT_MODEL_ID,
        ClassifierProfile::new(
            Calibration::Classifier,
            cratefield_core::DEFAULT_MAX_STATE_CHARS,
        ),
    )
}

#[test]
fn the_shared_conformance_suite_passes_over_the_workers_ai_adapter() {
    pollster::block_on(classifier_conformance(&adapter(CannedRunner)));
}

#[test]
fn the_shared_malformed_question_suite_passes() {
    pollster::block_on(classifier_rejects_malformed_questions(&adapter(
        CannedRunner,
    )));
}

#[test]
fn an_absent_binding_answers_not_configured() {
    pollster::block_on(classifier_not_configured(&adapter(AbsentBinding)));
}

#[test]
fn an_over_limit_state_still_answers() {
    pollster::block_on(classifier_truncates_long_state(&adapter(CannedRunner)));
}
