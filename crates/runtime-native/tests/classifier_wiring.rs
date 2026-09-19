//! `Native` reports the `Classifier` port it is handed (issue #456).
//!
//! The runtime's `provides()` is hand-written `if`s — the shape that once
//! lost `Port::Auth` out of `Ports::provides` — so the wired direction gets
//! its own assertion, the way `text_model_wiring.rs` buys it for
//! `Port::TextModel`: a runtime that holds an adapter must say it provides
//! the port, or a module requiring `Classifier` is refused a build it
//! could have served.

use std::collections::BTreeMap;
use std::sync::Arc;

use cratefield_core::{
    Answer, Calibration, Classifier, ClassifierError, ClassifierProfile, Port, Question, Runtime,
};
use cratefield_runtime_native::Native;

/// Stands in for an adapter the venture passed itself. Answers the
/// cheapest thing that satisfies the trait; what these tests assert is
/// wiring, not adapter behaviour.
struct StubClassifier;

#[async_trait::async_trait]
impl Classifier for StubClassifier {
    fn profile(&self) -> ClassifierProfile {
        ClassifierProfile::new(Calibration::LanguageModel, 1_000)
    }

    async fn ask(
        &self,
        _state: &str,
        _questions: &BTreeMap<String, Question>,
    ) -> Result<BTreeMap<String, Answer>, ClassifierError> {
        Err(ClassifierError::NotConfigured)
    }
}

#[test]
fn a_runtime_with_an_adapter_provides_the_port() {
    let runtime = Native::new().classifier(StubClassifier);
    assert!(runtime.provides().contains(&Port::Classifier));
}

#[test]
fn a_shared_adapter_provides_the_port_too() {
    let runtime = Native::new().classifier_arc(Arc::new(StubClassifier));
    assert!(runtime.provides().contains(&Port::Classifier));
}

#[test]
fn a_runtime_without_one_does_not() {
    let runtime = Native::new();
    assert!(!runtime.provides().contains(&Port::Classifier));
}
