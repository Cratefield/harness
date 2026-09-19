//! Text classification for cost-aware routing (issue #457): the smallest
//! [`Classifier`] contract that carries the accounting, shadow-mode and
//! agreement-measurement work, and the one classifier every venture
//! already has — [`TextModelClassifier`], a classifier over the existing
//! [`TextModel`](crate::TextModel) port.
//!
//! **Why this is a module and not a `Port`.** A sibling effort (issue
//! #456) is adding the classifier port to the harness proper: the
//! `Port::Classifier` variant, the `Ports` field, the runtime wiring, the
//! `cratefield-testing` fake. This module deliberately does none of that.
//! The trait lives outside `crates/core/src/ports/` so that file — #456's
//! hottest one — is never touched, nothing registers it as a port, and a
//! venture composes [`TextModelClassifier`] and the router explicitly in
//! its own wiring today. Registration is #456's change to make. What is
//! here is the part #457 adds on top of any classifier: answers that
//! carry their token counts ([`Classification`]), so the accounting chain
//! from the wire to the [`CostLedger`](crate::CostLedger) stays unbroken.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::ports::{Completion, ModelTier, Prompt, TextModel, TextModelError};

/// Which classifier adapter answered, chosen once by the venture when it
/// wires the adapter. Prices on a [`PriceSheet`](crate::PriceSheet),
/// routing thresholds and agreement evidence are all keyed by it, so it
/// must be a stable string that survives redeploys and config edits: if
/// it changes between runs, yesterday's agreement measurement silently
/// stops matching today's adapter, and the router falls back to
/// "expensive always".
///
/// Two adapters must never share an `AdapterId`. Nothing in the type can
/// stop it — the ids live in venture wiring — and the failure is quiet:
/// with a duplicate id the two adapters' costs merge into one ledger row,
/// and a threshold calibrated on one is applied to the other. The system
/// keeps running, on numbers that are about neither adapter.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AdapterId(String);

impl AdapterId {
    /// Names an adapter, once, at wiring time.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The id as the string it is keyed by.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AdapterId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The kind of question being classified — a coarse type the venture
/// names when it authors its questions (`email_intent`,
/// `support_topic`), carried alongside the text so agreement and
/// thresholds can be measured **per kind**. A classifier that is reliable
/// on one kind is not therefore reliable on the next, and per-kind keys
/// are what let the router say so.
///
/// Like [`AdapterId`], kinds are keys: a kind renamed between a
/// measurement run and the routing decision is a kind with no evidence,
/// and a kind with no evidence is never routed cheap.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct QuestionKind(String);

impl QuestionKind {
    /// Names a kind of question, once, when the questions are authored.
    #[must_use]
    pub fn new(kind: impl Into<String>) -> Self {
        Self(kind.into())
    }

    /// The kind as the string it is keyed by.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for QuestionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One question to classify: what kind it is, the text itself, and the
/// candidate labels the answer must choose among.
///
/// `#[non_exhaustive]`: build one with [`Question::new`] and the builder
/// methods, the way [`Prompt`](crate::Prompt) is built.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Question {
    pub kind: QuestionKind,
    pub text: String,
    pub labels: Vec<String>,
}

impl Question {
    /// A question with no candidate labels yet; everything else is a
    /// builder method.
    #[must_use]
    pub fn new(kind: QuestionKind, text: impl Into<String>) -> Self {
        Self {
            kind,
            text: text.into(),
            labels: Vec::new(),
        }
    }

    /// Adds one candidate label.
    #[must_use]
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.labels.push(label.into());
        self
    }

    /// Adds several candidate labels, in order.
    #[must_use]
    pub fn labels<I, S>(mut self, labels: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.labels.extend(labels.into_iter().map(Into::into));
        self
    }
}

/// One label and the classifier's probability for it.
#[derive(Debug, Clone, PartialEq)]
pub struct Score {
    pub label: String,
    pub probability: f32,
}

/// A classification: the scores, and the adapter and model that produced
/// them, with the token counts the call actually spent.
///
/// `#[non_exhaustive]` and private score fields on purpose: there is
/// always a top score, and that is a type invariant, not a convention
/// every caller has to remember. `Classification::new` and the builder
/// methods are the only path in.
///
/// The token counts are the point of the type (issue #457): an answer
/// that drops them breaks the chain from the wire to the ledger, and the
/// cost question — "is the cheap adapter actually cheaper?" — becomes
/// unanswerable. Every [`Classifier`] must carry them through.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Classification {
    /// The best score. Always present; see the type's docs.
    top: Score,
    /// Every other score, descending by probability.
    rest: Vec<Score>,
    pub adapter: AdapterId,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

impl Classification {
    /// A classification with one score, which is its top.
    #[must_use]
    pub fn new(
        adapter: AdapterId,
        model: impl Into<String>,
        label: impl Into<String>,
        probability: f32,
    ) -> Self {
        Self {
            top: Score {
                label: label.into(),
                probability,
            },
            rest: Vec::new(),
            adapter,
            model: model.into(),
            input_tokens: 0,
            output_tokens: 0,
        }
    }

    /// Adds a score and keeps the top the maximum, whatever the insertion
    /// order. The `rest` stay sorted descending, so [`Self::scores`] is
    /// always descending by construction.
    #[must_use]
    pub fn also(mut self, label: impl Into<String>, probability: f32) -> Self {
        let candidate = Score {
            label: label.into(),
            probability,
        };
        if candidate.probability.total_cmp(&self.top.probability) == std::cmp::Ordering::Greater {
            let displaced = std::mem::replace(&mut self.top, candidate);
            self.rest.insert(0, displaced);
        } else {
            self.rest.push(candidate);
        }
        // `total_cmp`, never `partial_cmp().unwrap()`: a NaN probability
        // from a misbehaving adapter must sort deterministically, not
        // panic the router mid-request.
        self.rest
            .sort_by(|a, b| b.probability.total_cmp(&a.probability));
        self
    }

    /// The token counts the underlying call reported, so the ledger can
    /// price this classification without asking again.
    #[must_use]
    pub fn usage(mut self, input_tokens: u64, output_tokens: u64) -> Self {
        self.input_tokens = input_tokens;
        self.output_tokens = output_tokens;
        self
    }

    /// The top label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.top.label
    }

    /// The top probability.
    #[must_use]
    pub fn confidence(&self) -> f32 {
        self.top.probability
    }

    /// The gap between the top probability and the runner-up's — how far
    /// ahead the winner is, which is often the more honest "how sure" than
    /// the confidence itself.
    ///
    /// With a single score there is no runner-up, and the margin is the
    /// whole confidence: a one-horse classification is maximally far
    /// ahead of nothing. A margin near zero is a near-tie, whichever way
    /// the top landed.
    #[must_use]
    pub fn margin(&self) -> f32 {
        self.top.probability - self.rest.first().map_or(0.0, |s| s.probability)
    }

    /// Every score, descending by probability, top first.
    #[must_use = "the scores are the answer; dropping them hides the runner-up"]
    pub fn scores(&self) -> impl Iterator<Item = &Score> {
        std::iter::once(&self.top).chain(self.rest.iter())
    }
}

/// Classification failures — the same shape as
/// [`TextModelError`](crate::TextModelError), variant for variant, so an
/// adapter (and [`TextModelClassifier`] in particular) can map one onto
/// the other without inventing policy.
///
/// [`Rejected`](Self::Rejected) and [`Transport`](Self::Transport) carry
/// the provider's own words, so their `Display` scrubs through
/// [`crate::logging::scrub_text`] exactly as [`TextModelError`]'s does
/// (issue #235): what an adapter wraps can quote a user's question back,
/// and a log line or a dead-letter row must not carry it. `Debug` still
/// shows the raw string for tests.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ClassifierError {
    /// No classifier is wired to answer this question. Nothing is wrong
    /// with the question: a caller may degrade, or route somewhere else.
    #[error("no classifier is wired for this question")]
    NotConfigured,
    /// The classifier refused the question or its candidate labels (a
    /// `4xx`), or its answer was rejected by the caller — an off-list
    /// label, unparseable output; not retryable without a change.
    #[error(
        "classification rejected: {scrubbed}",
        scrubbed = crate::logging::scrub_text(.0)
    )]
    Rejected(String),
    /// A transient failure (a `5xx`, a `429`, a transport error): retry
    /// later, and not before `retry_after` when the provider named one.
    #[error("classification failed, retryable")]
    Transient {
        /// How long the provider asked the caller to wait, where it said.
        retry_after: Option<Duration>,
    },
    /// The call never completed — the adapter could not reach the
    /// provider, or the answer did not survive the hop.
    #[error(
        "classification transport failed: {scrubbed}",
        scrubbed = crate::logging::scrub_text(.0)
    )]
    Transport(String),
}

/// Classifies a [`Question`], over whichever adapter a venture wired.
///
/// Deliberately **not** a harness `Port` — see the module docs for why
/// (issue #456 owns registration; issue #457 composes explicitly).
#[async_trait]
pub trait Classifier: Send + Sync {
    /// Which adapter this is. Prices, thresholds and agreement are keyed
    /// by it, so it must be stable and unique — see [`AdapterId`] for
    /// what a duplicate silently breaks.
    fn adapter(&self) -> &AdapterId;

    /// Classifies `question`.
    ///
    /// # Errors
    ///
    /// [`ClassifierError::NotConfigured`] when nothing is wired to answer;
    /// [`ClassifierError::Rejected`] when the question was refused or the
    /// answer could not be trusted; [`ClassifierError::Transient`] when a
    /// retry may succeed; [`ClassifierError::Transport`] when the call
    /// never completed. A caller cannot distinguish "the adapter failed"
    /// from "the adapter never got asked" beyond these variants, and the
    /// router records both in the ledger.
    async fn classify(&self, question: &Question) -> Result<Classification, ClassifierError>;
}

/// The LLM you already have: a [`Classifier`] over the existing
/// [`TextModel`] port (issue #457). Pure composition, no I/O of its own —
/// the model is the venture's wired [`ModelTier`], reached through the
/// same `Arc<dyn TextModel>` every module holds — which is why this lives
/// in core exactly as [`RoutingTextModel`](crate::RoutingTextModel) does.
///
/// **A probability an LLM writes into a JSON field is not a calibrated
/// posterior.** It is a number the model chose to type, shaped by the
/// prompt's wording and the schema's request, and it is not comparable to
/// a classifier's score — nor to another LLM's self-reported confidence.
/// It may be used with a threshold calibrated *for this adapter* and for
/// nothing else: reusing a threshold calibrated on a real classifier, or
/// on a different LLM, looks principled and is worse than no threshold.
/// That is why routing thresholds are keyed by [`AdapterId`] (issue
/// #457).
///
/// The answer is requested as structured output — `{"label": <one of the
/// question's labels>, "probability": number}` — via
/// [`Prompt::json_schema`]. An adapter whose provider cannot honour the
/// schema answers in plain text instead, so the text is parsed as a
/// fallback. An answer naming a label outside the question's list, or
/// one that parses as nothing, is
/// [`ClassifierError::Rejected`]: a made-up label is not an opinion, it
/// is no answer. Token counts from the [`Completion`] are carried into
/// the [`Classification`] — the accounting chain must be unbroken from
/// the wire to the ledger.
#[derive(Clone)]
pub struct TextModelClassifier {
    adapter: AdapterId,
    model: Arc<dyn TextModel>,
    tier: ModelTier,
}

impl TextModelClassifier {
    /// A classifier over `model`, asking for [`ModelTier::Strong`] by
    /// default — this is the expensive side of the routing decision, and
    /// the default should err that way.
    #[must_use]
    pub fn new(adapter: AdapterId, model: Arc<dyn TextModel>) -> Self {
        Self {
            adapter,
            model,
            tier: ModelTier::Strong,
        }
    }

    /// Which [`ModelTier`] the underlying prompt asks for.
    #[must_use]
    pub fn tier(mut self, tier: ModelTier) -> Self {
        self.tier = tier;
        self
    }

    /// The prompt one classification costs: the task and the candidate
    /// labels as the system message, the question as the user turn, and
    /// the answer shape requested as a schema.
    fn prompt_for(&self, question: &Question) -> Prompt {
        Prompt::new(self.tier)
            .system(format!(
                "You are a text classifier. Choose exactly one label from the candidate \
                 labels and estimate the probability that it is the right one, as a number \
                 between 0 and 1. Candidate labels: {}.",
                question.labels.join(", ")
            ))
            .user(&question.text)
            .json_schema(serde_json::json!({
                "type": "object",
                "properties": {
                    "label": {
                        "type": "string",
                        "enum": question.labels,
                    },
                    "probability": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 1,
                    },
                },
                "required": ["label", "probability"],
                "additionalProperties": false,
            }))
    }

    /// [`TextModelError`] maps onto [`ClassifierError`] one for one: the
    /// variants exist to carry the same distinctions, and inventing a
    /// second mapping per call site would blur them.
    fn map_error(error: TextModelError) -> ClassifierError {
        match error {
            TextModelError::NotConfigured => ClassifierError::NotConfigured,
            TextModelError::Rejected(message) => ClassifierError::Rejected(message),
            TextModelError::Transient { retry_after } => ClassifierError::Transient { retry_after },
            TextModelError::Transport(message) => ClassifierError::Transport(message),
        }
    }

    /// Turns one completion into a classification, or says why it cannot
    /// be trusted. The label must be on the question's list and the
    /// probability is clamped into `0.0..=1.0`: a model that answers
    /// `1.5` has told you it is confident, not that it can count.
    fn classify_completion(
        adapter: &AdapterId,
        question: &Question,
        completion: Completion,
    ) -> Result<Classification, ClassifierError> {
        let Completion {
            text,
            json,
            model,
            input_tokens,
            output_tokens,
        } = completion;
        // The parsed answer when the provider honoured the schema; the
        // raw text parsed as a fallback when it did not. A number typed
        // by the model is never trusted past this point.
        let value = match json {
            Some(value) => value,
            None => serde_json::from_str(text.trim()).map_err(|_| {
                ClassifierError::Rejected("the answer was not a JSON object".to_owned())
            })?,
        };
        let label = value
            .get("label")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ClassifierError::Rejected("the answer had no string `label`".to_owned())
            })?;
        if !question.labels.iter().any(|candidate| candidate == label) {
            return Err(ClassifierError::Rejected(format!(
                "the label `{label}` is not one of the question's candidate labels"
            )));
        }
        let raw_probability = value
            .get("probability")
            .and_then(serde_json::Value::as_f64)
            .ok_or_else(|| {
                ClassifierError::Rejected("the answer had no numeric `probability`".to_owned())
            })?;
        // JSON numbers are `f64`; a [`Score`]'s probability is `f32`. The
        // narrowing is this module's chosen representation for a
        // probability, not an accident of parsing, so the cast is
        // deliberate and scoped to this one line.
        #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
        let probability = (raw_probability as f32).clamp(0.0, 1.0);
        Ok(
            Classification::new(adapter.clone(), model, label, probability)
                .usage(input_tokens, output_tokens),
        )
    }
}

impl fmt::Debug for TextModelClassifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The model itself is an `Arc<dyn TextModel>` with no meaningful
        // `Debug`; naming the adapter and the tier is the whole report,
        // and `finish_non_exhaustive` says there is a model behind it
        // without pretending the trait object can be printed.
        f.debug_struct("TextModelClassifier")
            .field("adapter", &self.adapter)
            .field("tier", &self.tier)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Classifier for TextModelClassifier {
    fn adapter(&self) -> &AdapterId {
        &self.adapter
    }

    async fn classify(&self, question: &Question) -> Result<Classification, ClassifierError> {
        // A question with no candidate labels is unanswerable, and the
        // model must not be asked (and paid) to find that out.
        if question.labels.is_empty() {
            return Err(ClassifierError::Rejected(
                "the question names no candidate labels".to_owned(),
            ));
        }
        let prompt = self.prompt_for(question);
        let completion = self
            .model
            .complete(&prompt)
            .await
            .map_err(Self::map_error)?;
        Self::classify_completion(&self.adapter, question, completion)
    }
}

#[cfg(test)]
mod tests {
    // Recording fakes, not request state (ADR 0007). The scoped allow
    // follows the policy in the workspace clippy.toml, as the fakes in
    // `cratefield-testing` and the sibling tests in this crate do.
    #![allow(clippy::disallowed_types)]

    use super::*;
    use std::sync::Mutex;

    // -----------------------------------------------------------------
    // AdapterId and QuestionKind

    #[test]
    fn an_adapter_id_round_trips_through_json_and_displays_as_its_string() {
        let id = AdapterId::new("cheap-classifier");
        assert_eq!(id.as_str(), "cheap-classifier");
        assert_eq!(id.to_string(), "cheap-classifier");

        let json = serde_json::to_string(&id).expect("serialises");
        assert_eq!(
            json, "\"cheap-classifier\"",
            "the wire form is the bare string"
        );
        let back: AdapterId = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, id.clone());

        let kind = QuestionKind::new("email_intent");
        assert_eq!(kind.as_str(), "email_intent");
        let json = serde_json::to_string(&kind).expect("serialises");
        let back: QuestionKind = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, kind);
    }

    #[test]
    fn ids_order_and_hash_as_their_strings_so_they_key_maps() {
        use std::collections::BTreeMap;
        let mut by_id: BTreeMap<AdapterId, u8> = BTreeMap::new();
        by_id.insert(AdapterId::new("b"), 1);
        by_id.insert(AdapterId::new("a"), 2);
        let keys: Vec<_> = by_id.keys().map(ToString::to_string).collect();
        assert_eq!(keys, ["a", "b"], "ordered as strings, for stable reports");
    }

    #[test]
    fn a_question_builds_up_kind_text_and_labels() {
        let question = Question::new(QuestionKind::new("email_intent"), "Add me to the list")
            .label("subscribe")
            .labels(["unsubscribe", "complaint"]);
        assert_eq!(question.kind, QuestionKind::new("email_intent"));
        assert_eq!(question.text, "Add me to the list");
        assert_eq!(
            question.labels,
            ["subscribe", "unsubscribe", "complaint"],
            "labels accumulate in the order given"
        );
    }

    // -----------------------------------------------------------------
    // Classification

    #[test]
    fn also_keeps_top_the_maximum_regardless_of_insertion_order() {
        let id = AdapterId::new("cheap");
        let a = Classification::new(id.clone(), "model-a", "ham", 0.6).also("spam", 0.9);
        let b = Classification::new(id, "model-a", "spam", 0.9).also("ham", 0.6);
        assert_eq!(a.label(), "spam", "the higher score wins whenever it lands");
        assert_eq!(b.label(), "spam", "even when it was there first");
        let a_scores: Vec<_> = a.scores().map(|s| s.label.as_str()).collect();
        let b_scores: Vec<_> = b.scores().map(|s| s.label.as_str()).collect();
        assert_eq!(a_scores, ["spam", "ham"], "descending by probability");
        assert_eq!(b_scores, a_scores, "insertion order leaves no trace");
    }

    #[test]
    fn margin_equals_confidence_when_there_is_only_one_score() {
        let c = Classification::new(AdapterId::new("cheap"), "model", "ham", 0.8);
        assert!(
            (c.margin() - c.confidence()).abs() < f32::EPSILON,
            "no runner-up: the margin is the whole confidence"
        );
    }

    #[test]
    fn margin_is_the_gap_to_the_runner_up_in_a_near_tie() {
        // 0.75 and 0.6875 are exact in binary floating point, so the
        // margin is exactly 0.0625 and the assertion measures the
        // arithmetic, not rounding.
        let c = Classification::new(AdapterId::new("cheap"), "model", "a", 0.75).also("b", 0.6875);
        assert!(
            (c.margin() - 0.0625).abs() < f32::EPSILON,
            "a near-tie has a small margin"
        );
        assert!(
            (c.confidence() - 0.75).abs() < f32::EPSILON,
            "the top is untouched by `also`"
        );
    }

    #[test]
    fn usage_sets_the_token_counts_the_builder_carries() {
        let c = Classification::new(AdapterId::new("cheap"), "model", "ham", 0.9).usage(120, 8);
        assert_eq!(c.input_tokens, 120);
        assert_eq!(c.output_tokens, 8);
        assert_eq!(c.adapter, AdapterId::new("cheap"));
        assert_eq!(c.model, "model");
    }

    // -----------------------------------------------------------------
    // ClassifierError

    #[test]
    fn display_scrubs_the_provider_text() {
        // The same rule as `TextModelError` (issue #235): the text an
        // adapter wraps can quote a user's question straight back, so it
        // must not survive into a log line.
        let error = ClassifierError::Rejected(
            "provider 400 for https://api.example.test/v1/classify?token=secret-abcdef".to_owned(),
        );
        let text = error.to_string();
        assert!(text.contains("classification rejected"), "{text}");
        assert!(!text.contains("secret-abcdef"), "{text}");
        assert!(text.contains("?[redacted]"), "{text}");

        let error = ClassifierError::Transport("timeout quoting alice@example.test".to_owned());
        let text = error.to_string();
        assert!(text.contains("classification transport failed"), "{text}");
        assert!(!text.contains('@'), "{text}");
        // `Debug` still shows the raw string for a failing test to read.
        assert!(format!("{error:?}").contains("alice@example.test"));

        assert_eq!(
            ClassifierError::NotConfigured.to_string(),
            "no classifier is wired for this question"
        );
        assert_eq!(
            ClassifierError::Transient { retry_after: None }.to_string(),
            "classification failed, retryable"
        );
    }

    // -----------------------------------------------------------------
    // TextModelClassifier, over a hand-written TextModel stub

    struct StubTextModel {
        answer: Result<Completion, TextModelError>,
        calls: std::sync::atomic::AtomicUsize,
        prompts: Mutex<Vec<Prompt>>,
    }

    impl StubTextModel {
        fn answering(completion: Completion) -> Arc<Self> {
            Arc::new(Self {
                answer: Ok(completion),
                calls: std::sync::atomic::AtomicUsize::new(0),
                prompts: Mutex::new(Vec::new()),
            })
        }

        fn failing(error: TextModelError) -> Arc<Self> {
            Arc::new(Self {
                answer: Err(error),
                calls: std::sync::atomic::AtomicUsize::new(0),
                prompts: Mutex::new(Vec::new()),
            })
        }

        fn call_count(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::Relaxed)
        }

        fn last_prompt(&self) -> Option<Prompt> {
            self.prompts.lock().unwrap().last().cloned()
        }
    }

    #[async_trait]
    impl TextModel for StubTextModel {
        async fn complete(&self, prompt: &Prompt) -> Result<Completion, TextModelError> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.prompts.lock().unwrap().push(prompt.clone());
            self.answer.clone()
        }
    }

    fn question() -> Question {
        Question::new(QuestionKind::new("email_intent"), "Sign me up for updates")
            .label("subscribe")
            .label("unsubscribe")
    }

    #[pollster::test]
    async fn a_json_completion_becomes_a_classification_whose_usage_survives() {
        let completion = Completion::new(r#"{"label":"subscribe"}"#, "stub-model")
            .json(serde_json::json!({ "label": "subscribe", "probability": 0.93 }))
            .usage(120, 8);
        let model = StubTextModel::answering(completion);
        let classifier = TextModelClassifier::new(AdapterId::new("llm-strong"), model.clone());

        let classification = classifier.classify(&question()).await.expect("classifies");

        assert_eq!(
            classification.label(),
            "subscribe",
            "the label is the model's"
        );
        assert!((classification.confidence() - 0.93).abs() < f32::EPSILON);
        assert_eq!(
            classification.input_tokens, 120,
            "the accounting chain must be unbroken from the wire"
        );
        assert_eq!(classification.output_tokens, 8, "both sides carry through");
        assert_eq!(classification.adapter, AdapterId::new("llm-strong"));
        assert_eq!(classification.model, "stub-model");

        // And the prompt asked for what the spec says it asks for.
        let prompt = model.last_prompt().expect("the stub saw the prompt");
        assert_eq!(prompt.tier, ModelTier::Strong, "the default tier is Strong");
        assert!(
            prompt.system.as_deref().is_some_and(|system| {
                system.contains("subscribe") && system.contains("unsubscribe")
            }),
            "the system message names the candidate labels"
        );
        assert_eq!(prompt.messages.len(), 1, "the question is one user turn");
        assert_eq!(prompt.messages[0].content, "Sign me up for updates");
        assert!(
            prompt.json_schema.is_some(),
            "the answer shape is requested"
        );
    }

    #[pollster::test]
    async fn the_tier_builder_moves_the_underlying_prompt_off_the_strong_default() {
        let model =
            StubTextModel::answering(Completion::new("", "stub-model").json(serde_json::json!({
                "label": "subscribe", "probability": 0.5,
            })));
        let classifier = TextModelClassifier::new(AdapterId::new("llm-fast"), model.clone())
            .tier(ModelTier::Fast);
        classifier.classify(&question()).await.expect("classifies");
        let prompt = model.last_prompt().expect("the stub saw the prompt");
        assert_eq!(prompt.tier, ModelTier::Fast);
    }

    #[pollster::test]
    async fn a_plain_text_answer_is_parsed_when_the_provider_skipped_the_schema() {
        let completion = Completion::new(
            "\n  {\"label\": \"unsubscribe\", \"probability\": 0.7}  \n",
            "stub-model",
        );
        let classifier = TextModelClassifier::new(
            AdapterId::new("llm-strong"),
            StubTextModel::answering(completion),
        );
        let classification = classifier.classify(&question()).await.expect("classifies");
        assert_eq!(
            classification.label(),
            "unsubscribe",
            "the text fallback parses what `json` would have carried"
        );
        assert!((classification.confidence() - 0.7).abs() < f32::EPSILON);
    }

    #[pollster::test]
    async fn an_off_list_label_is_rejected_not_served() {
        let completion = Completion::new("", "stub-model").json(serde_json::json!({
            "label": "forward_to_a_friend", "probability": 0.99,
        }));
        let classifier = TextModelClassifier::new(
            AdapterId::new("llm-strong"),
            StubTextModel::answering(completion),
        );
        let error = classifier.classify(&question()).await.unwrap_err();
        let ClassifierError::Rejected(reason) = &error else {
            panic!("a made-up label is no answer: {error:?}");
        };
        assert!(
            reason.contains("not one of"),
            "the rejection names the off-list label: {error:?}"
        );
    }

    #[pollster::test]
    async fn unparseable_output_is_rejected_not_served() {
        let completion = Completion::new("I think this is probably a subscribe.", "stub-model");
        let classifier = TextModelClassifier::new(
            AdapterId::new("llm-strong"),
            StubTextModel::answering(completion),
        );
        let error = classifier.classify(&question()).await.unwrap_err();
        let ClassifierError::Rejected(reason) = &error else {
            panic!("prose is not an answer either: {error:?}");
        };
        assert!(reason.contains("not a JSON object"), "{error:?}");
    }

    #[pollster::test]
    async fn an_answer_without_a_usable_probability_is_rejected() {
        let completion =
            Completion::new("", "stub-model").json(serde_json::json!({ "label": "subscribe" }));
        let classifier = TextModelClassifier::new(
            AdapterId::new("llm-strong"),
            StubTextModel::answering(completion),
        );
        let error = classifier.classify(&question()).await.unwrap_err();
        let ClassifierError::Rejected(reason) = &error else {
            panic!("a label with no confidence cannot clear a threshold: {error:?}");
        };
        assert!(reason.contains("probability"), "{error:?}");
    }

    #[pollster::test]
    async fn a_question_with_no_labels_is_rejected_without_calling_the_model() {
        let model = StubTextModel::answering(Completion::new("", "stub-model"));
        let classifier = TextModelClassifier::new(AdapterId::new("llm-strong"), model.clone());
        let question = Question::new(QuestionKind::new("email_intent"), "Sign me up");
        let error = classifier.classify(&question).await.unwrap_err();
        assert!(matches!(error, ClassifierError::Rejected(_)), "{error:?}");
        assert_eq!(
            model.call_count(),
            0,
            "the model is never asked (and paid) to discover an unanswerable question"
        );
    }

    #[pollster::test]
    async fn text_model_errors_map_one_for_one_onto_classifier_errors() {
        let cases = [
            (
                TextModelError::NotConfigured,
                ClassifierError::NotConfigured,
            ),
            (
                TextModelError::Rejected("provider 422".to_owned()),
                ClassifierError::Rejected("provider 422".to_owned()),
            ),
            (
                TextModelError::Transient {
                    retry_after: Some(Duration::from_secs(30)),
                },
                ClassifierError::Transient {
                    retry_after: Some(Duration::from_secs(30)),
                },
            ),
            (
                TextModelError::Transport("connection reset".to_owned()),
                ClassifierError::Transport("connection reset".to_owned()),
            ),
        ];
        for (model_error, expected) in cases {
            let classifier = TextModelClassifier::new(
                AdapterId::new("llm-strong"),
                StubTextModel::failing(model_error),
            );
            let error = classifier.classify(&question()).await.unwrap_err();
            assert_eq!(error, expected, "the mapping is one for one, no invention");
        }
    }
}
