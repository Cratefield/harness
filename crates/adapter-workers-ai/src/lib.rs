//! `cratefield-adapter-workers-ai`: the `Classifier` port over the
//! Cloudflare Workers AI binding (issue #456). The model is reached through
//! `env.AI.run(...)` — a platform binding, no API key at all — so this
//! adapter exists only on the Workers runtime, and it bills through the
//! venture's Cloudflare account instead of to a vendor key.
//!
//! It is a convenience for ventures already on Workers, explicitly NOT the
//! primary way in: bring-your-own-key via `cratefield-adapter-typesafe` is
//! the default `Classifier`. But it is the same purpose-trained model, so
//! `profile()` reports `Calibration::Classifier` too — the same family of
//! numbers, and thresholds tuned on either hold on both (unlike the
//! `adapter-classifier-llm` family; see `CLASSIFIER.md`).
//!
//! Two shapes are load-bearing here. First, the JS binding: `worker::Ai` is
//! a `wasm-bindgen` handle held inside a `Send + Sync` trait object, which
//! is sound without a line of `unsafe` here because `wasm-bindgen` itself
//! declares `JsValue` `Send + Sync` off the atomics target (the same shape
//! `runtime-cloudflare`'s D1 wrapper uses); only the returned future needs
//! `worker`'s `into_send`. Second, the binding cannot be constructed off
//! wasm, while `ask` must still be testable natively — so the call goes
//! through the narrow `AiRunner` seam and tests inject a fake runner.
//!
//! There is no key in this adapter, so there is nothing to leak. A Workers
//! AI binding error can still echo platform identifiers (account ids,
//! binding names), so error text only ever travels inside
//! `ClassifierError` — whose `Display` scrubs — and this crate's log lines
//! carry outcome labels, never raw binding text.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use async_trait::async_trait;
use cratefield_core::{
    Answer, Calibration, Classifier, ClassifierError, ClassifierProfile, DEFAULT_MAX_STATE_CHARS,
    Question, validate_questions,
};
use std::collections::BTreeMap;
use worker::send::IntoSendFuture;

/// The model this adapter runs by default: the same purpose-trained
/// classifier the direct `adapter-typesafe` adapter calls over HTTP, one
/// transport further away. Override it per constructor.
pub const DEFAULT_MODEL_ID: &str = "typesafe/jev";

/// The context window Workers AI documents for the model, in tokens. At the
/// port's conservative ~4 chars/token the default state ceiling
/// (`DEFAULT_MAX_STATE_CHARS`, 96,000 chars) spends roughly 24,000 tokens
/// and leaves roughly a quarter of the window for the question set.
pub const WORKERS_AI_CONTEXT_TOKENS: usize = 32_000;

/// The runner seam: one call to the binding, all questions at once.
///
/// This exists because the binding itself cannot be constructed off wasm
/// (`env.ai(..)` inspects a live JS constructor name), while every line
/// around the call — request building, truncation, parsing, refusals —
/// must be testable in a native `cargo test`. The default implementation,
/// `AiBinding`, wraps the real binding; tests inject a fake instead.
///
/// The error type is `ClassifierError` itself so a fake can exercise every
/// mapping, and the real binding maps through `map_worker_error`.
#[async_trait]
pub trait AiRunner: Send + Sync {
    /// Run one model call. `input` is the full request document.
    ///
    /// # Errors
    /// Whatever mapping applies to the transport below: `NotConfigured`
    /// for an absent or unusable binding, `Rejected` when the model refuses
    /// the input, `Transient` for rate limits and overload (with a hint
    /// only when one exists), `Transport` otherwise.
    async fn run(
        &self,
        model: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ClassifierError>;
}

/// The real runner: the `env.AI` binding, obtained from
/// `worker::Env::ai(..)`.
///
/// Holding the JS handle inside a `Send + Sync` struct needs no `unsafe`
/// here — `wasm-bindgen` declares `JsValue` `Send + Sync` away from the
/// atomics target, the same shape `runtime-cloudflare`'s D1 wrapper relies
/// on. Only `Ai::run`'s future is `!Send`, and `worker`'s own `send` module
/// fixes that at the call site. Constructing this type off wasm is
/// impossible (there is no `Env`), which is exactly why the seam exists.
pub struct AiBinding(worker::Ai);

#[async_trait]
impl AiRunner for AiBinding {
    async fn run(
        &self,
        model: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ClassifierError> {
        self.0
            .run::<serde_json::Value, serde_json::Value>(model, input)
            .into_send()
            .await
            .map_err(|err| map_worker_error(&err))
    }
}

/// `Classifier` over the Cloudflare Workers AI binding.
///
/// The runner is a type parameter so tests can substitute the binding; the
/// default is the real one, and venture code writes `WorkersAi::from_env(..)`
/// and never names the parameter.
pub struct WorkersAi<R: AiRunner = AiBinding> {
    runner: R,
    model: String,
    profile: ClassifierProfile,
}

impl WorkersAi<AiBinding> {
    /// The adapter over the venture's `env.AI` binding. A missing or
    /// wrong-typed binding yields `None` — the runtime simply does not
    /// provide the port — never a panic. (`EnvBinding for worker::Ai`
    /// rejects a binding whose JS constructor name is not `Ai`, which is
    /// what happens under local miniflare/workerd configurations that do
    /// not provision the real class.)
    pub fn from_env(env: &worker::Env, binding: &str) -> Option<Self> {
        let ai = env.ai(binding).ok()?;
        Some(Self {
            runner: AiBinding(ai),
            model: DEFAULT_MODEL_ID.to_owned(),
            profile: ClassifierProfile::new(Calibration::Classifier, DEFAULT_MAX_STATE_CHARS),
        })
    }

    /// `from_env` with a model-id override and an explicit state ceiling:
    /// a venture pinning a newer revision of the model, or shrinking the
    /// ceiling below the documented window it has paid for.
    pub fn from_env_with_model(
        env: &worker::Env,
        binding: &str,
        model: impl Into<String>,
        profile: ClassifierProfile,
    ) -> Option<Self> {
        let ai = env.ai(binding).ok()?;
        Some(Self {
            runner: AiBinding(ai),
            model: model.into(),
            profile,
        })
    }
}

impl<R: AiRunner> WorkersAi<R> {
    /// The test constructor: any `AiRunner` stands in for the binding, so
    /// the whole of `ask` — request building, truncation, parsing, error
    /// mapping — runs in a native `cargo test`.
    pub fn with_runner(runner: R, model: impl Into<String>, profile: ClassifierProfile) -> Self {
        Self {
            runner,
            model: model.into(),
            profile,
        }
    }
}

/// The request document: one `state` and **all** questions of the call —
/// the binding evaluates the set against the state in a single `run()`,
/// which is the whole point of the port. Shapes not carried by a question's
/// kind are omitted rather than sent empty, so the model never sees a
/// `noul` with a stray `criteria` object. These are the same documents the
/// direct `adapter-typesafe` adapter sends over HTTP — same model, same
/// shape, one transport further away.
#[derive(serde::Serialize)]
struct ClassifyRequest<'a> {
    state: &'a str,
    questions: Vec<WireQuestion<'a>>,
}

#[derive(serde::Serialize)]
struct WireQuestion<'a> {
    id: &'a str,
    /// `choice`, `score` or `noul` — `Question::kind`'s names.
    kind: &'a str,
    instructions: &'a str,
    /// `Question::Choice` only: `criterion -> what it means`.
    #[serde(skip_serializing_if = "Option::is_none")]
    criteria: Option<BTreeMap<&'a str, &'a str>>,
    /// `Question::Score` only: the ordered levels.
    #[serde(skip_serializing_if = "Option::is_none")]
    levels: Option<Vec<WireLevel<'a>>>,
}

#[derive(serde::Serialize)]
struct WireLevel<'a> {
    name: &'a str,
    meaning: &'a str,
}

fn wire_question<'a>(id: &'a str, question: &'a Question) -> WireQuestion<'a> {
    match question {
        Question::Choice {
            instructions,
            criteria,
        } => WireQuestion {
            id,
            kind: question.kind(),
            instructions,
            criteria: Some(
                criteria
                    .iter()
                    .map(|(name, meaning)| (name.as_str(), meaning.as_str()))
                    .collect(),
            ),
            levels: None,
        },
        Question::Score {
            instructions,
            levels,
        } => WireQuestion {
            id,
            kind: question.kind(),
            instructions,
            criteria: None,
            levels: Some(
                levels
                    .iter()
                    .map(|(name, meaning)| WireLevel { name, meaning })
                    .collect(),
            ),
        },
        Question::Noul { instructions } => WireQuestion {
            id,
            kind: question.kind(),
            instructions,
            criteria: None,
            levels: None,
        },
    }
}

/// The success document: one answer per asked question id.
#[derive(serde::Deserialize)]
struct RunResponse {
    answers: Vec<WireAnswer>,
}

#[derive(serde::Deserialize)]
struct WireAnswer {
    id: String,
    /// A criterion or `true`/`false` label for `choice` and `noul`, a
    /// number on the scale for `score`.
    value: WireValue,
    #[serde(default)]
    probabilities: BTreeMap<String, f32>,
}

/// A model answer value. Untagged: a JSON string is a label, a JSON number
/// is a score.
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum WireValue {
    Label(String),
    Number(f32),
}

/// A score is matched against numeric level names within this much of the
/// model's number: both sides are decimals that parsed to `f32`, so exact
/// equality would be greedy and `clippy::float_cmp` has a point.
const SCORE_MATCH_TOLERANCE: f32 = 1.0e-6;

/// How far a distribution may sit from summing to one and still count as
/// already normalised. F32 sums of a handful of labels miss by at most a
/// few `ulp`s; a real shortfall (logits without a softmax) is orders of
/// magnitude wider.
const SUM_TOLERANCE: f32 = 1.0e-4;

/// Substrings (lowercased) that mark a binding error as the binding or the
/// class being absent — the `NotConfigured` family, not a network failure.
const BINDING_MARKERS: [&str; 5] = [
    "binding cannot be cast",
    "does not contain binding",
    "is undefined",
    "is not defined",
    "not a function",
];

/// Substrings (lowercased) that mark a binding error as throttling or
/// overload — retryable, and Workers AI offers no `Retry-After` hint
/// through the binding, so `retry_after` stays `None` rather than an
/// invented duration.
const TRANSIENT_MARKERS: [&str; 7] = [
    "rate limit",
    "rate-limit",
    "too many requests",
    "429",
    "overload",
    "throttl",
    "temporarily unavailable",
];

/// Substrings (lowercased) that mark a binding error as the model refusing
/// or rejecting the input — a wrong model id, an input that breaks the
/// model's contract.
const REJECTED_MARKERS: [&str; 9] = [
    "invalid",
    "not supported",
    "unsupported",
    "not found",
    "unauthorized",
    "forbidden",
    "not allowed",
    "malformed",
    "too large",
];

/// Maps a `worker::Error` onto the port's vocabulary. The text is only ever
/// carried inside `ClassifierError` — whose `Display` scrubs — never in a
/// log line: a Workers AI binding error can echo platform identifiers such
/// as account ids, and there is no scrubbing pass over log fields.
///
/// The keyword sets above are a documented heuristic, not a vendor
/// contract: Workers AI reports failures as free-form JS error strings, so
/// classification reads the text. Anything unrecognised is `Transport` —
/// an unknown shape must not masquerade as a retryable moment or as a
/// verdict on the input.
fn map_worker_error(err: &worker::Error) -> ClassifierError {
    // The one structured variant the crate already names as a rate limit.
    if matches!(err, worker::Error::RateLimitExceeded(_)) {
        return ClassifierError::Transient { retry_after: None };
    }
    let lowered = err.to_string().to_ascii_lowercase();
    if BINDING_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        return ClassifierError::NotConfigured;
    }
    if TRANSIENT_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        return ClassifierError::Transient { retry_after: None };
    }
    if REJECTED_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        return ClassifierError::Rejected(err.to_string());
    }
    ClassifierError::Transport(err.to_string())
}

/// Every refusal below is a `Rejected` with a message naming the question
/// and the offence. The log line stays generic on purpose: the message can
/// quote model-echoed text, and a log field is not scrubbed the way
/// `ClassifierError`'s `Display` is.
fn reject(message: String) -> ClassifierError {
    tracing::warn!(
        provider = "workers-ai",
        "a workers-ai answer does not match the question it answers"
    );
    ClassifierError::Rejected(message)
}

/// Validates one answer's probabilities against its own question's labels
/// and normalises them to sum to one. A NaN never lands in the map: every
/// comparison against NaN is false, so it falls out of the range check as
/// "outside [0, 1]".
fn checked_probabilities(
    id: &str,
    question: &Question,
    probabilities: BTreeMap<String, f32>,
) -> Result<BTreeMap<String, f32>, ClassifierError> {
    // The probabilities are keyed by the question's own labels — that is
    // what makes `confidence` and `probabilities` agree downstream.
    let labels = question.labels();
    let mut checked = BTreeMap::new();
    for (label, probability) in probabilities {
        if !labels.contains(&label.as_str()) {
            return Err(reject(format!(
                "workers-ai answered question {id:?} with label {label:?}, which it does not offer"
            )));
        }
        if !(0.0..=1.0).contains(&probability) {
            return Err(reject(format!(
                "workers-ai answered question {id:?} with probability {probability} for {label:?}, outside [0, 1]"
            )));
        }
        checked.insert(label, probability);
    }
    let total: f32 = checked.values().sum();
    if !total.is_finite() || total <= 0.0 {
        return Err(reject(format!(
            "workers-ai answered question {id:?} with a distribution that does not sum to a positive total"
        )));
    }
    if (total - 1.0).abs() > SUM_TOLERANCE {
        for probability in checked.values_mut() {
            *probability /= total;
        }
    }
    Ok(checked)
}

/// Maps the model's answer set onto the questions asked, refusing anything
/// that does not line up. Every answer is checked against *its own*
/// question: an answer for an id that was not asked, a second answer for
/// the same id, a probability on a label the question never offered, a
/// probability outside `[0.0, 1.0]`, or a distribution that cannot be
/// normalised is `Rejected` — the adapter does not invent answers for
/// questions the model skipped either.
///
/// Distributions that sum to something other than one are normalised:
/// nothing obliges the model's output to land exactly on one, and the core
/// `Answer` constructors derive `confidence` from the (normalised)
/// probabilities, so `confidence` always agrees with them.
fn map_answers(
    answers: Vec<WireAnswer>,
    questions: &BTreeMap<String, Question>,
) -> Result<BTreeMap<String, Answer>, ClassifierError> {
    let mut mapped = BTreeMap::new();
    for WireAnswer {
        id,
        value,
        probabilities,
    } in answers
    {
        let Some(question) = questions.get(&id) else {
            return Err(reject(format!(
                "workers-ai answered question id {id:?}, which was not asked"
            )));
        };
        if mapped.contains_key(&id) {
            return Err(reject(format!("workers-ai answered question {id:?} twice")));
        }
        let checked = checked_probabilities(&id, question, probabilities)?;

        let built = match question {
            Question::Choice { criteria, .. } => {
                let WireValue::Label(label) = value else {
                    return Err(reject(format!(
                        "workers-ai answered choice question {id:?} with a number, not a criterion"
                    )));
                };
                if !criteria.contains_key(&label) {
                    return Err(reject(format!(
                        "workers-ai answered choice question {id:?} with {label:?}, which is not one of its criteria"
                    )));
                }
                Answer::choice(label, checked)
            }
            Question::Score { levels, .. } => {
                let WireValue::Number(score) = value else {
                    return Err(reject(format!(
                        "workers-ai answered score question {id:?} with a label, not a number"
                    )));
                };
                if !score.is_finite() {
                    return Err(reject(format!(
                        "workers-ai scored question {id:?} at a value that is not a finite number"
                    )));
                }
                // When every level name is numeric, the score must land on
                // one of them; a scale named in words has nothing to check
                // the number against.
                let numeric_levels: Vec<_> = levels
                    .iter()
                    .map(|(name, _)| name.parse::<f32>().ok())
                    .collect();
                let all_numeric = numeric_levels.iter().all(Option::is_some);
                if all_numeric
                    && !numeric_levels.iter().any(|parsed| {
                        parsed.is_some_and(|level| (level - score).abs() < SCORE_MATCH_TOLERANCE)
                    })
                {
                    return Err(reject(format!(
                        "workers-ai scored question {id:?} at {score}, off its scale"
                    )));
                }
                Answer::score(score, checked)
            }
            Question::Noul { .. } => {
                let WireValue::Label(label) = value else {
                    return Err(reject(format!(
                        "workers-ai answered noul question {id:?} with a number, not true or false"
                    )));
                };
                let verdict = match label.as_str() {
                    "true" => true,
                    "false" => false,
                    other => {
                        return Err(reject(format!(
                            "workers-ai answered noul question {id:?} with {other:?}, which is neither true nor false"
                        )));
                    }
                };
                Answer::noul(verdict, checked)
            }
        };
        mapped.insert(id, built);
    }
    if mapped.len() != questions.len() {
        let missing: Vec<_> = questions
            .keys()
            .filter(|id| !mapped.contains_key(*id))
            .cloned()
            .collect();
        return Err(reject(format!(
            "workers-ai did not answer the question(s) {missing:?}"
        )));
    }
    Ok(mapped)
}

#[async_trait]
impl<R: AiRunner> Classifier for WorkersAi<R> {
    fn profile(&self) -> ClassifierProfile {
        self.profile
    }

    async fn ask(
        &self,
        state: &str,
        questions: &BTreeMap<String, Question>,
    ) -> Result<BTreeMap<String, Answer>, ClassifierError> {
        // A malformed set is a `Rejected`, never a panic — and nothing is
        // built or sent for one.
        validate_questions(questions)?;

        let profile = self.profile();
        let (state, dropped) = profile.truncate(state);
        if dropped {
            // The one failure mode a classifier must not have silently: a
            // trimmed state comes back confident and wrong, so the trim is
            // observable, with the limit that did it.
            tracing::warn!(
                provider = "workers-ai",
                limit = profile.max_state_chars,
                "workers-ai truncated the state; the answers see only the first `limit` chars"
            );
        }

        let request = ClassifyRequest {
            state,
            questions: questions
                .iter()
                .map(|(id, question)| wire_question(id, question))
                .collect(),
        };
        let input = serde_json::to_value(&request)
            .map_err(|err| ClassifierError::Transport(err.to_string()))?;

        let output = self.runner.run(&self.model, input).await?;

        let parsed: RunResponse = match serde_json::from_value(output) {
            Ok(parsed) => parsed,
            Err(err) => {
                // A body that does not parse is a transport failure, not a
                // verdict on the question set. The text may quote model
                // output, so it travels only inside `ClassifierError`.
                tracing::warn!(
                    provider = "workers-ai",
                    outcome = "transport",
                    "a workers-ai success body did not survive the binding as an answer set"
                );
                return Err(ClassifierError::Transport(err.to_string()));
            }
        };
        let answers = map_answers(parsed.answers, questions)?;
        tracing::debug!(
            provider = "workers-ai",
            outcome = "answered",
            questions = answers.len(),
            "classifier outcome"
        );
        Ok(answers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::AnswerValue;

    fn good_set() -> BTreeMap<String, Question> {
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

    fn request_value(state: &str, questions: &BTreeMap<String, Question>) -> serde_json::Value {
        let payload = ClassifyRequest {
            state,
            questions: questions
                .iter()
                .map(|(id, question)| wire_question(id, question))
                .collect(),
        };
        serde_json::to_value(&payload).expect("serialises")
    }

    #[test]
    fn the_request_carries_each_kind_in_its_own_shape() {
        let sent = request_value("the state", &good_set());
        assert_eq!(sent["state"], "the state");
        let questions = sent["questions"].as_array().expect("array");
        assert_eq!(questions.len(), 3);

        let choice = questions
            .iter()
            .find(|q| q["id"] == "topic")
            .expect("choice question");
        assert_eq!(choice["kind"], "choice");
        assert_eq!(choice["criteria"]["bugs"], "something is broken");
        assert!(choice.get("levels").is_none());

        let score = questions
            .iter()
            .find(|q| q["id"] == "severity")
            .expect("score question");
        assert_eq!(score["kind"], "score");
        assert!(score.get("criteria").is_none());
        assert_eq!(
            score["levels"],
            serde_json::json!([
                {"name": "1", "meaning": "a typo"},
                {"name": "5", "meaning": "data loss"},
            ])
        );

        let noul = questions
            .iter()
            .find(|q| q["id"] == "angry")
            .expect("noul question");
        assert_eq!(noul["kind"], "noul");
        assert!(noul.get("criteria").is_none());
        assert!(noul.get("levels").is_none());
    }

    #[test]
    fn the_default_model_id_is_the_shared_classifier() {
        assert_eq!(DEFAULT_MODEL_ID, "typesafe/jev");
    }

    #[test]
    fn the_documented_window_fits_inside_the_default_ceiling() {
        // 96,000 chars at ~4 chars/token is ~24k tokens of the 32k window.
        assert_eq!(WORKERS_AI_CONTEXT_TOKENS, 32_000);
        // Compile-time: the constants must keep this relationship.
        const {
            assert!(DEFAULT_MAX_STATE_CHARS < WORKERS_AI_CONTEXT_TOKENS * 4);
        }
    }

    #[test]
    fn a_well_formed_set_maps_through_the_core_constructors() {
        let answers = vec![
            WireAnswer {
                id: "topic".to_owned(),
                value: WireValue::Label("bugs".to_owned()),
                probabilities: BTreeMap::from([
                    ("billing".to_owned(), 0.1_f32),
                    ("bugs".to_owned(), 0.9_f32),
                ]),
            },
            WireAnswer {
                id: "severity".to_owned(),
                value: WireValue::Number(5.0),
                probabilities: BTreeMap::from([("5".to_owned(), 1.0_f32)]),
            },
            WireAnswer {
                id: "angry".to_owned(),
                value: WireValue::Label("false".to_owned()),
                probabilities: BTreeMap::from([
                    ("true".to_owned(), 0.2_f32),
                    ("false".to_owned(), 0.8_f32),
                ]),
            },
        ];
        let mapped = map_answers(answers, &good_set()).expect("maps");
        assert_eq!(mapped.len(), 3);
        let topic = &mapped["topic"];
        assert_eq!(topic.value, AnswerValue::Choice("bugs".to_owned()));
        assert!((topic.confidence - 0.9).abs() < f32::EPSILON, "{topic:?}");
        let severity = &mapped["severity"];
        assert_eq!(severity.value, AnswerValue::Score(5.0));
        let angry = &mapped["angry"];
        assert_eq!(angry.value, AnswerValue::Noul(false));
        // `confidence` agrees with `probabilities` on every answer.
        for (id, answer) in &mapped {
            let mass: f32 = answer.probabilities.values().sum();
            assert!((mass - 1.0).abs() < SUM_TOLERANCE, "{id}: {answer:?}");
        }
    }

    #[test]
    fn a_distribution_that_does_not_sum_to_one_is_normalised() {
        let answers = vec![WireAnswer {
            id: "topic".to_owned(),
            value: WireValue::Label("billing".to_owned()),
            probabilities: BTreeMap::from([
                ("billing".to_owned(), 0.3_f32),
                ("bugs".to_owned(), 0.3_f32),
            ]),
        }];
        let questions = BTreeMap::from([("topic".to_owned(), good_set()["topic"].clone())]);
        let mapped = map_answers(answers, &questions).expect("maps");
        let topic = &mapped["topic"];
        assert!(
            (topic.probabilities["billing"] - 0.5).abs() < 1.0e-6,
            "{topic:?}"
        );
        assert!(
            (topic.probabilities["bugs"] - 0.5).abs() < 1.0e-6,
            "{topic:?}"
        );
        assert!((topic.confidence - 0.5).abs() < 1.0e-6, "{topic:?}");
    }

    #[test]
    fn every_semantic_refusal_is_rejected() {
        let cases: Vec<(String, Vec<WireAnswer>)> = vec![
            (
                "missing id".to_owned(),
                vec![WireAnswer {
                    id: "offTopic".to_owned(),
                    value: WireValue::Label("bugs".to_owned()),
                    probabilities: BTreeMap::from([("bugs".to_owned(), 1.0_f32)]),
                }],
            ),
            (
                "unknown label".to_owned(),
                vec![WireAnswer {
                    id: "topic".to_owned(),
                    value: WireValue::Label("shipping".to_owned()),
                    probabilities: BTreeMap::from([("shipping".to_owned(), 1.0_f32)]),
                }],
            ),
            (
                "empty distribution".to_owned(),
                vec![WireAnswer {
                    id: "topic".to_owned(),
                    value: WireValue::Label("bugs".to_owned()),
                    probabilities: BTreeMap::new(),
                }],
            ),
            (
                "probability above one".to_owned(),
                vec![WireAnswer {
                    id: "topic".to_owned(),
                    value: WireValue::Label("bugs".to_owned()),
                    probabilities: BTreeMap::from([("bugs".to_owned(), 1.5_f32)]),
                }],
            ),
            (
                "score off its scale".to_owned(),
                vec![WireAnswer {
                    id: "severity".to_owned(),
                    value: WireValue::Number(3.5),
                    probabilities: BTreeMap::from([("5".to_owned(), 1.0_f32)]),
                }],
            ),
        ];
        for (what, answers) in cases {
            let mapped =
                map_answers(answers, &good_set()).expect_err(&format!("{what} must be refused"));
            assert!(
                matches!(mapped, ClassifierError::Rejected(_)),
                "{what}: {mapped:?}"
            );
        }
    }

    #[test]
    fn a_question_the_model_skipped_is_rejected() {
        let answers = vec![WireAnswer {
            id: "topic".to_owned(),
            value: WireValue::Label("bugs".to_owned()),
            probabilities: BTreeMap::from([("bugs".to_owned(), 1.0_f32)]),
        }];
        let mapped = map_answers(answers, &good_set()).expect_err("skipped set refused");
        assert!(matches!(mapped, ClassifierError::Rejected(_)), "{mapped:?}");
    }

    #[test]
    fn the_error_mapping_lands_on_the_right_vocabulary() {
        // Binding absent or unusable: `NotConfigured`.
        for text in [
            "Binding cannot be cast to the type Ai from Object",
            "Env does not contain binding `AI`",
            "Ai is not defined",
        ] {
            let mapped = map_worker_error(&worker::Error::JsError(text.to_owned()));
            assert!(
                matches!(mapped, ClassifierError::NotConfigured),
                "{text}: {mapped:?}"
            );
        }
        // Throttling and overload: `Transient`, with no invented duration.
        for text in [
            "rate limit exceeded",
            "Too Many Requests",
            "model is overloaded, try again",
        ] {
            let mapped = map_worker_error(&worker::Error::JsError(text.to_owned()));
            assert!(
                matches!(mapped, ClassifierError::Transient { retry_after: None }),
                "{text}: {mapped:?}"
            );
        }
        let structured =
            map_worker_error(&worker::Error::RateLimitExceeded("daily cap".to_owned()));
        assert!(matches!(
            structured,
            ClassifierError::Transient { retry_after: None }
        ));
        // The model refusing the input: `Rejected`.
        for text in [
            "model typesafe/jev not found",
            "invalid input: expected an object",
            "input too large for this model",
        ] {
            let mapped = map_worker_error(&worker::Error::JsError(text.to_owned()));
            assert!(matches!(mapped, ClassifierError::Rejected(_)), "{text}");
        }
        // Everything else, including shapes the heuristic does not know:
        // `Transport`.
        for err in [
            worker::Error::JsError("workerd hiccup".to_owned()),
            worker::Error::BadEncoding,
            worker::Error::RustError("connection reset".to_owned()),
        ] {
            let mapped = map_worker_error(&err);
            assert!(matches!(mapped, ClassifierError::Transport(_)), "{err}");
        }
    }
}
