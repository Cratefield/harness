//! `cratefield-adapter-classifier-llm`: the `Classifier` port over the
//! `TextModel` port the venture already wired (issue #456) — the third of
//! the three `Classifier` adapters, and the only one with no vendor of its
//! own. It reaches whichever model the `TextModel` tiers are routed to, a
//! local model included, through JSON-schema structured output, and it is
//! the honest fallback when neither a purpose-trained classifier nor a
//! vendor binding is wired.
//!
//! **Calibration is the language model's.** This adapter reports
//! `Calibration::LanguageModel`, and the point is not nominal: a
//! probability elicited from a general language model is *not* the same
//! number as one from a purpose-trained classifier. A `0.8` here is the
//! model's own rating of its certainty — a different sharpness at the
//! same number, drifting with every model version the venture re-wires
//! the tier to — so a threshold tuned against a `Calibration::Classifier`
//! adapter is wrong against this one, and a module that thresholds on
//! `Answer::confidence` says in its own docs which calibration it tuned.
//!
//! **The state ceiling is inherited, and the port cannot see the real
//! one.** Whatever `TextModel` allows, this adapter allows: it reports
//! the port's conservative `DEFAULT_MAX_STATE_CHARS` by default, and
//! `.max_state_chars` exists because the actual budget is the underlying
//! model's context window, which the `TextModel` port has no way to
//! report. Whoever wires the model knows it and says so here.
//!
//! Crate docs use plain backticks, never intra-doc links — the same rule
//! the rest of the classifier work follows.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use cratefield_core::{
    Answer, AnswerValue, Calibration, Classifier, ClassifierError, ClassifierProfile, Completion,
    DEFAULT_MAX_STATE_CHARS, ModelTier, Prompt, Question, TextModel, TextModelError,
    validate_questions,
};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;

/// The tier a classification prompt asks for when the constructor does
/// not override it: `Strong`, because a classification is a **judging**
/// task — the port's own docs put judging on `Strong` and drafting on
/// `Fast`. A venture that uses this adapter for cheap bulk triage, where
/// quality is not the point, overrides it with `.tier(ModelTier::Fast)`.
const DEFAULT_TIER: ModelTier = ModelTier::Strong;

/// The standing instruction every prompt carries.
const SYSTEM_PROMPT: &str = "You are a classification backend. You are given one state and a set of questions about it. For every question choose exactly one of the labels the question offers, and give a probability for every label the question offers; the probabilities of one question sum to 1. Answer with JSON conforming to the schema given, and with nothing else.";

/// `Classifier` over the venture's own `TextModel` wiring. Construct with
/// `ClassifierLlm::new` and the two builder methods; everything else is
/// the `Classifier` trait.
pub struct ClassifierLlm {
    model: Arc<dyn TextModel>,
    tier: ModelTier,
    max_state_chars: usize,
}

impl ClassifierLlm {
    /// Answers classification through `model` — the same `Arc<dyn
    /// TextModel>` a drafting module would hold. Defaults to the
    /// `Strong` tier (a judging task) and the port's conservative
    /// `DEFAULT_MAX_STATE_CHARS` state ceiling; both are overridable
    /// below.
    #[must_use]
    pub fn new(model: Arc<dyn TextModel>) -> Self {
        Self {
            model,
            tier: DEFAULT_TIER,
            max_state_chars: DEFAULT_MAX_STATE_CHARS,
        }
    }

    /// Asks for `tier` instead of the default `Strong`. A classification
    /// is a judging task, so `Strong` is the honest default; bulk triage
    /// that cannot afford it drops to `ModelTier::Fast` here.
    #[must_use]
    pub fn tier(mut self, tier: ModelTier) -> Self {
        self.tier = tier;
        self
    }

    /// Truncates `state` at `max_state_chars` instead of the port's
    /// default ceiling. The default inherits whatever `TextModel` allows,
    /// which is not a real answer: the true budget is the underlying
    /// model's context window, and this port cannot see it. Whoever
    /// wired the model knows the window and states it here.
    #[must_use]
    pub fn max_state_chars(mut self, max_state_chars: usize) -> Self {
        self.max_state_chars = max_state_chars;
        self
    }
}

#[async_trait::async_trait]
impl Classifier for ClassifierLlm {
    fn profile(&self) -> ClassifierProfile {
        ClassifierProfile::new(Calibration::LanguageModel, self.max_state_chars)
    }

    async fn ask(
        &self,
        state: &str,
        questions: &BTreeMap<String, Question>,
    ) -> Result<BTreeMap<String, Answer>, ClassifierError> {
        // A malformed set is `Rejected`, never a panic and never a wasted
        // model call: the question set is caller input, and the port
        // promises every adapter checks it before rendering.
        validate_questions(questions)?;

        let profile = self.profile();
        let (state, truncated) = profile.truncate(state);
        if truncated {
            // A silently trimmed state is the worst failure mode a
            // classifier has: the answer comes back confident and wrong.
            tracing::warn!(
                limit = profile.max_state_chars,
                "classifier state truncated to this adapter's state budget"
            );
        }

        // One prompt for ALL questions: the expensive part of the call is
        // carrying the state, not answering, which is why the port takes
        // a set. The schema is built per call so it pins the exact ids
        // and labels this question set actually offers.
        let prompt = Prompt::new(self.tier)
            .system(SYSTEM_PROMPT)
            .user(format!(
                "STATE:\n{state}\nEND STATE.\n\n{}",
                render_questions(questions)
            ))
            .json_schema(answer_schema(questions));

        let completion = self.model.complete(&prompt).await.map_err(model_error)?;
        let Some(answered) = answer_json(&completion) else {
            // Neither the structured payload nor the text parsed. The
            // message must not echo the completion back: the model was
            // just handed `state`, and its answer quotes it.
            return Err(ClassifierError::Transport(format!(
                "the model answered {} chars, but neither the structured payload nor the text parsed as the answer object",
                completion.text.len()
            )));
        };
        answers_of(&answered, questions)
    }
}

/// Maps a `TextModel` failure onto the `Classifier` failure it means.
/// `NotConfigured` passes through unchanged — it is how "no classifier
/// vendor wired" surfaces when the tier underneath is unwired — and the
/// provider text on `Rejected`/`Transport` rides inside variants whose
/// `Display` scrubs it, never bypassing the error types' own hygiene.
fn model_error(error: TextModelError) -> ClassifierError {
    match error {
        TextModelError::NotConfigured => ClassifierError::NotConfigured,
        TextModelError::Rejected(message) => ClassifierError::Rejected(message),
        TextModelError::Transient { retry_after } => ClassifierError::Transient { retry_after },
        TextModelError::Transport(message) => ClassifierError::Transport(message),
    }
}

/// Renders the whole question set into the one user message.
fn render_questions(questions: &BTreeMap<String, Question>) -> String {
    let mut rendered = String::from("QUESTIONS:\n");
    for (index, (id, question)) in questions.iter().enumerate() {
        let _ = writeln!(
            rendered,
            "{}. id {} ({}): {}",
            index + 1,
            id,
            question.kind(),
            question.instructions()
        );
        match question {
            Question::Choice { criteria, .. } => {
                rendered.push_str("   pick exactly one of:\n");
                for (name, meaning) in criteria {
                    let _ = writeln!(rendered, "   - {name}: {meaning}");
                }
            }
            Question::Score { levels, .. } => {
                rendered.push_str("   place on the ordered scale:\n");
                for (name, meaning) in levels {
                    let _ = writeln!(rendered, "   - {name}: {meaning}");
                }
            }
            Question::Noul { .. } => {
                rendered.push_str("   answer exactly true or false.\n");
            }
        }
    }
    rendered
}

/// Builds the JSON schema the completion is asked to conform to. Per
/// question id: the chosen value as an enum over exactly the labels
/// `Question::labels` offers, and a probability required for each of
/// those labels and no other key.
fn answer_schema(questions: &BTreeMap<String, Question>) -> Value {
    let mut properties = Map::new();
    let mut required: Vec<Value> = Vec::new();
    for (id, question) in questions {
        let labels = question.labels();
        let mut probability_properties = Map::new();
        for label in &labels {
            probability_properties
                .insert((*label).to_owned(), serde_json::json!({ "type": "number" }));
        }
        properties.insert(
            id.clone(),
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["value", "probabilities"],
                "properties": {
                    "value": { "enum": labels },
                    "probabilities": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": labels,
                        "properties": probability_properties,
                    },
                },
            }),
        );
        required.push(Value::String(id.clone()));
    }
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["answers"],
        "properties": {
            "answers": {
                "type": "object",
                "additionalProperties": false,
                "required": required,
                "properties": properties,
            },
        },
    })
}

/// The parsed answer object: `Completion::json` when the provider honored
/// the schema request, otherwise `Completion::text` parsed as JSON with
/// the markdown code fence real models wrap it in stripped off.
fn answer_json(completion: &Completion) -> Option<Value> {
    if let Some(json) = &completion.json {
        return Some(json.clone());
    }
    serde_json::from_str(strip_code_fence(&completion.text)).ok()
}

/// Strips one wrapping markdown code fence, tolerating the language tag
/// (`json`), a bare fence, and plain whitespace-only padding.
fn strip_code_fence(text: &str) -> &str {
    let trimmed = text.trim();
    let Some(after_open) = trimmed.strip_prefix("```") else {
        return trimmed;
    };
    let body = match after_open.split_once('\n') {
        Some((_, body)) => body,
        None => after_open,
    };
    match body.rfind("```") {
        Some(end) => body[..end].trim(),
        None => body.trim(),
    }
}

/// Validates the model's answer object against the question set and maps
/// it into the port's answers. Every way the model can be wrong becomes
/// `Rejected` — a missing or invented id, a label the question never
/// offered, a distribution that is not finite and normalisable — never a
/// silently invented answer.
fn answers_of(
    answered: &Value,
    questions: &BTreeMap<String, Question>,
) -> Result<BTreeMap<String, Answer>, ClassifierError> {
    let Some(answers) = answered.get("answers").and_then(Value::as_object) else {
        return Err(ClassifierError::Rejected(
            "the model's answer carries no `answers` object".to_owned(),
        ));
    };
    // The model inventing a question nobody asked is a schema violation,
    // same as dropping one: refuse the whole answer rather than pick
    // through what a provider that ignored the schema produced.
    for id in answers.keys() {
        if !questions.contains_key(id) {
            return Err(ClassifierError::Rejected(format!(
                "the model answered question {id:?}, which was not asked"
            )));
        }
    }
    let mut out = BTreeMap::new();
    for (id, question) in questions {
        let Some(entry) = answers.get(id) else {
            return Err(ClassifierError::Rejected(format!(
                "the model answered no question {id:?}"
            )));
        };
        out.insert(id.clone(), answer_for(question, entry)?);
    }
    Ok(out)
}

/// Validates one question's answer entry and builds the port's `Answer`
/// from it. The probabilities are normalised into f32s here, so
/// `confidence` (picked out of the same map by the answer constructors)
/// always agrees with `probabilities`.
fn answer_for(question: &Question, entry: &Value) -> Result<Answer, ClassifierError> {
    let object = entry.as_object().ok_or_else(|| {
        ClassifierError::Rejected("the answer to a question is not an object".to_owned())
    })?;
    let chosen = object.get("value").and_then(Value::as_str).ok_or_else(|| {
        ClassifierError::Rejected("the answer carries no chosen label as a string".to_owned())
    })?;
    let reported = object
        .get("probabilities")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ClassifierError::Rejected("the answer carries no `probabilities` object".to_owned())
        })?;

    let labels = question.labels();
    let mut weights = BTreeMap::<String, f64>::new();
    for (label, weight) in reported {
        if !labels.contains(&label.as_str()) {
            return Err(ClassifierError::Rejected(format!(
                "the model gave a probability under {label:?}, a label the question never offered"
            )));
        }
        let weight = weight.as_f64().ok_or_else(|| {
            ClassifierError::Rejected(format!("the probability under {label:?} is not a number"))
        })?;
        // Guard the float before any arithmetic: a JSON body can carry an
        // overflowing literal (parsed as an infinity) or a null where a
        // number belongs, and neither may survive into an answer.
        if !weight.is_finite() {
            return Err(ClassifierError::Rejected(format!(
                "the probability under {label:?} is not finite"
            )));
        }
        if weight < 0.0 {
            return Err(ClassifierError::Rejected(format!(
                "the probability under {label:?} is negative"
            )));
        }
        weights.insert(label.clone(), weight);
    }
    for label in &labels {
        if !weights.contains_key(*label) {
            return Err(ClassifierError::Rejected(format!(
                "the model gave no probability for the offered label {label:?}"
            )));
        }
    }
    let total: f64 = weights.values().sum();
    if !(total.is_finite() && total > 0.0) {
        return Err(ClassifierError::Rejected(
            "the probabilities do not add up to a distribution".to_owned(),
        ));
    }
    let mut probabilities = BTreeMap::<String, f32>::new();
    for (label, weight) in &weights {
        // `weight` is finite and non-negative and `total` is finite and
        // positive, so the quotient is finite; the f32 narrowing is the
        // port's own number type and cannot produce a NaN here.
        #[allow(clippy::cast_possible_truncation)]
        let narrowed = (weight / total) as f32;
        probabilities.insert(label.clone(), narrowed);
    }
    if !probabilities.contains_key(chosen) {
        return Err(ClassifierError::Rejected(format!(
            "the model chose {chosen:?}, a label the question never offered"
        )));
    }

    match question {
        Question::Choice { .. } => Ok(Answer::choice(chosen, probabilities)),
        Question::Score { .. } => {
            let parsed: f32 = chosen.parse().map_err(|_| {
                ClassifierError::Rejected(format!(
                    "the score question chose {chosen:?}, which is not a number on its scale"
                ))
            })?;
            // `Answer::score` looks the confidence up under the score's
            // own name, which only agrees with `probabilities` when the
            // level name is the canonical display of its parsed value
            // ("5", not "5.0"). Off the canonical form, core documents
            // `Answer::new` as the escape hatch: state the confidence
            // from the same map instead of letting it decay to 0.0.
            if parsed.to_string() == chosen {
                Ok(Answer::score(parsed, probabilities))
            } else {
                let confidence = probabilities[chosen];
                Ok(Answer::new(
                    AnswerValue::Score(parsed),
                    probabilities,
                    confidence,
                ))
            }
        }
        Question::Noul { .. } => {
            // The offered-label check above already pinned `chosen` to
            // the Noul labels, which are exactly "true" and "false".
            let value = chosen == "true";
            Ok(Answer::noul(value, probabilities))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_fence_is_stripped_and_bare_json_is_left_alone() {
        let fenced = "```json\n{\"answers\": {}}\n```";
        assert_eq!(strip_code_fence(fenced), "{\"answers\": {}}");
        let bare_fence = "```\n{\"answers\": {}}\n```";
        assert_eq!(strip_code_fence(bare_fence), "{\"answers\": {}}");
        let padded = "  \n{\"answers\": {}}\n ";
        assert_eq!(strip_code_fence(padded), "{\"answers\": {}}");
        assert_eq!(strip_code_fence("{\"answers\": {}}"), "{\"answers\": {}}");
        // A fence opened but never closed leaves the body, unparsed JSON
        // or not — the parse step owns that verdict, not the stripper.
        assert_eq!(strip_code_fence("```json\n{\"a\": 1}"), "{\"a\": 1}");
    }

    #[test]
    fn every_text_model_error_maps_one_to_one() {
        use std::time::Duration;
        assert_eq!(
            model_error(TextModelError::NotConfigured),
            ClassifierError::NotConfigured
        );
        assert_eq!(
            model_error(TextModelError::Rejected("4xx words".to_owned())),
            ClassifierError::Rejected("4xx words".to_owned())
        );
        assert_eq!(
            model_error(TextModelError::Transient {
                retry_after: Some(Duration::from_secs(7))
            }),
            ClassifierError::Transient {
                retry_after: Some(Duration::from_secs(7))
            }
        );
        assert_eq!(
            model_error(TextModelError::Transient { retry_after: None }),
            ClassifierError::Transient { retry_after: None }
        );
        assert_eq!(
            model_error(TextModelError::Transport("boom".to_owned())),
            ClassifierError::Transport("boom".to_owned())
        );
    }

    #[test]
    fn the_schema_pins_each_offered_label_and_nothing_else() {
        let questions = BTreeMap::from([
            (
                "topic".to_owned(),
                Question::Choice {
                    instructions: "Which?".to_owned(),
                    criteria: BTreeMap::from([
                        ("billing".to_owned(), "money".to_owned()),
                        ("bugs".to_owned(), "broken".to_owned()),
                    ]),
                },
            ),
            (
                "angry".to_owned(),
                Question::Noul {
                    instructions: "Angry?".to_owned(),
                },
            ),
        ]);
        let schema = answer_schema(&questions);
        let answers = &schema["properties"]["answers"];
        // A `BTreeMap` renders sorted, so `angry` precedes `topic`.
        assert_eq!(answers["required"], serde_json::json!(["angry", "topic"]));
        let topic = &answers["properties"]["topic"];
        assert_eq!(
            topic["properties"]["value"]["enum"],
            serde_json::json!(["billing", "bugs"])
        );
        assert_eq!(
            topic["properties"]["probabilities"]["required"],
            serde_json::json!(["billing", "bugs"])
        );
        let angry = &answers["properties"]["angry"];
        assert_eq!(
            angry["properties"]["value"]["enum"],
            serde_json::json!(["true", "false"])
        );
        let rendered = schema.to_string();
        assert!(
            !rendered.contains("spam"),
            "an unoffered label is not pinned"
        );
        assert_eq!(schema["additionalProperties"], serde_json::json!(false));
    }
}
