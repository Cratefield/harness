//! `cratefield-adapter-typesafe`: the `Classifier` port over `TypeSafe`'s
//! documented Jev evaluation API (`https://docs.typesafe.ai/api.md`).
//! Runs on the runtime's `HttpClient` port — no vendor SDK — so the same
//! adapter works on every runtime, and it bills **the operator's own
//! `TypeSafe` account**: the API key is a constructor argument, not a
//! port and not a platform binding.
//!
//! This is the default of the three `Classifier` adapters, and the only one
//! with a key at all. `profile()` reports `Calibration::Classifier`: the
//! probabilities come from a purpose-trained classifier model, not from a
//! general language model, and a threshold tuned against these numbers is
//! wrong against the `adapter-classifier-llm` family (see `CLASSIFIER.md`).
//!
//! The model is **pinned**, not aliased, and the version that actually
//! answered is recorded on every answer
//! ([`cratefield_core::Answer::model`]) — the "The model is pinned"
//! section below has the why.
//!
//! The adapter never trusts a response: an answer for a question that was
//! not asked, a question left unanswered, a label its question does not
//! offer, or a number outside `[0.0, 1.0]` is
//! `ClassifierError::Rejected`, not an invented answer.
//!
//! An absent or blank key is `ClassifierError::NotConfigured` from `ask`,
//! never a panic and never a network call — a venture that has not wired a
//! key degrades the way it degrades on an unwired port.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{
    Answer, AnswerValue, Calibration, Classifier, ClassifierError, ClassifierProfile, Clock,
    DEFAULT_MAX_STATE_CHARS, HttpClient, HttpError, HttpPolicy, MAX_RESPONSE_BYTES, Question,
    retry_after, validate_questions,
};
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{Request, StatusCode};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

/// The `TypeSafe` evaluation endpoint this adapter POSTs to, as documented
/// at `https://docs.typesafe.ai/api.md`. Tests point elsewhere with
/// [`TypeSafe::with_endpoint`].
pub const DEFAULT_ENDPOINT: &str = "https://api.typesafe.ai/v1/systemone";

/// The model every request carries unless overridden: a **pinned** version
/// id, not the `jev-latest` alias the vendor's examples use — an alias
/// moves without notice, and a threshold tuned to one version is wrong
/// against the next (see the crate docs). Move deliberately with
/// [`TypeSafe::with_model`].
pub const DEFAULT_MODEL: &str = "jev-1.13.0";

/// The most options a `choice` question may carry: the vendor's own
/// ceiling, refused pre-wire (`validate_questions` covers the minimum).
pub const MAX_CHOICE_OPTIONS: usize = 255;

/// The most levels a `score` question may carry: the vendor's own
/// ceiling, refused pre-wire (`validate_questions` covers the minimum).
pub const MAX_SCORE_LEVELS: usize = 10;

/// The request deadline asked of the [`HttpClient`] port: one evaluation
/// round trip, not a completion, so 20 s is generous and still under the
/// port's own 30 s ceiling.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// `TypeSafe`'s documented "overloaded" status, outside the standard 5xx
/// band: retryable, exactly like a 5xx.
const OVERLOADED: u16 = 529;

/// `Classifier` over `TypeSafe`'s Jev evaluation API, billed to the
/// operator's own key.
pub struct TypeSafe {
    http: Arc<dyn HttpClient>,
    /// Needed only to read the HTTP-date form of `Retry-After` (the same
    /// reason `adapter-resend` holds one, issue #278): a seconds-form
    /// header needs no clock, a "come back at 08:49:37 GMT" does.
    clock: Arc<dyn Clock>,
    /// `None`, or a blank string, is `ClassifierError::NotConfigured`.
    api_key: Option<String>,
    model: String,
    endpoint: String,
}

/// `Debug` names the endpoint, the model and whether a key is configured —
/// never the key: an adapter reaches debug output through harnesses and
/// panic messages, and the key rides the `Authorization` header and
/// nothing else.
impl fmt::Debug for TypeSafe {
    /// Never prints the key: it rides the `Authorization` header and
    /// nothing else.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypeSafe")
            .field("endpoint", &self.endpoint)
            .field("model", &self.model)
            .field("api_key_configured", &self.configured_key().is_some())
            // The `http` and `clock` ports are struct fields too; nothing
            // about either belongs in a debug line.
            .finish_non_exhaustive()
    }
}

impl TypeSafe {
    /// `api_key: None` (or a blank key) makes every `ask` answer
    /// `ClassifierError::NotConfigured` before any network call. The model
    /// is [`DEFAULT_MODEL`] and the endpoint [`DEFAULT_ENDPOINT`]; override
    /// either with [`TypeSafe::with_model`] / [`TypeSafe::with_endpoint`].
    pub fn new(http: Arc<dyn HttpClient>, clock: Arc<dyn Clock>, api_key: Option<String>) -> Self {
        Self {
            http,
            clock,
            api_key,
            model: DEFAULT_MODEL.to_owned(),
            endpoint: DEFAULT_ENDPOINT.to_owned(),
        }
    }

    /// Pins the model every request carries. The default is already a
    /// pinned version id rather than the `jev-latest` alias, because an
    /// alias moves without notice; use this to move to a new version on
    /// your own schedule.
    #[must_use]
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// Overrides the API endpoint (tests point this at a scripted client's
    /// expected host; production uses [`DEFAULT_ENDPOINT`]).
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    /// `Some(...)` only when `TYPESAFE_API_KEY` is set: an absent key means
    /// the port is not provided at all. `TYPESAFE_MODEL`, when set and
    /// non-blank, pins the model instead of [`DEFAULT_MODEL`] (the same
    /// pattern `ANTHROPIC_MODEL` follows). On Workers the venture should
    /// read the secret from its `Env` and use `TypeSafe::new` instead
    /// (`std::env` has no Workers vars). A key that is set but blank still
    /// constructs — and `ask` then answers `NotConfigured`.
    pub fn from_env(http: Arc<dyn HttpClient>, clock: Arc<dyn Clock>) -> Option<Self> {
        let api_key = std::env::var("TYPESAFE_API_KEY").ok()?;
        let model = model_from_env(std::env::var("TYPESAFE_MODEL").ok());
        Some(Self::new(http, clock, Some(api_key)).with_model(model))
    }

    /// The key this adapter authenticates with, trimmed: a padded key is
    /// still a key, a blank one is not configured at all.
    fn configured_key(&self) -> Option<&str> {
        self.api_key
            .as_deref()
            .map(str::trim)
            .filter(|key| !key.is_empty())
    }
}

/// `TYPESAFE_MODEL` honoured only when set and non-blank: a blank variable
/// is no configuration, not a model named `""`. Extracted for the same
/// reason `from_env` cannot be exercised directly — the environment is
/// process-global.
fn model_from_env(value: Option<String>) -> String {
    match value {
        Some(model) if !model.trim().is_empty() => model.trim().to_owned(),
        _ => DEFAULT_MODEL.to_owned(),
    }
}

/// The request body, as `https://docs.typesafe.ai/api.md` documents it:
/// one `state`, the pinned `model`, and **all** questions of the call as a
/// map keyed by the caller's own ids — the vendor evaluates the set
/// against the state in parallel, which is the whole point of the port.
#[derive(serde::Serialize)]
struct SystemOneRequest<'a> {
    state: &'a str,
    model: &'a str,
    questions: BTreeMap<&'a str, WireQuestion<'a>>,
}

/// One question on the wire. The three kinds share `type` and
/// `instructions`; each adds its own `criteria`, and a shape a kind does
/// not carry is omitted rather than sent empty — the vendor never sees a
/// `noul` with a stray `criteria`.
#[derive(serde::Serialize)]
struct WireQuestion<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    instructions: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    criteria: Option<WireCriteria<'a>>,
}

/// The two shapes `criteria` takes on the wire: a `choice`'s
/// `option -> what it means` map, and a `score`'s ordered array of level
/// descriptions. Jev's score criteria carries descriptions only — the
/// port's level *names* do not travel, and the answers re-key to them by
/// position (see `map_answers`).
#[derive(serde::Serialize)]
#[serde(untagged)]
enum WireCriteria<'a> {
    Options(BTreeMap<&'a str, &'a str>),
    Levels(Vec<&'a str>),
}

/// Pure request builder: the port's question set into the vendor's
/// documented request shape. Tested against the recorded example bodies
/// of the API docs (`tests/fixtures/`).
fn build_request<'a>(
    state: &'a str,
    model: &'a str,
    questions: &'a BTreeMap<String, Question>,
) -> SystemOneRequest<'a> {
    SystemOneRequest {
        state,
        model,
        questions: questions
            .iter()
            .map(|(id, question)| (id.as_str(), wire_question(question)))
            .collect(),
    }
}

fn wire_question(question: &Question) -> WireQuestion<'_> {
    match question {
        Question::Choice {
            instructions,
            criteria,
        } => WireQuestion {
            kind: question.kind(),
            instructions,
            criteria: Some(WireCriteria::Options(
                criteria
                    .iter()
                    .map(|(name, meaning)| (name.as_str(), meaning.as_str()))
                    .collect(),
            )),
        },
        Question::Score {
            instructions,
            levels,
        } => WireQuestion {
            kind: question.kind(),
            instructions,
            criteria: Some(WireCriteria::Levels(
                levels.iter().map(|(_, meaning)| meaning.as_str()).collect(),
            )),
        },
        Question::Noul { instructions } => WireQuestion {
            kind: question.kind(),
            instructions,
            criteria: None,
        },
    }
}

/// The vendor's own ceilings, checked after `validate_questions` and
/// before anything is built or sent.
///
/// # Errors
/// [`ClassifierError::Rejected`] when a question exceeds a limit — the
/// vendor would 422 the whole request, and the caller can know that
/// without paying for the round trip.
fn check_vendor_limits(questions: &BTreeMap<String, Question>) -> Result<(), ClassifierError> {
    for (id, question) in questions {
        match question {
            Question::Choice { criteria, .. } if criteria.len() > MAX_CHOICE_OPTIONS => {
                return Err(ClassifierError::Rejected(format!(
                    "choice question {id:?} carries {} options, over the {MAX_CHOICE_OPTIONS} the vendor accepts",
                    criteria.len()
                )));
            }
            Question::Score { levels, .. } if levels.len() > MAX_SCORE_LEVELS => {
                return Err(ClassifierError::Rejected(format!(
                    "score question {id:?} carries {} levels, over the {MAX_SCORE_LEVELS} the vendor accepts",
                    levels.len()
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

/// The success body, as documented: the versioned model that answered, one
/// answer under each asked id, and token usage.
#[derive(serde::Deserialize)]
struct SystemOneResponse {
    #[serde(default)]
    model: String,
    answers: BTreeMap<String, WireAnswer>,
    #[serde(default)]
    usage: Option<WireUsage>,
}

#[derive(serde::Deserialize, Default)]
struct WireUsage {
    #[serde(default)]
    input_tokens: u32,
    #[serde(default)]
    output_tokens: u32,
}

/// One answer, tagged by `type` the way the vendor tags it. A score answer
/// also carries a `legend` — the question's own level descriptions echoed
/// back under their indices; the question in hand is the authoritative
/// copy, so the legend is not read.
///
/// A body that does not fit these shapes never reaches the mapping below:
/// it is a parse failure, and that is a `Transport` — the answer did not
/// survive the hop — not a `Rejected` of the question set.
#[derive(serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WireAnswer {
    /// p(yes), on 0..=1. No confidence and no distribution of its own;
    /// both are derived below from this one number.
    Noul { noul: f32 },
    Choice {
        choice: String,
        probabilities: BTreeMap<String, f32>,
        confidence: f32,
    },
    Score {
        score: f32,
        probabilities: BTreeMap<String, f32>,
        confidence: f32,
    },
}

/// The kind name of a wire answer, for the mismatch message.
fn answer_kind(answer: &WireAnswer) -> &'static str {
    match answer {
        WireAnswer::Noul { .. } => "noul",
        WireAnswer::Choice { .. } => "choice",
        WireAnswer::Score { .. } => "score",
    }
}

/// Every refusal below is a `Rejected` with a message naming the question
/// and the offence. The log line stays generic on purpose: the message can
/// quote vendor-echoed text, and a log field is not scrubbed the way
/// `ClassifierError`'s `Display` is.
fn reject(message: String) -> ClassifierError {
    tracing::warn!(
        provider = "typesafe",
        "a typesafe answer does not match the question it answers"
    );
    ClassifierError::Rejected(message)
}

/// Maps the vendor's answer set onto the questions asked, refusing anything
/// that does not line up, and stamping the resolved model on every answer.
/// Every answer is checked against *its own* question: an answer for an id
/// that was not asked, a probability on a label the question never offered,
/// a number outside `[0.0, 1.0]`, or a value of the wrong shape is
/// `Rejected` — the adapter does not invent answers for questions the
/// vendor skipped, either. (Answers arrive as a JSON map keyed by id, so a
/// doubled id collapses in parsing rather than doubling here.)
fn map_answers(
    answers: BTreeMap<String, WireAnswer>,
    questions: &BTreeMap<String, Question>,
    model: &str,
) -> Result<BTreeMap<String, Answer>, ClassifierError> {
    let mut mapped = BTreeMap::new();
    for (id, answer) in answers {
        let Some(question) = questions.get(&id) else {
            return Err(reject(format!(
                "typesafe answered question id {id:?}, which was not asked"
            )));
        };
        let built = match (question, &answer) {
            (Question::Noul { .. }, WireAnswer::Noul { noul }) => noul_answer(&id, *noul)?,
            (
                Question::Choice { criteria, .. },
                WireAnswer::Choice {
                    choice,
                    probabilities,
                    confidence,
                },
            ) => choice_answer(&id, choice, probabilities, *confidence, criteria)?,
            (
                Question::Score { levels, .. },
                WireAnswer::Score {
                    score,
                    probabilities,
                    confidence,
                },
            ) => score_answer(&id, *score, probabilities, *confidence, levels)?,
            _ => {
                return Err(reject(format!(
                    "typesafe answered {} question {id:?} with a {} answer",
                    question.kind(),
                    answer_kind(&answer),
                )));
            }
        };
        mapped.insert(id, built.with_model(model));
    }
    if mapped.len() != questions.len() {
        let missing: Vec<_> = questions
            .keys()
            .filter(|id| !mapped.contains_key(*id))
            .cloned()
            .collect();
        return Err(reject(format!(
            "typesafe did not answer the question(s) {missing:?}"
        )));
    }
    Ok(mapped)
}

/// Jev answers a `noul` with one number: p(yes) — no confidence, no
/// probabilities. The port wants a verdict plus a probability per side, so
/// the other side is derived as `1 - p`, the verdict is `p >= 0.5`, and
/// `Answer::noul` reads its confidence out under the chosen side (the port's
/// bare-`f32` confidence has nowhere to say "derived"; making it optional is
/// a separate follow-up).
fn noul_answer(id: &str, noul: f32) -> Result<Answer, ClassifierError> {
    if !noul.is_finite() || !(0.0..=1.0).contains(&noul) {
        return Err(reject(format!(
            "typesafe answered noul question {id:?} with {noul}, outside [0, 1]"
        )));
    }
    let verdict = noul >= 0.5;
    let probabilities =
        BTreeMap::from([("true".to_owned(), noul), ("false".to_owned(), 1.0 - noul)]);
    Ok(Answer::noul(verdict, probabilities))
}

/// A `choice` answer: the chosen label must be one of the question's own
/// criteria, the probabilities keyed by criteria and inside the unit
/// interval, and the confidence inside it too.
fn choice_answer(
    id: &str,
    choice: &str,
    probabilities: &BTreeMap<String, f32>,
    confidence: f32,
    criteria: &BTreeMap<String, String>,
) -> Result<Answer, ClassifierError> {
    let checked = checked_probabilities(id, probabilities, criteria.keys().map(String::as_str))?;
    if !criteria.contains_key(choice) {
        return Err(reject(format!(
            "typesafe answered choice question {id:?} with {choice:?}, which is not one of its criteria"
        )));
    }
    if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
        return Err(reject(format!(
            "typesafe answered choice question {id:?} with confidence {confidence}, outside [0, 1]"
        )));
    }
    // The vendor's `confidence` is its own derivation from the
    // distribution — the docs' own example reports `0.81` over a `0.88`
    // top probability — so it is carried as reported through
    // `Answer::new` rather than re-derived from `probabilities` the way
    // `Answer::choice` would.
    Ok(Answer::new(
        AnswerValue::Choice(choice.to_owned()),
        checked,
        confidence,
    ))
}

/// A `score` answer: re-keys Jev's index-keyed probabilities to the
/// port's level names, and converts Jev's weighted index score onto the
/// scale the port's `AnswerValue::Score` lives on (see
/// `score_on_level_scale`).
fn score_answer(
    id: &str,
    score: f32,
    probabilities: &BTreeMap<String, f32>,
    confidence: f32,
    levels: &[(String, String)],
) -> Result<Answer, ClassifierError> {
    // Jev scores on the index axis of the criteria array it was sent —
    // index 0 is the port's first level. The weighted value must land
    // inside that axis; the tolerance absorbs the float noise of the
    // vendor's own weighted sum, not a real overshoot. (`validate_questions`
    // has already run, so a score question carries at least two levels and
    // the top index below exists.)
    #[allow(clippy::cast_precision_loss)] // a level count, never near f32's edge
    let top = (levels.len() - 1) as f32;
    if !score.is_finite()
        || !(-SCORE_RANGE_TOLERANCE..=top + SCORE_RANGE_TOLERANCE).contains(&score)
    {
        return Err(reject(format!(
            "typesafe scored question {id:?} at {score}, off its 0..={top} scale"
        )));
    }
    if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
        return Err(reject(format!(
            "typesafe answered score question {id:?} with confidence {confidence}, outside [0, 1]"
        )));
    }
    // Re-key by position: Jev's `"0"` is the port's first level *name*,
    // `"1"` its second, and so on. An index the question has no level for
    // is a refused answer, not a truncated distribution.
    let mut checked = BTreeMap::new();
    for (index, probability) in probabilities {
        let Ok(level) = index.parse::<usize>() else {
            return Err(reject(format!(
                "typesafe answered score question {id:?} under {index:?}, which is not a level index"
            )));
        };
        let Some((name, _)) = levels.get(level) else {
            return Err(reject(format!(
                "typesafe answered score question {id:?} at level {index}, which it does not have"
            )));
        };
        if !probability.is_finite() || !(0.0..=1.0).contains(probability) {
            return Err(reject(format!(
                "typesafe answered question {id:?} with probability {probability} for level {index}, outside [0, 1]"
            )));
        }
        checked.insert(name.clone(), *probability);
    }
    let value = score_on_level_scale(score, levels);
    // `Answer::score` looks confidence up under `value.to_string()`, which
    // only agrees with the vendor's report when the value happens to name
    // a level; an interpolated value (or the vendor's own confidence
    // derivation) does not, so the confidence is stated, not looked up.
    Ok(Answer::new(AnswerValue::Score(value), checked, confidence))
}

/// The probabilities are keyed by the question's own criteria — that is
/// what makes `confidence` and `probabilities` comparable. The port does
/// not require the masses to sum to one, so they are validated, not
/// renormalised.
fn checked_probabilities<'a>(
    id: &str,
    probabilities: &BTreeMap<String, f32>,
    criteria: impl Iterator<Item = &'a str>,
) -> Result<BTreeMap<String, f32>, ClassifierError> {
    let offered: Vec<&str> = criteria.collect();
    let mut checked = BTreeMap::new();
    for (label, probability) in probabilities {
        if !offered.contains(&label.as_str()) {
            return Err(reject(format!(
                "typesafe answered question {id:?} with label {label:?}, which it does not offer"
            )));
        }
        if !probability.is_finite() || !(0.0..=1.0).contains(probability) {
            return Err(reject(format!(
                "typesafe answered question {id:?} with probability {probability} for {label:?}, outside [0, 1]"
            )));
        }
        checked.insert(label.clone(), *probability);
    }
    Ok(checked)
}

/// Slack on a weighted score's range check: the vendor's own weighted sum
/// of reported probabilities can sit a hair outside `0..=levels-1` on a
/// rounded answer, and that is not an off-scale score.
const SCORE_RANGE_TOLERANCE: f32 = 1.0e-3;

/// Puts Jev's weighted index score on the scale `AnswerValue::Score` lives
/// on — the question's own level names (the port interpolates in that
/// space, and so does `adapter-classifier-llm`). Whole indices are exact —
/// index `i` is the port's `i`-th level — and the in-between is
/// interpolated linearly between the caller's names. Non-numeric names
/// (including a `"inf"` or `"NaN"`, which parse but are no axis) have no
/// name space to convert into, so the index position is carried as-is.
fn score_on_level_scale(score: f32, levels: &[(String, String)]) -> f32 {
    let parsed: Option<Vec<f32>> = levels
        .iter()
        .map(|(name, _)| name.parse::<f32>().ok().filter(|value| value.is_finite()))
        .collect();
    let Some(names) = parsed else {
        return score;
    };
    if names.len() < 2 {
        return names.first().copied().unwrap_or(score);
    }
    #[allow(clippy::cast_precision_loss)] // a level count, never near f32's edge
    let top = (names.len() - 1) as f32;
    let score = score.clamp(0.0, top);
    // clamped to 0..=top first, so neither the truncation nor the sign can bite
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let base = (score.floor() as usize).min(names.len() - 2);
    #[allow(clippy::cast_precision_loss)] // base <= names.len() - 2
    let fraction = score - base as f32;
    names[base] + fraction * (names[base + 1] - names[base])
}

#[async_trait]
impl Classifier for TypeSafe {
    fn profile(&self) -> ClassifierProfile {
        // `TypeSafe` serves purpose-trained classifier models: the numbers
        // are the model's own outputs. The state ceiling is core's
        // conservative default, not a `TypeSafe`-published budget.
        ClassifierProfile::new(Calibration::Classifier, DEFAULT_MAX_STATE_CHARS)
    }

    async fn ask(
        &self,
        state: &str,
        questions: &BTreeMap<String, Question>,
    ) -> Result<BTreeMap<String, Answer>, ClassifierError> {
        let Some(api_key) = self.configured_key() else {
            tracing::info!(
                provider = "typesafe",
                outcome = "not_configured",
                "classifier outcome"
            );
            return Err(ClassifierError::NotConfigured);
        };

        // A malformed set is a `Rejected`, never a panic, and the vendor's
        // own size ceilings are checked the same way, before the wire.
        validate_questions(questions)?;
        check_vendor_limits(questions)?;

        let profile = self.profile();
        let (state, dropped) = profile.truncate(state);
        if dropped {
            // The one failure mode a classifier must not have silently: a
            // trimmed state comes back confident and wrong, so the trim is
            // observable, with the limit that did it.
            tracing::warn!(
                limit = profile.max_state_chars,
                "typesafe classifier truncated the state; the answers see only the first `limit` chars"
            );
        }

        let payload = build_request(state, &self.model, questions);
        let body = serde_json::to_vec(&payload)
            .map_err(|err| ClassifierError::Transport(err.to_string()))?;
        let mut request = Request::builder()
            .method(http::Method::POST)
            .uri(&self.endpoint)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {api_key}"))
            .body(Bytes::from(body))
            .map_err(|err| ClassifierError::Transport(err.to_string()))?;
        // The port's defaults are ceilings, not choices, so the deadline is
        // stated explicitly (`adapter-anthropic` does the same).
        request.extensions_mut().insert(HttpPolicy {
            timeout: REQUEST_TIMEOUT,
            max_response_bytes: MAX_RESPONSE_BYTES,
        });

        let response = self.http.send(request).await.map_err(|err: HttpError| {
            tracing::warn!(
                provider = "typesafe",
                outcome = "transport",
                "typesafe transport failure"
            );
            ClassifierError::Transport(err.to_string())
        })?;

        let status = response.status();
        // One parser for both `Retry-After` forms; the date form needs the
        // clock this adapter is constructed with (issue #214/#278).
        let retry_after = retry_after(response.headers(), self.clock.as_ref());
        let text = String::from_utf8_lossy(response.body()).to_string();

        // Throttled or down: retryable, with the vendor's back-off where it
        // named one. 429 and 529 are named explicitly because neither sits
        // in the plain-5xx band this branch also covers.
        if status == StatusCode::TOO_MANY_REQUESTS
            || status.as_u16() == OVERLOADED
            || status.is_server_error()
        {
            tracing::warn!(
                provider = "typesafe",
                code = status.as_u16(),
                outcome = "transient",
                "classifier outcome"
            );
            return Err(ClassifierError::Transient { retry_after });
        }
        if !status.is_success() {
            // 401 for a bad key, 422 for a body the vendor's validation
            // refused: the request itself was refused, and the vendor's body
            // is the reason (`Display` scrubs the text, issue #235).
            tracing::warn!(
                provider = "typesafe",
                code = status.as_u16(),
                outcome = "rejected",
                "classifier outcome"
            );
            return Err(ClassifierError::Rejected(text));
        }

        let parsed: SystemOneResponse = match serde_json::from_str(&text) {
            Ok(parsed) => parsed,
            Err(err) => {
                tracing::warn!(
                    provider = "typesafe",
                    outcome = "transport",
                    "a typesafe success body did not survive the hop as an answer set"
                );
                return Err(ClassifierError::Transport(err.to_string()));
            }
        };
        // The docs' `model` is the version that actually answered — an
        // alias request (`jev-latest`) resolves here. Absent, it falls
        // back to what was asked, the way `adapter-anthropic` does.
        let resolved_model = if parsed.model.is_empty() {
            self.model.clone()
        } else {
            parsed.model
        };
        let answers = map_answers(parsed.answers, questions, &resolved_model)?;
        let usage = parsed.usage.unwrap_or_default();
        tracing::debug!(
            provider = "typesafe",
            outcome = "answered",
            model = %resolved_model,
            questions = answers.len(),
            input_tokens = usage.input_tokens,
            output_tokens = usage.output_tokens,
            "classifier outcome"
        );
        Ok(answers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                "angry".to_owned(),
                Question::Noul {
                    instructions: "Is the writer angry?".to_owned(),
                },
            ),
        ])
    }

    fn vendor_answer(id: &str, answer: WireAnswer) -> (String, WireAnswer) {
        (id.to_owned(), answer)
    }

    fn map(
        answers: Vec<(String, WireAnswer)>,
        questions: &BTreeMap<String, Question>,
    ) -> Result<BTreeMap<String, Answer>, ClassifierError> {
        map_answers(answers.into_iter().collect(), questions, DEFAULT_MODEL)
    }

    #[test]
    fn an_answer_for_an_id_that_was_not_asked_is_refused() {
        let answers = vec![vendor_answer("never-asked", WireAnswer::Noul { noul: 1.0 })];
        assert!(matches!(
            map(answers, &good_set()),
            Err(ClassifierError::Rejected(_))
        ));
    }

    #[test]
    fn a_label_outside_its_question_is_refused() {
        // Not a criterion of `topic`.
        let answers = vec![vendor_answer(
            "topic",
            WireAnswer::Choice {
                choice: "shipping".to_owned(),
                probabilities: BTreeMap::new(),
                confidence: 1.0,
            },
        )];
        assert!(matches!(
            map(answers, &good_set()),
            Err(ClassifierError::Rejected(_))
        ));
        // A probability on a label the question never offered.
        let answers = vec![vendor_answer(
            "topic",
            WireAnswer::Choice {
                choice: "bugs".to_owned(),
                probabilities: BTreeMap::from([("shipping".to_owned(), 1.0_f32)]),
                confidence: 1.0,
            },
        )];
        assert!(matches!(
            map(answers, &good_set()),
            Err(ClassifierError::Rejected(_))
        ));
    }

    #[test]
    fn a_number_outside_the_unit_interval_is_refused() {
        let answers = vec![vendor_answer(
            "topic",
            WireAnswer::Choice {
                choice: "bugs".to_owned(),
                probabilities: BTreeMap::from([("bugs".to_owned(), 1.5_f32)]),
                confidence: 0.5,
            },
        )];
        assert!(matches!(
            map(answers, &good_set()),
            Err(ClassifierError::Rejected(_))
        ));
        let answers = vec![vendor_answer(
            "topic",
            WireAnswer::Choice {
                choice: "bugs".to_owned(),
                probabilities: BTreeMap::from([("bugs".to_owned(), -0.1_f32)]),
                confidence: 0.5,
            },
        )];
        assert!(matches!(
            map(answers, &good_set()),
            Err(ClassifierError::Rejected(_))
        ));
        // An overflowing literal parses as an infinity; a non-finite
        // confidence is refused with the rest.
        let answers = vec![vendor_answer(
            "topic",
            WireAnswer::Choice {
                choice: "bugs".to_owned(),
                probabilities: BTreeMap::from([("bugs".to_owned(), 0.5_f32)]),
                confidence: f32::INFINITY,
            },
        )];
        assert!(matches!(
            map(answers, &good_set()),
            Err(ClassifierError::Rejected(_))
        ));
    }

    #[test]
    fn a_noul_is_derived_from_its_one_number() {
        let noul_only = BTreeMap::from([(
            "angry".to_owned(),
            Question::Noul {
                instructions: "Is the writer angry?".to_owned(),
            },
        )]);
        // p = 0.8: verdict true, the chosen side's probability the confidence.
        let answers = vec![vendor_answer("angry", WireAnswer::Noul { noul: 0.8 })];
        let mapped = map(answers, &noul_only).expect("maps");
        let angry = &mapped["angry"];
        assert_eq!(angry.value, AnswerValue::Noul(true));
        assert!((angry.probabilities["true"] - 0.8).abs() < f32::EPSILON);
        assert!((angry.probabilities["false"] - 0.2).abs() < f32::EPSILON);
        assert!((angry.confidence - 0.8).abs() < f32::EPSILON, "{angry:?}");

        // p = 0.3: verdict false, and the confidence is 1 - p.
        let answers = vec![vendor_answer("angry", WireAnswer::Noul { noul: 0.3 })];
        let mapped = map(answers, &noul_only).expect("maps");
        let angry = &mapped["angry"];
        assert_eq!(angry.value, AnswerValue::Noul(false));
        assert!((angry.confidence - 0.7).abs() < f32::EPSILON, "{angry:?}");
    }

    #[test]
    fn a_noul_outside_the_unit_interval_is_refused() {
        let noul_only = BTreeMap::from([(
            "angry".to_owned(),
            Question::Noul {
                instructions: "Is the writer angry?".to_owned(),
            },
        )]);
        for noul in [-0.1_f32, 1.1, f32::NAN] {
            let answers = vec![vendor_answer("angry", WireAnswer::Noul { noul })];
            assert!(
                matches!(map(answers, &noul_only), Err(ClassifierError::Rejected(_))),
                "noul {noul} refused"
            );
        }
    }

    #[test]
    fn a_score_re_keys_to_the_level_names_and_interpolates_the_value() {
        // Jev's own documented example: weighted index 1.05 on a
        // three-level scale whose names are words — no numeric name space,
        // so the index position itself is the value.
        let words = BTreeMap::from([(
            "frustration".to_owned(),
            Question::Score {
                instructions: "How frustrated?".to_owned(),
                levels: vec![
                    ("Calm".to_owned(), "Calm".to_owned()),
                    ("Frustrated".to_owned(), "Frustrated".to_owned()),
                    ("Very angry".to_owned(), "Very angry".to_owned()),
                ],
            },
        )]);
        let answers = vec![vendor_answer(
            "frustration",
            WireAnswer::Score {
                score: 1.05,
                probabilities: BTreeMap::from([
                    ("0".to_owned(), 0.0_f32),
                    ("1".to_owned(), 0.95_f32),
                    ("2".to_owned(), 0.05_f32),
                ]),
                confidence: 0.92,
            },
        )];
        let mapped = map(answers, &words).expect("maps");
        let frustration = &mapped["frustration"];
        assert!(
            (value_score(frustration) - 1.05).abs() < f32::EPSILON,
            "{frustration:?}"
        );
        assert!((frustration.probabilities["Frustrated"] - 0.95).abs() < f32::EPSILON);
        assert!((frustration.probabilities["Very angry"] - 0.05).abs() < f32::EPSILON);
        assert!((frustration.confidence - 0.92).abs() < f32::EPSILON);

        // The same weighted index on a scale named `"1"`/`"5"`: index 0 is
        // name `1`, index 1 name `5`, and 0.7 of the way between is
        // 1 + 0.7 * 4 = 3.8.
        let numeric = BTreeMap::from([(
            "severity".to_owned(),
            Question::Score {
                instructions: "How severe?".to_owned(),
                levels: vec![
                    ("1".to_owned(), "a typo".to_owned()),
                    ("5".to_owned(), "data loss".to_owned()),
                ],
            },
        )]);
        let answers = vec![vendor_answer(
            "severity",
            WireAnswer::Score {
                score: 0.7,
                probabilities: BTreeMap::from([
                    ("0".to_owned(), 0.3_f32),
                    ("1".to_owned(), 0.7_f32),
                ]),
                confidence: 0.7,
            },
        )];
        let mapped = map(answers, &numeric).expect("maps");
        let severity = &mapped["severity"];
        assert!((value_score(severity) - 3.8).abs() < 1.0e-5, "{severity:?}");
        assert!((severity.probabilities["1"] - 0.3).abs() < f32::EPSILON);
        assert!((severity.probabilities["5"] - 0.7).abs() < f32::EPSILON);

        // A whole index is exactly that level's name: index 1 on the
        // `"1"`/`"5"` scale is 5.
        let answers = vec![vendor_answer(
            "severity",
            WireAnswer::Score {
                score: 1.0,
                probabilities: BTreeMap::from([
                    ("0".to_owned(), 0.2_f32),
                    ("1".to_owned(), 0.8_f32),
                ]),
                confidence: 0.8,
            },
        )];
        let mapped = map(answers, &numeric).expect("maps");
        assert!((value_score(&mapped["severity"]) - 5.0).abs() < f32::EPSILON);
    }

    #[test]
    fn a_level_named_like_a_float_special_is_not_a_number_axis() {
        // `"inf"` and `"NaN"` parse as floats but are not points on a
        // scale: the names are words, so the index position is carried.
        let words = BTreeMap::from([(
            "odd".to_owned(),
            Question::Score {
                instructions: "How odd?".to_owned(),
                levels: vec![
                    ("inf".to_owned(), "not much".to_owned()),
                    ("NaN".to_owned(), "very".to_owned()),
                ],
            },
        )]);
        let answers = vec![vendor_answer(
            "odd",
            WireAnswer::Score {
                score: 0.5,
                probabilities: BTreeMap::from([
                    ("0".to_owned(), 0.5_f32),
                    ("1".to_owned(), 0.5_f32),
                ]),
                confidence: 0.5,
            },
        )];
        let mapped = map(answers, &words).expect("maps");
        assert!((value_score(&mapped["odd"]) - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn a_score_off_its_scale_or_over_its_levels_is_refused() {
        let numeric = BTreeMap::from([(
            "severity".to_owned(),
            Question::Score {
                instructions: "How severe?".to_owned(),
                levels: vec![
                    ("1".to_owned(), "a typo".to_owned()),
                    ("5".to_owned(), "data loss".to_owned()),
                ],
            },
        )]);
        let scored = |score: f32, probabilities: BTreeMap<String, f32>| {
            vec![vendor_answer(
                "severity",
                WireAnswer::Score {
                    score,
                    probabilities,
                    confidence: 0.7,
                },
            )]
        };
        // Past the top index.
        assert!(matches!(
            map(
                scored(1.5, BTreeMap::from([("0".to_owned(), 1.0_f32)])),
                &numeric
            ),
            Err(ClassifierError::Rejected(_))
        ));
        // A probability under an index the question has no level for.
        assert!(matches!(
            map(
                scored(0.5, BTreeMap::from([("7".to_owned(), 1.0_f32)])),
                &numeric
            ),
            Err(ClassifierError::Rejected(_))
        ));
        // A probability under something that is not an index at all.
        assert!(matches!(
            map(
                scored(0.5, BTreeMap::from([("data loss".to_owned(), 1.0_f32)])),
                &numeric
            ),
            Err(ClassifierError::Rejected(_))
        ));
    }

    #[test]
    fn typesafe_model_is_honoured_only_when_set_and_non_blank() {
        assert_eq!(model_from_env(None), DEFAULT_MODEL);
        assert_eq!(model_from_env(Some(String::new())), DEFAULT_MODEL);
        assert_eq!(model_from_env(Some("   ".to_owned())), DEFAULT_MODEL);
        assert_eq!(model_from_env(Some("jev-latest".to_owned())), "jev-latest");
        // And what it honours, it honours trimmed.
        assert_eq!(
            model_from_env(Some("  jev-preview  ".to_owned())),
            "jev-preview"
        );
    }

    /// The f32 of an [`AnswerValue::Score`], for the assertions above.
    fn value_score(answer: &Answer) -> f32 {
        match answer.value {
            AnswerValue::Score(score) => score,
            ref other => panic!("not a score: {other:?}"),
        }
    }
}
