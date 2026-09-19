//! `cratefield-adapter-typesafe`: the `Classifier` port over the `TypeSafe`
//! classify API (issue #456). Runs on the runtime's `HttpClient` port — no
//! vendor SDK — so the same adapter works on every runtime, and it bills
//! **the operator's own `TypeSafe` account**: the API key is a constructor
//! argument, not a port and not a platform binding.
//!
//! This is the default of the three `Classifier` adapters, and the only one
//! with a key at all. `profile()` reports `Calibration::Classifier`: the
//! probabilities come from a purpose-trained classifier model, not from a
//! general language model, and a threshold tuned against these numbers is
//! wrong against the `adapter-classifier-llm` family (see `CLASSIFIER.md`).
//!
//! The wire format below is this crate's *assumption* of `TypeSafe`'s API, not
//! something the vendor documents in this repository — a reviewer wiring a
//! real account should check it against the real API (the README restates
//! it with the four load-bearing choices spelled out). The adapter never
//! trusts a response either: an answer naming a label its question does not
//! offer, a missing or duplicated question id, or a probability outside
//! `[0.0, 1.0]` is `ClassifierError::Rejected`, not an invented answer.
//!
//! An absent or blank key is `ClassifierError::NotConfigured` from `ask`,
//! never a panic and never a network call — a venture that has not wired a
//! key degrades the way it degrades on an unwired port.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{
    Answer, Calibration, Classifier, ClassifierError, ClassifierProfile, Clock,
    DEFAULT_MAX_STATE_CHARS, HttpClient, HttpError, Question, retry_after, validate_questions,
};
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{Request, StatusCode};
use std::collections::BTreeMap;
use std::sync::Arc;

/// The `TypeSafe` classify endpoint this adapter assumes (see the crate docs
/// and the README's wire-format section).
const CLASSIFY_URL: &str = "https://api.typesafe.ai/v1/classify";

/// `Classifier` over the `TypeSafe` classify API, billed to the operator's
/// own key.
pub struct TypeSafe {
    http: Arc<dyn HttpClient>,
    /// Needed only to read the HTTP-date form of `Retry-After` (the same
    /// reason `adapter-resend` holds one, issue #278): a seconds-form
    /// header needs no clock, a "come back at 08:49:37 GMT" does.
    clock: Arc<dyn Clock>,
    /// `None`, or a blank string, is `ClassifierError::NotConfigured`.
    api_key: Option<String>,
}

impl TypeSafe {
    /// `api_key: None` (or a blank key) makes every `ask` answer
    /// `ClassifierError::NotConfigured` before any network call.
    pub fn new(http: Arc<dyn HttpClient>, clock: Arc<dyn Clock>, api_key: Option<String>) -> Self {
        Self {
            http,
            clock,
            api_key,
        }
    }

    /// `Some(...)` only when `TYPESAFE_API_KEY` is set: an absent key means
    /// the port is not provided at all. On Workers the venture should read
    /// the secret from its `Env` and use `TypeSafe::new` instead
    /// (`std::env` has no Workers vars). A key that is set but blank still
    /// constructs — and `ask` then answers `NotConfigured`.
    pub fn from_env(http: Arc<dyn HttpClient>, clock: Arc<dyn Clock>) -> Option<Self> {
        let api_key = std::env::var("TYPESAFE_API_KEY").ok()?;
        Some(Self::new(http, clock, Some(api_key)))
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

/// The request body: one `state` and **all** questions of the call — the
/// provider evaluates the set against the state in parallel, which is the
/// whole point of the port. Shapes not carried by a question's kind are
/// omitted rather than sent empty, so the vendor never sees a `noul` with
/// a stray `criteria` object.
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

/// The success body: one answer per asked question id.
#[derive(serde::Deserialize)]
struct ClassifyResponse {
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

/// A vendor answer value. Untagged: a JSON string is a label, a JSON
/// number is a score.
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum WireValue {
    Label(String),
    Number(f32),
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
/// that does not line up. Every answer is checked against *its own*
/// question: an answer for an id that was not asked, a second answer for
/// the same id, a probability on a label the question never offered, a
/// probability outside `[0.0, 1.0]`, or a value of the wrong shape is
/// `Rejected` — the adapter does not invent answers for questions the
/// vendor skipped, either.
fn map_answers(
    answers: Vec<WireAnswer>,
    questions: &BTreeMap<String, Question>,
) -> Result<BTreeMap<String, Answer>, ClassifierError> {
    let mut mapped = BTreeMap::new();
    for answer in answers {
        let WireAnswer {
            id,
            value,
            probabilities,
        } = answer;
        let Some(question) = questions.get(&id) else {
            return Err(reject(format!(
                "typesafe answered question id {id:?}, which was not asked"
            )));
        };
        if mapped.contains_key(&id) {
            return Err(reject(format!("typesafe answered question {id:?} twice")));
        }

        // The probabilities are keyed by the question's own labels — that
        // is what makes `confidence` and `probabilities` agree below. The
        // port does not require the masses to sum to one, so they are
        // validated, not renormalised.
        let labels = question.labels();
        let mut checked = BTreeMap::new();
        for (label, probability) in probabilities {
            if !labels.contains(&label.as_str()) {
                return Err(reject(format!(
                    "typesafe answered question {id:?} with label {label:?}, which it does not offer"
                )));
            }
            if !(0.0..=1.0).contains(&probability) {
                return Err(reject(format!(
                    "typesafe answered question {id:?} with probability {probability} for {label:?}, outside [0, 1]"
                )));
            }
            checked.insert(label, probability);
        }

        let built = match question {
            Question::Choice { criteria, .. } => {
                let WireValue::Label(label) = value else {
                    return Err(reject(format!(
                        "typesafe answered choice question {id:?} with a number, not a criterion"
                    )));
                };
                if !criteria.contains_key(&label) {
                    return Err(reject(format!(
                        "typesafe answered choice question {id:?} with {label:?}, which is not one of its criteria"
                    )));
                }
                Answer::choice(label, checked)
            }
            Question::Score { levels, .. } => {
                let WireValue::Number(score) = value else {
                    return Err(reject(format!(
                        "typesafe answered score question {id:?} with a label, not a number"
                    )));
                };
                // When every level name is numeric, the score must land on
                // one of them; a scale named in words has nothing to check
                // the number against. Compared with a tolerance: both sides
                // are decimals that parsed to floats.
                let numeric_levels: Vec<_> = levels
                    .iter()
                    .map(|(name, _)| name.parse::<f32>().ok())
                    .collect();
                let all_numeric = numeric_levels.iter().all(Option::is_some);
                if all_numeric
                    && !numeric_levels.iter().any(|parsed| {
                        parsed.is_some_and(|n| (n - score).abs() < SCORE_MATCH_TOLERANCE)
                    })
                {
                    return Err(reject(format!(
                        "typesafe scored question {id:?} at {score}, off its scale"
                    )));
                }
                Answer::score(score, checked)
            }
            Question::Noul { .. } => {
                let WireValue::Label(label) = value else {
                    return Err(reject(format!(
                        "typesafe answered noul question {id:?} with a number, not true or false"
                    )));
                };
                let verdict = match label.as_str() {
                    "true" => true,
                    "false" => false,
                    other => {
                        return Err(reject(format!(
                            "typesafe answered noul question {id:?} with {other:?}, which is neither true nor false"
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
            "typesafe did not answer the question(s) {missing:?}"
        )));
    }
    Ok(mapped)
}

/// A score is matched against numeric level names within this much of the
/// vendor's number: both sides are decimals that parsed to `f32`, so exact
/// equality would be greedy and `clippy::float_cmp` has a point.
const SCORE_MATCH_TOLERANCE: f32 = 1.0e-6;

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
                limit = profile.max_state_chars,
                "typesafe classifier truncated the state; the answers see only the first `limit` chars"
            );
        }

        let payload = ClassifyRequest {
            state,
            questions: questions
                .iter()
                .map(|(id, question)| wire_question(id, question))
                .collect(),
        };
        let body = serde_json::to_vec(&payload)
            .map_err(|err| ClassifierError::Transport(err.to_string()))?;
        let request = Request::builder()
            .method(http::Method::POST)
            .uri(CLASSIFY_URL)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {api_key}"))
            .body(Bytes::from(body))
            .map_err(|err| ClassifierError::Transport(err.to_string()))?;

        let response = self.http.send(request).await.map_err(|err: HttpError| {
            tracing::warn!(
                provider = "typesafe",
                outcome = "transport",
                "typesafe classify transport failure"
            );
            ClassifierError::Transport(err.to_string())
        })?;

        let status = response.status();
        // One parser for both `Retry-After` forms; the date form needs the
        // clock this adapter is constructed with (issue #214/#278).
        let retry_after = retry_after(response.headers(), self.clock.as_ref());
        let text = String::from_utf8_lossy(response.body()).to_string();

        // Throttled or down: retryable, with the vendor's back-off where it
        // named one. 429 is a 4xx but never a `Rejected` — the request was
        // fine, the moment is not.
        if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
            tracing::warn!(
                provider = "typesafe",
                code = status.as_u16(),
                outcome = "transient",
                "classifier outcome"
            );
            return Err(ClassifierError::Transient { retry_after });
        }
        if !status.is_success() {
            // A 4xx (or an unexpected 3xx): the vendor refused the request,
            // and its body is the reason. `Display` scrubs the text before
            // it can reach a log line or a dead-letter row (issue #235).
            tracing::warn!(
                provider = "typesafe",
                code = status.as_u16(),
                outcome = "rejected",
                "classifier outcome"
            );
            return Err(ClassifierError::Rejected(text));
        }

        let parsed: ClassifyResponse = match serde_json::from_str(&text) {
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
        let answers = map_answers(parsed.answers, questions)?;
        tracing::debug!(
            provider = "typesafe",
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

    fn wire_value(questions: &BTreeMap<String, Question>) -> serde_json::Value {
        let payload = ClassifyRequest {
            state: "the state",
            questions: questions
                .iter()
                .map(|(id, question)| wire_question(id, question))
                .collect(),
        };
        serde_json::to_value(&payload).expect("serialises")
    }

    #[test]
    fn the_request_carries_each_kind_in_its_own_shape() {
        let sent = wire_value(&good_set());
        assert_eq!(sent["state"], "the state");
        let questions = sent["questions"].as_array().expect("array");
        assert_eq!(questions.len(), 2);

        let choice = questions
            .iter()
            .find(|q| q["id"] == "topic")
            .expect("choice question");
        assert_eq!(choice["kind"], "choice");
        assert_eq!(choice["criteria"]["bugs"], "something is broken");
        assert!(choice.get("levels").is_none());

        let noul = questions
            .iter()
            .find(|q| q["id"] == "angry")
            .expect("noul question");
        assert_eq!(noul["kind"], "noul");
        assert!(noul.get("criteria").is_none());
        assert!(noul.get("levels").is_none());
    }

    #[test]
    fn a_score_question_travels_as_ordered_levels() {
        let questions = BTreeMap::from([(
            "severity".to_owned(),
            Question::Score {
                instructions: "How severe?".to_owned(),
                levels: vec![
                    ("1".to_owned(), "a typo".to_owned()),
                    ("5".to_owned(), "data loss".to_owned()),
                ],
            },
        )]);
        let sent = wire_value(&questions);
        let severity = &sent["questions"][0];
        assert_eq!(severity["kind"], "score");
        assert!(severity.get("criteria").is_none());
        let levels = severity["levels"].as_array().expect("levels array");
        assert_eq!(
            levels,
            &vec![
                serde_json::json!({"name": "1", "meaning": "a typo"}),
                serde_json::json!({"name": "5", "meaning": "data loss"}),
            ]
        );
    }

    fn vendor_answer(
        id: &str,
        value: WireValue,
        probabilities: BTreeMap<String, f32>,
    ) -> WireAnswer {
        WireAnswer {
            id: id.to_owned(),
            value,
            probabilities,
        }
    }

    #[test]
    fn a_well_formed_set_maps_through_the_core_constructors() {
        let answers = vec![
            vendor_answer(
                "topic",
                WireValue::Label("bugs".to_owned()),
                BTreeMap::from([
                    ("billing".to_owned(), 0.1_f32),
                    ("bugs".to_owned(), 0.9_f32),
                ]),
            ),
            vendor_answer(
                "angry",
                WireValue::Label("false".to_owned()),
                BTreeMap::from([("true".to_owned(), 0.2_f32), ("false".to_owned(), 0.8_f32)]),
            ),
        ];
        let mapped = map_answers(answers, &good_set()).expect("maps");
        assert_eq!(mapped.len(), 2);
        let topic = &mapped["topic"];
        assert_eq!(topic.value, Answer::choice("bugs", BTreeMap::new()).value);
        assert!((topic.confidence - 0.9).abs() < f32::EPSILON, "{topic:?}");
        let angry = &mapped["angry"];
        assert_eq!(angry.value, Answer::noul(false, BTreeMap::new()).value);
        assert!((angry.confidence - 0.8).abs() < f32::EPSILON, "{angry:?}");
    }

    #[test]
    fn an_answer_for_an_id_that_was_not_asked_is_refused() {
        let answers = vec![vendor_answer(
            "never-asked",
            WireValue::Label("bugs".to_owned()),
            BTreeMap::new(),
        )];
        assert!(matches!(
            map_answers(answers, &good_set()),
            Err(ClassifierError::Rejected(_))
        ));
    }

    #[test]
    fn a_twice_answered_question_is_refused() {
        let answers = vec![
            vendor_answer(
                "topic",
                WireValue::Label("bugs".to_owned()),
                BTreeMap::new(),
            ),
            vendor_answer(
                "topic",
                WireValue::Label("billing".to_owned()),
                BTreeMap::new(),
            ),
        ];
        assert!(matches!(
            map_answers(answers, &good_set()),
            Err(ClassifierError::Rejected(_))
        ));
    }

    #[test]
    fn a_label_outside_its_question_is_refused() {
        // Not a criterion of `topic`.
        let answers = vec![vendor_answer(
            "topic",
            WireValue::Label("shipping".to_owned()),
            BTreeMap::new(),
        )];
        assert!(matches!(
            map_answers(answers, &good_set()),
            Err(ClassifierError::Rejected(_))
        ));
        // Not `true`/`false`.
        let answers = vec![vendor_answer(
            "angry",
            WireValue::Label("maybe".to_owned()),
            BTreeMap::new(),
        )];
        assert!(matches!(
            map_answers(answers, &good_set()),
            Err(ClassifierError::Rejected(_))
        ));
        // A probability on a label the question never offered.
        let answers = vec![vendor_answer(
            "topic",
            WireValue::Label("bugs".to_owned()),
            BTreeMap::from([("shipping".to_owned(), 1.0_f32)]),
        )];
        assert!(matches!(
            map_answers(answers, &good_set()),
            Err(ClassifierError::Rejected(_))
        ));
    }

    #[test]
    fn a_probability_outside_the_unit_interval_is_refused() {
        let answers = vec![vendor_answer(
            "topic",
            WireValue::Label("bugs".to_owned()),
            BTreeMap::from([("bugs".to_owned(), 1.5_f32)]),
        )];
        assert!(matches!(
            map_answers(answers, &good_set()),
            Err(ClassifierError::Rejected(_))
        ));
        let answers = vec![vendor_answer(
            "topic",
            WireValue::Label("bugs".to_owned()),
            BTreeMap::from([("bugs".to_owned(), -0.1_f32)]),
        )];
        assert!(matches!(
            map_answers(answers, &good_set()),
            Err(ClassifierError::Rejected(_))
        ));
    }

    #[test]
    fn a_score_off_its_numeric_scale_is_refused_and_one_on_it_maps() {
        let severity = |score: f32| {
            vec![vendor_answer(
                "severity",
                WireValue::Number(score),
                BTreeMap::from([("1".to_owned(), 0.7_f32), ("5".to_owned(), 0.3_f32)]),
            )]
        };
        let questions = BTreeMap::from([(
            "severity".to_owned(),
            Question::Score {
                instructions: "How severe?".to_owned(),
                levels: vec![
                    ("1".to_owned(), "a typo".to_owned()),
                    ("5".to_owned(), "data loss".to_owned()),
                ],
            },
        )]);

        let mapped = map_answers(severity(1.0), &questions).expect("on the scale");
        assert_eq!(
            mapped["severity"].value,
            Answer::score(1.0, BTreeMap::new()).value
        );
        assert!((mapped["severity"].confidence - 0.7).abs() < f32::EPSILON);
        assert!(matches!(
            map_answers(severity(3.0), &questions),
            Err(ClassifierError::Rejected(_))
        ));
    }

    #[test]
    fn a_partly_answered_set_is_refused_rather_than_invented() {
        let answers = vec![vendor_answer(
            "topic",
            WireValue::Label("bugs".to_owned()),
            BTreeMap::new(),
        )];
        assert!(matches!(
            map_answers(answers, &good_set()),
            Err(ClassifierError::Rejected(_))
        ));
    }
}
