//! Cost-aware classifier routing end to end (issue #457), over a scripted
//! stub and the labelled corpus in `data/classifier-corpus.json`.
#![expect(
    clippy::disallowed_types,
    reason = "the stub records its calls, as the fakes in cratefield-testing do"
)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cratefield_core::{
    Accounting, AdapterId, AgreementReport, Answer, AnswerValue, Calibration, CallOutcome,
    CallRole, Classifier, ClassifierError, ClassifierProfile, CorpusItem, DEFAULT_MAX_STATE_CHARS,
    GroundTruth, InMemoryLedger, Price, PriceSheet, Question, QuestionKind, RouteReason,
    RoutingClassifier, RoutingError, RoutingPolicy, ShadowClassifier, Thresholds, TokenSource,
    measure_agreement, validate_questions,
};
use serde_json::Value;

const ACCESS: &str = "Under GDPR Article 15 I am requesting a copy of all personal data you hold about me, in a machine-readable format.";
const ERASURE: &str = "delete all my data";
const LIVE: &str = "a message the corpus has never seen";

/// Every question the corpus defines, and its items.
fn corpus() -> (BTreeMap<String, Question>, Vec<CorpusItem>) {
    let json: Value =
        serde_json::from_str(include_str!("data/classifier-corpus.json")).expect("corpus JSON");
    let text = |v: &Value| v.as_str().expect("a string").to_owned();
    let questions: BTreeMap<String, Question> = json["questions"]
        .as_object()
        .expect("questions")
        .iter()
        .map(|(id, q)| {
            let question = match (q.get("choice"), q.get("noul")) {
                (Some(c), _) => Question::Choice {
                    instructions: text(&c["instructions"]),
                    criteria: c["criteria"]
                        .as_object()
                        .expect("criteria")
                        .iter()
                        .map(|(k, v)| (k.clone(), text(v)))
                        .collect(),
                },
                (_, Some(n)) => Question::Noul {
                    instructions: text(&n["instructions"]),
                },
                _ => panic!("unknown question shape for {id}"),
            };
            (id.clone(), question)
        })
        .collect();
    let items = json["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| {
            let expected: BTreeMap<String, AnswerValue> = item["expected"]
                .as_object()
                .expect("expected")
                .iter()
                .map(|(id, v)| match v {
                    Value::String(label) => (id.clone(), AnswerValue::Choice(label.clone())),
                    Value::Bool(verdict) => (id.clone(), AnswerValue::Noul(*verdict)),
                    other => panic!("unsupported gold value {other}"),
                })
                .collect();
            CorpusItem {
                state: text(&item["state"]),
                questions: expected
                    .keys()
                    .map(|id| (id.clone(), questions[id].clone()))
                    .collect(),
                expected,
            }
        })
        .collect();
    (questions, items)
}

fn label_of(value: &AnswerValue) -> String {
    match value {
        AnswerValue::Choice(label) => label.clone(),
        AnswerValue::Noul(verdict) => verdict.to_string(),
        AnswerValue::Score(score) => score.to_string(),
    }
}

fn value_for(question: &Question, label: &str) -> AnswerValue {
    match question {
        Question::Noul { .. } => AnswerValue::Noul(label == "true"),
        _ => AnswerValue::Choice(label.to_owned()),
    }
}

/// `value` at `confidence`, the rest of the mass on one other label.
fn answer(question: &Question, value: &AnswerValue, confidence: f32, runner_up: f32) -> Answer {
    let label = label_of(value);
    let other = question
        .labels()
        .into_iter()
        .find(|l| *l != label)
        .expect("two labels");
    let probabilities = BTreeMap::from([(label, confidence), (other.to_owned(), runner_up)]);
    Answer::new(value.clone(), probabilities, confidence)
}

fn sure(question: &Question, value: &AnswerValue) -> Answer {
    answer(question, value, 0.9, 0.1)
}

/// A scripted classifier: a set answer per (state, question id), else a
/// sure answer of the question's first label; failing on chosen states.
struct Stub {
    calibration: Calibration,
    answers: BTreeMap<(String, String), Answer>,
    fails: fn(&str) -> bool,
    calls: Mutex<Vec<Vec<String>>>,
}

impl Stub {
    fn new(calibration: Calibration) -> Self {
        Self {
            calibration,
            answers: BTreeMap::new(),
            fails: |_| false,
            calls: Mutex::default(),
        }
    }

    /// Answers every corpus item with its gold value.
    fn oracle(items: &[CorpusItem], calibration: Calibration) -> Self {
        let mut stub = Self::new(calibration);
        for item in items {
            for (id, gold) in &item.expected {
                stub = stub.with(&item.state, id, sure(&item.questions[id], gold));
            }
        }
        stub
    }

    fn with(mut self, state: &str, id: &str, answer: Answer) -> Self {
        self.answers
            .insert((state.to_owned(), id.to_owned()), answer);
        self
    }

    fn failing(mut self, fails: fn(&str) -> bool) -> Self {
        self.fails = fails;
        self
    }

    fn calls(&self) -> Vec<Vec<String>> {
        self.calls.lock().expect("calls").clone()
    }
}

#[async_trait]
impl Classifier for Stub {
    fn profile(&self) -> ClassifierProfile {
        ClassifierProfile::new(self.calibration, DEFAULT_MAX_STATE_CHARS)
    }

    async fn ask(
        &self,
        state: &str,
        questions: &BTreeMap<String, Question>,
    ) -> Result<BTreeMap<String, Answer>, ClassifierError> {
        self.calls
            .lock()
            .expect("calls")
            .push(questions.keys().cloned().collect());
        if (self.fails)(state) {
            return Err(ClassifierError::Transport("stub down".to_owned()));
        }
        Ok(questions
            .iter()
            .map(|(id, q)| {
                let scripted = self.answers.get(&(state.to_owned(), id.clone())).cloned();
                (
                    id.clone(),
                    scripted.unwrap_or_else(|| sure(q, &value_for(q, q.labels()[0]))),
                )
            })
            .collect())
    }
}

fn cheap_id() -> AdapterId {
    AdapterId::new("workers-ai")
}

fn dear_id() -> AdapterId {
    AdapterId::new("frontier-llm")
}

fn named(id: AdapterId, stub: &Arc<Stub>) -> (AdapterId, Arc<dyn Classifier>) {
    (id, Arc::clone(stub) as Arc<dyn Classifier>)
}

fn accounting() -> (Accounting, Arc<InMemoryLedger>) {
    let prices = PriceSheet::new()
        .with(cheap_id(), Price::per_million_tokens(10_000, 40_000))
        .with(dear_id(), Price::per_million_tokens(3_000_000, 15_000_000));
    let ledger = Arc::new(InMemoryLedger::new());
    (Accounting::new(prices, ledger.clone()), ledger)
}

/// Measures `cheap` against a perfect expensive adapter over `items`.
async fn measure(cheap: Stub, items: &[CorpusItem]) -> (AgreementReport, Arc<InMemoryLedger>) {
    let dear = Arc::new(Stub::oracle(items, Calibration::LanguageModel));
    let (accounting, ledger) = accounting();
    let cheap = named(cheap_id(), &Arc::new(cheap));
    let report = measure_agreement(&cheap, &named(dear_id(), &dear), items, &accounting).await;
    (report, ledger)
}

/// Evidence where the two adapters agree on everything.
async fn all_agree(items: &[CorpusItem]) -> AgreementReport {
    measure(Stub::oracle(items, Calibration::Classifier), items)
        .await
        .0
}

/// Evidence where the cheap adapter agrees except on `release-note-kind`,
/// which it always gets wrong.
async fn evidence(items: &[CorpusItem]) -> AgreementReport {
    let mut cheap = Stub::oracle(items, Calibration::Classifier);
    for item in items {
        if let Some(gold) = item.expected.get("release-note-kind") {
            let question = &item.questions["release-note-kind"];
            let labels = question.labels();
            let wrong = labels
                .iter()
                .find(|l| **l != label_of(gold))
                .expect("a wrong label");
            let answer = sure(question, &value_for(question, wrong));
            cheap = cheap.with(&item.state, "release-note-kind", answer);
        }
    }
    measure(cheap, items).await.0
}

fn thresholds(min_confidence: f32, min_margin: f32) -> Thresholds {
    Thresholds {
        calibration: Calibration::Classifier,
        min_confidence,
        min_margin,
    }
}

fn router(
    cheap: &Arc<Stub>,
    dear: &Arc<Stub>,
    policy: RoutingPolicy,
) -> (RoutingClassifier, Arc<InMemoryLedger>) {
    let (accounting, ledger) = accounting();
    let router = RoutingClassifier::new(
        named(cheap_id(), cheap),
        named(dear_id(), dear),
        policy,
        accounting,
    )
    .expect("a valid policy");
    (router, ledger)
}

#[pollster::test]
async fn the_corpus_is_well_formed_and_every_measured_call_is_recorded_at_an_estimated_price() {
    let (_, items) = corpus();
    assert_eq!(items.len(), 56);
    for item in &items {
        validate_questions(&item.questions).expect("valid questions");
        for (id, gold) in &item.expected {
            assert!(
                item.questions[id]
                    .labels()
                    .contains(&label_of(gold).as_str()),
                "{id}: {gold:?}"
            );
        }
    }

    let (report, ledger) = measure(Stub::oracle(&items, Calibration::Classifier), &items).await;
    for (kind, k) in &report.kinds {
        assert_eq!(k.agreement_rate(), Some(1.0), "{kind}");
        assert_eq!(
            (k.graded, k.cheap_right, k.expensive_right),
            (k.questions, k.questions, k.questions)
        );
    }

    let records = ledger.records();
    assert_eq!(
        records.len(),
        2 * items.len(),
        "one call per adapter per item"
    );
    let prices =
        PriceSheet::new().with(dear_id(), Price::per_million_tokens(3_000_000, 15_000_000));
    for record in records.iter().filter(|r| r.adapter == dear_id()) {
        assert_eq!(
            (record.role, record.outcome),
            (CallRole::Shadow, CallOutcome::Ok)
        );
        assert_eq!(record.tokens.source, TokenSource::Estimated);
        assert!(record.tokens.input > 0 && record.tokens.output > 0);
        assert_eq!(record.kinds.len(), 1);
        assert_eq!(record.cost, prices.cost_of(&dear_id(), &record.tokens));
    }
    let totals = ledger.totals();
    assert!(totals[&cheap_id()].pico_usd < totals[&dear_id()].pico_usd);
    assert_eq!(totals[&cheap_id()].unpriced_calls, 0);
}

#[pollster::test]
async fn disagreement_says_who_was_right_and_a_failed_item_is_skipped_not_fatal() {
    let (_, items) = corpus();
    let (_, question) = items
        .iter()
        .find(|i| i.state == ACCESS)
        .expect("the access item")
        .questions
        .first_key_value()
        .expect("one question");
    let cheap = Stub::oracle(&items, Calibration::Classifier)
        .with(
            ACCESS,
            "privacy-request-kind",
            sure(question, &AnswerValue::Choice("erasure".to_owned())),
        )
        .failing(|state| state == ERASURE);
    let (report, ledger) = measure(cheap, &items).await;

    let privacy = &report.kinds[&QuestionKind::new("privacy-request-kind")];
    assert_eq!(
        (privacy.questions, privacy.agreed, privacy.skipped),
        (11, 10, 1)
    );
    assert_eq!((privacy.cheap_right, privacy.expensive_right), (10, 11));
    let wrong = &privacy.disagreements[0];
    assert_eq!(
        (
            wrong.cheap.as_str(),
            wrong.expensive.as_str(),
            wrong.expected.as_deref()
        ),
        ("erasure", "access", Some("access"))
    );
    assert_eq!(wrong.right, GroundTruth::Expensive);
    assert_eq!(wrong.item.map(|i| items[i].state.as_str()), Some(ACCESS));

    let failed: Vec<_> = ledger
        .records()
        .into_iter()
        .filter(|r| r.outcome == CallOutcome::Failed)
        .collect();
    assert_eq!(
        failed.len(),
        1,
        "the expensive adapter is not asked once the cheap one failed"
    );
    assert_eq!((failed[0].cost, failed[0].tokens.output), (None, 0));
    assert_eq!(ledger.totals()[&cheap_id()].failed_calls, 1);

    let round_trip: AgreementReport =
        serde_json::from_str(&serde_json::to_string(&report).expect("serialises"))
            .expect("deserialises");
    assert_eq!(round_trip, report);
}

#[pollster::test]
async fn shadow_mode_serves_exactly_the_expensive_answers_even_when_the_cheap_one_fails() {
    let (questions, _) = corpus();
    let dear = Arc::new(Stub::new(Calibration::LanguageModel));
    let expected = dear.ask(LIVE, &questions).await.expect("answers");

    for cheap in [
        Stub::new(Calibration::Classifier).failing(|_| true),
        Stub::new(Calibration::Classifier),
    ] {
        let (accounting, ledger) = accounting();
        let shadow = ShadowClassifier::new(
            named(cheap_id(), &Arc::new(cheap)),
            named(dear_id(), &dear),
            accounting,
        );
        assert_eq!(shadow.ask(LIVE, &questions).await, Ok(expected.clone()));
        assert_eq!(shadow.profile().calibration, Calibration::LanguageModel);

        let roles: Vec<_> = ledger
            .records()
            .iter()
            .map(|r| (r.adapter.clone(), r.role))
            .collect();
        assert_eq!(
            roles,
            [
                (dear_id(), CallRole::Served),
                (cheap_id(), CallRole::Shadow)
            ]
        );
        let kind = &shadow.report().kinds[&QuestionKind::new("release-note-kind")];
        assert_eq!(kind.questions + kind.skipped, 1);
    }
}

#[pollster::test]
async fn routing_sends_to_the_cheap_adapter_only_the_kinds_it_measured_well_on() {
    let (questions, items) = corpus();
    let report = evidence(&items).await;
    let policy =
        || RoutingPolicy::measured(report.clone()).thresholds(cheap_id(), thresholds(0.5, 0.2));
    let (cheap, dear) = (
        Arc::new(Stub::new(Calibration::Classifier)),
        Arc::new(Stub::new(Calibration::LanguageModel)),
    );

    let (routed, ledger) = router(&cheap, &dear, policy().min_questions(10));
    let answers = routed.ask_routed(LIVE, &questions).await.expect("answers");
    let reasons: BTreeMap<&str, (AdapterId, RouteReason)> = answers
        .iter()
        .map(|(id, r)| (id.as_str(), (r.adapter.clone(), r.reason)))
        .collect();
    assert_eq!(
        reasons["release-note-kind"],
        (dear_id(), RouteReason::DisagreementTooHigh)
    );
    for id in [
        "waitlist-signup-quality",
        "inbound-message-language",
        "privacy-request-kind",
        "cms-draft-review",
    ] {
        assert_eq!(
            reasons[id],
            (cheap_id(), RouteReason::CheapAccepted),
            "{id}"
        );
    }
    assert_eq!(dear.calls(), [["release-note-kind"]]);
    assert!(ledger.records().iter().all(|r| r.role == CallRole::Served));
    assert_eq!(routed.profile().calibration, Calibration::LanguageModel);

    let (strict, _) = router(&cheap, &dear, policy().min_questions(11));
    let answers = strict.ask_routed(LIVE, &questions).await.expect("answers");
    assert_eq!(
        answers["cms-draft-review"].reason,
        RouteReason::NotMeasuredEnough,
        "10 items < 11"
    );

    let unmeasured =
        BTreeMap::from([("new-kind".to_owned(), questions["cms-draft-review"].clone())]);
    let answers = strict.ask_routed(LIVE, &unmeasured).await.expect("answers");
    assert_eq!(answers["new-kind"].reason, RouteReason::NoMeasurement);

    let (uncalibrated, _) = router(&cheap, &dear, RoutingPolicy::measured(report.clone()));
    let answers = uncalibrated
        .ask_routed(LIVE, &questions)
        .await
        .expect("answers");
    assert!(
        answers
            .values()
            .all(|r| r.reason == RouteReason::NoCalibration && r.adapter == dear_id())
    );
}

#[pollster::test]
async fn unsure_cheap_answers_escalate_together_in_one_second_ask() {
    let (questions, items) = corpus();
    let lang = &questions["inbound-message-language"];
    let privacy = &questions["privacy-request-kind"];
    let cheap = Arc::new(
        Stub::new(Calibration::Classifier)
            .with(
                LIVE,
                "inbound-message-language",
                answer(lang, &value_for(lang, "en"), 0.6, 0.1),
            )
            .with(
                LIVE,
                "privacy-request-kind",
                answer(privacy, &value_for(privacy, "access"), 0.85, 0.6),
            ),
    );
    let dear = Arc::new(Stub::new(Calibration::LanguageModel));
    let policy = RoutingPolicy::measured(all_agree(&items).await)
        .thresholds(cheap_id(), thresholds(0.8, 0.3))
        .min_questions(10);
    let (routed, ledger) = router(&cheap, &dear, policy);

    let answers = routed.ask_routed(LIVE, &questions).await.expect("answers");
    assert_eq!(
        answers["inbound-message-language"].reason,
        RouteReason::EscalatedLowConfidence
    );
    assert_eq!(
        answers["privacy-request-kind"].reason,
        RouteReason::EscalatedNarrowMargin
    );
    assert_eq!(
        answers["release-note-kind"].reason,
        RouteReason::CheapAccepted
    );
    assert_eq!(
        answers.keys().collect::<Vec<_>>(),
        questions.keys().collect::<Vec<_>>()
    );
    assert_eq!(cheap.calls().len(), 1);
    assert_eq!(
        dear.calls(),
        [["inbound-message-language", "privacy-request-kind"]]
    );
    assert!(ledger.records().iter().all(|r| r.role == CallRole::Served));
}

#[pollster::test]
async fn a_cheap_failure_escalates_and_an_expensive_failure_is_the_error() {
    let (questions, items) = corpus();
    let report = all_agree(&items).await;
    let policy = || {
        RoutingPolicy::measured(report.clone())
            .thresholds(cheap_id(), thresholds(0.5, 0.2))
            .min_questions(10)
    };

    let down = Arc::new(Stub::new(Calibration::Classifier).failing(|_| true));
    let dear = Arc::new(Stub::new(Calibration::LanguageModel));
    let (routed, ledger) = router(&down, &dear, policy());
    let answers = routed
        .ask_routed(LIVE, &questions)
        .await
        .expect("escalated");
    assert!(
        answers
            .values()
            .all(|r| r.reason == RouteReason::EscalatedCheapFailed && r.adapter == dear_id())
    );
    assert_eq!(dear.calls().len(), 1, "one escalation for every question");
    let cheap_row = ledger
        .records()
        .into_iter()
        .find(|r| r.adapter == cheap_id())
        .expect("recorded");
    assert_eq!(
        (cheap_row.role, cheap_row.outcome),
        (CallRole::Discarded, CallOutcome::Failed)
    );

    let unsure = Arc::new(Stub::new(Calibration::Classifier).with(
        LIVE,
        "cms-draft-review",
        answer(
            &questions["cms-draft-review"],
            &AnswerValue::Noul(true),
            0.3,
            0.2,
        ),
    ));
    let dear_down = Arc::new(Stub::new(Calibration::LanguageModel).failing(|_| true));
    let (routed, ledger) = router(&unsure, &dear_down, policy());
    assert_eq!(
        routed.ask(LIVE, &questions).await,
        Err(ClassifierError::Transport("stub down".to_owned()))
    );
    let roles: Vec<_> = ledger
        .records()
        .iter()
        .map(|r| (r.adapter.clone(), r.role))
        .collect();
    assert_eq!(
        roles,
        [
            (cheap_id(), CallRole::Served),
            (dear_id(), CallRole::Served)
        ],
        "the cheap call is recorded when it returns, and four of its answers were accepted"
    );

    let empty = BTreeMap::new();
    assert!(matches!(
        routed.ask(LIVE, &empty).await,
        Err(ClassifierError::Rejected(_))
    ));
    assert_eq!(
        ledger.records().len(),
        2,
        "a rejected set reaches no adapter"
    );
}

/// Answers only once `gate` has been opened: the expensive half of the
/// concurrency test below.
struct Gated {
    gate: Mutex<Option<futures_channel::oneshot::Receiver<()>>>,
}

/// Opens `gate` when asked: the cheap half.
struct Opener {
    gate: Mutex<Option<futures_channel::oneshot::Sender<()>>>,
}

#[async_trait]
impl Classifier for Gated {
    fn profile(&self) -> ClassifierProfile {
        ClassifierProfile::new(Calibration::LanguageModel, DEFAULT_MAX_STATE_CHARS)
    }

    async fn ask(
        &self,
        state: &str,
        questions: &BTreeMap<String, Question>,
    ) -> Result<BTreeMap<String, Answer>, ClassifierError> {
        let gate = self.gate.lock().expect("gate").take().expect("asked once");
        gate.await.expect("the cheap call opens the gate");
        Stub::new(Calibration::LanguageModel)
            .ask(state, questions)
            .await
    }
}

#[async_trait]
impl Classifier for Opener {
    fn profile(&self) -> ClassifierProfile {
        ClassifierProfile::new(Calibration::Classifier, DEFAULT_MAX_STATE_CHARS)
    }

    async fn ask(
        &self,
        state: &str,
        questions: &BTreeMap<String, Question>,
    ) -> Result<BTreeMap<String, Answer>, ClassifierError> {
        let gate = self.gate.lock().expect("gate").take().expect("asked once");
        gate.send(()).expect("the expensive call is waiting");
        Stub::new(Calibration::Classifier)
            .ask(state, questions)
            .await
    }
}

#[test]
fn shadow_mode_asks_both_adapters_at_once() {
    // The expensive call cannot finish until the cheap one has started, so
    // asking them one after the other would stay pending for ever; asked
    // together, a few polls finish it.
    let (questions, _) = corpus();
    let (open, gate) = futures_channel::oneshot::channel();
    let cheap: Arc<dyn Classifier> = Arc::new(Opener {
        gate: Some(open).into(),
    });
    let dear: Arc<dyn Classifier> = Arc::new(Gated {
        gate: Some(gate).into(),
    });
    let (accounting, ledger) = accounting();
    let shadow = ShadowClassifier::new((cheap_id(), cheap), (dear_id(), dear), accounting);

    let mut call = shadow.ask(LIVE, &questions);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    let answered = (0..4).find_map(|_| match call.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(answers) => Some(answers),
        std::task::Poll::Pending => None,
    });
    assert!(answered.expect("finished within a few polls").is_ok());
    assert_eq!(ledger.records().len(), 2);
}

#[pollster::test]
async fn a_policy_that_cannot_mean_what_it_says_is_refused_at_wiring() {
    let (_, items) = corpus();
    let (cheap, dear) = (
        Arc::new(Stub::new(Calibration::LanguageModel)),
        Arc::new(Stub::new(Calibration::LanguageModel)),
    );
    let refusal = |policy: RoutingPolicy| {
        let (accounting, _) = accounting();
        RoutingClassifier::new(
            named(cheap_id(), &cheap),
            named(dear_id(), &dear),
            policy,
            accounting,
        )
        .err()
    };

    assert_eq!(
        refusal(RoutingPolicy::off().thresholds(cheap_id(), thresholds(0.9, 0.3))),
        Some(RoutingError::CalibrationMismatch {
            adapter: cheap_id(),
            declared: Calibration::Classifier,
            reported: Calibration::LanguageModel,
        })
    );
    let stranger = AdapterId::new("stranger");
    assert_eq!(
        refusal(RoutingPolicy::pinned(stranger.clone())),
        Some(RoutingError::UnknownAdapter(stranger.clone()))
    );
    assert_eq!(
        refusal(RoutingPolicy::off().thresholds(stranger.clone(), thresholds(0.9, 0.3))),
        Some(RoutingError::UnknownAdapter(stranger))
    );

    let mut elsewhere = evidence(&items).await;
    elsewhere.cheap = AdapterId::new("last-years-model");
    assert!(matches!(
        refusal(RoutingPolicy::measured(elsewhere)),
        Some(RoutingError::EvidenceForOtherAdapters { .. })
    ));
    let language_model = Thresholds {
        calibration: Calibration::LanguageModel,
        ..thresholds(0.9, 0.3)
    };
    assert_eq!(
        refusal(RoutingPolicy::off().thresholds(cheap_id(), language_model)),
        None
    );
}

#[pollster::test]
async fn off_and_pinned_bypass_routing_entirely() {
    let (questions, _) = corpus();
    assert_eq!(RoutingPolicy::default(), RoutingPolicy::off());
    let lang = &questions["inbound-message-language"];
    let unsure = answer(lang, &value_for(lang, "de"), 0.2, 0.1);
    let cheap = Arc::new(Stub::new(Calibration::Classifier).with(
        LIVE,
        "inbound-message-language",
        unsure.clone(),
    ));
    let dear = Arc::new(Stub::new(Calibration::LanguageModel));

    let (off, _) = router(&cheap, &dear, RoutingPolicy::default());
    let answers = off.ask_routed(LIVE, &questions).await.expect("answers");
    assert!(
        answers
            .values()
            .all(|r| r.adapter == dear_id() && r.reason == RouteReason::RoutingOff)
    );
    assert!(cheap.calls().is_empty());

    let (pinned, ledger) = router(&cheap, &dear, RoutingPolicy::pinned(cheap_id()));
    let answers = pinned.ask_routed(LIVE, &questions).await.expect("answers");
    assert_eq!(
        answers["inbound-message-language"].answer, unsure,
        "a pin never escalates"
    );
    assert!(
        answers
            .values()
            .all(|r| r.adapter == cheap_id() && r.reason == RouteReason::Pinned)
    );
    assert_eq!(pinned.profile().calibration, Calibration::Classifier);
    assert_eq!(dear.calls().len(), 1, "only the off router's call");
    assert_eq!(ledger.records()[0].role, CallRole::Served);

    let down = Arc::new(Stub::new(Calibration::Classifier).failing(|_| true));
    let (pinned_down, _) = router(&down, &dear, RoutingPolicy::pinned(cheap_id()));
    assert!(
        pinned_down.ask(LIVE, &questions).await.is_err(),
        "a pinned failure is not escalated"
    );
    assert_eq!(dear.calls().len(), 1);
}
