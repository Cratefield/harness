//! The corpus run (issue #457): the authored corpus in
//! `tests/data/classifier-corpus.json` is measured through two
//! deterministic stub classifiers whose behaviour each test controls, and
//! the resulting [`AgreementReport`] is asserted against what those stubs
//! imply, per kind.
//!
//! No real adapter is involved and no number here is a claim about any
//! model — the stubs are scripted, the corpus is authored, and what the
//! test buys is confidence in the arithmetic (counts, rates, who-was-right
//! tallies, skipped errors): the part a venture's routing decision will
//! stand on.
//!
//! The routing tests at the bottom run the whole loop of the issue, end
//! to end: the measured report is serialised and reloaded as committed
//! evidence, a [`RoutingPolicy`] is built from the reloaded report, and a
//! [`RoutingClassifier`] drives real corpus questions through to a
//! ledger — including the honesty default, that with the evidence
//! withheld everything routes expensive. Same rule as above: the stubs
//! are scripted, and no number here is a claim about any model.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use serde::Deserialize;

use cratefield_core::{
    AdapterId, AgreementReport, CallOutcome, CallRole, Classification, Classifier, ClassifierError,
    CorpusQuestion, Cost, InMemoryLedger, MeasurementOptions, Price, PriceSheet, Question,
    QuestionKind, RouteReason, RoutingClassifier, RoutingPolicy, Thresholds, measure_agreement,
};

const CORPUS_JSON: &str = include_str!("data/classifier-corpus.json");

/// The confidence a scripted answer carries when the test has not
/// scripted otherwise: comfortably above the routing tests' calibrated
/// confidence floor of `0.8`.
const SCRIPTED_CONFIDENCE: f32 = 0.9;

/// The gold-label question the disagreement tests script the cheap stub
/// to miss: a privacy access request the cheap stub answers `other` to.
const GDPR_ACCESS_REQUEST: &str = "Under GDPR Article 15 I am requesting a copy of all personal \
                                   data you hold about me, in a machine-readable format.";

/// The gold-label question the error tests script the cheap stub to fail
/// on: a short erasure request.
const DELETE_ALL_DATA: &str = "delete all my data";

#[derive(Deserialize)]
struct CorpusFile {
    questions: Vec<CorpusQuestion>,
}

fn corpus() -> Vec<CorpusQuestion> {
    let file: CorpusFile = serde_json::from_str(CORPUS_JSON).expect("the authored corpus parses");
    file.questions
}

fn corpus_questions_for(kind: &QuestionKind, corpus: &[CorpusQuestion]) -> u64 {
    u64::try_from(
        corpus
            .iter()
            .filter(|question| &question.kind == kind)
            .count(),
    )
    .expect("a corpus fits in a u64")
}

/// A classifier whose answers are scripted: the corpus's gold label by
/// default, a named override where a test wants a disagreement, a
/// per-kind answer where the routing tests want a whole kind the cheap
/// stub is bad at, a scripted low confidence where a test wants an
/// answer that falls below a threshold, and a scripted error where a
/// test wants a skip.
struct Scripted {
    adapter: AdapterId,
    gold: HashMap<String, String>,
    overrides: HashMap<String, String>,
    kind_answers: HashMap<String, String>,
    confidences: HashMap<String, f32>,
    fail_on: HashSet<String>,
    input_tokens: u64,
    output_tokens: u64,
    calls: AtomicUsize,
}

impl Scripted {
    /// The oracle: the gold answer to every question in the corpus.
    fn oracle(adapter: &str, corpus: &[CorpusQuestion]) -> Self {
        Self {
            adapter: AdapterId::new(adapter),
            gold: corpus
                .iter()
                .filter_map(|question| {
                    question
                        .gold
                        .clone()
                        .map(|gold| (question.text.clone(), gold))
                })
                .collect(),
            overrides: HashMap::new(),
            kind_answers: HashMap::new(),
            confidences: HashMap::new(),
            fail_on: HashSet::new(),
            input_tokens: 0,
            output_tokens: 0,
            calls: AtomicUsize::new(0),
        }
    }

    /// Overrides the answer to one question, to force a disagreement.
    fn answering(mut self, text: &str, label: &str) -> Self {
        self.overrides.insert(text.to_owned(), label.to_owned());
        self
    }

    /// Answers `label` to every question of `kind`, whatever the gold
    /// answer: how the routing tests script one whole kind the cheap
    /// stub is bad at, without scripting its questions one by one.
    fn answering_kind(mut self, kind: &str, label: &str) -> Self {
        self.kind_answers.insert(kind.to_owned(), label.to_owned());
        self
    }

    /// Scripts one question's confidence, its label unchanged: how the
    /// routing tests script an answer that is right but falls below a
    /// calibrated threshold.
    fn hedging_on(mut self, text: &str, confidence: f32) -> Self {
        self.confidences.insert(text.to_owned(), confidence);
        self
    }

    /// Sets the token counts every answer carries, so a routed run
    /// prices the stubs like real adapters.
    fn with_usage(mut self, input_tokens: u64, output_tokens: u64) -> Self {
        self.input_tokens = input_tokens;
        self.output_tokens = output_tokens;
        self
    }

    /// Scripts an error on the given questions, to force skips.
    fn failing_on(mut self, texts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.fail_on.extend(texts.into_iter().map(Into::into));
        self
    }

    /// Clears the call counter, so a test that measures and then routes
    /// with the same stub instance counts only the routed calls: the
    /// measurement run and the routed run are different phases, and it
    /// is the router's asking that the routing tests assert on.
    fn reset_calls(&self) {
        self.calls.store(0, Ordering::Relaxed);
    }
}

#[async_trait]
impl Classifier for Scripted {
    fn adapter(&self) -> &AdapterId {
        &self.adapter
    }

    async fn classify(&self, question: &Question) -> Result<Classification, ClassifierError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.fail_on.contains(&question.text) {
            return Err(ClassifierError::Transport("scripted failure".to_owned()));
        }
        // The most specific script wins: a per-question override, then a
        // per-kind answer, then the gold label.
        let label = self
            .overrides
            .get(&question.text)
            .or_else(|| self.kind_answers.get(question.kind.as_str()))
            .or_else(|| self.gold.get(&question.text))
            .expect("the test scripts every question it feeds");
        let confidence = self
            .confidences
            .get(&question.text)
            .copied()
            .unwrap_or(SCRIPTED_CONFIDENCE);
        Ok(
            Classification::new(self.adapter.clone(), "scripted", label.clone(), confidence)
                .usage(self.input_tokens, self.output_tokens),
        )
    }
}

#[test]
fn every_corpus_question_is_well_formed_so_the_stubs_can_script_it() {
    let corpus = corpus();
    let kinds: HashSet<&str> = corpus
        .iter()
        .map(|question| question.kind.as_str())
        .collect();
    assert!(
        kinds.len() > 1,
        "agreement is measured per kind; one kind would say nothing about the rest"
    );
    for question in &corpus {
        assert!(
            question.labels.len() > 1,
            "`{}` offers more than one candidate label, like production questions do",
            question.kind
        );
        let gold = question
            .gold
            .as_ref()
            .expect("the corpus is authored with gold answers, which the stubs script from");
        assert!(
            question.labels.iter().any(|label| label == gold),
            "the gold answer `{gold}` is on its own question's label list"
        );
        assert!(
            !question.text.trim().is_empty(),
            "a question with no text measures nothing"
        );
    }
}

#[pollster::test]
async fn the_corpus_reports_perfect_agreement_when_both_stubs_are_the_oracle() {
    let corpus = corpus();
    let cheap = Scripted::oracle("stub-cheap", &corpus);
    let expensive = Scripted::oracle("stub-expensive", &corpus);

    let report =
        measure_agreement(&cheap, &expensive, &corpus, &MeasurementOptions::default()).await;

    assert_eq!(
        report.cheap(),
        &AdapterId::new("stub-cheap"),
        "the report names the pair it measured, cheap side first"
    );
    assert_eq!(report.expensive(), &AdapterId::new("stub-expensive"));
    assert_eq!(report.skipped(), 0, "the oracle never errors");
    let compared: u64 = report.kinds().map(|(_, kind)| kind.questions).sum();
    let total = u64::try_from(corpus.len()).expect("a corpus fits in a u64");
    assert_eq!(
        compared, total,
        "every corpus question was compared exactly once"
    );
    for (kind, entry) in report.kinds() {
        assert_eq!(
            entry.questions,
            corpus_questions_for(kind, &corpus),
            "the whole kind was compared, for every kind"
        );
        assert_eq!(
            entry.agreed, entry.questions,
            "both stubs answer the gold label, so everything agrees"
        );
        assert_eq!(entry.errors, 0);
        assert!(entry.disagreements.is_empty());
        assert_eq!(
            entry.cheap_right + entry.expensive_right + entry.neither_right,
            0,
            "no disagreement means no who-was-right tally"
        );
        let rate = entry.disagreement_rate().expect("the kind was measured");
        assert!(
            rate.abs() < 1e-9,
            "a perfect run disagrees about nothing: {rate}"
        );
    }
}

#[pollster::test]
async fn a_scripted_disagreement_is_graded_against_the_gold_label() {
    let corpus = corpus();
    let privacy = QuestionKind::new("privacy-request-kind");
    let expected = corpus_questions_for(&privacy, &corpus);
    let cheap = Scripted::oracle("stub-cheap", &corpus).answering(GDPR_ACCESS_REQUEST, "other");
    let expensive = Scripted::oracle("stub-expensive", &corpus);

    let report =
        measure_agreement(&cheap, &expensive, &corpus, &MeasurementOptions::default()).await;

    let entry = report.kind(&privacy).expect("the privacy kind is measured");
    assert_eq!(
        entry.questions, expected,
        "a disagreement is still a compared question"
    );
    assert_eq!(entry.agreed, expected - 1);
    assert_eq!(
        entry.disagreements.len(),
        1,
        "exactly the scripted question disagrees"
    );
    let disagreement = &entry.disagreements[0];
    assert_eq!(
        disagreement.cheap_label, "other",
        "the cheap stub's scripted answer"
    );
    assert_eq!(
        disagreement.expensive_label, "access",
        "the expensive stub holds the gold answer"
    );
    assert_eq!(
        disagreement.gold.as_deref(),
        Some("access"),
        "the gold answer is kept"
    );
    assert!(
        disagreement.question.is_none(),
        "the run did not opt into recording question text"
    );
    assert_eq!(
        entry.graded, 1,
        "the gold answer grades exactly this disagreement"
    );
    assert_eq!(
        entry.expensive_right, 1,
        "the gold side is the expensive side here"
    );
    assert_eq!(entry.cheap_right, 0);
    assert_eq!(entry.neither_right, 0);
    let rate = entry.disagreement_rate().expect("the kind was measured");
    let one_in = 1.0 / f64::from(u32::try_from(expected).expect("a kind fits in a u32"));
    assert!(
        (rate - one_in).abs() < 1e-9,
        "one disagreement in {expected} compared: {rate}"
    );
}

#[pollster::test]
async fn a_cheap_error_is_skipped_and_counted_and_never_counts_as_agreement() {
    let corpus = corpus();
    let privacy = QuestionKind::new("privacy-request-kind");
    let expected = corpus_questions_for(&privacy, &corpus);
    let cheap = Scripted::oracle("stub-cheap", &corpus).failing_on([DELETE_ALL_DATA]);
    let expensive = Scripted::oracle("stub-expensive", &corpus);

    let report =
        measure_agreement(&cheap, &expensive, &corpus, &MeasurementOptions::default()).await;

    assert_eq!(
        report.skipped(),
        1,
        "the errored question is counted in the report, not dropped"
    );
    let entry = report.kind(&privacy).expect("the privacy kind is measured");
    assert_eq!(entry.errors, 1, "the error lands on its kind");
    assert_eq!(
        entry.questions,
        expected - 1,
        "the errored question is in no rate's denominator"
    );
    assert_eq!(
        entry.agreed,
        expected - 1,
        "and it is never counted as agreement"
    );
    let rate = entry.agreement_rate().expect("questions were compared");
    assert!(
        (rate - 1.0).abs() < 1e-9,
        "the compared questions agreed, honestly, with the skip counted beside them: {rate}"
    );
    let asked = u64::try_from(expensive.calls.load(Ordering::Relaxed)).expect("fits");
    let total = u64::try_from(corpus.len()).expect("fits");
    assert_eq!(
        asked,
        total - 1,
        "the expensive half of a question the cheap side failed is never asked: \
         the run prices like the router it informs"
    );
}

/// The measurement run is itself accounted (issue #457: every classifier
/// call records tokens, adapter and price): wired with a price sheet and
/// a ledger, the corpus run books both sides of every question it
/// compares — each as `CallRole::Shadow`, asked to compare and never
/// served — and the failed question's lone cheap half, so a venture
/// knows what the last run cost before pointing it at a larger corpus.
#[pollster::test]
async fn a_measured_corpus_run_with_a_ledger_books_both_sides_of_every_question_it_compares() {
    let corpus = corpus();
    let cheap_id = AdapterId::new("stub-cheap");
    let expensive_id = AdapterId::new("stub-expensive");
    let sheet = PriceSheet::new()
        .with(
            cheap_id.clone(),
            Price::per_million_tokens(100_000, 200_000),
        )
        .with(
            expensive_id.clone(),
            Price::per_million_tokens(3_000_000, 15_000_000),
        );
    let cheap_per_call = sheet
        .cost_of(&cheap_id, CHEAP_USAGE.0, CHEAP_USAGE.1)
        .expect("the cheap stub is priced");
    let expensive_per_call = sheet
        .cost_of(&expensive_id, EXPENSIVE_USAGE.0, EXPENSIVE_USAGE.1)
        .expect("the expensive stub is priced");
    let cheap = Scripted::oracle("stub-cheap", &corpus)
        .with_usage(CHEAP_USAGE.0, CHEAP_USAGE.1)
        .failing_on([DELETE_ALL_DATA]);
    let expensive = Scripted::oracle("stub-expensive", &corpus)
        .with_usage(EXPENSIVE_USAGE.0, EXPENSIVE_USAGE.1);
    let ledger = Arc::new(InMemoryLedger::new());
    let options = MeasurementOptions::default()
        .prices(sheet)
        .ledger(ledger.clone());

    let report = measure_agreement(&cheap, &expensive, &corpus, &options).await;

    // The report is unchanged by the accounting: the same run without a
    // ledger wired reports the same evidence.
    let unaccounted =
        measure_agreement(&cheap, &expensive, &corpus, &MeasurementOptions::default()).await;
    assert_eq!(
        report, unaccounted,
        "the accounting rides beside the measurement and never changes what it reports"
    );

    assert_eq!(
        report.skipped(),
        1,
        "the scripted cheap failure was skipped and counted"
    );
    let records = ledger.records();
    let compared = u64::try_from(corpus.len()).expect("a corpus fits in a u64") - 1;
    assert_eq!(
        u64::try_from(records.len()).expect("small"),
        compared * 2 + 1,
        "two records per compared question plus the failed question's lone cheap half"
    );
    assert!(
        records.iter().all(|record| record.role == CallRole::Shadow),
        "every record of a measurement run is a call asked to compare, never served"
    );
    let failed = records
        .iter()
        .filter(|record| record.outcome == CallOutcome::Failed)
        .count();
    assert_eq!(
        u64::try_from(failed).expect("small"),
        1,
        "the one cheap failure is the only failed call"
    );
    let cheap_totals = &ledger.totals()[&cheap_id];
    assert_eq!(
        cheap_totals.calls,
        compared + 1,
        "the cheap adapter was asked once per question, failed or not"
    );
    assert_eq!(
        cheap_totals.failed_calls, 1,
        "and the failure is counted as a failure, not a wiring gap"
    );
    assert_eq!(
        cheap_totals.pico_usd,
        u128::from(cheap_per_call.pico_usd()) * u128::from(compared),
        "the answered cheap calls total exactly the per-call price times the count"
    );
    let expensive_totals = &ledger.totals()[&expensive_id];
    assert_eq!(
        expensive_totals.calls, compared,
        "the expensive side was never asked the question the cheap side failed"
    );
    assert_eq!(
        expensive_totals.pico_usd,
        u128::from(expensive_per_call.pico_usd()) * u128::from(compared),
        "and its bill is exactly its per-call price times the questions it answered"
    );
}

#[pollster::test]
async fn a_kind_the_cheap_stub_always_fails_on_has_no_rate_and_the_table_says_na() {
    let corpus = corpus();
    let kind = QuestionKind::new("release-note-kind");
    let expected = corpus_questions_for(&kind, &corpus);
    let failing: Vec<&str> = corpus
        .iter()
        .filter(|question| question.kind == kind)
        .map(|question| question.text.as_str())
        .collect();
    let cheap = Scripted::oracle("stub-cheap", &corpus).failing_on(failing);
    let expensive = Scripted::oracle("stub-expensive", &corpus);

    let report = measure_agreement(
        &cheap,
        &expensive,
        &corpus,
        &MeasurementOptions::default().record_question_text(true),
    )
    .await;

    assert_eq!(
        report.skipped(),
        expected,
        "every question of the kind was skipped"
    );
    let entry = report
        .kind(&kind)
        .expect("the kind is still reported, errors and all");
    assert_eq!(entry.questions, 0, "nothing was compared");
    assert_eq!(entry.errors, expected);
    assert!(
        entry.agreement_rate().is_none() && entry.disagreement_rate().is_none(),
        "no compared questions, no rate — never a NaN a threshold comparison \
         would misread as measured-and-safe"
    );
    assert!(
        entry.disagreements.is_empty(),
        "nothing was compared, so there is nothing to audit"
    );

    let table = report.to_string();
    assert!(
        table.contains("release-note-kind"),
        "the kind still gets a row: {table}"
    );
    assert!(
        table.contains("n/a"),
        "the row reads n/a rather than a number about nothing: {table}"
    );
    let privacy = QuestionKind::new("privacy-request-kind");
    let untouched = report
        .kind(&privacy)
        .expect("an untouched kind is measured");
    assert_eq!(
        untouched.questions,
        corpus_questions_for(&privacy, &corpus),
        "the kinds the cheap stub survived are measured in full"
    );
}

#[pollster::test]
async fn the_report_is_evidence_it_round_trips_through_json_and_names_its_adapters() {
    let corpus = corpus();
    let cheap = Scripted::oracle("stub-cheap", &corpus).answering(GDPR_ACCESS_REQUEST, "other");
    let expensive = Scripted::oracle("stub-expensive", &corpus);

    let report = measure_agreement(
        &cheap,
        &expensive,
        &corpus,
        &MeasurementOptions::default().record_question_text(true),
    )
    .await;

    let json = serde_json::to_string_pretty(&report).expect("the report serialises");
    let reloaded: AgreementReport = serde_json::from_str(&json).expect("a committed report loads");
    assert_eq!(
        reloaded, report,
        "the committed evidence is the measured evidence, field for field"
    );
    let privacy = QuestionKind::new("privacy-request-kind");
    let entry = reloaded
        .kind(&privacy)
        .expect("the loaded report has the kind");
    assert_eq!(
        entry.disagreements[0].question.as_deref(),
        Some(GDPR_ACCESS_REQUEST),
        "the opted-in text survives the round trip, so the disagreement can be read"
    );
    assert!(
        reloaded.kind(&QuestionKind::new("no-such-kind")).is_none(),
        "an unmeasured kind reads as no evidence"
    );
}

// ---------------------------------------------------------------------
// The whole loop of the issue, end to end. The expensive stub is the
// oracle everywhere; the cheap stub is the oracle except on
// `release-note-kind`, where it answers `fix` to everything — right for
// the fix notes and wrong for every feature and breaking one — and
// except that it hedges (low confidence, label still right) on two
// questions of kinds it is otherwise good at. So four kinds earn cheap
// routing, one plainly does not, and the good kinds still escalate on
// the questions the cheap stub itself was unsure about. The hedges also
// fall below the cheap adapter's confidence floor, so the gate's
// restricted measurement — agreement over just the answers the floors
// would serve — excludes them, and the kinds still earn cheap routing
// on their sure answers.

/// The kind the cheap stub is scripted to be bad at: the one kind the
/// measured policy must refuse.
const UNRELIABLE_KIND: &str = "release-note-kind";

/// What the cheap stub answers to every `release-note-kind` question.
/// On the corpus's gold distribution that is right for the fix notes
/// and wrong for every feature and breaking one, so the kind measures a
/// half-and-half disagreement rate.
const CHEAP_GUESS: &str = "fix";

/// The confidence a hedged answer carries: below the cheap adapter's
/// calibrated confidence floor, with the label still the right one — so
/// the agreement measurement sees nothing, and the router's own
/// threshold gate is what catches it.
const HEDGED_CONFIDENCE: f32 = 0.5;

/// The token counts the cheap stub's every answer carries, and the
/// expensive one's — a strong model reads the same question and spends
/// tenfold on both sides.
const CHEAP_USAGE: (u64, u64) = (1_000, 100);
const EXPENSIVE_USAGE: (u64, u64) = (10_000, 1_000);

/// How many questions of each kind the routed run drives: a handful of
/// real corpus questions, the same few of every kind.
const HANDFUL_PER_KIND: usize = 3;

/// The corpus's first question of `kind`, by its text — the text the
/// stubs script against.
fn first_text_of_kind(kind: &str, corpus: &[CorpusQuestion]) -> String {
    corpus
        .iter()
        .find(|question| question.kind.as_str() == kind)
        .expect("the corpus has every kind the routing tests route on")
        .text
        .clone()
}

/// The questions the cheap stub hedges on: the first waitlist question
/// and the GDPR access request. Hedging changes the confidence, never
/// the label, so the measured agreement is unaffected — the hedge only
/// shows when a router serves the cheap answer and applies its own
/// thresholds.
fn hedged_questions(corpus: &[CorpusQuestion]) -> Vec<String> {
    vec![
        first_text_of_kind("waitlist-signup-quality", corpus),
        GDPR_ACCESS_REQUEST.to_owned(),
    ]
}

/// The routing half's stubs: the expensive stub is the oracle; the
/// cheap one is the oracle except on [`UNRELIABLE_KIND`] and on the
/// questions [`hedged_questions`] names.
fn routing_stubs(corpus: &[CorpusQuestion]) -> (Scripted, Scripted) {
    let mut cheap = Scripted::oracle("stub-cheap", corpus)
        .answering_kind(UNRELIABLE_KIND, CHEAP_GUESS)
        .with_usage(CHEAP_USAGE.0, CHEAP_USAGE.1);
    for text in hedged_questions(corpus) {
        cheap = cheap.hedging_on(&text, HEDGED_CONFIDENCE);
    }
    let expensive =
        Scripted::oracle("stub-expensive", corpus).with_usage(EXPENSIVE_USAGE.0, EXPENSIVE_USAGE.1);
    (cheap, expensive)
}

/// A `Measured` policy over the stub pair, with both adapters
/// calibrated and the gates sized to the corpus: every kind is measured
/// on ten or more questions, and the disagreement cap sits well under
/// what the unreliable kind measures. The expensive adapter gets
/// thresholds too — calibration is per adapter — though the gate
/// consults only the cheap side it routes from: an escalation asks the
/// expensive adapter unconditionally. `evidence` is the committed
/// report, or `None` for the withheld-evidence honesty case.
fn routing_policy(evidence: Option<AgreementReport>) -> RoutingPolicy {
    let policy = RoutingPolicy::measured()
        .thresholds(
            AdapterId::new("stub-cheap"),
            Thresholds {
                min_confidence: 0.8,
                min_margin: 0.2,
            },
        )
        .thresholds(
            AdapterId::new("stub-expensive"),
            Thresholds {
                min_confidence: 0.7,
                min_margin: 0.1,
            },
        )
        .min_questions(10)
        .max_disagreement_rate(0.2);
    match evidence {
        Some(report) => policy.evidence(report),
        None => policy,
    }
}

/// The price sheet the routed run books against: the cheap adapter at a
/// small fraction of the expensive one, per million tokens, both sides.
fn routing_price_sheet() -> PriceSheet {
    PriceSheet::new()
        .with(
            AdapterId::new("stub-cheap"),
            Price::per_million_tokens(100_000, 200_000),
        )
        .with(
            AdapterId::new("stub-expensive"),
            Price::per_million_tokens(3_000_000, 15_000_000),
        )
}

/// The handful of real corpus questions the routed run drives: the
/// first few of every kind, kinds in a fixed order, so the ledger's
/// record order is deterministic.
fn a_handful_of_corpus_questions(corpus: &[CorpusQuestion]) -> Vec<CorpusQuestion> {
    const ROUTED_KINDS: [&str; 5] = [
        "waitlist-signup-quality",
        "inbound-message-language",
        "privacy-request-kind",
        "cms-draft-review",
        "release-note-kind",
    ];
    let mut handful = Vec::new();
    for kind in ROUTED_KINDS {
        handful.extend(
            corpus
                .iter()
                .filter(|question| question.kind.as_str() == kind)
                .take(HANDFUL_PER_KIND)
                .cloned(),
        );
    }
    assert_eq!(
        handful.len(),
        ROUTED_KINDS.len() * HANDFUL_PER_KIND,
        "every kind of the corpus contributed its share — the corpus is the fixture"
    );
    handful
}

/// The corpus question as the `Question` an adapter is asked — the same
/// translation `measure_agreement` does.
fn as_question(sample: &CorpusQuestion) -> Question {
    Question::new(sample.kind.clone(), sample.text.clone()).labels(sample.labels.iter().cloned())
}

/// What the fixture says the router should do with one question of the
/// handful.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Expected {
    /// A measured kind, a sure answer: served by the cheap adapter.
    CheapAccepted,
    /// A measured kind, a hedged answer: the cheap attempt is thrown
    /// away and the expensive adapter answers.
    Escalated,
    /// The unreliable kind: never routed cheap at all.
    Refused,
}

/// The verdict the fixture implies for `sample`, which every routing
/// test checks the run against.
fn expected_outcome(sample: &CorpusQuestion, hedged: &HashSet<String>) -> Expected {
    if sample.kind.as_str() == UNRELIABLE_KIND {
        Expected::Refused
    } else if hedged.contains(&sample.text) {
        Expected::Escalated
    } else {
        Expected::CheapAccepted
    }
}

/// One question of a routed run, and what actually happened to it.
struct RoutedQuestion {
    sample: CorpusQuestion,
    reason: RouteReason,
    answered_by: AdapterId,
}

/// Everything one driven run made happen, and everything a routing test
/// asserts on: the questions and how each was answered, the stubs' call
/// counters, the ledger, and what one call to each adapter costs on the
/// run's sheet.
struct RoutedRun {
    questions: Vec<RoutedQuestion>,
    hedged: HashSet<String>,
    cheap_id: AdapterId,
    expensive_id: AdapterId,
    cheap: Arc<Scripted>,
    expensive: Arc<Scripted>,
    ledger: Arc<InMemoryLedger>,
    cheap_per_call: Cost,
    expensive_per_call: Cost,
}

/// Sets a routed run up and drives it: the corpus measured through the
/// routing stubs, the report serialised and reloaded, `policy_from`
/// handed the reloaded evidence to build the policy it wants (declining
/// it is the withheld-evidence case), and every question of the handful
/// put through the router with prices and a ledger wired.
async fn routed_run(policy_from: impl FnOnce(AgreementReport) -> RoutingPolicy) -> RoutedRun {
    let corpus = corpus();
    let (cheap_stub, expensive_stub) = routing_stubs(&corpus);

    // Measure, commit, reload: the policy is built from the reloaded
    // form of the report, never from the measured one, because that is
    // the path a venture walks.
    let measured = measure_agreement(
        &cheap_stub,
        &expensive_stub,
        &corpus,
        &MeasurementOptions::default().record_question_text(true),
    )
    .await;
    let json = serde_json::to_string(&measured).expect("the report serialises");
    let reloaded: AgreementReport =
        serde_json::from_str(&json).expect("a committed report loads back");
    let policy = policy_from(reloaded);

    // The measurement was its own phase; from here the counters count
    // the routed run only.
    cheap_stub.reset_calls();
    expensive_stub.reset_calls();

    let cheap_id = AdapterId::new("stub-cheap");
    let expensive_id = AdapterId::new("stub-expensive");
    let sheet = routing_price_sheet();
    let cheap_per_call = sheet
        .cost_of(&cheap_id, CHEAP_USAGE.0, CHEAP_USAGE.1)
        .expect("the cheap adapter is priced");
    let expensive_per_call = sheet
        .cost_of(&expensive_id, EXPENSIVE_USAGE.0, EXPENSIVE_USAGE.1)
        .expect("the expensive adapter is priced");

    let cheap = Arc::new(cheap_stub);
    let expensive = Arc::new(expensive_stub);
    let ledger = Arc::new(InMemoryLedger::new());
    let router = RoutingClassifier::new(
        AdapterId::new("router"),
        cheap.clone(),
        expensive.clone(),
        policy,
    )
    .prices(sheet)
    .ledger(ledger.clone());

    let hedged: HashSet<String> = hedged_questions(&corpus).into_iter().collect();
    let mut questions = Vec::new();
    for sample in a_handful_of_corpus_questions(&corpus) {
        let answer = router.classify_routed(&as_question(&sample)).await.expect(
            "every question of the run gets an answer: a refusal serves \
                 expensive, it does not fail",
        );
        questions.push(RoutedQuestion {
            sample,
            reason: answer.reason,
            answered_by: answer.classification.adapter,
        });
    }

    RoutedRun {
        questions,
        hedged,
        cheap_id,
        expensive_id,
        cheap,
        expensive,
        ledger,
        cheap_per_call,
        expensive_per_call,
    }
}

#[pollster::test]
async fn the_committed_evidence_routes_the_good_kinds_cheap_and_refuses_the_kind_the_cheap_stub_is_bad_at()
 {
    let corpus = corpus();
    let (cheap, expensive) = routing_stubs(&corpus);
    let waitlist = QuestionKind::new("waitlist-signup-quality");
    let release_notes = QuestionKind::new(UNRELIABLE_KIND);

    let report = measure_agreement(
        &cheap,
        &expensive,
        &corpus,
        &MeasurementOptions::default().record_question_text(true),
    )
    .await;
    assert_eq!(
        report.skipped(),
        0,
        "the routing stubs never error, so nothing was skipped"
    );

    let good = report
        .kind(&waitlist)
        .expect("the waitlist kind is measured");
    assert_eq!(
        good.questions,
        corpus_questions_for(&waitlist, &corpus),
        "the whole kind was compared"
    );
    assert_eq!(
        good.agreed, good.questions,
        "the cheap stub is the oracle on this kind: it earns cheap routing"
    );
    let good_rate = good.disagreement_rate().expect("the kind was measured");
    assert!(
        good_rate.abs() < 1e-9,
        "no disagreements on the kind the cheap stub is right about: {good_rate}"
    );

    let bad = report
        .kind(&release_notes)
        .expect("the unreliable kind is measured too");
    assert_eq!(
        bad.questions,
        corpus_questions_for(&release_notes, &corpus),
        "the whole kind was compared, including the part the cheap stub got right"
    );
    let bad_rate = bad.disagreement_rate().expect("the kind was measured");
    assert!(
        (bad_rate - 0.5).abs() < 1e-9,
        "`fix` is the gold answer for half the release notes and wrong for the \
         other half: {bad_rate}"
    );
    assert_eq!(
        bad.cheap_right, 0,
        "on every disagreement the cheap stub is the side that is wrong"
    );
    assert_eq!(
        bad.expensive_right, bad.graded,
        "the expensive stub holds the gold answer on every graded disagreement"
    );

    // The real path: serialise the report, commit it, reload it, and
    // build the policy from the reloaded evidence.
    let json = serde_json::to_string_pretty(&report).expect("the report serialises");
    let reloaded: AgreementReport =
        serde_json::from_str(&json).expect("a committed report loads back");
    assert_eq!(
        reloaded, report,
        "the committed evidence is the measured evidence, field for field"
    );

    // The gate measures at the cheap adapter's committed floors (0.8
    // confidence, 0.2 margin — the pair `routing_policy` calibrates),
    // so the committed evidence has to carry what those floors select.
    // On the waitlist kind the cheap stub is sure everywhere except the
    // one hedged question, so exactly that one falls out of the subset
    // the floors would serve, and the rest of the subset agrees.
    let restricted = reloaded
        .kind(&waitlist)
        .expect("the waitlist kind is measured")
        .agreement_at(0.8, 0.2)
        .expect("the sure answers clear the floors");
    assert_eq!(
        restricted.questions,
        good.questions - 1,
        "the hedged question sits below the confidence floor and is not in \
         the subset the floors would serve"
    );
    assert_eq!(
        restricted.agreed, restricted.questions,
        "every answer the floors would serve is one the cheap stub got right"
    );
    let restricted_rate = restricted.disagreement_rate().expect("measured");
    assert!(
        restricted_rate.abs() < 1e-9,
        "the restricted rate the gate consults is clean: {restricted_rate}"
    );

    // And on the unreliable kind the cheap stub is sure about its wrong
    // answers too: the floors select all of them, so the restricted
    // rate is the same half-and-half the whole kind measures, and the
    // refusal stands at the floors rather than hiding behind them.
    let bad_restricted = reloaded
        .kind(&release_notes)
        .expect("the unreliable kind is measured")
        .agreement_at(0.8, 0.2)
        .expect("its answers are sure — just wrong half the time");
    assert_eq!(
        bad_restricted.questions, bad.questions,
        "no release-note answer was hedged, so the floors select the whole kind"
    );
    let bad_restricted_rate = bad_restricted.disagreement_rate().expect("measured");
    assert!(
        (bad_restricted_rate - 0.5).abs() < 1e-9,
        "the refusal stands at the floors: {bad_restricted_rate}"
    );

    let policy = routing_policy(Some(reloaded));
    let good_plan = policy.plan_for(&waitlist, &AdapterId::new("stub-cheap"));
    assert!(
        good_plan.cheap_first,
        "measured and agreed everywhere: the cheap adapter answers first"
    );
    assert_eq!(
        good_plan.reason,
        RouteReason::CheapAccepted,
        "the cheap-first plan names the gate that allows it"
    );
    let bad_plan = policy.plan_for(&release_notes, &AdapterId::new("stub-cheap"));
    assert!(
        !bad_plan.cheap_first,
        "measured and disagreed about half the time: the kind is refused"
    );
    assert_eq!(
        bad_plan.reason,
        RouteReason::DisagreementTooHigh,
        "the refusal is the disagreement cap, not a missing measurement"
    );
}

#[pollster::test]
async fn the_routed_run_answers_each_question_from_the_adapter_its_evidence_earns() {
    let run = routed_run(|reloaded| routing_policy(Some(reloaded))).await;

    let mut cheap_served = 0;
    let mut escalations = 0;
    let mut refusals = 0;
    for routed in &run.questions {
        match expected_outcome(&routed.sample, &run.hedged) {
            Expected::CheapAccepted => {
                cheap_served += 1;
                assert_eq!(
                    routed.reason,
                    RouteReason::CheapAccepted,
                    "a measured kind and an answer above the cheap adapter's own \
                     thresholds: `{}` served cheap",
                    routed.sample.kind
                );
                assert_eq!(
                    routed.answered_by, run.cheap_id,
                    "the cheap adapter's answer is the one served for `{}`",
                    routed.sample.kind
                );
            }
            Expected::Escalated => {
                escalations += 1;
                assert_eq!(
                    routed.reason,
                    RouteReason::EscalatedLowConfidence,
                    "the cheap answer fell below its own confidence floor on `{}`, \
                     agreement evidence notwithstanding",
                    routed.sample.kind
                );
                assert_eq!(
                    routed.answered_by, run.expensive_id,
                    "the caller gets the expensive adapter's answer for `{}`",
                    routed.sample.kind
                );
            }
            Expected::Refused => {
                refusals += 1;
                assert_eq!(
                    routed.reason,
                    RouteReason::DisagreementTooHigh,
                    "the kind measured half-and-half is refused at the plan, so \
                     `{}` never reached the cheap adapter",
                    routed.sample.kind
                );
                assert_eq!(
                    routed.answered_by, run.expensive_id,
                    "the expensive adapter answered the refused kind's `{}`",
                    routed.sample.kind
                );
            }
        }
    }

    assert!(
        cheap_served > 0 && escalations > 0 && refusals > 0,
        "the run exercised all three outcomes or it proves nothing about routing: \
         {cheap_served} served cheap, {escalations} escalated, {refusals} refused"
    );
    assert_eq!(
        refusals, HANDFUL_PER_KIND,
        "every release-note question of the handful was refused"
    );
    let hedged_in_handful = run
        .questions
        .iter()
        .filter(|routed| run.hedged.contains(&routed.sample.text))
        .count();
    assert_eq!(
        escalations, hedged_in_handful,
        "exactly the hedged questions escalated: hedging is the cheap adapter's \
         own uncertainty, visible to no agreement rate"
    );
    assert_eq!(
        run.cheap.calls.load(Ordering::Relaxed),
        cheap_served + escalations,
        "the cheap adapter was asked exactly where the plan allowed cheap-first"
    );
    assert_eq!(
        run.expensive.calls.load(Ordering::Relaxed),
        escalations + refusals,
        "the expensive adapter was asked for every escalation and every refusal"
    );
}

#[pollster::test]
async fn the_routed_run_costs_strictly_more_than_always_cheap_and_strictly_less_than_always_expensive()
 {
    let run = routed_run(|reloaded| routing_policy(Some(reloaded))).await;

    // Both halves of every escalation are in the ledger, priced: the
    // cheap attempt as `Discarded`, immediately followed by the
    // expensive answer as `Served`.
    let records = run.ledger.records();
    assert!(
        records
            .iter()
            .any(|record| record.role == CallRole::Discarded),
        "the run escalated at least once, or there is no double payment to see"
    );
    for (index, record) in records.iter().enumerate() {
        if record.role != CallRole::Discarded {
            continue;
        }
        assert_eq!(
            record.adapter, run.cheap_id,
            "the discarded half of an escalation is always the cheap attempt"
        );
        assert_eq!(
            record.outcome,
            CallOutcome::Ok,
            "the cheap adapter answered and the router threw the answer away; \
             the call itself did not fail"
        );
        assert_eq!(
            record.cost,
            Some(run.cheap_per_call),
            "the thrown-away cheap answer is priced for what it spent"
        );
        let follow_up = records.get(index + 1).expect(
            "a discarded cheap half is followed by the expensive half that \
             answered instead",
        );
        assert_eq!(
            follow_up.role,
            CallRole::Served,
            "the second half of the escalation is the answer that was served"
        );
        assert_eq!(
            follow_up.adapter, run.expensive_id,
            "the second half of the escalation is the expensive adapter"
        );
        assert_eq!(
            follow_up.kind, record.kind,
            "both halves of the escalation are for the same question"
        );
        assert_eq!(
            follow_up.cost,
            Some(run.expensive_per_call),
            "the served expensive half is priced for what it spent"
        );
    }

    // What the run actually cost, against both extremes over the same
    // questions — both bounds computed here from the same sheet and the
    // same stub token counts, never hard-coded.
    let routed_pico: u64 = records
        .iter()
        .map(|record| {
            record
                .cost
                .as_ref()
                .expect("both adapters of this run are priced")
                .pico_usd()
        })
        .sum();
    let expected_pico: u64 = run
        .questions
        .iter()
        .map(
            |routed| match expected_outcome(&routed.sample, &run.hedged) {
                Expected::CheapAccepted => run.cheap_per_call.pico_usd(),
                Expected::Escalated => {
                    run.cheap_per_call.pico_usd() + run.expensive_per_call.pico_usd()
                }
                Expected::Refused => run.expensive_per_call.pico_usd(),
            },
        )
        .sum();
    assert_eq!(
        routed_pico, expected_pico,
        "the ledger booked exactly what the routed decisions imply"
    );
    let questions = u64::try_from(run.questions.len()).expect("a handful fits in a u64");
    let always_cheap = Cost::from_pico_usd(run.cheap_per_call.pico_usd() * questions);
    let always_expensive = Cost::from_pico_usd(run.expensive_per_call.pico_usd() * questions);
    assert!(
        routed_pico > always_cheap.pico_usd(),
        "routing cost strictly more than always-cheap over the same questions: \
         the escalations and the refused kind paid for answers that were thrown \
         away or asked for twice"
    );
    assert!(
        routed_pico < always_expensive.pico_usd(),
        "and strictly less than always-expensive: the cheap-served majority is \
         where routing earns its keep"
    );
}

#[pollster::test]
async fn with_the_evidence_withheld_the_same_stubs_over_the_same_corpus_send_every_question_expensive()
 {
    // The run is identical — same corpus, same stubs, same prices, same
    // calibration — except that the measured report is never loaded
    // into the policy.
    let run = routed_run(|_committed| routing_policy(None)).await;

    let plan =
        routing_policy(None).plan_for(&QuestionKind::new("waitlist-signup-quality"), &run.cheap_id);
    assert!(
        !plan.cheap_first,
        "withheld evidence is no evidence: the plan refuses cheap-first"
    );
    assert_eq!(
        plan.reason,
        RouteReason::NoMeasurement,
        "the gate that refused is the missing measurement, not calibration"
    );

    for routed in &run.questions {
        assert_eq!(
            routed.reason,
            RouteReason::NoMeasurement,
            "every kind alike routes on nothing when nothing was committed: `{}`",
            routed.sample.kind
        );
        assert_eq!(
            routed.answered_by, run.expensive_id,
            "the expensive adapter answered `{}`, however good the cheap stub \
             is scripted to be",
            routed.sample.kind
        );
    }
    assert_eq!(
        run.cheap.calls.load(Ordering::Relaxed),
        0,
        "the cheap adapter is never even asked without evidence"
    );
    assert_eq!(
        run.expensive.calls.load(Ordering::Relaxed),
        run.questions.len(),
        "every question of the handful went to the expensive adapter"
    );

    // And the money: withholding the evidence books the full
    // always-expensive bill — exactly the ceiling the measured run was
    // asserted to sit strictly under.
    let routed_pico: u64 = run
        .ledger
        .records()
        .iter()
        .map(|record| {
            record
                .cost
                .as_ref()
                .expect("both adapters of this run are priced")
                .pico_usd()
        })
        .sum();
    let questions = u64::try_from(run.questions.len()).expect("a handful fits in a u64");
    assert_eq!(
        routed_pico,
        run.expensive_per_call.pico_usd() * questions,
        "withheld evidence costs the whole always-expensive bill"
    );
    assert!(
        !run.ledger.role_totals().contains_key(&CallRole::Discarded),
        "nothing was discarded: there was never a cheap call to throw away"
    );
}
