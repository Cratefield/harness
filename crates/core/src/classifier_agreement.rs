//! Whether a cheap classifier may answer in place of an expensive one is
//! a measurement, not an opinion (issue #457). This module runs the same
//! questions through both adapters, compares the answers per
//! [`QuestionKind`], and keeps the comparison as an [`AgreementReport`] —
//! because a classifier that is reliable on one kind of question is not
//! therefore reliable on the next, and only a per-kind report can say so.
//!
//! The report is **evidence**, not a setting: a venture measures once,
//! commits the serialised report, and loads it later to configure its
//! router. It round-trips through `serde` for exactly that reason, and it
//! keeps the disagreements themselves — a rate without its
//! counter-examples cannot be audited, and a router configured from an
//! unaudited number is trusting a stranger with every cheap call — and
//! it keeps every answer as the cheap adapter scored it, confidence and
//! margin alike ([`KindAgreement::calibration`]), because thresholds
//! are per adapter and the run that measured agreement is the only
//! honest place to calibrate them: [`KindAgreement::agreement_at`]
//! measures agreement over just the answers a candidate pair of floors
//! would serve.
//!
//! Nothing here ships a number. [`measure_agreement`] is how one is
//! produced; the corpus run in `crates/core/tests/classifier_agreement.rs`
//! is the worked example, and any agreement figure a venture has is its
//! own measurement, not this module's claim.
//!
//! The run accounts for itself like the calls it measures (issue #457:
//! every classifier call records tokens, adapter and price). A
//! [`MeasurementOptions`] carries a [`PriceSheet`](crate::PriceSheet) and
//! a [`CostLedger`], and with both wired the runner records every call it
//! makes — both sides of each compared question, and the lone cheap side
//! of a question the cheap adapter failed — each as
//! [`CallRole::Shadow`], because a measurement call is asked in order to
//! compare and its answer reaches a report, never a caller. A venture
//! deciding whether to measure a larger corpus reads what the last run
//! cost off the ledger instead of guessing it.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::classifier::{
    AdapterId, Classification, Classifier, ClassifierError, Question, QuestionKind,
};
use crate::cost::{CallOutcome, CallRecord, CallRole, CostLedger, PriceSheet};

/// One question both adapters answered, as the log receives it.
///
/// `#[non_exhaustive]` with public fields: [`measure_agreement`] (and the
/// shadow classifier issue #457 adds alongside it) produce these inside
/// core, so the struct literal from within the crate is the whole
/// construction path — the same treatment
/// [`CallRecord`](crate::CallRecord) gets.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Observation {
    pub kind: QuestionKind,
    /// The cheap adapter's id, and the label it answered.
    pub cheap: AdapterId,
    pub cheap_label: String,
    /// The confidence the cheap adapter reported for its answer, kept so
    /// the same run that measured agreement can later calibrate the
    /// cheap adapter's thresholds: thresholds are per adapter, and these
    /// are the numbers this adapter actually produced when it was being
    /// compared (issue #457).
    pub cheap_confidence: f32,
    /// The cheap adapter's margin — top score minus runner-up — kept for
    /// the same calibration as [`Self::cheap_confidence`].
    pub cheap_margin: f32,
    /// The expensive adapter's id, and the label it answered.
    pub expensive: AdapterId,
    pub expensive_label: String,
    /// The right answer, when the question carried one. `None` leaves a
    /// disagreement ungraded: the adapters differed, and nobody can say
    /// which of them was wrong.
    pub gold: Option<String>,
    /// The question's text, when the caller opted into recording it.
    ///
    /// **Off by default, on purpose.** In production shadow mode the text
    /// is a user's, and the agreement arithmetic never needs it — an
    /// [`AgreementLog`] counts labels, not prose. Only an offline corpus
    /// run opts in, because there the text is authored data and a
    /// disagreement you cannot read cannot be audited.
    /// [`MeasurementOptions::record_question_text`] is exactly this
    /// switch, for [`measure_agreement`] and for shadow mode alike.
    pub question: Option<String>,
}

/// One question the two adapters answered differently, kept in the report
/// so a disagreement rate can be audited rather than believed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Disagreement {
    /// The cheap adapter's answer.
    pub cheap_label: String,
    /// The expensive adapter's answer.
    pub expensive_label: String,
    /// The right answer, when the question carried one. `None` means the
    /// disagreement is ungraded — kept, but in no who-was-right tally.
    pub gold: Option<String>,
    /// The question's text, only when the run opted into recording it —
    /// the same switch as [`Observation::question`].
    pub question: Option<String>,
}

/// One answer as the cheap adapter gave it, kept so a threshold can be
/// chosen from the same run that measured agreement.
///
/// Thresholds are per adapter and are not transferable (see
/// [`Thresholds`](crate::Thresholds)), so the numbers an adapter
/// actually produced while it was being compared are the only honest
/// source for its floors. [`KindAgreement`] keeps one point per
/// compared answer, in ask order, and
/// [`KindAgreement::agreement_at`] restricts them to the answers a
/// candidate pair of floors would serve — which is also, exactly, the
/// measurement the routing gate takes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CalibrationPoint {
    /// The confidence the cheap adapter reported for this answer.
    pub cheap_confidence: f32,
    /// The cheap adapter's margin — top score minus runner-up.
    pub cheap_margin: f32,
    /// Whether the expensive adapter answered with the same label.
    pub agreed: bool,
    /// Whether the cheap answer was the right one, when the right
    /// answer was known. [`Option::None`] leaves the point measured for
    /// raw agreement but ungraded — the same rule as
    /// [`KindAgreement::graded`].
    pub cheap_right: Option<bool>,
}

/// How the two adapters behaved on one [`QuestionKind`].
///
/// Every count is over the questions **both** adapters answered; a
/// question either of them errored on is not in any of these numbers'
/// denominators — it is counted once in `errors` instead, so a kind the
/// cheap adapter keeps failing on is visible as exactly that, and never
/// as a flattering rate over the questions it happened to survive.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct KindAgreement {
    /// Questions where both adapters answered; the denominator of both
    /// rates.
    pub questions: u64,
    /// Questions where both answered the same label.
    pub agreed: u64,
    /// Disagreements where the right answer was known — the ones graded
    /// at all.
    pub graded: u64,
    /// Of the graded disagreements, how many the cheap adapter won.
    pub cheap_right: u64,
    /// Of the graded disagreements, how many the expensive adapter won.
    pub expensive_right: u64,
    /// Of the graded disagreements, how many neither got right. A hard
    /// question is not evidence against the cheap side in particular;
    /// this tally keeps that mistake visible.
    pub neither_right: u64,
    /// Questions dropped because one of the two adapters errored, so no
    /// comparison was possible. Counted, not dropped: a report that
    /// quietly discards the questions the cheap adapter choked on
    /// overstates agreement.
    pub errors: u64,
    /// Every disagreement, in the order the questions were asked. The
    /// rate is the summary; these are the counter-examples an audit
    /// reads.
    pub disagreements: Vec<Disagreement>,
    /// Every compared answer as the cheap adapter gave it — the
    /// confidence and margin it reported, whether the expensive adapter
    /// agreed, and whether the cheap answer was right when that was
    /// known — in ask order. Kept so a venture can pick its thresholds
    /// from the same run that measured agreement, and so the routing
    /// gate can measure agreement at exactly the floors it commits
    /// ([`Self::agreement_at`]); `serde(default)` so a report committed
    /// before this field existed still loads.
    #[serde(default)]
    pub calibration: Vec<CalibrationPoint>,
}

impl KindAgreement {
    /// The share of compared questions both adapters answered the same,
    /// `agreed / questions`.
    ///
    /// [`Option::None`] when `questions` is zero: a kind with no compared
    /// questions has **no** rate, not a zero and not a `NaN`. A `NaN`
    /// compares false against every threshold and so reads as "measured
    /// and safe" to any `rate > max` check; `None` says what actually
    /// happened — no evidence — and a router must treat it exactly like a
    /// missing kind.
    #[must_use]
    pub fn agreement_rate(&self) -> Option<f64> {
        ratio(self.agreed, self.questions)
    }

    /// The share of compared questions the adapters answered differently,
    /// the number a routing policy caps. Same [`Option::None`]-when-
    /// unmeasured rule as [`Self::agreement_rate`].
    #[must_use]
    pub fn disagreement_rate(&self) -> Option<f64> {
        ratio(self.questions.saturating_sub(self.agreed), self.questions)
    }

    /// Agreement over just the answers that would clear a threshold
    /// pair — the only question a threshold-setter actually has: *if
    /// the floors sat here, how often would the answers I would have
    /// served have agreed?*
    ///
    /// Restricts [`Self::calibration`] to the points whose confidence
    /// clears `min_confidence` **and** whose margin clears
    /// `min_margin` — both floors, meeting one is not enough — and
    /// reports the counts over exactly that subset. [`Option::None`]
    /// when no answer clears: a floor nothing clears has no measured
    /// agreement, not a zero and not a free pass.
    ///
    /// The floors are taken as plain `f32` rather than a
    /// [`Thresholds`](crate::Thresholds) because thresholds live in the
    /// routing module; the two numbers are the same two floors, and
    /// keeping them here plain keeps this module from depending on that
    /// one.
    ///
    /// The whole-kind numbers ([`Self::questions`],
    /// [`Self::disagreement_rate`]) stay beside this for context, and
    /// are worth reading — but they answer a different question, how
    /// often the adapters agreed on every answer sure or not, and a
    /// routing gate that capped on them would measure the wrong set.
    #[must_use]
    pub fn agreement_at(&self, min_confidence: f32, min_margin: f32) -> Option<AgreementAt> {
        let mut at = AgreementAt::default();
        for point in &self.calibration {
            // Positive form on purpose: every comparison against a NaN
            // is false, so an answer reporting NaN can never be read as
            // having cleared a floor, here or in the routing gate.
            if point.cheap_confidence >= min_confidence && point.cheap_margin >= min_margin {
                at.questions = at.questions.saturating_add(1);
                if point.agreed {
                    at.agreed = at.agreed.saturating_add(1);
                }
            }
        }
        (at.questions > 0).then_some(at)
    }

    /// Folds one doubly-answered comparison in, in ask order. The
    /// cheap answer's confidence and margin come along so the answer
    /// lands in [`Self::calibration`] as the adapter gave it — dropping
    /// them here would leave the report promising calibration data it
    /// never kept.
    fn record(
        &mut self,
        cheap_label: &str,
        cheap_confidence: f32,
        cheap_margin: f32,
        expensive_label: &str,
        gold: Option<&str>,
        question: Option<String>,
    ) {
        let agreed = cheap_label == expensive_label;
        self.calibration.push(CalibrationPoint {
            cheap_confidence,
            cheap_margin,
            agreed,
            cheap_right: gold.map(|gold| gold == cheap_label),
        });
        self.questions = self.questions.saturating_add(1);
        if agreed {
            self.agreed = self.agreed.saturating_add(1);
            return;
        }
        self.disagreements.push(Disagreement {
            cheap_label: cheap_label.to_owned(),
            expensive_label: expensive_label.to_owned(),
            gold: gold.map(str::to_owned),
            question,
        });
        let Some(gold) = gold else {
            return; // Ungraded: kept above, in no who-was-right tally.
        };
        self.graded = self.graded.saturating_add(1);
        match (gold == cheap_label, gold == expensive_label) {
            (true, _) => self.cheap_right = self.cheap_right.saturating_add(1),
            (false, true) => {
                self.expensive_right = self.expensive_right.saturating_add(1);
            }
            // The labels differ, so both cannot equal the gold answer.
            (false, false) => {
                self.neither_right = self.neither_right.saturating_add(1);
            }
        }
    }

    /// Counts a question dropped because an adapter errored on it.
    fn count_error(&mut self) {
        self.errors = self.errors.saturating_add(1);
    }
}

/// Agreement restricted to the answers that cleared a threshold pair —
/// what [`KindAgreement::agreement_at`] returns.
///
/// The same shape as a [`KindAgreement`]'s headline counts, over a
/// smaller denominator: only the answers the floors would actually
/// serve. The per-kind disagreements, grading tallies and errors are
/// deliberately not restated here — read them from the
/// [`KindAgreement`] the restriction came from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AgreementAt {
    /// Answers that cleared both floors; the denominator of both
    /// rates.
    pub questions: u64,
    /// Of those, the answers where both adapters gave the same label.
    pub agreed: u64,
}

impl AgreementAt {
    /// The share of the clearing answers the adapters answered
    /// differently — the number a routing policy caps at those floors.
    ///
    /// [`Option::None`] cannot come back from a value
    /// [`KindAgreement::agreement_at`] handed over — at least one
    /// answer cleared, so the denominator is not zero — but the rate
    /// stays an [`Option`] so the type makes no promise its fields do
    /// not enforce.
    #[must_use]
    pub fn disagreement_rate(&self) -> Option<f64> {
        ratio(self.questions.saturating_sub(self.agreed), self.questions)
    }

    /// The share of the clearing answers the adapters answered the
    /// same — see [`Self::disagreement_rate`].
    #[must_use]
    pub fn agreement_rate(&self) -> Option<f64> {
        ratio(self.agreed, self.questions)
    }
}

/// A numerator over a denominator as the rate, or [`Option::None`] when
/// nothing was measured — never a `NaN`.
///
/// The casts are scoped to this one function: a count fits an `f64`'s
/// 53-bit mantissa exactly, so the narrowing loses nothing a corpus could
/// produce, and every rate in the module goes through here.
#[allow(clippy::cast_precision_loss)]
fn ratio(numerator: u64, denominator: u64) -> Option<f64> {
    if denominator == 0 {
        None
    } else {
        Some(numerator as f64 / denominator as f64)
    }
}

/// The measurement a venture routes on (issue #457): which two adapters
/// were compared, how each [`QuestionKind`] behaved, and how many
/// questions were skipped because an adapter errored.
///
/// It round-trips through `serde` because it is **evidence**: measure
/// once, commit the report, load it to configure the router. The kind
/// fields are private on purpose — read them through the accessors, the
/// same way the router will.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgreementReport {
    /// The adapter the measurement would route **from** — the cheap one,
    /// the side whose labels a disagreement rate is measured against.
    cheap: AdapterId,
    /// The adapter the measurement would route **to** on a disagreement
    /// or a skip.
    expensive: AdapterId,
    kinds: BTreeMap<QuestionKind, KindAgreement>,
    /// Questions skipped because an adapter errored on them, across all
    /// kinds. Equal to the sum of the kinds' `errors`. The corpus runner
    /// counts these; live shadow mode leaves it at zero, because a
    /// swallowed shadow error never becomes an observation to count —
    /// the ledger is where its failure is recorded.
    skipped: u64,
}

impl AgreementReport {
    /// The cheap adapter the evidence is about. Evidence is about one
    /// pair: a report measured on other adapters is not evidence here,
    /// and a router must refuse it.
    #[must_use]
    pub const fn cheap(&self) -> &AdapterId {
        &self.cheap
    }

    /// The expensive adapter the evidence is about — see [`Self::cheap`].
    #[must_use]
    pub const fn expensive(&self) -> &AdapterId {
        &self.expensive
    }

    /// The evidence for one kind, or [`Option::None`] when the run had no
    /// question of it. `None` and a [`KindAgreement`] with
    /// `questions == 0` mean the same thing to a router: no evidence.
    #[must_use]
    pub fn kind(&self, kind: &QuestionKind) -> Option<&KindAgreement> {
        self.kinds.get(kind)
    }

    /// Every kind measured, with its evidence, ordered by kind so a
    /// report is stable across runs.
    pub fn kinds(&self) -> impl Iterator<Item = (&QuestionKind, &KindAgreement)> {
        self.kinds.iter()
    }

    /// Questions skipped because an adapter errored on them, across all
    /// kinds — see [`KindAgreement::errors`] for the per-kind count.
    #[must_use]
    pub const fn skipped(&self) -> u64 {
        self.skipped
    }
}

impl fmt::Display for AgreementReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let compared: u64 = self.kinds.values().map(|kind| kind.questions).sum();
        let width = self
            .kinds
            .keys()
            .map(|kind| kind.as_str().chars().count())
            .max()
            .unwrap_or(0)
            .max(4);
        writeln!(
            f,
            "agreement of `{}` against `{}`: {} questions compared, {} skipped on an error",
            self.cheap, self.expensive, compared, self.skipped
        )?;
        writeln!(
            f,
            "{:<width$}  {:>9}  {:>9}  {:>6}  {:>6}  {:>5}  {:>9}  {:>7}",
            "kind",
            "questions",
            "agreement",
            "errors",
            "graded",
            "cheap",
            "expensive",
            "neither",
            width = width
        )?;
        for (kind, entry) in &self.kinds {
            let rate = match entry.agreement_rate() {
                Some(rate) => format!("{:.1}%", rate * 100.0),
                None => "n/a".to_owned(),
            };
            writeln!(
                f,
                "{:<width$}  {:>9}  {:>9}  {:>6}  {:>6}  {:>5}  {:>9}  {:>7}",
                kind.as_str(),
                entry.questions,
                rate,
                entry.errors,
                entry.graded,
                entry.cheap_right,
                entry.expensive_right,
                entry.neither_right,
                width = width
            )?;
        }
        Ok(())
    }
}

/// The state under [`AgreementLog`]'s lock: kinds accumulate in place,
/// the skip total beside them so the report's invariant — `skipped`
/// equals the sum of the per-kind `errors` — holds by construction.
#[derive(Debug, Default)]
struct LogState {
    kinds: BTreeMap<QuestionKind, KindAgreement>,
    skipped: u64,
}

/// Accumulates [`Observation`]s into an [`AgreementReport`] as they
/// happen, so a shadow classifier can feed it live and the report is
/// ready when the measurement window closes.
///
/// Same interior-mutability treatment as
/// [`InMemoryLedger`](crate::InMemoryLedger): the log is handed to its
/// caller as an explicitly-wired value, not ambient request state (ADR
/// 0007), so the one `std::sync::Mutex` under the scoped allow is the
/// recording cell.
#[derive(Debug)]
pub struct AgreementLog {
    cheap: AdapterId,
    expensive: AdapterId,
    #[allow(clippy::disallowed_types)]
    state: std::sync::Mutex<LogState>,
}

impl AgreementLog {
    /// A log for the `cheap`-vs-`expensive` pair. The ids come from the
    /// same wiring that produces the observations, and the report names
    /// the pair it was wired for whether or not anything was observed.
    //
    // The `Mutex` is the recording cell named on the field below —
    // explicitly-wired, not request state (ADR 0007).
    #[allow(clippy::disallowed_types)]
    #[must_use]
    pub fn new(cheap: AdapterId, expensive: AdapterId) -> Self {
        Self {
            cheap,
            expensive,
            state: std::sync::Mutex::new(LogState::default()),
        }
    }

    /// Locks the log, recovering from a poison rather than panicking:
    /// the state is plain counters appended under a short lock, so a
    /// poison would mean a panic mid-record — and throwing away the
    /// measurement so far because of it would be the dishonest choice
    /// for evidence.
    fn lock(&self) -> std::sync::MutexGuard<'_, LogState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Records one doubly-answered comparison.
    pub fn observe(&self, observation: Observation) {
        let mut state = self.lock();
        let entry = state.kinds.entry(observation.kind.clone()).or_default();
        entry.record(
            &observation.cheap_label,
            observation.cheap_confidence,
            observation.cheap_margin,
            &observation.expensive_label,
            observation.gold.as_deref(),
            observation.question,
        );
    }

    /// The report so far — the evidence the measurement has earned,
    /// ready to serialise and commit.
    #[must_use]
    pub fn report(&self) -> AgreementReport {
        let state = self.lock();
        AgreementReport {
            cheap: self.cheap.clone(),
            expensive: self.expensive.clone(),
            kinds: state.kinds.clone(),
            skipped: state.skipped,
        }
    }

    /// Counts a question the run dropped because an adapter errored on
    /// it. Private: only the corpus runner produces skips today, and the
    /// live shadow mode's contract is that a swallowed shadow error
    /// becomes a ledger row, not an observation-shaped thing.
    fn skip(&self, kind: &QuestionKind) {
        let mut state = self.lock();
        let entry = state.kinds.entry(kind.clone()).or_default();
        entry.count_error();
        state.skipped = state.skipped.saturating_add(1);
    }
}

/// One authored question with its gold answer, the unit a corpus is made
/// of.
///
/// This is the shape `data/classifier-corpus.json` deserialises into per
/// question: `kind` is a bare string, as [`QuestionKind`]'s serde is,
/// and `gold` is the right answer when the question has one. A question
/// without a gold answer can still be measured for raw agreement, but
/// its disagreements stay ungraded — see [`KindAgreement::graded`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorpusQuestion {
    pub kind: QuestionKind,
    pub text: String,
    /// The candidate labels an adapter must answer within.
    pub labels: Vec<String>,
    /// The right answer, when the corpus author knows it.
    pub gold: Option<String>,
}

/// The switches a measurement run is given beyond the two adapters and
/// the corpus: whether the question text is kept, and the accounting
/// that makes the run costed like the calls it makes (issue #457's
/// first acceptance criterion — every classifier call records tokens,
/// adapter and price — and a run that measures two adapters makes
/// plenty of calls).
///
/// Builder-style, the same shape [`ShadowClassifier`](crate::ShadowClassifier)
/// takes: `MeasurementOptions::default()` records no question text and
/// wires no accounting, and each builder returns the options with one
/// switch moved. The default is the honest floor either way — an
/// unaccounted run still produces the same report — but a run pointed at
/// a corpus is real spend, and `.prices(..)` plus `.ledger(..)` is how
/// the answer to "what did proving this cost" becomes a lookup rather
/// than a guess.
#[derive(Clone, Default)]
pub struct MeasurementOptions {
    /// Whether the question's text is recorded on the observations and
    /// disagreements. Off by default; see [`Observation::question`].
    record_question_text: bool,
    /// The sheet the run's calls are priced off. Empty by default, which
    /// leaves every recorded call unpriced — known-unknown, never free.
    prices: PriceSheet,
    /// The ledger every call the run makes is recorded to. `None` by
    /// default, which leaves the run unaccounted and the report unchanged.
    ledger: Option<Arc<dyn CostLedger>>,
}

impl MeasurementOptions {
    /// Records the question's text on each observation and disagreement.
    /// **Off by default**: in production the text is a user's. An offline
    /// corpus run opts in, because there the text is authored data and a
    /// disagreement you cannot read cannot be audited — the same switch
    /// `ShadowClassifier::record_question_text` is for shadow mode.
    #[must_use]
    pub fn record_question_text(mut self, record_question_text: bool) -> Self {
        self.record_question_text = record_question_text;
        self
    }

    /// Wires the price sheet the run's calls are priced off. Without
    /// one, every recorded call is unpriced — known-unknown, not free.
    #[must_use]
    pub fn prices(mut self, prices: PriceSheet) -> Self {
        self.prices = prices;
        self
    }

    /// Wires the ledger every call the run makes is recorded to. Without
    /// one, the run is not accounted — and the report is identical, so
    /// turning the accounting on changes what is known about the run and
    /// nothing about what the run produces.
    #[must_use]
    pub fn ledger(mut self, ledger: Arc<dyn CostLedger>) -> Self {
        self.ledger = Some(ledger);
        self
    }
}

impl fmt::Debug for MeasurementOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MeasurementOptions")
            .field("record_question_text", &self.record_question_text)
            .field("prices", &self.prices)
            .field("ledger", &self.ledger.is_some())
            .finish()
    }
}

/// Records one measurement call to the ledger, both halves of a compared
/// question alike. Skipped entirely when no ledger is wired — recording
/// is the runner's side duty, never a reason to fail the measurement.
///
/// The measurement twin of the routers' `record_call` in
/// `classifier_routing.rs`, with the role fixed: a measurement call is
/// always [`CallRole::Shadow`], asked in order to compare and never
/// served. An answered call is priced off the sheet — [`Option::None`]
/// when the adapter has no price, which means *unknown*, not free — and
/// a failed call is recorded unpriced at zero tokens rather than
/// guessed, because the error carries no token counts to price. The call
/// still happened, and the ledger row is how a cheap adapter that fails
/// often during measurement stops looking cheap.
fn record_call(
    ledger: Option<&Arc<dyn CostLedger>>,
    prices: &PriceSheet,
    adapter: &AdapterId,
    kind: &QuestionKind,
    call: &Result<Classification, ClassifierError>,
) {
    let Some(ledger) = ledger else {
        return;
    };
    let (answered, outcome) = match call {
        Ok(answer) => (Some(answer), CallOutcome::Ok),
        Err(_) => (None, CallOutcome::Failed),
    };
    let (input_tokens, output_tokens, cost) = match answered {
        Some(answer) => (
            answer.input_tokens,
            answer.output_tokens,
            prices.cost_of(adapter, answer.input_tokens, answer.output_tokens),
        ),
        None => (0, 0, None),
    };
    ledger.record(CallRecord {
        adapter: adapter.clone(),
        kind: kind.clone(),
        input_tokens,
        output_tokens,
        cost,
        role: CallRole::Shadow,
        outcome,
    });
}

/// Runs a corpus through both adapters and reports how often they agree,
/// per kind.
///
/// This is the offline runner that produces the evidence a router is
/// configured from: authored questions with gold answers (the
/// `data/classifier-corpus.json` shape, [`CorpusQuestion`]), asked of the
/// cheap adapter first and of the expensive one only when the cheap one
/// answered — a question the cheap adapter errored on has no comparison
/// in it, and paying for the expensive half anyway would price the run
/// like the worst possible router.
///
/// A question either adapter **errors** on is skipped, and counted, not
/// dropped: [`AgreementReport::skipped`] totals them and each kind's
/// [`KindAgreement::errors`] carries its own. Skipped questions sit in no
/// rate's denominator and are never counted as agreement — a report that
/// quietly loses the questions the cheap adapter choked on overstates
/// agreement, and that is precisely the dishonesty this module exists to
/// prevent.
///
/// The options are a [`MeasurementOptions`].
/// `.record_question_text(true)` opts the run into keeping the question
/// text on the observations and disagreements
/// ([`Observation::question`]). An offline corpus run opts in — the text
/// is authored data, and a disagreement you cannot read cannot be
/// audited. Production shadow mode leaves it off, because there the text
/// is a user's.
///
/// The run accounts for itself when `.ledger(..)` is wired, with
/// `.prices(..)` beside it: every call it makes is recorded — both sides
/// of each compared question, and the lone cheap side of a question the
/// cheap adapter failed — each as [`CallRole::Shadow`] (asked to
/// compare, never served) and priced off the sheet, [`Option::None`]
/// where the adapter has no price. A cheap call that errors is recorded
/// [`CallOutcome::Failed`], unpriced, and no expensive record follows it
/// for that question: the expensive adapter is never asked, so the
/// ledger showing one record there is the truth about what the run
/// spent. Without a ledger the report is identical — the accounting
/// rides beside the measurement, never in it. Either way the totals are
/// the number a venture reads before pointing the runner at a larger
/// corpus: what proving the switch cost, not a guess.
#[must_use = "the report is the evidence; running the corpus and dropping it measured nothing"]
pub async fn measure_agreement(
    cheap: &dyn Classifier,
    expensive: &dyn Classifier,
    corpus: &[CorpusQuestion],
    options: &MeasurementOptions,
) -> AgreementReport {
    let log = AgreementLog::new(cheap.adapter().clone(), expensive.adapter().clone());
    for sample in corpus {
        let question = Question::new(sample.kind.clone(), sample.text.clone())
            .labels(sample.labels.iter().cloned());
        let cheap_call = cheap.classify(&question).await;
        record_call(
            options.ledger.as_ref(),
            &options.prices,
            cheap.adapter(),
            &sample.kind,
            &cheap_call,
        );
        let Ok(cheap_answer) = cheap_call else {
            log.skip(&sample.kind);
            continue;
        };
        let expensive_call = expensive.classify(&question).await;
        record_call(
            options.ledger.as_ref(),
            &options.prices,
            expensive.adapter(),
            &sample.kind,
            &expensive_call,
        );
        let Ok(expensive_answer) = expensive_call else {
            log.skip(&sample.kind);
            continue;
        };
        log.observe(Observation {
            kind: sample.kind.clone(),
            cheap: cheap.adapter().clone(),
            cheap_label: cheap_answer.label().to_owned(),
            cheap_confidence: cheap_answer.confidence(),
            cheap_margin: cheap_answer.margin(),
            expensive: expensive.adapter().clone(),
            expensive_label: expensive_answer.label().to_owned(),
            gold: sample.gold.clone(),
            question: options.record_question_text.then(|| sample.text.clone()),
        });
    }
    log.report()
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    use async_trait::async_trait;

    use super::*;
    use crate::classifier::{Classification, ClassifierError};
    use crate::cost::{InMemoryLedger, Price};

    // -----------------------------------------------------------------
    // Fixtures

    fn observation(
        kind: &str,
        cheap_label: &str,
        expensive_label: &str,
        gold: Option<&str>,
    ) -> Observation {
        Observation {
            kind: QuestionKind::new(kind),
            cheap: AdapterId::new("cheap"),
            cheap_label: cheap_label.to_owned(),
            cheap_confidence: 0.9,
            cheap_margin: 0.8,
            expensive: AdapterId::new("expensive"),
            expensive_label: expensive_label.to_owned(),
            gold: gold.map(str::to_owned),
            question: None,
        }
    }

    fn sample(kind: &str, text: &str) -> CorpusQuestion {
        CorpusQuestion {
            kind: QuestionKind::new(kind),
            text: text.to_owned(),
            labels: vec!["a".to_owned(), "b".to_owned()],
            gold: Some("a".to_owned()),
        }
    }

    /// A stub whose answers are scripted per question text: `label` for
    /// everything, an override where a test wants a disagreement, and a
    /// scripted error where a test wants a skip.
    struct Stub {
        adapter: AdapterId,
        label: String,
        overrides: HashMap<String, String>,
        fail_on: HashSet<String>,
        usage: (u64, u64),
    }

    impl Stub {
        fn answering(adapter: &str, label: &str) -> Self {
            Self {
                adapter: AdapterId::new(adapter),
                label: label.to_owned(),
                overrides: HashMap::new(),
                fail_on: HashSet::new(),
                usage: (0, 0),
            }
        }

        fn answering_one(mut self, text: &str, label: &str) -> Self {
            self.overrides.insert(text.to_owned(), label.to_owned());
            self
        }

        fn failing_on(mut self, text: &str) -> Self {
            self.fail_on.insert(text.to_owned());
            self
        }

        /// Sets the token counts every answer carries, so a run wired to
        /// a ledger and a price sheet books the stubs like real adapters.
        fn with_usage(mut self, input_tokens: u64, output_tokens: u64) -> Self {
            self.usage = (input_tokens, output_tokens);
            self
        }
    }

    #[async_trait]
    impl Classifier for Stub {
        fn adapter(&self) -> &AdapterId {
            &self.adapter
        }

        async fn classify(&self, question: &Question) -> Result<Classification, ClassifierError> {
            if self.fail_on.contains(&question.text) {
                return Err(ClassifierError::Transport("scripted failure".to_owned()));
            }
            let label = self.overrides.get(&question.text).unwrap_or(&self.label);
            Ok(
                Classification::new(self.adapter.clone(), "stub", label.clone(), 0.9)
                    .usage(self.usage.0, self.usage.1),
            )
        }
    }

    // -----------------------------------------------------------------
    // The report's arithmetic

    #[test]
    fn the_report_tallies_counts_and_who_was_right_per_kind() {
        let log = AgreementLog::new(AdapterId::new("cheap"), AdapterId::new("expensive"));
        log.observe(observation("kind", "ham", "ham", Some("ham")));
        log.observe(observation("kind", "ham", "spam", Some("ham")));
        log.observe(observation("kind", "ham", "spam", Some("spam")));
        log.observe(observation("kind", "ham", "spam", Some("newsletter")));
        log.observe(observation("kind", "ham", "spam", None));
        log.observe(observation("other", "ham", "ham", Some("ham")));

        let report = log.report();
        assert_eq!(report.cheap(), &AdapterId::new("cheap"));
        assert_eq!(report.expensive(), &AdapterId::new("expensive"));
        let kind = report.kind(&QuestionKind::new("kind")).expect("observed");
        assert_eq!(kind.questions, 5, "every doubly-answered question counts");
        assert_eq!(kind.agreed, 1, "only identical answers agree");
        assert_eq!(
            u64::try_from(kind.disagreements.len()).expect("small"),
            kind.questions - kind.agreed,
            "agreed plus disagreements is every compared question"
        );
        assert_eq!(
            kind.graded, 3,
            "only disagreements with a gold answer are graded"
        );
        assert_eq!(kind.cheap_right, 1);
        assert_eq!(kind.expensive_right, 1);
        assert_eq!(
            kind.neither_right, 1,
            "a hard question is not evidence against the cheap side"
        );
        assert_eq!(report.skipped(), 0, "nothing errored");
        let other = report.kind(&QuestionKind::new("other")).expect("observed");
        assert_eq!(other.questions, 1, "kinds are counted separately");
        assert_eq!(other.agreed, 1);
    }

    #[test]
    fn rates_are_shares_of_the_questions_actually_compared() {
        let kind = KindAgreement {
            questions: 4,
            agreed: 3,
            ..KindAgreement::default()
        };
        let agreement = kind.agreement_rate().expect("measured");
        let disagreement = kind.disagreement_rate().expect("measured");
        assert!(
            (agreement - 0.75).abs() < 1e-9,
            "3 agreed of 4: {agreement}"
        );
        assert!(
            (disagreement - 0.25).abs() < 1e-9,
            "the two rates are shares of the same denominator and sum to one: {disagreement}"
        );
    }

    #[test]
    fn a_kind_with_no_compared_questions_has_no_rate_rather_than_a_nan() {
        let kind = KindAgreement::default();
        assert!(kind.agreement_rate().is_none(), "no denominator, no rate");
        assert!(
            kind.disagreement_rate().is_none(),
            "a caller comparing to a threshold must see `None` — no evidence — \
             never a `NaN`, which compares false against every threshold and \
             so reads as measured-and-safe"
        );
    }

    #[test]
    fn a_kind_the_run_never_saw_reads_as_no_evidence() {
        let report = AgreementLog::new(AdapterId::new("c"), AdapterId::new("e")).report();
        assert!(
            report.kind(&QuestionKind::new("kind")).is_none(),
            "no entry is the no-evidence signal a router must route expensive on"
        );
        assert_eq!(report.skipped(), 0);
        assert_eq!(report.kinds().count(), 0);
    }

    // -----------------------------------------------------------------
    // Calibration points and the restricted measurement

    #[test]
    fn the_calibration_points_keep_what_the_cheap_adapter_reported() {
        let log = AgreementLog::new(AdapterId::new("cheap"), AdapterId::new("expensive"));
        let mut unsure = observation("kind", "ham", "ham", Some("ham"));
        unsure.cheap_confidence = 0.55;
        unsure.cheap_margin = 0.1;
        log.observe(unsure);
        let mut wrong = observation("kind", "ham", "spam", Some("spam"));
        wrong.cheap_confidence = 0.95;
        wrong.cheap_margin = 0.9;
        log.observe(wrong);
        log.observe(observation("kind", "ham", "spam", None));

        let report = log.report();
        let kind = report.kind(&QuestionKind::new("kind")).expect("observed");
        assert_eq!(
            u64::try_from(kind.calibration.len()).expect("small"),
            kind.questions,
            "every compared answer is kept as the cheap adapter gave it"
        );
        let first = &kind.calibration[0];
        assert!(
            (first.cheap_confidence - 0.55).abs() < f32::EPSILON,
            "the confidence the adapter reported survives: {}",
            first.cheap_confidence
        );
        assert!(
            (first.cheap_margin - 0.1).abs() < f32::EPSILON,
            "the margin too: {}",
            first.cheap_margin
        );
        assert!(first.agreed, "both stubs said `ham`");
        assert_eq!(
            first.cheap_right,
            Some(true),
            "the gold answer grades the point where it is known"
        );
        let second = &kind.calibration[1];
        assert!(!second.agreed);
        assert_eq!(
            second.cheap_right,
            Some(false),
            "the cheap answer was wrong and the gold answer says so"
        );
        assert_eq!(
            kind.calibration[2].cheap_right, None,
            "no gold answer, no grading — the point is kept ungraded"
        );
    }

    #[test]
    fn agreement_at_restricts_to_the_answers_that_clear_both_floors() {
        let log = AgreementLog::new(AdapterId::new("cheap"), AdapterId::new("expensive"));
        // Two answers clearing both floors — one agreeing, one not —
        // one below the confidence floor, one short of the margin
        // floor with confidence to spare.
        let mut low_confidence = observation("kind", "ham", "spam", Some("ham"));
        low_confidence.cheap_confidence = 0.5;
        low_confidence.cheap_margin = 0.4;
        let mut narrow_margin = observation("kind", "ham", "spam", Some("ham"));
        narrow_margin.cheap_confidence = 0.9;
        narrow_margin.cheap_margin = 0.1;
        for point in [
            observation("kind", "ham", "ham", Some("ham")),
            observation("kind", "ham", "spam", Some("spam")),
            low_confidence,
            narrow_margin,
        ] {
            log.observe(point);
        }

        let report = log.report();
        let kind = report.kind(&QuestionKind::new("kind")).expect("observed");
        let at = kind
            .agreement_at(0.8, 0.5)
            .expect("two answers clear both floors");
        assert_eq!(
            at.questions, 2,
            "only the answers clearing both floors are in the subset"
        );
        assert_eq!(
            at.agreed, 1,
            "and their agreement is counted over just them"
        );
        let restricted = at.disagreement_rate().expect("measured");
        assert!(
            (restricted - 0.5).abs() < 1e-9,
            "one disagreement in the two answers the floors would serve: {restricted}"
        );
        let whole = kind.disagreement_rate().expect("measured");
        assert!(
            (whole - 0.75).abs() < 1e-9,
            "the whole-kind rate is a different number over a different set — \
             three of four compared disagreed: {whole}"
        );
    }

    #[test]
    fn an_answer_exactly_on_the_floors_clears_them_for_they_are_floors() {
        let log = AgreementLog::new(AdapterId::new("cheap"), AdapterId::new("expensive"));
        let mut on_the_line = observation("kind", "ham", "ham", Some("ham"));
        on_the_line.cheap_confidence = 0.8;
        on_the_line.cheap_margin = 0.5;
        log.observe(on_the_line);

        let report = log.report();
        let kind = report.kind(&QuestionKind::new("kind")).expect("observed");
        let at = kind
            .agreement_at(0.8, 0.5)
            .expect("meeting both floors exactly is clearing them");
        assert_eq!(
            at.questions, 1,
            "a threshold is a floor, not a wall to stand short of"
        );
    }

    #[test]
    fn agreement_at_answers_none_when_no_answer_clears_the_floors() {
        let log = AgreementLog::new(AdapterId::new("cheap"), AdapterId::new("expensive"));
        let mut unsure = observation("kind", "ham", "ham", Some("ham"));
        unsure.cheap_confidence = 0.5;
        unsure.cheap_margin = 0.4;
        log.observe(unsure);
        let mut nan = observation("kind", "ham", "ham", Some("ham"));
        nan.cheap_confidence = f32::NAN;
        nan.cheap_margin = f32::NAN;
        log.observe(nan);

        let report = log.report();
        let kind = report.kind(&QuestionKind::new("kind")).expect("observed");
        assert!(
            kind.agreement_at(0.8, 0.5).is_none(),
            "a floor nothing clears has no measured agreement, not a zero — and a \
             NaN clears nothing, because every comparison against it is false"
        );
    }

    // -----------------------------------------------------------------
    // Serde round trip: the report is committed evidence

    #[test]
    fn the_report_round_trips_through_json_including_the_disagreements() {
        let log = AgreementLog::new(AdapterId::new("cheap"), AdapterId::new("expensive"));
        log.observe(observation("kind", "ham", "spam", Some("spam")));
        let mut recorded = observation("kind", "spam", "ham", None);
        recorded.question = Some("Is this spam?".to_owned());
        log.observe(recorded);

        let report = log.report();
        let json = serde_json::to_string(&report).expect("the report serialises");
        let back: AgreementReport = serde_json::from_str(&json).expect("and loads again");
        assert_eq!(
            back, report,
            "every field survives: the committed evidence is the measured evidence"
        );
        let kind = back
            .kind(&QuestionKind::new("kind"))
            .expect("the kind survives");
        assert_eq!(kind.disagreements.len(), 2);
        assert_eq!(
            kind.disagreements[0].gold.as_deref(),
            Some("spam"),
            "the grading survives the round trip"
        );
        assert_eq!(
            kind.disagreements[1].question.as_deref(),
            Some("Is this spam?"),
            "the recorded text survives the round trip"
        );
        assert_eq!(back.cheap(), report.cheap(), "the named pair survives");
        assert_eq!(back.expensive(), report.expensive());
        assert_eq!(
            kind.calibration.len(),
            2,
            "the calibration survives the round trip too: the committed \
             evidence is what a threshold is calibrated from"
        );
        assert!(
            (kind.calibration[0].cheap_confidence - 0.9).abs() < f32::EPSILON,
            "the cheap adapter's own numbers are part of the evidence: {}",
            kind.calibration[0].cheap_confidence
        );
        assert_eq!(
            kind.calibration[0].cheap_right,
            Some(false),
            "so is whether its answer was right"
        );
    }

    // -----------------------------------------------------------------
    // Errors are counted, never folded into agreement

    #[pollster::test]
    async fn a_cheap_adapter_error_is_counted_as_skipped_and_never_as_agreement() {
        let cheap = Stub::answering("cheap", "a").failing_on("question 1");
        let expensive = Stub::answering("expensive", "a");
        let corpus = vec![
            sample("kind", "question 1"),
            sample("kind", "question 2"),
            sample("kind", "question 3"),
        ];

        let report =
            measure_agreement(&cheap, &expensive, &corpus, &MeasurementOptions::default()).await;

        assert_eq!(
            report.skipped(),
            1,
            "the errored question is counted, not dropped"
        );
        let kind = report
            .kind(&QuestionKind::new("kind"))
            .expect("the kind is still reported");
        assert_eq!(kind.errors, 1, "the error lands on its kind");
        assert_eq!(
            kind.questions, 2,
            "the errored question is in no rate's denominator"
        );
        assert_eq!(kind.agreed, 2, "and it is never counted as agreement");
        let rate = kind.agreement_rate().expect("questions were compared");
        assert!(
            (rate - 1.0).abs() < 1e-9,
            "the compared questions agreed — and the rate is honest because \
             the skip sits beside it: {rate}"
        );
    }

    #[pollster::test]
    async fn an_expensive_adapter_error_is_counted_the_same_way() {
        let cheap = Stub::answering("cheap", "a");
        let expensive = Stub::answering("expensive", "a").failing_on("question 2");
        let corpus = vec![
            sample("kind", "question 1"),
            sample("kind", "question 2"),
            sample("kind", "question 3"),
        ];

        let report =
            measure_agreement(&cheap, &expensive, &corpus, &MeasurementOptions::default()).await;

        assert_eq!(
            report.skipped(),
            1,
            "either side erroring skips the question"
        );
        let kind = report
            .kind(&QuestionKind::new("kind"))
            .expect("the kind is still reported");
        assert_eq!(kind.errors, 1);
        assert_eq!(kind.questions, 2, "two comparisons happened, not three");
        assert_eq!(kind.agreed, 2);
    }

    // -----------------------------------------------------------------
    // The question text is opt-in

    #[pollster::test]
    async fn question_text_is_absent_by_default_and_present_when_opted_in() {
        let cheap = Stub::answering("cheap", "a").answering_one("question 1", "b");
        let expensive = Stub::answering("expensive", "a");
        let corpus = vec![sample("kind", "question 1"), sample("kind", "question 2")];

        let off =
            measure_agreement(&cheap, &expensive, &corpus, &MeasurementOptions::default()).await;
        let on = measure_agreement(
            &cheap,
            &expensive,
            &corpus,
            &MeasurementOptions::default().record_question_text(true),
        )
        .await;

        let off_kind = off
            .kind(&QuestionKind::new("kind"))
            .expect("the kind is measured");
        assert_eq!(
            off_kind.disagreements.len(),
            1,
            "the override forces exactly one disagreement"
        );
        assert!(
            off_kind.disagreements.iter().all(|d| d.question.is_none()),
            "default: the text is a user's and stays out of the report"
        );
        let on_kind = on
            .kind(&QuestionKind::new("kind"))
            .expect("the kind is measured");
        assert_eq!(on_kind.disagreements.len(), 1);
        assert_eq!(
            on_kind.disagreements[0].question.as_deref(),
            Some("question 1"),
            "the run that opted in keeps the text so the disagreement can be read"
        );
    }

    // -----------------------------------------------------------------
    // The run is itself accounted

    #[pollster::test]
    async fn a_measured_run_with_a_ledger_records_both_sides_of_every_compared_question() {
        let cheap_id = AdapterId::new("cheap");
        let expensive_id = AdapterId::new("expensive");
        let prices = PriceSheet::new()
            .with(
                cheap_id.clone(),
                Price::per_million_tokens(1_000_000, 2_000_000),
            )
            .with(
                expensive_id.clone(),
                Price::per_million_tokens(3_000_000, 15_000_000),
            );
        let cheap = Stub::answering("cheap", "a").with_usage(1_000, 100);
        let expensive = Stub::answering("expensive", "a").with_usage(10_000, 1_000);
        let corpus = vec![
            sample("kind", "question 1"),
            sample("kind", "question 2"),
            sample("kind", "question 3"),
        ];
        let ledger = Arc::new(InMemoryLedger::new());
        let options = MeasurementOptions::default()
            .prices(prices.clone())
            .ledger(ledger.clone());

        let report = measure_agreement(&cheap, &expensive, &corpus, &options).await;

        assert_eq!(
            report.skipped(),
            0,
            "nothing failed, so nothing was skipped"
        );
        // The per-call prices, off the same sheet the run was wired
        // with; the totals below are asserted against these, computed
        // in the test, never hard-coded.
        let cheap_per_call = prices
            .cost_of(&cheap_id, 1_000, 100)
            .expect("the cheap adapter is priced");
        let expensive_per_call = prices
            .cost_of(&expensive_id, 10_000, 1_000)
            .expect("the expensive adapter is priced");
        let records = ledger.records();
        assert_eq!(
            u64::try_from(records.len()).expect("small"),
            6,
            "both sides of each of the three compared questions is recorded"
        );
        assert!(
            records.iter().all(|record| record.role == CallRole::Shadow),
            "a measurement call is asked in order to compare and never served"
        );
        let compared: u64 = report.kinds().map(|(_, kind)| kind.questions).sum();
        assert_eq!(compared, 3, "every corpus question was compared");
        let cheap_records = records
            .iter()
            .filter(|record| record.adapter == cheap_id)
            .count();
        assert_eq!(
            u64::try_from(cheap_records).expect("small"),
            compared,
            "the cheap adapter was asked once per question"
        );
        let expensive_records = records
            .iter()
            .filter(|record| record.adapter == expensive_id)
            .count();
        assert_eq!(
            u64::try_from(expensive_records).expect("small"),
            compared,
            "and so was the expensive one"
        );
        assert!(
            records
                .iter()
                .filter(|record| record.adapter == cheap_id)
                .all(|record| record.cost == Some(cheap_per_call)),
            "each cheap call is priced for the tokens it actually spent"
        );
        let totals = ledger.totals();
        let cheap_totals = &totals[&cheap_id];
        assert_eq!(cheap_totals.calls, compared);
        assert_eq!(
            cheap_totals.pico_usd,
            u128::from(cheap_per_call.pico_usd()) * u128::from(compared),
            "the cheap side totals exactly its per-call price times its call count"
        );
        let expensive_totals = &totals[&expensive_id];
        assert_eq!(expensive_totals.calls, compared);
        assert_eq!(
            expensive_totals.pico_usd,
            u128::from(expensive_per_call.pico_usd()) * u128::from(compared),
            "the expensive side totals exactly its per-call price times its call count"
        );
    }

    #[pollster::test]
    async fn a_cheap_failure_books_one_failed_record_and_no_expensive_one() {
        let cheap = Stub::answering("cheap", "a")
            .with_usage(1_000, 100)
            .failing_on("question 1");
        let expensive = Stub::answering("expensive", "a").with_usage(10_000, 1_000);
        let corpus = vec![sample("kind", "question 1"), sample("kind", "question 2")];
        let ledger = Arc::new(InMemoryLedger::new());
        let options = MeasurementOptions::default().ledger(ledger.clone());

        let report = measure_agreement(&cheap, &expensive, &corpus, &options).await;

        assert_eq!(
            report.skipped(),
            1,
            "the failed question is still counted in the report"
        );
        let records = ledger.records();
        assert_eq!(
            records.len(),
            3,
            "one compared question books two records and the failed one books \
             only its cheap half: three"
        );
        let failed: Vec<_> = records
            .iter()
            .filter(|record| record.outcome == CallOutcome::Failed)
            .collect();
        assert_eq!(failed.len(), 1, "exactly the failed cheap call");
        assert_eq!(
            failed[0].adapter,
            cheap.adapter().clone(),
            "the failure is the cheap side's"
        );
        assert_eq!(
            failed[0].cost, None,
            "a failed call carries no token counts to price"
        );
        assert_eq!(
            failed[0].input_tokens, 0,
            "and no tokens are counted for it rather than guessed"
        );
        let expensive_id = expensive.adapter().clone();
        assert!(
            records
                .iter()
                .filter(|record| record.adapter == expensive_id)
                .all(|record| record.outcome == CallOutcome::Ok),
            "the expensive adapter was asked only for the questions the cheap one answered"
        );
        let expensive_records = records
            .iter()
            .filter(|record| record.adapter == expensive_id)
            .count();
        assert_eq!(
            u64::try_from(expensive_records).expect("small"),
            1,
            "one expensive record for the one compared question, none for the failure"
        );
        assert!(
            records.iter().all(|record| record.role == CallRole::Shadow),
            "a failed call is still a measurement call: asked to compare, never served"
        );
    }

    #[pollster::test]
    async fn a_measured_run_without_a_ledger_produces_the_same_report_as_one_with() {
        let cheap = Stub::answering("cheap", "a").answering_one("question 1", "b");
        let expensive = Stub::answering("expensive", "a");
        let corpus = vec![sample("kind", "question 1"), sample("kind", "question 2")];

        let accounted = measure_agreement(
            &cheap,
            &expensive,
            &corpus,
            &MeasurementOptions::default()
                .prices(
                    PriceSheet::new()
                        .with(cheap.adapter().clone(), Price::per_million_tokens(1, 1)),
                )
                .ledger(Arc::new(InMemoryLedger::new())),
        )
        .await;
        let unaccounted =
            measure_agreement(&cheap, &expensive, &corpus, &MeasurementOptions::default()).await;

        assert_eq!(
            accounted, unaccounted,
            "the accounting rides beside the measurement: wiring a ledger and a \
             price sheet changes what is known about the run, never what it reports"
        );
        let kind = accounted
            .kind(&QuestionKind::new("kind"))
            .expect("the kind is measured");
        assert_eq!(
            kind.questions, 2,
            "the compared pair is the same either way"
        );
    }

    // -----------------------------------------------------------------
    // The plain-text table

    #[test]
    fn the_display_table_renders_per_kind_rows_and_an_unmeasured_kind_as_na() {
        let mut kinds = BTreeMap::new();
        let measured = KindAgreement {
            questions: 4,
            agreed: 3,
            graded: 1,
            expensive_right: 1,
            errors: 1,
            ..KindAgreement::default()
        };
        kinds.insert(QuestionKind::new("cms-draft-review"), measured);
        kinds.insert(
            QuestionKind::new("release-note-kind"),
            KindAgreement::default(),
        );
        let report = AgreementReport {
            cheap: AdapterId::new("cheap"),
            expensive: AdapterId::new("expensive"),
            kinds,
            skipped: 1,
        };

        let table = report.to_string();
        assert!(
            table.contains("cheap"),
            "the compared pair is named: {table}"
        );
        assert!(table.contains("expensive"), "both sides: {table}");
        assert!(
            table.contains("cms-draft-review"),
            "one row per kind: {table}"
        );
        assert!(
            table.contains("75.0%"),
            "the agreement rate renders as a percentage: {table}"
        );
        assert!(
            table.contains("n/a"),
            "a kind with no compared questions reads n/a, never a NaN: {table}"
        );
    }
}
