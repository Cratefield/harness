//! Routing a classification to the cheapest adapter allowed to answer
//! it (issue #457): the policy that decides ([`RoutingPolicy`]), the
//! router that asks ([`RoutingClassifier`]), and the shadow classifier
//! that measures without ever changing what callers get
//! ([`ShadowClassifier`]).
//!
//! The decision is conservative by construction. The shipped default is
//! [`RoutingMode::Off`] — every question to the expensive adapter — and
//! [`RoutingMode::Measured`] routes cheap only where **all** of these
//! hold: the committed evidence is about exactly the pair of adapters
//! the router holds, the question's kind was measured, the cheap
//! adapter carries thresholds calibrated **for that adapter**, enough
//! of the answers clearing those floors were compared, and the
//! disagreement among just those answers sits under the policy's cap.
//! Measuring at the floors is the point: the answers a threshold would
//! serve are the only ones whose agreement is evidence about serving
//! them, and the whole-kind average would refuse a kind whose sure
//! answers agree perfectly because its unsure ones differ — and accept
//! one whose average is fine while every answer it would serve is a bad
//! one. Miss any one of the gates and the expensive adapter answers.
//! Whatever happens, [`Routed`] carries the [`RouteReason`], so an
//! answer says why it came from where it came from — and
//! [`RoutingPolicy::plan_for`] answers the same question before any
//! call is made, for whoever is debugging the policy rather than the
//! call.
//!
//! **No number ships here.** No real-adapter agreement figures exist in
//! this crate and none may be invented: the thresholds and caps on a
//! [`RoutingPolicy`] are knobs a venture tunes, the evidence is a
//! report the venture measured on its own adapters (through
//! [`measure_agreement`](crate::measure_agreement) or
//! [`ShadowClassifier`]) and committed, and until then the mode is
//! `Off` — nothing routes cheap until somebody runs the measurement.
//! `docs/CLASSIFIER-ROUTING.md` walks a venture through that sequence.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;

use crate::classifier::{
    AdapterId, Classification, Classifier, ClassifierError, Question, QuestionKind,
};
use crate::classifier_agreement::{AgreementLog, AgreementReport, Observation};
use crate::cost::{CallOutcome, CallRecord, CallRole, CostLedger, PriceSheet};

/// How many compared questions a kind needs before its disagreement
/// rate means anything at all, when a venture has not tuned the policy.
/// Deliberately awkward to satisfy: a rate over a handful of questions
/// is noise, and noise must not win a routing decision.
const DEFAULT_MIN_QUESTIONS: u64 = 20;

/// The disagreement cap for a policy a venture has not tuned. A knob
/// chosen to be strict, not a measurement — no real-adapter figure
/// exists in this crate, and none may be invented (see the module
/// docs).
const DEFAULT_MAX_DISAGREEMENT_RATE: f64 = 0.05;

/// The confidence floor and margin floor **one adapter** must clear
/// before the router serves its answer (issue #457).
///
/// **Thresholds are per adapter and are not transferable.** A `0.8`
/// from a trained classifier and a `0.8` an LLM typed into a JSON field
/// are not the same claim about the world; a threshold calibrated on
/// one and applied to the other looks principled and is worse than no
/// threshold. That is why a policy keys thresholds by [`AdapterId`]
/// ([`RoutingPolicy::thresholds`]) and why an adapter with no entry is
/// never preferred ([`RouteReason::NoCalibration`]) — however good its
/// agreement evidence looks.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Thresholds {
    /// The smallest confidence an answer may carry and still be served.
    /// A floor: meeting it clears it.
    pub min_confidence: f32,
    /// The smallest margin — top score minus runner-up — an answer may
    /// carry. A floor: meeting it clears it. A near-tie is a coin flip
    /// wearing a label.
    pub min_margin: f32,
}

/// How the router decides, set once when the policy is built.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RoutingMode {
    /// Every question goes to the expensive adapter. The shipped
    /// default ([`RoutingPolicy::default`]): nothing routes cheap until
    /// somebody runs the measurement and commits the evidence.
    Off,
    /// Every question goes to this one adapter, and the router never
    /// escalates: the pinned adapter's answers **and its errors** reach
    /// the caller unchanged. Pinning exists so a person can take the
    /// router out of the picture while debugging — a pin that silently
    /// escalated would defeat that. A pin naming an adapter the router
    /// does not hold is refused at call time with
    /// [`ClassifierError::NotConfigured`] — the router then genuinely
    /// has no classifier wired for the question — never silently
    /// rerouted to one it does hold.
    Pinned(AdapterId),
    /// The cheap adapter answers first where the committed evidence and
    /// the cheap adapter's own calibration both allow it, and the
    /// router escalates to the expensive adapter when the cheap answer
    /// is unsure — or the cheap adapter failed.
    Measured,
}

/// Why a classification went where it went (issue #457).
///
/// The reason is part of the answer ([`Routed::reason`]) and of the
/// plan ([`RoutingPolicy::plan_for`]), because "the cheap adapter
/// answered" and "the cheap adapter was never allowed to try" look
/// identical from the outside and are opposite facts about a system.
/// Every variant names the gate that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RouteReason {
    /// The policy pins one adapter, and the router asked it. A pinned
    /// adapter never escalates: its answers and its errors both reach
    /// the caller unchanged, because pinning is the escape hatch that
    /// takes the router out of the picture.
    Pinned,
    /// The policy is [`RoutingMode::Off`] — the shipped default — so
    /// the expensive adapter answers and nothing goes cheap.
    RoutingOff,
    /// [`RoutingMode::Measured`] with no committed evidence at all, or
    /// no evidence for this question's kind: there is nothing measured
    /// to route on, so the expensive adapter answers.
    NoMeasurement,
    /// Fewer answers cleared both of the cheap adapter's own floors
    /// than the policy's `min_questions` — or none cleared them at all.
    /// The gate measures agreement over the answers the floors would
    /// serve, so `min_questions` applies to that subset: a rate over
    /// too few answers is noise, and noise must not win a routing
    /// decision wherever it is measured.
    NotMeasuredEnough,
    /// The disagreement rate over the answers that cleared the cheap
    /// adapter's own floors is above the policy's
    /// `max_disagreement_rate`: the two adapters differ too often on
    /// exactly the answers the router would serve for the cheap answer
    /// to stand in for the expensive one.
    DisagreementTooHigh,
    /// The cheap adapter has no [`Thresholds`] entry of its own. **This
    /// is the trap the module exists to close**: a threshold calibrated
    /// on one adapter is not transferable to another, and an adapter
    /// with no calibration is never preferred, however perfect its
    /// evidence looks. The gate consults calibration before the
    /// measurement numbers, because the floors are what select the
    /// answers the measurement is taken over — without them there is
    /// nothing to measure.
    NoCalibration,
    /// The committed evidence names a different cheap/expensive pair
    /// than the router holds. A report measured on other adapters is
    /// not evidence here, and is refused wholesale rather than mined
    /// for the kinds that happen to look usable.
    EvidenceIsAboutOtherAdapters,
    /// The cheap adapter answered and cleared both of its own
    /// thresholds; its answer is the one served.
    CheapAccepted,
    /// The cheap adapter answered, but below its own `min_confidence`:
    /// its answer was discarded and the expensive adapter was asked.
    EscalatedLowConfidence,
    /// The cheap adapter cleared its `min_confidence` but not its
    /// `min_margin` — a near-tie — and was discarded for it.
    EscalatedNarrowMargin,
    /// The cheap adapter errored. The error is recorded, not surfaced:
    /// a router that failed closed on the cheap adapter would make the
    /// cheap adapter's reliability the whole system's, so it escalates
    /// instead and serves the expensive answer.
    EscalatedCheapFailed,
}

/// What the policy would do for one kind of question, and why — the
/// answer a person debugging asks before any call is made, from
/// [`RoutingPolicy::plan_for`].
///
/// A plan is only the first move: where it says cheap-first, a bad
/// cheap answer can still escalate ([`RouteReason::CheapAccepted`] is
/// the plan's reason *and* the served answer's reason only when the
/// cheap answer clears its thresholds).
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct Plan {
    /// Whether the router should ask the cheap adapter first. Always
    /// `false` where the table below says expensive.
    pub cheap_first: bool,
    /// The gate that decided.
    pub reason: RouteReason,
}

impl Plan {
    /// The plan that asks the cheap adapter first.
    fn cheap(reason: RouteReason) -> Self {
        Self {
            cheap_first: true,
            reason,
        }
    }

    /// The plan that goes straight to the expensive adapter.
    fn expensive(reason: RouteReason) -> Self {
        Self {
            cheap_first: false,
            reason,
        }
    }
}

/// The routing decision, made once at wiring time: the
/// [`RoutingMode`], the per-adapter [`Thresholds`], and the committed
/// evidence.
///
/// **The default is `Off`.** Unmeasured routing is not the default
/// anywhere in this crate: a venture builds [`RoutingPolicy::measured`]
/// deliberately, after measuring an [`AgreementReport`] on its own
/// adapters and committing it. The policy never measures anything
/// itself — it only refuses to route cheap without evidence.
#[derive(Debug, Clone)]
pub struct RoutingPolicy {
    mode: RoutingMode,
    thresholds: BTreeMap<AdapterId, Thresholds>,
    evidence: Option<AgreementReport>,
    min_questions: u64,
    max_disagreement_rate: f64,
}

impl RoutingPolicy {
    /// Everything expensive: the shipped default, and what
    /// `RoutingPolicy::default()` builds.
    #[must_use]
    pub fn off() -> Self {
        Self {
            mode: RoutingMode::Off,
            thresholds: BTreeMap::new(),
            evidence: None,
            min_questions: DEFAULT_MIN_QUESTIONS,
            max_disagreement_rate: DEFAULT_MAX_DISAGREEMENT_RATE,
        }
    }

    /// Pins one adapter: its answers and its errors reach the caller
    /// unchanged, with no escalation — the debugging escape hatch that
    /// takes the router out of the picture. Pinning an adapter the
    /// router does not hold fails every call with
    /// [`ClassifierError::NotConfigured`] rather than rerouting.
    #[must_use]
    pub fn pinned(adapter: AdapterId) -> Self {
        Self {
            mode: RoutingMode::Pinned(adapter),
            ..Self::off()
        }
    }

    /// Measured routing: cheap first where the evidence and the cheap
    /// adapter's own calibration allow it, escalating when unsure or on
    /// a cheap error. Without `.evidence(..)` this behaves exactly like
    /// `Off` ([`RouteReason::NoMeasurement`]) — that is the point.
    #[must_use]
    pub fn measured() -> Self {
        Self {
            mode: RoutingMode::Measured,
            ..Self::off()
        }
    }

    /// Calibrates `adapter` with its **own** thresholds. An adapter
    /// without an entry is never preferred, whatever its evidence says.
    #[must_use]
    pub fn thresholds(mut self, adapter: AdapterId, thresholds: Thresholds) -> Self {
        self.thresholds.insert(adapter, thresholds);
        self
    }

    /// Commits the evidence the `Measured` mode routes on: the report a
    /// venture measured and serialised. A report about a pair of
    /// adapters other than the router's is refused, not mined.
    #[must_use]
    pub fn evidence(mut self, evidence: AgreementReport) -> Self {
        self.evidence = Some(evidence);
        self
    }

    /// How many compared questions a kind needs before its
    /// disagreement rate is consulted at all.
    #[must_use]
    pub fn min_questions(mut self, min_questions: u64) -> Self {
        self.min_questions = min_questions;
        self
    }

    /// The largest measured disagreement rate that still allows
    /// cheap-first for a kind. A rate **equal** to the cap passes: the
    /// cap is a ceiling, and only going above it refuses.
    #[must_use]
    pub fn max_disagreement_rate(mut self, max_disagreement_rate: f64) -> Self {
        self.max_disagreement_rate = max_disagreement_rate;
        self
    }

    /// What the policy would do for `kind`, asked with the cheap
    /// adapter's id — public, pure, and callable without a router, so a
    /// person debugging can ask the policy what it would do before any
    /// call is made.
    ///
    /// The behaviour table, in the order the gates are applied:
    ///
    /// - mode `Off` ⇒ expensive, [`RouteReason::RoutingOff`]
    /// - mode `Pinned` ⇒ the pinned adapter, [`RouteReason::Pinned`]
    ///   (`cheap_first` records only whether the pin names the cheap
    ///   adapter; the router resolves the pin against both of its
    ///   adapters)
    /// - `Measured` with no evidence ⇒ expensive,
    ///   [`RouteReason::NoMeasurement`]
    /// - the evidence is about a different pair of adapters ⇒
    ///   expensive, [`RouteReason::EvidenceIsAboutOtherAdapters`]
    /// - evidence has no entry for `kind` ⇒ expensive, `NoMeasurement`
    /// - no [`Thresholds`] entry for the cheap adapter ⇒ expensive,
    ///   [`RouteReason::NoCalibration`]
    /// - fewer answers clear both of the cheap adapter's own floors
    ///   than `min_questions`, including no answer clearing them at
    ///   all ⇒ expensive, [`RouteReason::NotMeasuredEnough`]
    /// - the disagreement rate over **just those clearing answers** is
    ///   above `max_disagreement_rate` ⇒ expensive,
    ///   [`RouteReason::DisagreementTooHigh`]
    /// - otherwise ⇒ cheap first
    ///
    /// Why the rate is taken over the clearing answers only: those are
    /// the answers the floors would actually serve, so they are the
    /// only ones whose agreement is evidence about the decision being
    /// made. The whole-kind average measures the wrong thing in both
    /// directions — it refuses a kind whose high-confidence answers
    /// agree perfectly, because its unsure answers happen to differ,
    /// and it accepts a kind whose average looks fine while every
    /// answer that would clear the floors is one of the bad ones. The
    /// whole-kind counts stay on the report for context (see
    /// [`KindAgreement`](crate::classifier_agreement::KindAgreement))
    /// and are worth reading; they are just not what the gate caps.
    /// Calibration is therefore consulted before the measurement
    /// numbers: the floors are what select the answers the measurement
    /// is taken over, so without them there is nothing to measure.
    ///
    /// The policy is pure and holds no adapters — only the evidence
    /// names a pair — so this plan borrows the evidence's own expensive
    /// side: a plan against a report is a plan for the pair that report
    /// measured. The router applies the same gate against the adapters
    /// it actually holds, which is where a report about a different
    /// pair is refused outright.
    ///
    /// A kind the cheap adapter often **errored** on during the
    /// measurement (the kind's `errors` count in
    /// [`KindAgreement`](crate::classifier_agreement::KindAgreement))
    /// is deliberately not a gate here: that count is a property of the
    /// measurement run, not of the adapter. In a live shadow run it is
    /// structurally zero — a swallowed shadow error never becomes an
    /// observation — while a corpus run carries its skips, so gating on
    /// it would enforce two different policies depending on where the
    /// report came from. The honest reliability signal in production is
    /// the ledger's [`CallOutcome::Failed`] rows; the response to a
    /// cheap adapter that fails often is to re-measure or to pin.
    #[must_use]
    pub fn plan_for(&self, kind: &QuestionKind, cheap: &AdapterId) -> Plan {
        match self.evidence.as_ref() {
            Some(report) => self.gate(kind, cheap, report.expensive()),
            None => self.gate(kind, cheap, cheap),
        }
    }

    /// The full gate, with both adapter ids known — the router's view of
    /// [`Self::plan_for`]. See that method for the behaviour table and
    /// for why an error count is not a gate.
    fn gate(&self, kind: &QuestionKind, cheap: &AdapterId, expensive: &AdapterId) -> Plan {
        match &self.mode {
            RoutingMode::Off => Plan::expensive(RouteReason::RoutingOff),
            RoutingMode::Pinned(pinned) => Plan {
                cheap_first: pinned == cheap,
                reason: RouteReason::Pinned,
            },
            RoutingMode::Measured => {
                let Some(report) = self.evidence.as_ref() else {
                    return Plan::expensive(RouteReason::NoMeasurement);
                };
                // The evidence is about one pair. A report measured on
                // other adapters says nothing about these two, and the
                // parts of it that happen to look usable are exactly
                // the parts that are most tempting and least true.
                if report.cheap() != cheap || report.expensive() != expensive {
                    return Plan::expensive(RouteReason::EvidenceIsAboutOtherAdapters);
                }
                let Some(entry) = report.kind(kind) else {
                    return Plan::expensive(RouteReason::NoMeasurement);
                };
                // Calibration comes before the measurement numbers,
                // because the floors are what select the answers the
                // measurement is taken over: without a threshold pair
                // for the cheap adapter there is no subset to measure.
                let Some(thresholds) = self.thresholds.get(cheap) else {
                    return Plan::expensive(RouteReason::NoCalibration);
                };
                // The rate that decides is over the answers that would
                // actually be served — the ones clearing both of the
                // cheap adapter's own floors. Capping the whole-kind
                // average would refuse a kind whose high-confidence
                // answers agree perfectly just because its unsure
                // answers differ, and accept one whose average is fine
                // while every answer it would serve is one of the bad
                // ones. `agreement_at` answers `None` when nothing
                // clears, which is the honest reading: no answer would
                // be served, so nothing about serving is measured.
                let Some(at) = entry.agreement_at(thresholds.min_confidence, thresholds.min_margin)
                else {
                    return Plan::expensive(RouteReason::NotMeasuredEnough);
                };
                if at.questions < self.min_questions {
                    return Plan::expensive(RouteReason::NotMeasuredEnough);
                }
                // Enough clearing answers were compared that the rate
                // exists — `agreement_at` returned `Some`, so at least
                // one did — and when a venture has tuned
                // `min_questions` down to zero this arm still keeps the
                // gate total rather than trusting that invariant.
                let Some(rate) = at.disagreement_rate() else {
                    return Plan::expensive(RouteReason::NotMeasuredEnough);
                };
                // A cap is a ceiling: meeting it passes, so a rate
                // exactly on it goes cheap. The check is positive on
                // purpose, matching the threshold floors in
                // `cheap_first`: every comparison against a NaN is
                // false, so a `rate > cap` gate would read a NaN rate
                // — or a NaN cap — as *not* over the cap and route
                // cheap. The kind proceeds cheap-first only when the
                // rate provably sits within the cap, so a NaN on
                // either side refuses.
                if rate <= self.max_disagreement_rate {
                    return Plan::cheap(RouteReason::CheapAccepted);
                }
                Plan::expensive(RouteReason::DisagreementTooHigh)
            }
        }
    }
}

impl Default for RoutingPolicy {
    /// The shipped default: [`RoutingMode::Off`]. Unmeasured routing is
    /// not the default anywhere.
    fn default() -> Self {
        Self::off()
    }
}

/// Records one classifier call to the ledger, shared by both routers in
/// this module. Skipped entirely when no ledger is wired — recording is
/// the routers' side duty, never a reason to fail a classification.
///
/// An answered call is priced off the sheet: [`Option::None`] when the
/// adapter has no price, which means *unknown*, not free. A failed
/// call's token counts never reach the router — the error carries
/// none — so it is recorded unpriced at zero tokens rather than
/// guessed: the call still happened, and the ledger row is how a cheap
/// adapter that fails often stops looking cheap.
fn record_call(
    ledger: Option<&Arc<dyn CostLedger>>,
    prices: &PriceSheet,
    adapter: &AdapterId,
    kind: &QuestionKind,
    answered: Option<&Classification>,
    role: CallRole,
    outcome: CallOutcome,
) {
    let Some(ledger) = ledger else {
        return;
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
        role,
        outcome,
    });
}

/// What one answer cost, as the ledger will book it: `"unpriced"` when
/// the adapter has no price on the sheet — unknown, never free.
fn cost_line(prices: &PriceSheet, classification: &Classification) -> String {
    prices
        .cost_of(
            &classification.adapter,
            classification.input_tokens,
            classification.output_tokens,
        )
        .map_or_else(|| "unpriced".to_owned(), |cost| cost.to_string())
}

/// The one-line story of a served answer, for whoever is debugging a
/// wrong decision: which adapter answered, why, how sure it was, and
/// what the answer cost. A propagated error gets no line — the ledger
/// row is its record, and the error itself reaches the caller.
fn debug_served(
    prices: &PriceSheet,
    classification: &Classification,
    kind: &QuestionKind,
    reason: RouteReason,
) {
    tracing::debug!(
        adapter = %classification.adapter,
        kind = %kind,
        reason = ?reason,
        confidence = classification.confidence(),
        margin = classification.margin(),
        cost = %cost_line(prices, classification),
        "classifier routing served an answer",
    );
}

/// A [`Classifier`] that routes between a cheap and an expensive
/// adapter by a [`RoutingPolicy`] (issue #457) — pure composition, no
/// I/O of its own, which is why it lives in core exactly as
/// [`RoutingTextModel`](crate::RoutingTextModel) does.
///
/// The shape of the deal, in `Measured` mode: the cheap adapter is
/// asked first where the evidence and its own calibration allow; its
/// answer is served when it clears **both** of its own thresholds; a
/// cheap answer below `min_confidence`, or with a margin below
/// `min_margin`, is discarded and the expensive adapter is asked
/// instead; a cheap **error** is escalated rather than surfaced, because
/// a router that fails closed on the cheap adapter would make the cheap
/// adapter's reliability the whole system's.
///
/// Every call that happens is recorded to the wired
/// [`CostLedger`], **including both halves of an escalation** — the
/// cheap call as [`CallRole::Discarded`], the expensive one as
/// [`CallRole::Served`] — so "what did routing cost me over
/// always-cheap" is one lookup in the ledger's role totals, not an
/// argument. Calls are priced off the wired [`PriceSheet`]; an adapter
/// with no price there is recorded unpriced, never free.
///
/// The router's own [`AdapterId`] exists only so it can sit behind the
/// [`Classifier`] trait; the ledger is always keyed by the adapter that
/// actually answered.
pub struct RoutingClassifier {
    /// The router's own id, for the [`Classifier`] trait; recordings
    /// never use it.
    adapter: AdapterId,
    cheap: Arc<dyn Classifier>,
    expensive: Arc<dyn Classifier>,
    policy: RoutingPolicy,
    prices: PriceSheet,
    ledger: Option<Arc<dyn CostLedger>>,
}

impl RoutingClassifier {
    /// A router over a cheap and an expensive adapter, deciding by
    /// `policy`.
    #[must_use]
    pub fn new(
        adapter: AdapterId,
        cheap: Arc<dyn Classifier>,
        expensive: Arc<dyn Classifier>,
        policy: RoutingPolicy,
    ) -> Self {
        Self {
            adapter,
            cheap,
            expensive,
            policy,
            prices: PriceSheet::new(),
            ledger: None,
        }
    }

    /// Wires the price sheet calls are priced off. Without one, every
    /// recorded call is unpriced — known-unknown, not free.
    #[must_use]
    pub fn prices(mut self, prices: PriceSheet) -> Self {
        self.prices = prices;
        self
    }

    /// Wires the ledger every call is recorded to, both halves of an
    /// escalation included. Without one, calls are not recorded.
    #[must_use]
    pub fn ledger(mut self, ledger: Arc<dyn CostLedger>) -> Self {
        self.ledger = Some(ledger);
        self
    }

    /// Asks, routes, and answers — the full behaviour, and the method
    /// the [`Classifier`] impl delegates to (dropping the reason, for
    /// callers that want a classifier and not an audit).
    ///
    /// # Errors
    ///
    /// The **served** adapter's error, unchanged. In `Off` and `Pinned`
    /// modes that is the one adapter asked — a pinned adapter's error
    /// always propagates, because a pin that silently escalated would
    /// defeat the escape hatch. In `Measured` mode a cheap failure
    /// escalates, and it is the expensive adapter's error that surfaces;
    /// an escalation the expensive side fails after surfaces that error
    /// rather than falling back to a cheap answer the policy just
    /// refused. The one error the adapters did not produce:
    /// [`ClassifierError::NotConfigured`] when the policy pins an
    /// adapter the router does not hold.
    pub async fn classify_routed(&self, question: &Question) -> Result<Routed, ClassifierError> {
        let kind = &question.kind;
        let cheap_id = self.cheap.adapter();
        let expensive_id = self.expensive.adapter();
        match &self.policy.mode {
            RoutingMode::Off => {
                self.serve_direct(
                    &self.expensive,
                    expensive_id,
                    RouteReason::RoutingOff,
                    question,
                )
                .await
            }
            RoutingMode::Pinned(pinned) => {
                if pinned == cheap_id {
                    self.serve_direct(&self.cheap, cheap_id, RouteReason::Pinned, question)
                        .await
                } else if pinned == expensive_id {
                    self.serve_direct(&self.expensive, expensive_id, RouteReason::Pinned, question)
                        .await
                } else {
                    // The pin names an adapter this router does not
                    // hold. Refuse, loudly and every time: the caller
                    // asked for exactly one adapter and the router
                    // cannot produce it, which is what
                    // `NotConfigured` means — never a silent reroute
                    // to whichever adapter happens to be wired.
                    Err(ClassifierError::NotConfigured)
                }
            }
            RoutingMode::Measured => {
                let plan = self.policy.gate(kind, cheap_id, expensive_id);
                if plan.cheap_first {
                    self.cheap_first(question, cheap_id).await
                } else {
                    self.serve_direct(&self.expensive, expensive_id, plan.reason, question)
                        .await
                }
            }
        }
    }

    /// The single-call paths: `Off`, `Pinned`, and the `Measured` plans
    /// that say expensive. One adapter, one call, whatever it returns —
    /// answer or error — is what the caller gets.
    async fn serve_direct(
        &self,
        adapter: &Arc<dyn Classifier>,
        id: &AdapterId,
        reason: RouteReason,
        question: &Question,
    ) -> Result<Routed, ClassifierError> {
        let answered = adapter.classify(question).await;
        match &answered {
            Ok(classification) => {
                record_call(
                    self.ledger.as_ref(),
                    &self.prices,
                    id,
                    &question.kind,
                    Some(classification),
                    CallRole::Served,
                    CallOutcome::Ok,
                );
            }
            Err(_) => {
                record_call(
                    self.ledger.as_ref(),
                    &self.prices,
                    id,
                    &question.kind,
                    None,
                    CallRole::Served,
                    CallOutcome::Failed,
                );
            }
        }
        answered.map(|classification| {
            debug_served(&self.prices, &classification, &question.kind, reason);
            Routed {
                classification,
                reason,
            }
        })
    }

    /// The `Measured` cheap-first path: ask cheap, then serve it, or
    /// throw it away and escalate. `cheap_id` is guaranteed calibrated
    /// — the gate refuses an uncalibrated adapter before this runs.
    async fn cheap_first(
        &self,
        question: &Question,
        cheap_id: &AdapterId,
    ) -> Result<Routed, ClassifierError> {
        match self.cheap.classify(question).await {
            Ok(answer) => {
                let thresholds = self
                    .policy
                    .thresholds
                    .get(cheap_id)
                    .expect("the gate never routes cheap-first to an uncalibrated adapter");
                // A threshold is a floor: meeting it clears it. The
                // check is positive on purpose: every comparison
                // against a NaN is false, so a `confidence < min` test
                // would read a NaN answer as *not* below the floor and
                // serve it. `TextModelClassifier` clamps its
                // probabilities and cannot produce a NaN, but
                // `Classifier` is a public trait anyone may implement,
                // and a number that cannot be compared cannot clear a
                // floor.
                let clears = answer.confidence() >= thresholds.min_confidence
                    && answer.margin() >= thresholds.min_margin;
                if clears {
                    record_call(
                        self.ledger.as_ref(),
                        &self.prices,
                        cheap_id,
                        &question.kind,
                        Some(&answer),
                        CallRole::Served,
                        CallOutcome::Ok,
                    );
                    debug_served(
                        &self.prices,
                        &answer,
                        &question.kind,
                        RouteReason::CheapAccepted,
                    );
                    return Ok(Routed {
                        classification: answer,
                        reason: RouteReason::CheapAccepted,
                    });
                }
                // Which escalation reason a NaN gets is of no
                // consequence — it failed `clears` on both counts and
                // escalates either way — so the naming below keeps the
                // ordinary reading: below the confidence floor when it
                // is, a narrow margin otherwise.
                let reason = if answer.confidence() < thresholds.min_confidence {
                    RouteReason::EscalatedLowConfidence
                } else {
                    RouteReason::EscalatedNarrowMargin
                };
                record_call(
                    self.ledger.as_ref(),
                    &self.prices,
                    cheap_id,
                    &question.kind,
                    Some(&answer),
                    CallRole::Discarded,
                    CallOutcome::Ok,
                );
                self.escalate(question, reason).await
            }
            Err(cheap_error) => {
                tracing::debug!(
                    adapter = %cheap_id,
                    kind = %question.kind,
                    error = %cheap_error,
                    "the cheap adapter failed; escalating to the expensive one",
                );
                record_call(
                    self.ledger.as_ref(),
                    &self.prices,
                    cheap_id,
                    &question.kind,
                    None,
                    CallRole::Discarded,
                    CallOutcome::Failed,
                );
                self.escalate(question, RouteReason::EscalatedCheapFailed)
                    .await
            }
        }
    }

    /// Asks the expensive adapter after the cheap attempt was thrown
    /// away, and serves whatever comes back. A failed escalation
    /// surfaces the expensive error unchanged rather than falling back
    /// to the discarded cheap answer: serving an answer the policy had
    /// already refused is the one thing worse than an error.
    async fn escalate(
        &self,
        question: &Question,
        reason: RouteReason,
    ) -> Result<Routed, ClassifierError> {
        let expensive_id = self.expensive.adapter().clone();
        match self.expensive.classify(question).await {
            Ok(answer) => {
                record_call(
                    self.ledger.as_ref(),
                    &self.prices,
                    &expensive_id,
                    &question.kind,
                    Some(&answer),
                    CallRole::Served,
                    CallOutcome::Ok,
                );
                debug_served(&self.prices, &answer, &question.kind, reason);
                Ok(Routed {
                    classification: answer,
                    reason,
                })
            }
            Err(error) => {
                record_call(
                    self.ledger.as_ref(),
                    &self.prices,
                    &expensive_id,
                    &question.kind,
                    None,
                    CallRole::Served,
                    CallOutcome::Failed,
                );
                Err(error)
            }
        }
    }
}

impl fmt::Debug for RoutingClassifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoutingClassifier")
            .field("adapter", &self.adapter)
            .field("cheap", self.cheap.adapter())
            .field("expensive", self.expensive.adapter())
            .field("policy", &self.policy)
            .field("ledger", &self.ledger.is_some())
            .finish_non_exhaustive()
    }
}

/// The answer, and why it came from where it came from.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Routed {
    /// The classification the caller would have got from the adapter
    /// directly — unchanged by the routing.
    pub classification: Classification,
    /// The gate that produced this answer: which adapter was asked and
    /// why, from [`RouteReason`].
    pub reason: RouteReason,
}

#[async_trait]
impl Classifier for RoutingClassifier {
    fn adapter(&self) -> &AdapterId {
        &self.adapter
    }

    async fn classify(&self, question: &Question) -> Result<Classification, ClassifierError> {
        // The reason is the router's extra; a caller holding this
        // behind the plain trait wants the answer, unannotated.
        Ok(self.classify_routed(question).await?.classification)
    }
}

/// The measurement wrapper (issue #457): serves the **expensive**
/// adapter's answer — and its error — to the caller unchanged, and asks
/// the cheap one alongside purely to compare.
///
/// That contract is the whole point of shadow mode: it must not change
/// what callers get, so a shadow answer is never served and a shadow
/// **error is swallowed** — recorded to the ledger as
/// [`CallOutcome::Failed`], left out of the observation log, and never
/// surfaced. Shadow mode costs strictly more than not running it and
/// adds the shadow call's latency, because the two calls are
/// sequential; it is temporary, and it is the only honest way to earn
/// the switch to [`RoutingClassifier`].
///
/// Both calls are recorded to the wired [`CostLedger`] — the serve half
/// as [`CallRole::Served`], the shadow half as [`CallRole::Shadow`] —
/// and priced off the wired [`PriceSheet`]. An observation is logged
/// only when **both** adapters answered, into an
/// [`AgreementLog`] the classifier owns; read the measurement back with
/// [`Self::report`] when the window closes.
///
/// The question's text is **not** recorded by default: in production it
/// is a user's, and the agreement arithmetic counts labels, not prose.
/// Opt in with [`Self::record_question_text`] only where the text is
/// authored data.
pub struct ShadowClassifier {
    /// Serves as the expensive adapter it wraps, so this classifier can
    /// sit behind the [`Classifier`] trait under that adapter's id.
    adapter: AdapterId,
    serve: Arc<dyn Classifier>,
    shadow: Arc<dyn Classifier>,
    log: AgreementLog,
    prices: PriceSheet,
    ledger: Option<Arc<dyn CostLedger>>,
    record_question_text: bool,
}

impl ShadowClassifier {
    /// Shadows `shadow` (the cheap side) against `serve` (the
    /// expensive side the callers actually get).
    #[must_use]
    pub fn new(serve: Arc<dyn Classifier>, shadow: Arc<dyn Classifier>) -> Self {
        let log = AgreementLog::new(shadow.adapter().clone(), serve.adapter().clone());
        Self {
            adapter: serve.adapter().clone(),
            serve,
            shadow,
            log,
            prices: PriceSheet::new(),
            ledger: None,
            record_question_text: false,
        }
    }

    /// Wires the price sheet calls are priced off. Without one, every
    /// recorded call is unpriced — known-unknown, not free.
    #[must_use]
    pub fn prices(mut self, prices: PriceSheet) -> Self {
        self.prices = prices;
        self
    }

    /// Wires the ledger both calls are recorded to. Without one, calls
    /// are not recorded.
    #[must_use]
    pub fn ledger(mut self, ledger: Arc<dyn CostLedger>) -> Self {
        self.ledger = Some(ledger);
        self
    }

    /// Records the question's text on each observation. **Off by
    /// default**: in production the text is a user's, and the
    /// arithmetic never needs it. Opt in only where the text is
    /// authored data — an offline run, a rehearsal — because a
    /// disagreement you cannot read cannot be audited.
    #[must_use]
    pub fn record_question_text(mut self, record_question_text: bool) -> Self {
        self.record_question_text = record_question_text;
        self
    }

    /// The measurement so far — the evidence shadow mode exists to
    /// produce, ready to serialise, commit, and load into a
    /// [`RoutingPolicy`] when the window closes.
    #[must_use]
    pub fn report(&self) -> AgreementReport {
        self.log.report()
    }
}

impl fmt::Debug for ShadowClassifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowClassifier")
            .field("adapter", &self.adapter)
            .field("serve", self.serve.adapter())
            .field("shadow", self.shadow.adapter())
            .field("record_question_text", &self.record_question_text)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Classifier for ShadowClassifier {
    fn adapter(&self) -> &AdapterId {
        &self.adapter
    }

    /// # Errors
    ///
    /// Exactly the serve adapter's error, unchanged: shadow mode must
    /// not change what callers get, and a swallowed shadow error never
    /// surfaces from here.
    async fn classify(&self, question: &Question) -> Result<Classification, ClassifierError> {
        let kind = &question.kind;
        // The serve half first: its answer is the contract, and the
        // shadow half is the added tail of a sequential pair.
        let served = self.serve.classify(question).await;
        let shadowed = self.shadow.classify(question).await;

        match &served {
            Ok(answer) => record_call(
                self.ledger.as_ref(),
                &self.prices,
                self.serve.adapter(),
                kind,
                Some(answer),
                CallRole::Served,
                CallOutcome::Ok,
            ),
            Err(_) => record_call(
                self.ledger.as_ref(),
                &self.prices,
                self.serve.adapter(),
                kind,
                None,
                CallRole::Served,
                CallOutcome::Failed,
            ),
        }
        match &shadowed {
            Ok(answer) => record_call(
                self.ledger.as_ref(),
                &self.prices,
                self.shadow.adapter(),
                kind,
                Some(answer),
                CallRole::Shadow,
                CallOutcome::Ok,
            ),
            // Swallowed, and recorded: a shadow call can still cost
            // money, and it produces no observation to log.
            Err(_) => record_call(
                self.ledger.as_ref(),
                &self.prices,
                self.shadow.adapter(),
                kind,
                None,
                CallRole::Shadow,
                CallOutcome::Failed,
            ),
        }

        if let (Ok(served_answer), Ok(shadow_answer)) = (&served, &shadowed) {
            self.log.observe(Observation {
                kind: kind.clone(),
                cheap: self.shadow.adapter().clone(),
                cheap_label: shadow_answer.label().to_owned(),
                cheap_confidence: shadow_answer.confidence(),
                cheap_margin: shadow_answer.margin(),
                expensive: self.serve.adapter().clone(),
                expensive_label: served_answer.label().to_owned(),
                // Live production carries no gold answers; the corpus
                // run, where they exist, is `measure_agreement`.
                gold: None,
                question: self.record_question_text.then(|| question.text.clone()),
            });
        }

        served.inspect(|classification| {
            // No `RouteReason` here: shadow mode does not route, it
            // measures. The line names both adapters so whoever reads
            // it sees the comparison that ran beside the served answer.
            tracing::debug!(
                adapter = %classification.adapter,
                kind = %kind,
                shadow = %self.shadow.adapter(),
                confidence = classification.confidence(),
                margin = classification.margin(),
                cost = %cost_line(&self.prices, classification),
                "shadow mode served the serve adapter's answer",
            );
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;
    use crate::cost::{Cost, InMemoryLedger, Price};

    // -----------------------------------------------------------------
    // Fixtures: stubs that count their calls, evidence, routers

    const CHEAP: &str = "cheap";
    const EXPENSIVE: &str = "expensive";

    fn cheap_id() -> AdapterId {
        AdapterId::new(CHEAP)
    }

    fn expensive_id() -> AdapterId {
        AdapterId::new(EXPENSIVE)
    }

    /// One scripted answer: a classification with a chosen top score
    /// and runner-up (which sets the margin) and known token counts, or
    /// a scripted failure.
    enum Answer {
        Classify {
            label: &'static str,
            confidence: f32,
            runner_up: Option<(&'static str, f32)>,
            input_tokens: u64,
            output_tokens: u64,
        },
        Fail(ClassifierError),
    }

    /// A well-classified, well-separated answer: confidence 0.9, margin
    /// 0.85, on the cheap side's usual token counts. The runner-up is
    /// whichever label the top is not, so the margin is a real gap.
    fn good(label: &'static str) -> Answer {
        let other = if label == "a" { "b" } else { "a" };
        Answer::Classify {
            label,
            confidence: 0.9,
            runner_up: Some((other, 0.05)),
            input_tokens: 1_000,
            output_tokens: 100,
        }
    }

    /// The expensive side's usual answer: the same shape, at the larger
    /// token counts a strong model spends.
    fn good_expensive(label: &'static str) -> Answer {
        let other = if label == "a" { "b" } else { "a" };
        Answer::Classify {
            label,
            confidence: 0.9,
            runner_up: Some((other, 0.05)),
            input_tokens: 10_000,
            output_tokens: 1_000,
        }
    }

    fn fails(error: ClassifierError) -> Answer {
        Answer::Fail(error)
    }

    impl Answer {
        /// The same answer shape, at a different confidence — how a test
        /// scripts a low-confidence answer that still has a wide margin.
        fn at_confidence(self, confidence: f32) -> Answer {
            match self {
                Answer::Classify {
                    label,
                    runner_up,
                    input_tokens,
                    output_tokens,
                    ..
                } => Answer::Classify {
                    label,
                    confidence,
                    runner_up,
                    input_tokens,
                    output_tokens,
                },
                other @ Answer::Fail(_) => other,
            }
        }
    }

    /// A hand-written [`Classifier`] whose answers are scripted (one
    /// default, overrides per question text) and which counts its
    /// calls, so a test can see exactly who was asked.
    struct Stub {
        adapter: AdapterId,
        default: Answer,
        per_text: HashMap<String, Answer>,
        calls: AtomicUsize,
    }

    impl Stub {
        fn answering(adapter: &str, default: Answer) -> Self {
            Self {
                adapter: AdapterId::new(adapter),
                default,
                per_text: HashMap::new(),
                calls: AtomicUsize::new(0),
            }
        }

        fn on(mut self, text: &str, answer: Answer) -> Self {
            self.per_text.insert(text.to_owned(), answer);
            self
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl Classifier for Stub {
        fn adapter(&self) -> &AdapterId {
            &self.adapter
        }

        async fn classify(&self, question: &Question) -> Result<Classification, ClassifierError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let answer = self.per_text.get(&question.text).unwrap_or(&self.default);
            match answer {
                Answer::Classify {
                    label,
                    confidence,
                    runner_up,
                    input_tokens,
                    output_tokens,
                } => {
                    let mut classification =
                        Classification::new(self.adapter.clone(), "stub", *label, *confidence);
                    if let Some((other, probability)) = runner_up {
                        classification = classification.also(*other, *probability);
                    }
                    Ok(classification.usage(*input_tokens, *output_tokens))
                }
                Answer::Fail(error) => Err(error.clone()),
            }
        }
    }

    fn question(kind: &str) -> Question {
        Question::new(QuestionKind::new(kind), "Sign me up for updates")
            .label("a")
            .label("b")
    }

    /// Evidence over the standard pair for one kind: `questions`
    /// compared, `disagreements` of them answered differently. Both
    /// stubs are scripted well apart from the scripted disagreements,
    /// so a report built this way reads as a clean measurement.
    fn evidence(kind: &str, questions: u64, disagreements: u64) -> AgreementReport {
        let log = AgreementLog::new(cheap_id(), expensive_id());
        for index in 0..questions {
            let agrees = index >= disagreements;
            log.observe(Observation {
                kind: QuestionKind::new(kind),
                cheap: cheap_id(),
                cheap_label: "a".to_owned(),
                cheap_confidence: 0.9,
                cheap_margin: 0.85,
                expensive: expensive_id(),
                expensive_label: if agrees { "a" } else { "b" }.to_owned(),
                gold: None,
                question: None,
            });
        }
        log.report()
    }

    /// Evidence over the standard pair for one kind, with each answer's
    /// confidence and margin scripted: `(confidence, margin, agreed)`.
    /// The gold answers are left off — raw agreement is all the gate
    /// reads — and the confidence floors, not the labels, are what a
    /// test uses to say which answers the router would have served.
    fn calibrated_evidence(kind: &str, answers: &[(f32, f32, bool)]) -> AgreementReport {
        let log = AgreementLog::new(cheap_id(), expensive_id());
        for (confidence, margin, agrees) in answers {
            log.observe(Observation {
                kind: QuestionKind::new(kind),
                cheap: cheap_id(),
                cheap_label: "a".to_owned(),
                cheap_confidence: *confidence,
                cheap_margin: *margin,
                expensive: expensive_id(),
                expensive_label: if *agrees { "a" } else { "b" }.to_owned(),
                gold: None,
                question: None,
            });
        }
        log.report()
    }

    /// A `Measured` policy over the standard pair, with roomy gates the
    /// tests narrow: enough questions measured, disagreement under the
    /// cap, the cheap adapter calibrated at 0.8 confidence / 0.1 margin.
    fn measured_policy(evidence: AgreementReport) -> RoutingPolicy {
        RoutingPolicy::measured()
            .evidence(evidence)
            .thresholds(
                cheap_id(),
                Thresholds {
                    min_confidence: 0.8,
                    min_margin: 0.1,
                },
            )
            .min_questions(2)
            .max_disagreement_rate(0.25)
    }

    /// Prices both adapters of the standard pair and returns the costs
    /// one default stub answer books, so tests assert real money.
    fn priced_sheet() -> (PriceSheet, Cost, Cost) {
        let sheet = PriceSheet::new()
            .with(cheap_id(), Price::per_million_tokens(1_000_000, 2_000_000))
            .with(
                expensive_id(),
                Price::per_million_tokens(3_000_000, 15_000_000),
            );
        let cheap_cost = sheet.cost_of(&cheap_id(), 1_000, 100).expect("priced");
        let expensive_cost = sheet
            .cost_of(&expensive_id(), 10_000, 1_000)
            .expect("priced");
        (sheet, cheap_cost, expensive_cost)
    }

    /// A router over the standard pair with both adapters priced and
    /// the ledger wired; the stubs answer `good("a")` (cheap) and
    /// `good_expensive("b")` (expensive) unless the test scripts
    /// otherwise.
    fn router(
        policy: RoutingPolicy,
    ) -> (RoutingClassifier, Arc<Stub>, Arc<Stub>, Arc<InMemoryLedger>) {
        let cheap = Arc::new(Stub::answering(CHEAP, good("a")));
        let expensive = Arc::new(Stub::answering(EXPENSIVE, good_expensive("b")));
        let ledger = Arc::new(InMemoryLedger::new());
        let (sheet, _, _) = priced_sheet();
        let routed = RoutingClassifier::new(
            AdapterId::new("routed"),
            cheap.clone(),
            expensive.clone(),
            policy,
        )
        .prices(sheet)
        .ledger(ledger.clone());
        (routed, cheap, expensive, ledger)
    }

    // -----------------------------------------------------------------
    // The policy's table: default, Off, Pinned

    #[test]
    fn the_default_policy_is_off_and_sends_everything_to_the_expensive_adapter() {
        assert_eq!(
            RoutingPolicy::default().plan_for(&QuestionKind::new("any"), &cheap_id()),
            Plan {
                cheap_first: false,
                reason: RouteReason::RoutingOff,
            },
            "unmeasured routing is not the default anywhere"
        );
        assert_eq!(
            RoutingPolicy::off().plan_for(&QuestionKind::new("any"), &cheap_id()),
            RoutingPolicy::default().plan_for(&QuestionKind::new("any"), &cheap_id()),
            "`off()` and `default()` are the same decision"
        );
    }

    #[pollster::test]
    async fn off_mode_serves_the_expensive_adapter_and_never_calls_the_cheap_one() {
        let (routed, cheap, expensive, ledger) = router(RoutingPolicy::default());

        let answer = routed
            .classify_routed(&question("any"))
            .await
            .expect("the expensive adapter answers");

        assert_eq!(
            answer.reason,
            RouteReason::RoutingOff,
            "the answer says why it came from the expensive side"
        );
        assert_eq!(answer.classification.label(), "b");
        assert_eq!(answer.classification.adapter, expensive_id());
        assert_eq!(cheap.call_count(), 0, "nothing routes cheap while Off");
        assert_eq!(expensive.call_count(), 1);
        let records = ledger.records();
        assert_eq!(records.len(), 1, "the one call that happened is recorded");
        assert_eq!(records[0].role, CallRole::Served);
        assert_eq!(records[0].outcome, CallOutcome::Ok);
    }

    #[pollster::test]
    async fn pinned_to_the_cheap_adapter_it_serves_cheap_and_lets_its_error_through_unchanged() {
        let error = ClassifierError::Transient {
            retry_after: Some(Duration::from_secs(30)),
        };
        let (routed, cheap, expensive, _) = router(RoutingPolicy::pinned(cheap_id()));

        let served = routed
            .classify_routed(&question("any"))
            .await
            .expect("the pinned cheap adapter answers");
        assert_eq!(
            served.reason,
            RouteReason::Pinned,
            "pinning is its own reason, not an agreement verdict"
        );
        assert_eq!(expensive.call_count(), 0, "a pin never escalates");
        assert_eq!(
            cheap.call_count(),
            1,
            "the pinned cheap adapter is the only one asked"
        );

        // Now the same pin, with the cheap adapter failing: the escape
        // hatch must be exact, so the error comes out as it went in.
        let failing_cheap = Arc::new(
            Stub::answering(CHEAP, good("a")).on("Sign me up for updates", fails(error.clone())),
        );
        let expensive = Arc::new(Stub::answering(EXPENSIVE, good_expensive("b")));
        let ledger = Arc::new(InMemoryLedger::new());
        let routed = RoutingClassifier::new(
            AdapterId::new("routed"),
            failing_cheap.clone(),
            expensive.clone(),
            RoutingPolicy::pinned(cheap_id()),
        )
        .ledger(ledger.clone());
        let failing = routed.classify_routed(&question("any")).await.unwrap_err();
        assert_eq!(
            failing, error,
            "a pin that silently escalated would defeat the debugging escape hatch"
        );
        assert_eq!(
            failing_cheap.call_count(),
            1,
            "only the pinned adapter was asked"
        );
        assert_eq!(expensive.call_count(), 0);
        let records = ledger.records();
        assert_eq!(
            records.len(),
            1,
            "the failed call is recorded, and nothing after it"
        );
        assert_eq!(records[0].outcome, CallOutcome::Failed);
    }

    #[pollster::test]
    async fn pinned_to_the_expensive_adapter_it_serves_expensive_and_lets_its_error_through() {
        let error = ClassifierError::Transport("connection reset".to_owned());
        let (routed, cheap, expensive, _) = router(RoutingPolicy::pinned(expensive_id()));

        let served = routed
            .classify_routed(&question("any"))
            .await
            .expect("the pinned expensive adapter answers");
        assert_eq!(served.reason, RouteReason::Pinned);
        assert_eq!(cheap.call_count(), 0, "a pin to expensive never asks cheap");
        assert_eq!(
            expensive.call_count(),
            1,
            "the pinned expensive adapter answers"
        );

        let cheap = Arc::new(Stub::answering(CHEAP, good("a")));
        let failing_expensive = Arc::new(
            Stub::answering(EXPENSIVE, good_expensive("b"))
                .on("Sign me up for updates", fails(error.clone())),
        );
        let routed = RoutingClassifier::new(
            AdapterId::new("routed"),
            cheap.clone(),
            failing_expensive.clone(),
            RoutingPolicy::pinned(expensive_id()),
        );
        let failing = routed.classify_routed(&question("any")).await.unwrap_err();
        assert_eq!(failing, error, "the pinned adapter's error is the caller's");
        assert_eq!(cheap.call_count(), 0, "a pin never falls back to cheap");
        assert_eq!(failing_expensive.call_count(), 1);
    }

    #[pollster::test]
    async fn a_pin_to_an_adapter_the_router_does_not_hold_is_refused_not_rerouted() {
        let (routed, cheap, expensive, ledger) =
            router(RoutingPolicy::pinned(AdapterId::new("something-else")));

        let error = routed.classify_routed(&question("any")).await.unwrap_err();

        assert_eq!(
            error,
            ClassifierError::NotConfigured,
            "the router has no classifier wired for that pin, and says so"
        );
        assert_eq!(
            cheap.call_count() + expensive.call_count(),
            0,
            "refusing a pin never falls back to whichever adapter happens to be wired"
        );
        assert!(
            ledger.records().is_empty(),
            "no call happened, none recorded"
        );
    }

    // -----------------------------------------------------------------
    // The policy's table: the Measured gates

    #[pollster::test]
    async fn measured_mode_with_no_evidence_routes_expensive_and_says_no_measurement() {
        let policy = RoutingPolicy::measured();
        assert_eq!(
            policy.plan_for(&QuestionKind::new("any"), &cheap_id()),
            Plan {
                cheap_first: false,
                reason: RouteReason::NoMeasurement,
            },
            "no committed evidence: nothing measured to route on"
        );

        let (routed, cheap, expensive, _) = router(RoutingPolicy::measured());
        let answer = routed
            .classify_routed(&question("any"))
            .await
            .expect("the expensive adapter answers");
        assert_eq!(answer.reason, RouteReason::NoMeasurement);
        assert_eq!(cheap.call_count(), 0);
        assert_eq!(expensive.call_count(), 1);
    }

    #[pollster::test]
    async fn a_kind_the_measurement_never_saw_routes_expensive_while_a_measured_kind_routes_cheap()
    {
        let policy = measured_policy(evidence("email_intent", 4, 0));
        let (routed, cheap, expensive, _) = router(policy);

        let measured = routed
            .classify_routed(&question("email_intent"))
            .await
            .expect("the measured kind has evidence");
        assert_eq!(
            measured.reason,
            RouteReason::CheapAccepted,
            "evidence for this kind, and the cheap adapter is calibrated"
        );
        assert_eq!(cheap.call_count(), 1);
        assert_eq!(expensive.call_count(), 0);

        let unmeasured = routed
            .classify_routed(&question("support_topic"))
            .await
            .expect("the expensive adapter answers the unmeasured kind");
        assert_eq!(
            unmeasured.reason,
            RouteReason::NoMeasurement,
            "reliable on one kind is not reliable on the next"
        );
        assert_eq!(
            cheap.call_count(),
            1,
            "the unmeasured kind never reached the cheap adapter"
        );
        assert_eq!(expensive.call_count(), 1);
    }

    #[test]
    fn evidence_on_fewer_questions_than_the_policy_requires_is_not_measured_enough() {
        let policy = measured_policy(evidence("email_intent", 1, 0)).min_questions(2);
        assert_eq!(
            policy.plan_for(&QuestionKind::new("email_intent"), &cheap_id()),
            Plan {
                cheap_first: false,
                reason: RouteReason::NotMeasuredEnough,
            },
            "one question is a rumour, not a rate"
        );
    }

    #[test]
    fn evidence_disagreeing_more_than_the_policy_allows_is_disagreement_too_high() {
        // Two disagreements in four: a rate of 0.5, over the 0.25 cap.
        let policy = measured_policy(evidence("email_intent", 4, 2));
        assert_eq!(
            policy.plan_for(&QuestionKind::new("email_intent"), &cheap_id()),
            Plan {
                cheap_first: false,
                reason: RouteReason::DisagreementTooHigh,
            },
            "the adapters differ too often on this kind"
        );
    }

    #[test]
    fn a_disagreement_rate_exactly_at_the_cap_still_routes_cheap_for_the_cap_is_a_ceiling() {
        // One disagreement in four: exactly the 0.25 cap, so it passes.
        let policy = measured_policy(evidence("email_intent", 4, 1));
        assert_eq!(
            policy
                .plan_for(&QuestionKind::new("email_intent"), &cheap_id())
                .reason,
            RouteReason::CheapAccepted,
            "only going above `max_disagreement_rate` refuses"
        );
    }

    #[test]
    fn a_nan_cap_refuses_rather_than_routes_cheap_for_a_comparison_against_nan_is_never_true() {
        // `f64::NAN > rate` is false, so a `rate > cap` gate would
        // wave every kind through to cheap-first on a cap that cannot
        // be compared. The gate is positive — cheap only when the
        // rate provably sits within the cap — so a NaN cap refuses,
        // the same way a NaN answer cannot clear a floor.
        let policy =
            measured_policy(evidence("email_intent", 4, 0)).max_disagreement_rate(f64::NAN);
        assert_eq!(
            policy.plan_for(&QuestionKind::new("email_intent"), &cheap_id()),
            Plan {
                cheap_first: false,
                reason: RouteReason::DisagreementTooHigh,
            },
            "a cap that cannot be compared cannot be sat within: refuse, never allow"
        );
    }

    #[test]
    fn the_gate_measures_at_the_floors_so_a_kind_whose_sure_answers_agree_routes_cheap() {
        // Two sure answers agreeing, two unsure answers disagreeing.
        // The whole-kind rate is 0.5 — double the 0.25 cap — and a
        // gate that capped the whole-kind average would refuse the
        // kind for it. The rate that decides is over the answers the
        // floors would actually serve, and both of those agree.
        let report = calibrated_evidence(
            "email_intent",
            &[
                (0.9, 0.85, true),
                (0.9, 0.85, true),
                (0.3, 0.05, false),
                (0.3, 0.05, false),
            ],
        );
        let whole = report
            .kind(&QuestionKind::new("email_intent"))
            .expect("measured")
            .disagreement_rate()
            .expect("measured");
        assert!(
            (whole - 0.5).abs() < 1e-9,
            "the fixture's whole-kind rate really is over the cap: {whole}"
        );
        let policy = measured_policy(report);
        assert_eq!(
            policy.plan_for(&QuestionKind::new("email_intent"), &cheap_id()),
            Plan {
                cheap_first: true,
                reason: RouteReason::CheapAccepted,
            },
            "the sure answers — the only ones the floors would serve — agree: \
             the kind routes cheap despite its poor whole-kind average"
        );
    }

    #[test]
    fn too_few_answers_clearing_the_floors_is_not_measured_enough_even_when_they_all_agree() {
        // Four answers compared, so the whole kind clears
        // `min_questions(2)` — but only one of them clears the floors,
        // and one answer is a rumour of a rate wherever it is measured.
        let report = calibrated_evidence(
            "email_intent",
            &[
                (0.9, 0.85, true),
                (0.3, 0.05, true),
                (0.3, 0.05, false),
                (0.3, 0.05, false),
            ],
        );
        let policy = measured_policy(report);
        assert_eq!(
            policy
                .plan_for(&QuestionKind::new("email_intent"), &cheap_id())
                .reason,
            RouteReason::NotMeasuredEnough,
            "`min_questions` applies to the answers the floors would serve, \
             not to the kind's whole count"
        );
    }

    #[test]
    fn a_kind_where_no_answer_clears_the_floors_is_not_measured_enough() {
        let report = calibrated_evidence("email_intent", &[(0.3, 0.05, true), (0.3, 0.05, false)]);
        let policy = measured_policy(report);
        assert_eq!(
            policy
                .plan_for(&QuestionKind::new("email_intent"), &cheap_id())
                .reason,
            RouteReason::NotMeasuredEnough,
            "a floor nothing clears has no measured agreement, not a free pass"
        );
    }

    #[pollster::test]
    async fn a_cheap_adapter_without_its_own_thresholds_is_never_preferred_even_on_perfect_evidence()
     {
        // The issue's central trap: flawless evidence, and no
        // calibration for the cheap adapter. The 0.9 confidence the
        // stub reports is a number from *this* stub; without a
        // threshold calibrated for the adapter, the router has no idea
        // what that number means, and refuses.
        let policy = RoutingPolicy::measured()
            .evidence(evidence("email_intent", 10, 0))
            .min_questions(2)
            .max_disagreement_rate(0.25);
        assert_eq!(
            policy.plan_for(&QuestionKind::new("email_intent"), &cheap_id()),
            Plan {
                cheap_first: false,
                reason: RouteReason::NoCalibration,
            },
            "no thresholds for the adapter, no cheap route — however perfect the evidence"
        );

        let (routed, cheap, expensive, _) = router(policy);
        let answer = routed
            .classify_routed(&question("email_intent"))
            .await
            .expect("the expensive adapter answers");
        assert_eq!(answer.reason, RouteReason::NoCalibration);
        assert_eq!(
            cheap.call_count(),
            0,
            "the uncalibrated adapter is never asked, let alone served"
        );
        assert_eq!(expensive.call_count(), 1);
    }

    #[test]
    fn evidence_about_a_different_cheap_adapter_is_refused_as_about_other_adapters() {
        let policy = measured_policy(evidence("email_intent", 4, 0));
        assert_eq!(
            policy.plan_for(
                &QuestionKind::new("email_intent"),
                &AdapterId::new("other-cheap")
            ),
            Plan {
                cheap_first: false,
                reason: RouteReason::EvidenceIsAboutOtherAdapters,
            },
            "a report about another pair is not evidence about this one"
        );
    }

    #[pollster::test]
    async fn evidence_about_a_different_expensive_adapter_is_refused_by_the_router() {
        // The report names (cheap, expensive); this router holds
        // (cheap, something-else). `plan_for` cannot see that — it
        // borrows the report's own expensive side — and the router can.
        let third = Arc::new(Stub::answering("third", good("a")));
        let ledger = Arc::new(InMemoryLedger::new());
        let routed = RoutingClassifier::new(
            AdapterId::new("routed"),
            Arc::new(Stub::answering(CHEAP, good("a"))),
            third.clone(),
            measured_policy(evidence("email_intent", 4, 0)),
        )
        .ledger(ledger.clone());

        let answer = routed
            .classify_routed(&question("email_intent"))
            .await
            .expect("the router's own expensive adapter answers");
        assert_eq!(
            answer.reason,
            RouteReason::EvidenceIsAboutOtherAdapters,
            "refused wholesale, not mined for the kinds that look usable"
        );
        assert_eq!(third.call_count(), 1, "the refusal routes expensive");
    }

    // -----------------------------------------------------------------
    // The Measured cheap-first path: accept, escalate, fail over

    #[pollster::test]
    async fn a_cheap_answer_that_clears_both_thresholds_is_served_as_cheap_accepted() {
        let (routed, cheap, expensive, ledger) = router(measured_policy(evidence("k", 4, 0)));

        let answer = routed
            .classify_routed(&question("k"))
            .await
            .expect("the cheap answer clears 0.8 confidence and 0.1 margin");

        assert_eq!(answer.reason, RouteReason::CheapAccepted);
        assert_eq!(answer.classification.label(), "a");
        assert_eq!(answer.classification.adapter, cheap_id());
        assert_eq!(cheap.call_count(), 1);
        assert_eq!(
            expensive.call_count(),
            0,
            "an accepted cheap answer costs one call"
        );
        let records = ledger.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].role, CallRole::Served);
        assert_eq!(records[0].adapter, cheap_id());
    }

    #[pollster::test]
    async fn meeting_the_thresholds_exactly_clears_them_for_they_are_floors() {
        // 0.75 and 0.6875 are exact in binary floating point, so the
        // margin is exactly 0.0625 and the comparison measures the
        // threshold, not rounding.
        let policy = measured_policy(evidence("k", 4, 0)).thresholds(
            cheap_id(),
            Thresholds {
                min_confidence: 0.75,
                min_margin: 0.0625,
            },
        );
        let cheap = Arc::new(Stub::answering(CHEAP, good("a")).on(
            "Sign me up for updates",
            Answer::Classify {
                label: "a",
                confidence: 0.75,
                runner_up: Some(("b", 0.6875)),
                input_tokens: 1_000,
                output_tokens: 100,
            },
        ));
        let expensive = Arc::new(Stub::answering(EXPENSIVE, good("b")));
        let routed = RoutingClassifier::new(
            AdapterId::new("routed"),
            cheap.clone(),
            expensive.clone(),
            policy,
        );

        let answer = routed
            .classify_routed(&question("k"))
            .await
            .expect("meeting both floors exactly is clearing them");

        assert_eq!(
            answer.reason,
            RouteReason::CheapAccepted,
            "a threshold is a floor, not a wall to stand short of"
        );
        assert_eq!(expensive.call_count(), 0);
    }

    #[pollster::test]
    async fn a_cheap_answer_below_min_confidence_is_discarded_and_the_expensive_answer_served() {
        let cheap = Arc::new(
            Stub::answering(CHEAP, good("a"))
                .on("Sign me up for updates", good("a").at_confidence(0.5)),
        );
        let expensive = Arc::new(Stub::answering(EXPENSIVE, good("b")));
        let ledger = Arc::new(InMemoryLedger::new());
        let routed = RoutingClassifier::new(
            AdapterId::new("routed"),
            cheap.clone(),
            expensive.clone(),
            measured_policy(evidence("k", 4, 0)),
        )
        .ledger(ledger.clone());

        let answer = routed
            .classify_routed(&question("k"))
            .await
            .expect("the expensive adapter bails the low-confidence cheap answer out");

        assert_eq!(
            answer.reason,
            RouteReason::EscalatedLowConfidence,
            "the answer said so itself: below its own confidence floor"
        );
        assert_eq!(
            answer.classification.label(),
            "b",
            "the caller gets the expensive adapter's answer"
        );
        assert_eq!(answer.classification.adapter, expensive_id());
        assert_eq!(cheap.call_count(), 1);
        assert_eq!(expensive.call_count(), 1);

        let records = ledger.records();
        assert_eq!(records.len(), 2, "an escalation pays twice, visibly");
        assert_eq!(records[0].adapter, cheap_id());
        assert_eq!(
            records[0].role,
            CallRole::Discarded,
            "the cheap answer was paid for and thrown away"
        );
        assert_eq!(records[0].outcome, CallOutcome::Ok);
        assert_eq!(records[1].adapter, expensive_id());
        assert_eq!(records[1].role, CallRole::Served);
    }

    #[pollster::test]
    async fn a_cheap_answer_with_a_narrow_margin_is_discarded_and_the_expensive_answer_served() {
        // Confidence clears 0.8; the margin (0.9 - 0.85) does not clear
        // 0.1. A near-tie is a coin flip wearing a label.
        let cheap = Arc::new(Stub::answering(CHEAP, good("a")).on(
            "Sign me up for updates",
            Answer::Classify {
                label: "a",
                confidence: 0.9,
                runner_up: Some(("b", 0.85)),
                input_tokens: 1_000,
                output_tokens: 100,
            },
        ));
        let expensive = Arc::new(Stub::answering(EXPENSIVE, good("b")));
        let routed = RoutingClassifier::new(
            AdapterId::new("routed"),
            cheap,
            expensive.clone(),
            measured_policy(evidence("k", 4, 0)),
        );

        let answer = routed
            .classify_routed(&question("k"))
            .await
            .expect("the expensive adapter settles the near-tie");

        assert_eq!(
            answer.reason,
            RouteReason::EscalatedNarrowMargin,
            "confident enough, but not decisively ahead"
        );
        assert_eq!(answer.classification.adapter, expensive_id());
    }

    #[pollster::test]
    async fn a_nan_answer_never_reads_as_clearing_the_floors_so_it_escalates() {
        // `Classifier` is a public trait anyone may implement, and
        // every comparison against a NaN is false — so the floor check
        // must be positive (`>=`), or a NaN confidence and margin would
        // both read as "not below the floor" and the answer would be
        // served. This stub is exactly such an implementation.
        let cheap = Arc::new(Stub::answering(CHEAP, good("a")).on(
            "Sign me up for updates",
            Answer::Classify {
                label: "a",
                confidence: f32::NAN,
                runner_up: Some(("b", 0.05)),
                input_tokens: 1_000,
                output_tokens: 100,
            },
        ));
        let expensive = Arc::new(Stub::answering(EXPENSIVE, good("b")));
        let ledger = Arc::new(InMemoryLedger::new());
        let routed = RoutingClassifier::new(
            AdapterId::new("routed"),
            cheap.clone(),
            expensive.clone(),
            measured_policy(evidence("k", 4, 0)),
        )
        .ledger(ledger.clone());

        let answer = routed
            .classify_routed(&question("k"))
            .await
            .expect("a NaN answer is discarded, not surfaced as a failure");

        assert_eq!(cheap.call_count(), 1, "the cheap adapter was asked");
        assert_eq!(
            expensive.call_count(),
            1,
            "and the expensive adapter was asked instead"
        );
        assert_eq!(
            answer.classification.adapter,
            expensive_id(),
            "the caller got the expensive answer, never the NaN"
        );
        assert!(
            matches!(
                answer.reason,
                RouteReason::EscalatedLowConfidence | RouteReason::EscalatedNarrowMargin
            ),
            "a number that cannot be compared cannot clear a floor, so the \
             answer escalated: {:?}",
            answer.reason
        );
    }

    #[pollster::test]
    async fn a_cheap_error_is_recorded_not_surfaced_and_the_expensive_answer_is_served() {
        let cheap = Arc::new(Stub::answering(CHEAP, good("a")).on(
            "Sign me up for updates",
            fails(ClassifierError::Transport("cheap side died".to_owned())),
        ));
        let expensive = Arc::new(Stub::answering(EXPENSIVE, good("b")));
        let ledger = Arc::new(InMemoryLedger::new());
        let routed = RoutingClassifier::new(
            AdapterId::new("routed"),
            cheap.clone(),
            expensive.clone(),
            measured_policy(evidence("k", 4, 0)),
        )
        .ledger(ledger.clone());

        let answer = routed
            .classify_routed(&question("k"))
            .await
            .expect("a cheap failure escalates instead of failing the caller");

        assert_eq!(
            answer.reason,
            RouteReason::EscalatedCheapFailed,
            "a router that failed closed on the cheap adapter would make \
             the cheap adapter's reliability the whole system's"
        );
        assert_eq!(answer.classification.label(), "b");
        assert_eq!(cheap.call_count(), 1);
        assert_eq!(expensive.call_count(), 1);

        let records = ledger.records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].adapter, cheap_id());
        assert_eq!(records[0].outcome, CallOutcome::Failed);
        assert_eq!(
            records[0].role,
            CallRole::Discarded,
            "its answer — had there been one — was never going to be served"
        );
        assert_eq!(records[1].role, CallRole::Served);
        assert_eq!(records[1].outcome, CallOutcome::Ok);
    }

    #[pollster::test]
    async fn an_escalation_ending_in_an_expensive_error_surfaces_that_error_unchanged() {
        let error = ClassifierError::Rejected("provider 422".to_owned());
        let cheap = Arc::new(
            Stub::answering(CHEAP, good("a"))
                .on("Sign me up for updates", good("a").at_confidence(0.5)),
        );
        let expensive = Arc::new(
            Stub::answering(EXPENSIVE, good("b"))
                .on("Sign me up for updates", fails(error.clone())),
        );
        let ledger = Arc::new(InMemoryLedger::new());
        let routed = RoutingClassifier::new(
            AdapterId::new("routed"),
            cheap,
            expensive,
            measured_policy(evidence("k", 4, 0)),
        )
        .ledger(ledger.clone());

        let failed = routed.classify_routed(&question("k")).await.unwrap_err();

        assert_eq!(
            failed, error,
            "falling back to a cheap answer the policy just refused would \
             be the one thing worse than an error"
        );
        let records = ledger.records();
        assert_eq!(
            records.len(),
            2,
            "both halves happened and both are recorded"
        );
        assert_eq!(records[0].role, CallRole::Discarded);
        assert_eq!(records[0].outcome, CallOutcome::Ok);
        assert_eq!(records[1].role, CallRole::Served);
        assert_eq!(records[1].outcome, CallOutcome::Failed);
    }

    #[pollster::test]
    async fn the_ledger_records_both_halves_of_an_escalation_with_their_costs() {
        let (sheet, cheap_cost, expensive_cost) = priced_sheet();
        let cheap = Arc::new(
            Stub::answering(CHEAP, good("a"))
                .on("Sign me up for updates", good("a").at_confidence(0.5)),
        );
        let expensive = Arc::new(Stub::answering(EXPENSIVE, good_expensive("b")));
        let ledger = Arc::new(InMemoryLedger::new());
        let routed = RoutingClassifier::new(
            AdapterId::new("routed"),
            cheap,
            expensive,
            measured_policy(evidence("k", 4, 0)),
        )
        .prices(sheet)
        .ledger(ledger.clone());

        routed
            .classify_routed(&question("k"))
            .await
            .expect("the escalation serves the expensive answer");

        let records = ledger.records();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].cost,
            Some(cheap_cost),
            "the discarded cheap half is priced for what it spent"
        );
        assert_eq!(
            records[1].cost,
            Some(expensive_cost),
            "the served expensive half is priced for what it spent"
        );

        // And the role totals answer "what did routing cost me over
        // always-cheap" in one lookup: the Discarded row is what the
        // escalation paid for nothing.
        let roles = ledger.role_totals();
        assert_eq!(roles[&CallRole::Discarded].calls, 1);
        assert_eq!(
            roles[&CallRole::Discarded].pico_usd,
            u128::from(cheap_cost.pico_usd())
        );
        assert_eq!(roles[&CallRole::Served].calls, 1);
        assert_eq!(
            roles[&CallRole::Served].pico_usd,
            u128::from(expensive_cost.pico_usd())
        );
    }

    #[pollster::test]
    async fn a_cheap_call_with_no_price_on_the_sheet_is_recorded_unpriced_not_free() {
        // Only the expensive side is priced. The cheap adapter's
        // recorded call must read as unknown, never as zero — a
        // cheap-vs-expensive argument built on a silently-zero cost is
        // the mistake this accounting exists to prevent.
        let sheet = PriceSheet::new().with(
            expensive_id(),
            Price::per_million_tokens(3_000_000, 15_000_000),
        );
        let cheap = Arc::new(Stub::answering(CHEAP, good("a")));
        let expensive = Arc::new(Stub::answering(EXPENSIVE, good("b")));
        let ledger = Arc::new(InMemoryLedger::new());
        let routed = RoutingClassifier::new(
            AdapterId::new("routed"),
            cheap,
            expensive,
            measured_policy(evidence("k", 4, 0)),
        )
        .prices(sheet)
        .ledger(ledger.clone());

        routed
            .classify_routed(&question("k"))
            .await
            .expect("the cheap answer is served");

        let records = ledger.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].adapter, cheap_id());
        assert_eq!(
            records[0].cost, None,
            "unpriced: the call happened, the money is just not known"
        );
        let totals = &ledger.totals()[&cheap_id()];
        assert_eq!(
            totals.unpriced_calls, 1,
            "the gap is counted, not folded into a zero"
        );
        assert_eq!(totals.pico_usd, 0);
        assert_eq!(totals.calls, 1, "and the call still happened");
    }

    // -----------------------------------------------------------------
    // Shadow mode

    fn shadow_pair() -> (ShadowClassifier, Arc<Stub>, Arc<Stub>, Arc<InMemoryLedger>) {
        let serve = Arc::new(Stub::answering(EXPENSIVE, good("b")));
        let shadow = Arc::new(Stub::answering(CHEAP, good("a")));
        let ledger = Arc::new(InMemoryLedger::new());
        let (sheet, _, _) = priced_sheet();
        let shadowed = ShadowClassifier::new(serve.clone(), shadow.clone())
            .prices(sheet)
            .ledger(ledger.clone());
        (shadowed, serve, shadow, ledger)
    }

    #[pollster::test]
    async fn shadow_mode_serves_the_expensive_answer_and_records_both_calls_and_one_observation() {
        let (shadowed, serve, shadow, ledger) = shadow_pair();

        let answer = shadowed
            .classify(&question("k"))
            .await
            .expect("the serve adapter answers");

        assert_eq!(
            answer.label(),
            "b",
            "the caller gets the serve adapter's answer, not the shadow's"
        );
        assert_eq!(answer.adapter, expensive_id());
        assert_eq!(serve.call_count(), 1);
        assert_eq!(shadow.call_count(), 1);

        let records = ledger.records();
        assert_eq!(records.len(), 2, "both calls happened, both are recorded");
        assert_eq!(records[0].adapter, expensive_id());
        assert_eq!(records[0].role, CallRole::Served);
        assert_eq!(records[0].outcome, CallOutcome::Ok);
        assert_eq!(records[1].adapter, cheap_id());
        assert_eq!(records[1].role, CallRole::Shadow);

        let report = shadowed.report();
        let entry = report
            .kind(&QuestionKind::new("k"))
            .expect("both answered, so an observation was logged");
        assert_eq!(entry.questions, 1);
        assert_eq!(
            entry.agreed, 0,
            "the stubs were scripted to differ: that is the comparison"
        );
        assert_eq!(entry.disagreements[0].cheap_label, "a");
        assert_eq!(entry.disagreements[0].expensive_label, "b");
    }

    #[pollster::test]
    async fn a_shadow_error_is_swallowed_recorded_and_never_reaches_the_caller() {
        let shadow = Arc::new(Stub::answering(CHEAP, good("a")).on(
            "Sign me up for updates",
            fails(ClassifierError::Transport("shadow died".to_owned())),
        ));
        let serve = Arc::new(Stub::answering(EXPENSIVE, good("b")));
        let ledger = Arc::new(InMemoryLedger::new());
        let (sheet, _, _) = priced_sheet();
        let shadowed = ShadowClassifier::new(serve.clone(), shadow.clone())
            .prices(sheet)
            .ledger(ledger.clone());

        let answer = shadowed
            .classify(&question("k"))
            .await
            .expect("a swallowed shadow error never surfaces; the serve answer is the contract");

        assert_eq!(
            answer.label(),
            "b",
            "the caller cannot tell the shadow failed"
        );
        assert_eq!(shadow.call_count(), 1, "the shadow was asked");

        let records = ledger.records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].adapter, cheap_id());
        assert_eq!(records[1].role, CallRole::Shadow);
        assert_eq!(
            records[1].outcome,
            CallOutcome::Failed,
            "a shadow call can still cost money, and is recorded as failed"
        );
        assert!(
            shadowed.report().kind(&QuestionKind::new("k")).is_none(),
            "no doubly-answered comparison, no observation"
        );
    }

    #[pollster::test]
    async fn a_serve_error_reaches_the_caller_unchanged_and_produces_no_observation() {
        let error = ClassifierError::Transient {
            retry_after: Some(Duration::from_secs(5)),
        };
        let serve = Arc::new(
            Stub::answering(EXPENSIVE, good("b"))
                .on("Sign me up for updates", fails(error.clone())),
        );
        let shadow = Arc::new(Stub::answering(CHEAP, good("a")));
        let ledger = Arc::new(InMemoryLedger::new());
        let shadowed = ShadowClassifier::new(serve.clone(), shadow.clone()).ledger(ledger.clone());

        let failed = shadowed.classify(&question("k")).await.unwrap_err();

        assert_eq!(
            failed, error,
            "the serve adapter's error is what the caller gets, unchanged"
        );
        assert_eq!(
            shadow.call_count(),
            1,
            "the shadow half is still asked and still recorded"
        );
        let records = ledger.records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].role, CallRole::Served);
        assert_eq!(records[0].outcome, CallOutcome::Failed);
        assert_eq!(records[1].role, CallRole::Shadow);
        assert_eq!(records[1].outcome, CallOutcome::Ok);
        assert!(
            shadowed.report().kind(&QuestionKind::new("k")).is_none(),
            "no serve answer, no comparison, no observation"
        );
    }

    #[pollster::test]
    async fn shadow_mode_omits_the_question_text_by_default_and_records_it_when_opted_in() {
        let serve = Arc::new(Stub::answering(EXPENSIVE, good("b")));
        let shadow = Arc::new(Stub::answering(CHEAP, good("a")));
        let off = ShadowClassifier::new(serve.clone(), shadow.clone());
        off.classify(&question("k")).await.expect("serves");
        let off_report = off.report();
        let entry = off_report
            .kind(&QuestionKind::new("k"))
            .expect("the observation was logged");
        assert_eq!(
            entry.disagreements[0].question, None,
            "default: the text is a user's and stays out of the log"
        );

        let on = ShadowClassifier::new(serve, shadow).record_question_text(true);
        on.classify(&question("k")).await.expect("serves");
        let on_report = on.report();
        let entry = on_report
            .kind(&QuestionKind::new("k"))
            .expect("the observation was logged");
        assert_eq!(
            entry.disagreements[0].question.as_deref(),
            Some("Sign me up for updates"),
            "opted in: the disagreement can be read"
        );
    }
}
