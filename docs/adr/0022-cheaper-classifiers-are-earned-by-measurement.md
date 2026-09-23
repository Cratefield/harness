# ADR 0022: Cheaper classifiers are earned by measurement

Status: accepted, 2026-09-23. Issue #457. Records how a venture moves
questions from an expensive classifier to a cheap one, and why nothing
moves until the venture has measured that the cheap answer is the same
answer.

## Context

The [`Classifier` port](../CLASSIFIER.md) lets a venture swap a frontier
language model for a small trained classifier behind the same trait. The
argument for doing so is always the same: the strong model is
over-qualified for most of its questions. Before this ADR the argument
could not be made honestly. Nothing priced a classifier call, so
"cheaper" had no ledger behind it, and nothing compared answers, so "as
good" had no measurement behind it. Confidence did not help. The port
already says `Answer::confidence` is not comparable across adapters: a
`0.8` a classifier computes and a `0.8` a language model reports are
different claims, so any rule of the form "trust whichever adapter is
more confident" is wrong for at least one of them.

ADR 0019 fixed the discipline for performance changes: a change is
admitted by a number, not by an argument. This ADR applies it to money
and answer quality, where it matters more. A latency regression can be
reverted. A routing switch that was never measured has already served its
wrong labels by the time anyone looks.

## Decision

**Nothing routes cheap by default.** `RoutingPolicy::default()` sends
every question to the expensive adapter. `RoutingMode::Pinned` sends every
question to one named adapter. Neither consults evidence, and both are the
escape hatch when evidence is in doubt.

**Evidence is per kind of question.** A kind is the question's id in the
map `Classifier::ask` takes. `measure_agreement` (on a labelled corpus)
and `ShadowClassifier` (on live traffic, serving the expensive answers
unchanged) build an `AgreementReport` per kind. Agreement is defined for
each `AnswerValue`, and a `Score` agrees on the same whole level after
rounding, so it is an equivalence. The report also records which adapter
matched the ground truth when the two disagreed.

**The router trusts a kind only on evidence at its own thresholds.**
Under `RoutingMode::Measured`, a kind goes to the cheap adapter only if
the report names this router's two adapters, and if enough measured
answers clear the cheap adapter's `Thresholds` with a disagreement rate
at or under the cap. Any cheap answer that falls below the confidence or
margin floor on the live call escalates. So does a cheap failure. All
escalations go to the expensive adapter in one second `ask`. Every answer
comes back with a `RouteReason`, so a caller can see who answered and
why.

**Thresholds are per adapter and name their calibration.**
`RoutingClassifier::new` refuses thresholds whose declared `Calibration`
is not what the adapter's `profile()` reports. It also refuses thresholds
or a pin naming an adapter the router does not hold, and evidence about
another pair of adapters. A policy that cannot mean what it says is
refused when it is wired, not discovered when a question is asked.

**Every call is accounted, and the tokens are estimates.** The
wrappers and the corpus runner take an `Accounting`, a `PriceSheet` plus
a `CostLedger`, as a required argument, so no call through them goes
unrecorded. The port carries no usage, so a `CallRecord` holds tokens
estimated at four characters per token over what was sent and what came
back, tagged `TokenSource::Estimated`. Money is integer pico-USD. An
unpriced adapter is unknown rather than free. The ledger's `record` is
synchronous and cannot fail, so recording a decision cannot break it.

## Rejected

- **One threshold across adapters.** It compares numbers the port says
  are not comparable.
- **Cheap by default, with escalation on low confidence.** Confidence is
  exactly the number that is uncalibrated before measurement. Under this
  rule a confidently wrong cheap adapter would never escalate.
- **Averaging agreement across kinds, or over all answers.** A good
  average over easy kinds hides a bad kind. An average over every answer
  includes answers the router would have escalated, so it does not
  measure the answers it actually serves.
- **Asking providers for real token counts.** That would change the
  port's public API, which this issue does not do. `TokenSource` is
  `#[non_exhaustive]` so a reported count can be added later.
- **Floating-point money.** Totals must add up exactly, and they must
  saturate instead of wrapping.

## Consequences

A venture that wants the cheaper adapter first runs `ShadowClassifier`
or commits a corpus and a report. It tunes thresholds for the cheap
adapter's calibration, and then switches to `RoutingMode::Measured`. The
ledger's `role_totals` shows what serving, measuring and wasted
escalation each cost. The estimate is fair between adapters asked the
same questions, but it is not a bill. Replacing an adapter invalidates
its thresholds, and the router refuses them if the calibration changed.

## References

- [docs/CLASSIFIER-ROUTING.md](../CLASSIFIER-ROUTING.md): how to wire,
  measure and read the report.
- [docs/CLASSIFIER.md](../CLASSIFIER.md): the port, and why confidence is
  per adapter.
- ADR 0019: a change is admitted by a measurement.
- `crates/core/src/cost.rs`, `crates/core/src/classifier_agreement.rs`
  and `crates/core/src/classifier_routing.rs`.
