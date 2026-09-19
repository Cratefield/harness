# ADR 0021: Cheaper classifiers are earned by measurement

Status: accepted, 2026-09-19. Issue #457. Records the accounting, the
measurement gate and the escape hatches around cost-aware classifier
routing — and why nothing routes cheap until a venture runs the
measurement.

## Context

The harness's model calls were unaccounted and unmeasured. The `TextModel`
port's `Completion` carried the token counts the provider reported and
nothing totalled them; no price existed anywhere in the tree; and the
argument every venture eventually wants to make — the strong model is
over-qualified for most of its questions, and a cheaper classifier could
answer them — could not even be posed honestly, because both halves of it
were unverifiable. "Cheaper" was a claim with no ledger to make it to, and
"as good" was a claim with no measurement behind it at all. The confidence
numbers made it worse rather than better: a `0.8` a classifier computes
and a `0.8` an LLM types into a JSON field are different claims about the
world, so any single-threshold shortcut between adapters silently lies
while wearing the vocabulary of measurement.

A sibling effort, issue #456, is adding the classifier port itself — the
`Port::Classifier` variant, the runtime wiring, the testing fake. This
issue is deliberately not that: it is the accounting, the shadow mode, the
agreement measurement and the gate around *any* classifier, composed
explicitly by the venture, and it never touches `crates/core/src/ports/`
so the two efforts cannot collide.

The discipline this ADR applies is the one ADR 0019 fixed for
performance: a change is admitted by a number, not by an argument. The
difference is the currency. ADR 0019's gate protects latency; this one
protects both money and answer quality, and its conservative direction is
stronger — an unmeasured latency change can be reverted, while an
unmeasured routing switch has already served its wrong labels to callers
by the time anyone looks.

## Decision

**Cost accounting lands in core as value types and a sink trait, not a
registered port.** `Price`, `Cost`, `PriceSheet` and `CostLedger`
(`crates/core/src/cost.rs`) are plain value types and one
deliberately-sync, infallibly-`record` sink, wired explicitly by whatever
composes the router. ADR 0002 puts every vendor integration behind an
adapter crate and a port trait, and the classifier adapters themselves
are exactly that shape — but the ledger is not vendor wiring: it is the
instrument that judges the vendors, so it belongs beside the types it
prices. Its interior mutability is the recording cell, handed to a
constructor as an explicitly-wired `Arc`, not ambient request state, which
is what ADR 0007 requires; a `Mutex` behind a scoped allow is the same
treatment `InMemoryLedger`'s neighbours get. `record` cannot fail and
cannot add a network hop, because recording what a decision cost must
never be able to fail the decision.

**Money is an integer, and a missing price is unknown rather than free.**
`Cost` is pico-USD — `u64`, saturating, never `f64` — and `Price` is
pico-USD per token, chosen so a vendor's `$X.YZ per million tokens` in
micro-USD is numerically the same integer and the pricing page pastes in
unchanged. An adapter with no entry on the sheet prices as `None`, never
`Cost(0)`: an unpriced call is a call whose cost nobody wrote down, and a
cheap-vs-expensive argument built on a silently-zero cost is precisely the
mistake this issue exists to prevent. Totals count `unpriced_calls`
beside the sum, so a total is never mistaken for complete.

**Routing to the cheap adapter is gated on measured evidence, per
question kind, and the shipped default is off.** `RoutingPolicy` routes
cheap for a kind only when a committed `AgreementReport` names exactly the
pair of adapters the router holds, the kind was measured, the cheap
adapter carries thresholds calibrated for it, enough answers clear both
of those floors, and the disagreement over just those clearing answers
sits under the policy's cap. Miss any one and the expensive adapter
answers, with a `RouteReason` naming the gate.
`RoutingPolicy::default()` is `Off`: unmeasured routing is not the default
anywhere, so nothing routes cheap until somebody runs the measurement —
the conservative shipped state, and the same gate-as-decision shape as
ADR 0019, applied to spend. The evidence is per kind because a classifier
reliable on one kind of question is not therefore reliable on the next,
and an average over kinds is exactly the number that hides that. For the
same reason the disagreement rate is measured over the answers the floors
would serve, not over the kind's whole average: the whole-kind number
would refuse a kind whose high-confidence answers agree perfectly because
its unsure answers happen to differ, and accept one whose average is fine
while every answer that would clear the floors is one of the bad ones —
and `min_questions` applies to the restricted subset too, because a rate
over a handful of clearing answers is noise wherever it is measured.

**Thresholds are per adapter and are not transferable.** The confidence
floors a policy routes on are keyed by `AdapterId`, and an adapter with
no entry is never preferred however good its evidence looks. A `0.8`
from a trained classifier and a `0.8` an LLM typed into a JSON field are
not the same claim; a threshold calibrated on one and applied to the
other looks principled and is worse than no threshold. The shadow run
records the cheap answer's confidence and margin on every observation
precisely so the same window that measured agreement can calibrate that
adapter's own floors: the report keeps them per compared answer
(`KindAgreement::calibration`), `agreement_at` measures the agreement
over just the answers any candidate pair of floors would serve, and the
routing gate takes its measurement at exactly the floors the venture
commits — the number a threshold is calibrated from is the number the
gate enforces.

**A pin is absolute.** `RoutingMode::Pinned` sends every question to the
one named adapter and never escalates: its answers and its errors reach
the caller unchanged, because pinning exists to take the router out of
the picture while a person debugs. A pin naming an adapter the router
does not hold fails every call with `ClassifierError::NotConfigured`
rather than quietly rerouting — the honest answer to "I asked for exactly
this adapter and you cannot produce it", and the useless-as-a-fallback
behaviour that makes the escape hatch trustworthy.

## Rejected

**1. One shared default threshold for all adapters.** The tempting
simplification — `min_confidence: 0.8` and every adapter is routed. It
loses because confidence is not a currency exchangeable across adapters:
the threshold would look principled, be unfalsifiable in operation, and
serve answers that one adapter never meant to stand behind. Per-adapter
calibration is more wiring for exactly the reason wiring is owed: the
numbers mean different things.

**2. Routing cheap by default, with an opt-out.** The inverted default —
every venture routes cheap until it flips a flag. It loses because it
reverses the burden of proof: the person who forgot to measure is the
person who pays, in wrong labels rather than in a shadow window, and the
flag's existence would make the measurement feel optional. `Off` by
default means the only path to cheap-first runs through a committed
report.

**3. Floating-point money.** `f64` for prices and costs, converting for
display. It loses because a ledger that cannot add a million small calls
honestly is not an accounting but a rendering, and because the pico-USD
integer is what makes the vendor's published figure map 1:1 — a float
mapping would need a conversion and a rounding decision at every price
update, each one a place to be silently wrong about money.

## Consequences

- Nothing routes cheap anywhere until a venture measures and commits. The
  apparatus — the corpus, the report, the stub run proving the
  arithmetic — is exercisable without API keys, but no real-adapter
  agreement numbers exist, none may be invented, and this ADR records the
  gate rather than any number behind it, because ADRs are not edited
  after acceptance and the numbers are a venture's to measure.
- Shadow mode costs strictly more than not running it and adds latency
  for as long as it runs; that is the price of the only honest switch,
  and it is temporary by construction — the serve adapter's answers and
  errors reach callers unchanged throughout.
- Escalations pay twice, and the ledger's role totals are what make the
  waste visible: the `Discarded` row is what routing paid for nothing,
  and "what did routing cost me over always-cheap" is a lookup, not an
  argument.
- The ledger is process-local, one isolate's view, and is not a billing
  system; a venture needing durable totals implements `CostLedger` over
  its own sink, whose buffering and flushing are its own.
- Issue #456 owns port registration. This work adds no `Port` variant, no
  `Ports` field, no `cratefield-testing` fake, and no ports-table row; a
  venture composes the router explicitly in its own wiring until that
  lands.
- The question text is not recorded by default in production runs,
  because there it is a user's; only an offline corpus run opts in, where
  the text is authored data and an unreadable disagreement cannot be
  audited.

## References

Issue #457; issue #456 (the classifier port this deliberately does not
register); ADR
[0002](0002-ports-and-adapters.md) (ports and adapters — where vendor
wiring is decided, and the shape the classifier adapters themselves
follow); ADR
[0007](0007-request-scope-in-extensions.md) (no ambient request state —
the ledger's interior mutability is explicitly wired, not ambient); ADR
[0019](0019-a-performance-change-is-admitted-by-a-measurement-and-replication-goes-last.md)
(a change is admitted by a number, not an argument — the same gate
applied to latency);
`docs/CLASSIFIER-ROUTING.md`; `crates/core/src/cost.rs`;
`crates/core/src/classifier.rs`; `crates/core/src/classifier_agreement.rs`;
`crates/core/src/classifier_routing.rs`;
`crates/core/tests/classifier_agreement.rs`;
`crates/core/tests/data/classifier-corpus.json`.
