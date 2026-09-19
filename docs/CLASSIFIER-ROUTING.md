# Classifier routing

`cratefield-core`'s classifier routing (issue #457) is how a venture stops
paying its strong model for questions a cheaper classifier answers just as
well — and how it proves *just as well* before it takes the saving. The
apparatus is four pieces: the accounting that makes "cheaper" a number
(`crates/core/src/cost.rs`), a shadow mode that measures without changing
what callers get, the agreement report that is the measurement, and the
router that refuses to act on anything less.

The boundary in one line: **nothing routes cheap until a committed
measurement says so.** `RoutingPolicy::default()` is `Off` — every question
goes to the expensive adapter — and that is the correct shipped state, not a
missing feature. A default that routed cheap would make every venture that
never ran the measurement an experiment subject, paying for the switch in
wrong labels instead of in a shadow window.

One scope note before the pieces. The `Classifier` trait is deliberately
**not** a registered harness `Port`: issue #456 owns registration (the
`Port::Classifier` variant, the `Ports` field, the runtime wiring, the
testing fake), and this work never touches `crates/core/src/ports/`, so the
two efforts cannot collide. A venture composes what is here explicitly in
its own wiring — the same pure-composition rule that puts
`TextModelClassifier` in core beside the `TextModel` port it wraps. The
decisions behind all of this are recorded in
[ADR 0021](adr/0021-cheaper-classifiers-are-earned-by-measurement.md).

## The question the issue poses

Every classification has two prices on the table: the strong model the
venture already wired, and a cheap classifier that might answer the same
question as well for a fraction of the cost. "Might" is the whole problem.
The cheap adapter will *claim* to be as good — every adapter does — and an
unmeasured switch converts that claim into production labels. Issue #457
poses the deal in the only honest direction: when a cheaper answer is
provably the same answer, take it — and the proof is the work. Not a
benchmark from the vendor, not a held opinion from whoever wired the
adapter: a measurement of these two adapters on this venture's own
questions, committed where the router can refuse without it.

Reliability is also not one number. A classifier that is reliable on one
kind of question is not therefore reliable on the next — a cheap adapter
that reads waitlist signups perfectly can mangle privacy requests, and the
two kinds have exactly the same average. That is why everything below is
keyed per question kind, and why "cheap unless this particular question is
hard" is the routing rule rather than "always cheap".

## Accounting, because "cheaper" is a claim about money

Before this issue the harness had no cost accounting at all. The
`TextModel` port's `Completion` carried the token counts the provider
reported, and nothing anywhere totalled them; there was no price in the
tree, no sheet, no ledger. A venture could not have answered "what did this
decision cost" even after the fact — and a cheap-vs-expensive decision *is*
a claim about money, so without accounting it could not be defended, only
asserted. The ledger also exists so the argument can be lost, not just won:
if the cheap adapter's failures and the router's escalations eat the
saving, the ledger is where that shows up.

Money is an integer, never a float: `f64` cannot add a million small calls
and stay honest about the sum. `Price` stores **pico-USD per token**
(10^-12 USD), a unit chosen for one convenience that pays for itself
repeatedly — a vendor's published `$X.YZ per million tokens`, written in
micro-USD, is numerically the same integer as pico-USD per token.
`Price::per_million_tokens(3_000_000, ..)` *is* the pricing-page line
`$3.00 / Mtok`, pasted in unchanged; a million tokens at that price cost
exactly `$3.000000000000`, and `Cost`'s `Display` renders all twelve
decimals because fewer would round a small call to `$0.00` and lie about
it. Arithmetic saturates rather than wrapping: an astronomical bill is a
bug to surface, never a credit to book. The two money types carry
different ceilings on purpose: a per-call `Cost` is a `u64` of pico-USD,
saturating near **$18.4 million**, which no single classification
spends — while the ledger's `LedgerTotals::pico_usd` is a `u128`,
because a total is a running sum over the ledger's whole life and a
`u64` would saturate it at that same $18.4 million. A `u128` of pico-USD
saturates near $3.4 × 10^26, which no ledger reaches.

**An adapter with no price on the sheet records an unknown cost, not a free
one.** `PriceSheet::cost_of` answers `None` for it, never
`Some(Cost::ZERO)`; `Price::FREE` is the *deliberate* zero, a wiring choice
such as a self-hosted model. The distinction is load-bearing. A
cheap-vs-expensive argument built on a silently-zero cost is precisely the
mistake this issue exists to prevent, so a totals row carries an
`unpriced_calls` count beside its summed pico-USD, and zero is the only
healthy value: **answered** calls the sheet never priced are a wiring gap
to fix, not a cheap adapter to promote. The count is careful about what
it blames. A call the adapter **errored** on is missing a cost for a
different reason — the error carries no token counts to price — so
failures have their own `failed_calls` count, and one cheap-side failure
never fires the wiring-gap diagnostic on a correctly wired sheet.

The ledger contract (`CostLedger`) is deliberately sync and infallible —
recording what a decision cost must not be able to fail a classification
or add a network hop — so a durable sink buffers locally and flushes on
its own schedule, owning its delivery failures. `InMemoryLedger` is
process-local: one isolate's view, gone when it is recycled. That is the
right instrument for a measurement run and a report, and it is not a
billing system; a venture that needs totals to survive implements
`CostLedger` over its own durable store. Failed calls are recorded too: a
failed call can still cost money, and a cheap adapter that fails often is
not cheap — its `failed_calls` count is where that shows. (A failed
call's token counts never reach the router — the error carries none — so
it is recorded at zero tokens rather than guessed, and it counts as
`failed_calls`, not `unpriced_calls`: the failure is not a missing
price.)

The accounting chain stays unbroken from the wire to the ledger:
`Classification` carries the token counts its call actually spent, and
`TextModelClassifier` carries the `Completion`'s usage straight through, so
pricing a classification never means asking again.

## Shadow mode: measuring without changing what callers get

`ShadowClassifier` wraps the pair while the measurement runs. The contract
is the whole point of the thing: the serve adapter — the expensive one —
answers, and its answer *and its error* reach the caller unchanged. The
cheap adapter is asked alongside, its answer recorded, and it is never
served. A shadow failure is swallowed: a `Failed` row in the ledger, no
observation, and nothing the caller can see. Shadow mode must not change
what callers get, because a measurement that altered behaviour would be
measuring its own interference.

The honest costs, stated rather than buried: shadow mode is strictly more
expensive than not running it, and it adds the shadow call's latency to
every request, because the two calls are sequential — serve first, since
its answer is the contract; shadow second, as the added tail. It is
temporary, and it is the only honest way to earn the switch. The
alternative to paying the window is switching on an argument, and an
argument is what the section above just finished disqualifying.

The question's text is **not** recorded by default. In production it is a
user's, and the agreement arithmetic counts labels, not prose — there is
nothing for the text to do in the number. `.record_question_text(true)`
opts in where the text is authored data: an offline corpus run, a
rehearsal, where a disagreement you cannot read cannot be audited. Live
runs also carry no gold answers — production does not know the right
label — so grading disagreements against truth happens in the corpus run
below, while a shadow run measures raw agreement.

```rust,ignore
let shadowed = ShadowClassifier::new(strong.clone(), cheap.clone())
    .prices(prices.clone())
    .ledger(ledger.clone());
// text recording stays off in production: the questions are users'.
// ... serve traffic through `shadowed` for the window, then:
let report = shadowed.report();
let committed = serde_json::to_string_pretty(&report).expect("serialises");
```

## The agreement report

The measurement an `AgreementReport` carries is per question kind: how
many questions both adapters answered, how many they answered the same,
and — where the corpus knew the right answer — who was right on the
disagreements: the cheap adapter, the expensive one, or neither. The
disagreements themselves are kept in the report, not just the rate, so an
auditor reads the counter-examples instead of believing a number; a router
configured from an unaudited rate is trusting a stranger with every cheap
call it ever serves.

Two honesty rules in the arithmetic deserve their own sentences. First, a
question either adapter **errored** on is counted as skipped —
`KindAgreement::errors` per kind, `AgreementReport::skipped` in total —
and sits in no rate's denominator, never in agreement's numerator. A
report that quietly dropped the questions the cheap adapter choked on
would overstate agreement by exactly the amount the adapter could not
cope, so the skips are counted beside the rates instead. A kind with
nothing compared has **no** rate at all (`n/a` in the rendered table),
never a `NaN` — a `NaN` compares false against every threshold check and
so reads as measured-and-safe, which is the one reading it must never get.
Second, the report round-trips through `serde` because it is **evidence**:
a venture measures once, commits the serialised report, and loads it later
to configure the router. The committed file is the whole contract between
the measurement and the routing decision.

The in-tree corpus (`crates/core/tests/data/classifier-corpus.json`) is 56
authored questions across 5 kinds drawn from the harness's own domain —
waitlist signup quality, inbound message language, privacy request kind,
CMS draft review, release note kind — each with a gold answer, and only
example addresses in its text. The run in
`crates/core/tests/classifier_agreement.rs` measures it through two
deterministic stub classifiers and asserts the report's arithmetic:
counts, rates, who-was-right tallies, skipped errors, the serde round
trip. It proves the arithmetic, not any adapter:

```
cargo test -p cratefield-core --test classifier_agreement
```

No real adapter is involved in that run and no number it produces is a
claim about any model. It is the worked example; the venture's own
measurement is the real one.

The offline runner is accounted like the apparatus around it, because its
calls are real calls: `measure_agreement` takes a `MeasurementOptions`
rather than a bare flag, and wiring it with a price sheet and a ledger
makes the run book itself. Both sides of every compared question are
recorded as `CallRole::Shadow` — asked to compare, never served, the
same role live shadow mode uses, because a measurement run is the same
shape: both adapters asked, neither answer delivered to a caller — and
priced off the sheet, `None` where an adapter has no price, unknown and
not free. A question the cheap adapter errors on books exactly one
record: the failed cheap call, `CallOutcome::Failed`, unpriced, and no
expensive record after it, because the expensive adapter is never asked
for a question that cannot be compared — the ledger showing one record
there is the truth about what the run spent, not a gap. Without a
ledger the report comes out identical, so turning the accounting on
changes what is known about the run and nothing about what it produces:

```rust,ignore
let ledger = Arc::new(InMemoryLedger::new());
let options = MeasurementOptions::default()
    // the corpus is authored data, so the run opts into keeping text
    .record_question_text(true)
    .prices(prices)
    .ledger(ledger.clone());
let report = measure_agreement(&cheap, &strong, &corpus, &options).await;
// `ledger.totals()` is what the run cost — the number a venture reads
// before pointing the runner at a larger corpus, not a guess about one.
```

## The routing rule: cheap unless this particular question is hard

`RoutingPolicy` in `Measured` mode does not mean "always cheap". It means
the cheap adapter is asked first only where evidence and calibration both
hold, and the gates are applied in a fixed order, each able to refuse the
plan before the next is consulted. `plan_for` is public and pure — a
person debugging the policy can ask it what it would do before any call
is made — and the router applies the same gates with the adapters it
actually holds.

| Gate, in the order the code applies them | `RouteReason` | Answers |
|---|---|---|
| Mode is `Off` — the shipped default | `RouteReason::RoutingOff` | expensive |
| Mode is `Pinned` | `RouteReason::Pinned` | the pinned adapter, no escalation |
| `Measured`, and nothing is committed | `RouteReason::NoMeasurement` | expensive |
| The committed evidence names a different cheap/expensive pair | `RouteReason::EvidenceIsAboutOtherAdapters` | expensive — refused wholesale, not mined for the kinds that look usable |
| The evidence has no entry for this question's kind | `RouteReason::NoMeasurement` | expensive |
| The cheap adapter has no `Thresholds` entry of its own | `RouteReason::NoCalibration` | expensive, however good the evidence looks — the floors are what select the answers the next two gates measure over, so without them there is nothing to measure |
| Fewer answers clear both of the cheap adapter's own floors than `min_questions` — including no answer clearing them at all | `RouteReason::NotMeasuredEnough` | expensive — a rate over a handful of answers is noise, and noise must not win a routing decision wherever it is measured |
| The disagreement rate over just the answers that cleared the floors is above `max_disagreement_rate` | `RouteReason::DisagreementTooHigh` | expensive — the cap is a ceiling; equal to it passes |
| All of the above passed | `RouteReason::CheapAccepted` | cheap first — and then only if the answer clears both of its own floors |

Two of those gates deserve their reasoning written out. The rate that
decides is taken over **the answers that cleared the cheap adapter's own
floors** — `KindAgreement::agreement_at` restricts the committed
calibration points to them — because those are the answers the router
would actually serve, and their agreement is the only agreement that is
evidence about serving them. The whole-kind average measures the wrong
thing in both directions: it would refuse a kind whose high-confidence
answers agree perfectly just because its unsure answers happen to
differ, and it would accept a kind whose average looks fine while every
answer that would clear the floors is one of the bad ones. The whole-kind
counts stay on the report for context and are worth reading; they are
just not what the gate caps. And `min_questions` applies to the
restricted subset, not the kind's whole count — a rate over a handful of
clearing answers is noise even when the kind measured hundreds.

The untuned defaults are a twenty-clearing-answers floor and a 0.05 disagreement
cap: knobs chosen to be strict, not numbers measured anywhere, and a
venture is expected to tune both from its own run.

What happens after cheap-first is the answer's own business. An answer
clearing **both** of its adapter's floors is served, reason
`RouteReason::CheapAccepted`. Below `min_confidence`, it is discarded and
the expensive adapter is asked — `RouteReason::EscalatedLowConfidence`.
Confident but indecisive — the margin, top score minus runner-up, under
`min_margin`, a near-tie wearing a label — is
`RouteReason::EscalatedNarrowMargin`. A cheap **error** escalates too
(`RouteReason::EscalatedCheapFailed`) rather than failing the caller: a
router that failed closed on the cheap adapter would make the cheap
adapter's reliability the whole system's, which is the opposite of the
deal. And if that escalation itself fails, the expensive adapter's error
surfaces unchanged — falling back to a cheap answer the policy just
refused would be the one thing worse than an error.

Every call that happens is recorded, **including both halves of an
escalation**: the cheap call as `CallRole::Discarded`, the expensive one as
`CallRole::Served`. An escalation pays twice — once for the answer thrown
away, once for the answer served — and the ledger's role totals make that
waste a lookup instead of an argument. "What did routing cost me over
always-cheap" is the `Discarded` row in `role_totals()` (the
`Shadow` rows answer the same question for the measurement window —
live shadow mode and an offline `measure_agreement` run both record
their calls as `Shadow`). Every
served answer also carries its `RouteReason` on `Routed`, and logs
adapter, kind, reason, confidence, margin and cost at debug level, so a
wrong decision says which adapter answered and why.

## Thresholds are per adapter, because confidence is not a currency

This is the trap the issue's "done when" list demands be closed, so it is
stated plainly: **confidence is not comparable across adapters.** A `0.8`
from a trained classifier and a `0.8` an LLM typed into a JSON field are
not the same claim about the world — the second is a number the model
chose to write, shaped by the prompt's wording and the schema's request,
and it is not a calibrated posterior. A threshold tuned on one and applied
to the other is worse than no threshold, because it looks principled: it
has the vocabulary of measurement and none of the substance, and it will
silently serve answers one adapter never meant to stand behind.

So thresholds are keyed by `AdapterId` — `min_confidence` and `min_margin`
per adapter, set through `.thresholds(..)` — and **an adapter with no
entry is never preferred**, whatever its evidence says: the router refuses
with `RouteReason::NoCalibration` rather than guess what the adapter's
numbers mean. A threshold is a floor: meeting it clears it.

Calibrating one is the shadow run's second payoff, and the run keeps what
it needs. Every compared answer is recorded as the cheap adapter gave it —
a `CalibrationPoint` on `KindAgreement::calibration`, carrying the
confidence and margin the adapter actually produced (`Observation`'s
`cheap_confidence` and `cheap_margin`), whether the expensive adapter
agreed, and whether the cheap answer was right where a gold answer
existed — so the same run that measured agreement holds its own
calibration data, committed and reloadable with the rest of the report.
`KindAgreement::agreement_at(min_confidence, min_margin)` is the tool
that makes the data answer the only question a threshold-setter has: *if
the floors sat here, how often would the answers I would have served
have agreed?* It restricts the points to those clearing both floors and
reports the rate over exactly that subset — the same measurement the
routing gate takes, which is why a venture can pick floors the run's own
distribution supports and know the gate will measure at them: tight
enough that the answers below them are the ones the run shows to be
unreliable, loose enough that the cheap adapter is not escalated into
oblivion. There is no portable number here, and this document refuses to
invent one.

## The escape hatches

Two ways out, both absolute. `RoutingMode::Off` disables routing: every
question to the expensive adapter, and it is what `RoutingPolicy::default()`
builds. `RoutingMode::Pinned(adapter)` pins one adapter — its answers *and
its errors* reach the caller unchanged, with no escalation of any kind.
Pinning exists so a person can take the router out of the picture while
debugging a suspect answer, and a pin that silently escalated would defeat
the only thing it is for: a pin is a person saying "show me exactly this
adapter", not a preference the router may second-guess.

A pin naming an adapter the router does not hold fails every call with
`ClassifierError::NotConfigured` rather than quietly rerouting to whichever
adapter happens to be wired. That is the right behaviour for a debugging
escape precisely because it is useless as a fallback: the caller asked for
exactly one adapter, the router cannot produce it, and `NotConfigured` is
what that fact means. A silent reroute would serve from the other adapter
and call it the pin, and the person debugging would be reading answers
from the thing they thought they had removed.

## What is not measured yet

The apparatus exists: the accounting, the shadow wrapper, the corpus and
the report, and the stub run that proves the arithmetic. **No
real-adapter agreement numbers have been recorded**, because producing
them needs a venture's own adapters and its own keys. No number in this
document, in the code, or in the ADR is a measurement, and none may be
invented — the thresholds and caps on a policy are knobs, the defaults
are chosen strict, and the one table in this document is format only.

That is why the shipped default is `Off`. Nothing routes cheap until
somebody runs the measurement, and the steps are:

1. **Author the questions.** The corpus shape is `kind`, `text`,
   `labels`, `gold` — your own questions from your own traffic's domain,
   with gold answers where you know the truth. The in-tree corpus is the
   worked example of the shape.
2. **Run the window.** Either offline — `measure_agreement` over your
   corpus with both adapters — or live, through a `ShadowClassifier` in
   production wiring. Both produce an `AgreementReport`, and both book
   every call's cost to a wired ledger while they run: hand the offline
   runner a `MeasurementOptions` with `.prices(..)` and `.ledger(..)`,
   and wire the `ShadowClassifier` the same way. A measurement is spend
   like any other, and the totals are what proving the switch cost —
   the number to read before widening the corpus and running it again.
3. **Commit the report.** Serialise it and commit the JSON next to your
   venture's wiring. The committed file is the evidence, and the router
   accepts nothing else — a policy without it stays at
   `RouteReason::NoMeasurement`, which is the point.
4. **Calibrate the cheap adapter's floors** from the same run, per the
   section above — `agreement_at` reads the restricted rate at any
   candidate pair of floors. Nothing about the thresholds is
   transferable from another adapter or another venture.
5. **Switch.** Load the committed report
   (`serde_json::from_str::<AgreementReport>`), build
   `RoutingPolicy::measured()` with the evidence, the thresholds and your
   tuned `min_questions` and `max_disagreement_rate`, and swap the
   `ShadowClassifier` wiring for a `RoutingClassifier` over the same two
   adapters. Keep the report; when the adapters or the question mix
   change, the evidence is stale and the window runs again.

```rust,ignore
let report: AgreementReport =
    serde_json::from_str(&committed_json).expect("the committed evidence loads");
let policy = RoutingPolicy::measured()
    .evidence(report)
    // Every number in this block — the two floors, the question count
    // and the cap — is a placeholder your own run has to justify, and
    // copying any of them would be calibrating on nothing.
    .thresholds(cheap_id.clone(), Thresholds { min_confidence: 0.9, min_margin: 0.3 })
    .min_questions(50)
    .max_disagreement_rate(0.02);
let router = RoutingClassifier::new(AdapterId::new("routed"), cheap, strong, policy)
    .prices(prices)
    .ledger(ledger);
```

## What a report looks like

**Format only. The table below is typed to show the rendering of
`AgreementReport`'s `Display` — the adapter ids and every number in it are
placeholders for an example venture, not a measurement of anything. No
real-adapter report exists in this repository.**

```
agreement of `fast-classifier` against `strong-classifier`: 18 questions compared, 2 skipped on an error
kind           questions  agreement  errors  graded  cheap  expensive  neither
ticket-topic          18      94.4%       0       1      0          1        0
refund-intent          0        n/a       2       0      0          0        0
```

One row per question kind: the questions both adapters answered, the share
that agreed, the questions dropped on an adapter error (which sit in no
rate's denominator), the graded disagreements and who won them. The
`refund-intent` row is the shape the arithmetic rules above protect: the
cheap adapter errored on every question of the kind, so the kind keeps its
row and its two errors, and reads `n/a` — no rate — instead of a number
about nothing. The header line carries the total skipped across all kinds.
That is the document a venture commits in step 3, and the only thing
`Measured` mode will ever route on.
