# Cheaper classifiers, earned by measurement

A venture that asks a frontier model every question through the
[`Classifier` port](CLASSIFIER.md) pays frontier prices for questions a
small classifier would answer the same way. Core has three pieces that let
a venture move those questions, and only those, to the cheap adapter
(issue #457; the decision is [ADR 0022](adr/0022-cheaper-classifiers-are-earned-by-measurement.md)):

- **measure**: `measure_agreement` runs a labelled corpus through both
  adapters, and `ShadowClassifier` does the same on live traffic while
  serving the expensive answers. Both produce an `AgreementReport`.
  Shadow mode asks both adapters concurrently on the caller's task, so a
  shadowed call takes `max(cheap, expensive)`, not their sum — but a cheap
  call that stalls still holds it, so **the cheap adapter must enforce its
  own deadline**.
- **route**: `RoutingClassifier` sends a question to the cheap adapter
  only when the report shows it agrees on that kind of question, and
  escalates any answer it is unsure of.
- **account**: every call either wrapper makes is recorded to a
  `CostLedger` with its adapter, question ids, estimated tokens and price.

All three sit on the port as it is. Adapters are named by the wiring
(`AdapterId`), because the port does not name them.

## Wiring

```rust
let cheap = (AdapterId::new("workers-ai"), workers_ai as Arc<dyn Classifier>);
let dear = (AdapterId::new("frontier-llm"), frontier as Arc<dyn Classifier>);
let ledger = Arc::new(InMemoryLedger::new());
let accounting = Accounting::new(
    PriceSheet::new()
        .with(cheap.0.clone(), Price::per_million_tokens(11_000, 11_000))
        .with(dear.0.clone(), Price::per_million_tokens(3_000_000, 15_000_000)),
    ledger.clone(),
);

// 1. Measure, on a labelled corpus or with ShadowClassifier in production.
let report = measure_agreement(&cheap, &dear, &corpus, &accounting).await;
println!("{report}");

// 2. Route on the committed report.
let policy = RoutingPolicy::measured(report).thresholds(
    cheap.0.clone(),
    Thresholds { calibration: Calibration::Classifier, min_confidence: 0.8, min_margin: 0.3 },
);
let classifier = RoutingClassifier::new(cheap, dear, policy, accounting)?;
```

`RoutingPolicy::default()` is `RoutingPolicy::off()`: everything goes to
the expensive adapter until someone commits evidence.

## What agreement means

A question kind is its id in the map `ask` takes — a venture asks the same
kind of question under the same id — and agreement is measured per kind,
because a classifier that is right about languages is not therefore right
about privacy requests. Two answers agree when:

| `AnswerValue` | agree when |
| --- | --- |
| `Choice` | same label |
| `Noul` | same verdict |
| `Score` | same whole level after rounding (`3.2` and `2.9` agree, `3.4` and `3.6` do not); a non-finite score agrees with nothing |

Different shapes never agree. A corpus item's gold answer is matched by
the same rule, so each `KindAgreement` counts how often each adapter was
right, and each `Disagreement` says which one the ground truth sided with
(`GroundTruth`). Disagreements keep the answer values and the corpus
index, never the state, so a report can be pasted into a ticket.

Each compared question also keeps a `CalibrationPoint`: the cheap answer's
confidence, its top-two margin (`answer_margin`), and whether it agreed.
`KindAgreement::agreement_at` replays the evidence at a pair of thresholds,
which is how the router judges a kind *at the thresholds it will use*.

The margin is the top reported probability less the runner-up, where the
runner-up is the larger of the second reported probability and the mass
left unreported (`1 −` the sum reported), never below zero. A `Noul`
reported as `{"true": 0.55}` has a margin of `0.10`, not `0.55`. With no
probabilities at all, the top is the confidence and the runner-up its
complement: `max(0, 2 × confidence − 1)`. A non-finite confidence or
margin is stored as absent, so a report always round-trips through JSON,
and `agreement_at` counts an absent value as not clearing.

The corpus test data is `crates/core/tests/data/classifier-corpus.json`: 56
items over five kinds, four `Choice` and one `Noul`. It is a sample, not
evidence: with 10 to 12 items per kind, no kind can earn routing at the
default `min_questions` of 20, which is why the tests lower `min_questions`
to 10.

## How a question is routed

Under `RoutingMode::Measured` the question set is first validated as the
adapters validate it (`validate_questions`): an empty or malformed set is
`ClassifierError::Rejected` and reaches no adapter. Then each kind passes
these gates in order, and a kind that fails one goes to the expensive
adapter with that `RouteReason`:

1. the cheap adapter has `Thresholds` — else `NoCalibration`;
2. the report measured the kind — else `NoMeasurement`;
3. at least `min_questions` (default 20) measured answers clear the
   thresholds — else `NotMeasuredEnough`;
4. their disagreement rate is at most `max_disagreement_rate` (default
   0.05) — else `DisagreementTooHigh`.

The trusted kinds go to the cheap adapter in one `ask`. A cheap answer is
served (`CheapAccepted`) only if its confidence and its margin both clear
the thresholds; otherwise it escalates with `EscalatedLowConfidence` or
`EscalatedNarrowMargin`, and if the cheap call fails or leaves an id out,
`EscalatedCheapFailed`. Every untrusted and escalated question goes to the
expensive adapter together, in one second `ask`, and the answers are
merged under the ids asked. An expensive failure is the call's error.

`RoutingClassifier::ask_routed` returns a `Routed` per question — the
adapter that answered, the reason, the answer — and `ask` returns the
answers alone. **Measured answers mix confidence scales**: one call can
return cheap and expensive answers side by side, each `confidence` on its
own adapter's scale. A caller that thresholds confidence must use
`ask_routed` and threshold per `Routed::adapter`, never the merged map
`ask` returns.

`RoutingMode::Off` and `RoutingMode::Pinned` bypass all of this: one call
to the expensive or the pinned adapter, no escalation, its error is the
error. They are the escape hatch when the evidence is in doubt.

## Thresholds are per adapter

`Answer::confidence` from a trained classifier is a calibrated
probability; from a language model it is a token probability that runs
high whether or not the answer is right. A `0.8` from one is not a `0.8`
from the other, so thresholds are keyed by `AdapterId` and each names the
`Calibration` it was tuned under. `RoutingClassifier::new` refuses, with a
`RoutingError`:

- `CalibrationMismatch` — thresholds whose calibration is not the
  adapter's `profile().calibration`, so swapping an adapter cannot
  silently inherit numbers tuned for another;
- `UnknownAdapter` — a pin or thresholds naming an adapter the router
  does not hold;
- `EvidenceForOtherAdapters` — a report measuring a different pair.

## What the wrappers report as their profile

- `ShadowClassifier`: the expensive adapter's; every answer is its.
- `RoutingClassifier`, off: the expensive adapter's; pinned: the pinned
  adapter's; measured: the expensive adapter's `Calibration` (a cheap
  answer is only served where it was measured to agree with the expensive
  one) and the smaller `max_state_chars` of the two. That calibration
  describes the expensive answers only; use `ask_routed` to see who
  answered, and threshold each adapter's answers on its own scale.

## What a call costs

The port reports no token usage, so tokens are **estimated**: `Tokens`
carries `TokenSource::Estimated`, input is `ceil(chars / 4)` of the state
as the adapter truncates it plus each question's id, instructions and
criteria or levels, and output is `ceil(chars / 4)` of the answers
rendered as id, value and probabilities. It compares two adapters asked
the same questions fairly; it is not an invoice.

A `Price` is integer pico-USD per token (`Price::per_million_tokens` takes
the vendor's micro-USD per million, the same number). An adapter missing
from the `PriceSheet` is unknown, not free: its calls cost `None` and are
counted in `LedgerTotals::unpriced_calls`. A failed call records its input
estimate and no cost, and counts in `failed_calls`.

Each `CallRecord` has a `CallRole`: `Served` (at least one of its answers
was accepted to serve, or its error reached the caller), `Shadow` (asked
only to compare) or `Discarded` (asked to serve, and none of its answers
was accepted: every one escalated, or the call failed).
`InMemoryLedger::role_totals` puts the price of measuring and of wasted
escalation next to the price of serving.

Each call is recorded as soon as it returns, so a caller that drops the
future afterwards loses no cost. The cheap call's role is decided then,
from which of its answers the router accepted, and a later failure of the
expensive escalation does not change it: the cheap call stays `Served`
even though the caller gets the expensive error.

## Tests

```sh
cargo test -p cratefield-core --test classifier_agreement
```

The tests run over a scripted stub and the corpus: shadow answers are
unchanged when the cheap adapter fails, shadow mode asks both adapters at
once, every call lands in the ledger
with estimated tokens and a price, disagreements say who was right, and
routing serves cheap only for measured kinds, escalates unsure answers in
one second `ask`, refuses a calibration mismatch, and is bypassed when off
or pinned.
