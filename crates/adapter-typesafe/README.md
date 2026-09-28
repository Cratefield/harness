# cratefield-adapter-typesafe

`Classifier` port over `TypeSafe`'s Jev evaluation API for the Cratefield harness
(issue #456). Runs on the runtime's `HttpClient` port — no vendor SDK, no
`reqwest` — so the same adapter works on every runtime, the Workers binary
included. **Bring-your-own-key is the point**: the request is billed to the
operator's own `TypeSafe` account, authenticated with the operator's own API
key, not a platform-side binding.

This is the default of the three `Classifier` adapters: `Calibration::Classifier`
means the probabilities come from a purpose-trained classifier model, not from
a general language model — a different family of numbers than the
`adapter-classifier-llm` adapter serves, and thresholds are not portable
between the two.

## Usage

```rust,ignore
use std::sync::Arc;
use cratefield_adapter_typesafe::TypeSafe;
use cratefield_runtime_native::{HttpClient as NativeHttpClient, SystemClock};

// Keys are constructor arguments, not a port. `from_env` returns `None`
// when TYPESAFE_API_KEY is absent — the port is then simply not provided,
// and an unwired `Classifier` answers `ClassifierError::NotConfigured`.
// On Workers, read the secret from `Env` and call `TypeSafe::new` instead
// (`std::env` has no Workers vars).
let runtime = match TypeSafe::from_env(Arc::new(NativeHttpClient), Arc::new(SystemClock)) {
    Some(typesafe) => runtime.classifier(typesafe),
    None => runtime,
};
```

Behavior:

- `ask(state, questions)` validates the set with core's `validate_questions`
  first, so a malformed set is `ClassifierError::Rejected` and never a panic.
  The vendor's own size ceilings — 255 options on a choice, 10 levels on a
  score — are refused the same way, before any request is spent.
- `state` longer than `profile().max_state_chars` (`96_000` chars) is truncated
  by core's deterministic, char-boundary-safe `truncate` — and a
  `tracing::warn!` records that it happened, with the limit. A silently
  trimmed state answers confident and wrong; the log line is how a
  maintainer connects the two.
- All questions of one call go into **one** request: the provider evaluates
  them against one `state` in parallel.
- A `None` or blank API key makes `ask` return `ClassifierError::NotConfigured`
  before any network call.
- Error mapping: 429 and `TypeSafe`'s 529 "overloaded", then any 5xx, →
  `Transient`, with the back-off parsed from `Retry-After` (both the seconds
  and the IMF-fixdate form, via the `Clock` the adapter is built with); 401,
  422 and any other 4xx → `Rejected` with the response body; a transport
  failure or an unparseable success body → `Transport`.

## The model is pinned

`DEFAULT_MODEL` is `"jev-1.13.0"`, a version id — not the `jev-latest` alias
`TypeSafe`'s examples use. Aliases move when a new release ships, "without
notice" in the vendor's own words, and a threshold tuned against one version's
numbers is wrong against the next. `.with_model("...")` moves you to a new
version on your own schedule; `from_env` additionally honours a non-blank
`TYPESAFE_MODEL`. The response's `model` field — the version that actually
answered — is recorded on every answer (`Answer::model`) and logged, so an
alias or a moved pin is observable after the fact.

## Wire format

As documented at [docs.typesafe.ai/api.md](https://docs.typesafe.ai/api.md)
([models.md](https://docs.typesafe.ai/models.md) for the models): a `POST`
to `DEFAULT_ENDPOINT` with `Authorization: Bearer <key>` and one JSON body —
the `state`, the pinned `model`, and all questions keyed by their ids (a
`choice`'s criteria as an `option -> meaning` map, a `score`'s levels as an
ordered array of descriptions, a `noul` bare). The success body carries the
resolved model version, one answer under each asked id (tagged by `type`),
and token usage. The docs' own example request and response are recorded
verbatim as `tests/fixtures/request.json` and `tests/fixtures/response.json`,
and the wire tests assert against them.

Three mapping choices are worth spelling out:

- **Score is converted onto the caller's scale.** Jev only ever sees the
  ordered level *descriptions* — the port's level names do not travel — so
  its weighted score is an index: exact at whole numbers (index 1 is the
  port's second level), between them otherwise. The port's
  `AnswerValue::Score` lives on the question's own level names (its docs'
  example is a `3.5` on a `"1"`/`"5"` scale), so whole indices map to the
  level's name exactly and the in-between is interpolated linearly between
  those names. A scale named in words has no name space to convert into; the
  index position is carried as-is. The index-keyed probabilities are re-keyed
  to the level names by position either way, and Jev's reported `confidence`
  is carried as reported.
- **Noul confidence is derived, not reported.** Jev answers a noul with one
  number, p(yes) — no confidence, no distribution. The adapter maps it to
  probabilities `{"true": p, "false": 1-p}`, takes the verdict as `p >= 0.5`,
  and `Answer::noul` reads the confidence out under the chosen side. The
  port's `confidence` is a bare `f32` with nowhere to say "derived, the
  vendor reported none", so the probability of the chosen side is what it
  carries — derived from Jev's own number, nothing invented.
- **Answers are validated, never trusted**: an answer for a question that
  was not asked, a question left unanswered, a probability under a label the
  question never offered, an answer of the wrong shape, or a number outside
  `[0.0, 1.0]` is `Rejected` — the adapter does not silently invent an
  answer.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
