# cratefield-adapter-typesafe

`Classifier` port over the `TypeSafe` classify API for the Cratefield harness
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
- `state` longer than `profile().max_state_chars` (`96_000` chars) is truncated
  by core's deterministic, char-boundary-safe `truncate` — and a
  `tracing::warn!` records that it happened, with the limit. A silently
  trimmed state answers confident and wrong; the log line is how a
  maintainer connects the two.
- All questions of one call go into **one** request: the provider evaluates
  them against one `state` in parallel.
- A `None` or blank API key makes `ask` return `ClassifierError::NotConfigured`
  before any network call.
- Error mapping: HTTP 4xx → `Rejected` with the response body; 429 and any
  5xx → `Transient`, with the back-off parsed from `Retry-After` (both the
  seconds and the IMF-fixdate form, via the `Clock` the adapter is built
  with); a transport failure or an unparseable success body → `Transport`.

## Wire format (assumption)

`TypeSafe`'s classify API is documented here as this crate assumes it, not as
the vendor has published it. A reviewer wiring a real account should check
the four load-bearing choices — endpoint, auth header, request field names,
response field names — against the actual API and adjust:

```text
POST https://api.typesafe.ai/v1/classify
Authorization: Bearer <TYPESAFE_API_KEY>
Content-Type: application/json

{
  "state": "the text the questions are asked about",
  "questions": [
    { "id": "topic", "kind": "choice", "instructions": "Which topic?",
      "criteria": { "billing": "money, invoices", "bugs": "broken" } },
    { "id": "severity", "kind": "score", "instructions": "How severe?",
      "levels": [ { "name": "1", "meaning": "a typo" },
                  { "name": "5", "meaning": "data loss" } ] },
    { "id": "angry", "kind": "noul", "instructions": "Is the writer angry?" }
  ]
}
```

and a success answer is one entry per question id:

```text
200 OK
{ "answers": [
    { "id": "topic",    "value": "bugs",
      "probabilities": { "billing": 0.1, "bugs": 0.9 } },
    { "id": "severity", "value": 2,
      "probabilities": { "1": 0.2, "2": 0.6, "5": 0.2 } },
    { "id": "angry",    "value": "false",
      "probabilities": { "true": 0.2, "false": 0.8 } } ] }
```

Answers are validated, never trusted: a probabilities key the question never
offered, an answer naming a label outside its question, a missing or
duplicated question id, or a probability outside `[0.0, 1.0]` is
`Rejected` — the adapter does not silently invent an answer. A `score` value
comes back as a number and is checked against the question's level names;
`Answer::score` then reads the confidence out of the probabilities under the
score's own name, the convention for scales named for their scores
(`"1"`..`"5"`).

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
