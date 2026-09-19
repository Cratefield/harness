# cratefield-adapter-classifier-llm

`Classifier` port over the harness's own `TextModel` port for the Cratefield
harness (issue #456). The third of the three `Classifier` adapters and the
only one with **no vendor of its own**: it reaches whichever model the
venture's `TextModel` tiers are wired to — a local model included — asking
for JSON-schema structured output. When neither a purpose-trained classifier
nor a vendor binding is wired, this is the honest fallback.

## Usage

```rust,ignore
use cratefield_adapter_classifier_llm::ClassifierLlm;
use std::sync::Arc;

// `text_model` is the `Arc<dyn TextModel>` the venture already wired —
// the same router its drafting modules use. No new account, no new key.
let runtime = runtime.classifier(Arc::new(ClassifierLlm::new(text_model)));

// A model whose context window cannot carry the default 96_000-char
// state budget says so here, the only place that knows it:
let adapter = ClassifierLlm::new(text_model)
    .tier(cratefield_core::ModelTier::Fast)
    .max_state_chars(24_000);
```

## Calibration is the language model's

This adapter reports `Calibration::LanguageModel`, and that is not a
technicality. **A probability elicited from a general language model is not
the same number as one from a purpose-trained classifier.** A `0.8` this
adapter returns is the model's own rating of its certainty — sharper when
the model is confident, floppier at the decision boundary, and drifting
with every model version the venture re-wires the tier to. A threshold
tuned against a `Calibration::Classifier` adapter is simply wrong against
this one. A module that thresholds on `Answer::confidence` documents the
calibration it tuned against, and re-tunes when the adapter swaps.

## Behaviour

- One `TextModel::complete` call per `ask`, carrying **all** questions —
  asking as a set is the port's whole point. The prompt requests
  structured output through `Prompt::json_schema`, with a schema built per
  call that pins, for every question id, the chosen label and a
  probability for every label the question actually offers.
- Structured output is a *request*: a provider that cannot honour the
  schema answers plain text (`Completion::json` is `None`). The adapter
  then parses `Completion::text` as JSON, tolerating the markdown code
  fence real models wrap it in. Neither yields a JSON object with an
  `answers` mapping and the call fails `Transport` — with a message that
  does not quote the completion back.
- The model's answer is validated, never trusted: a missing or invented
  question id, a chosen label the question never offered, a probability
  under a label the question never offered, or a distribution that is not
  finite and normalisable is `Rejected`. A distribution that sums to
  something other than 1 is normalised; NaN and infinities never pass.
- `state` longer than `max_state_chars` is truncated with the port's
  deterministic, char-boundary-safe cut, and a `tracing::warn!` fires.
  The default is the port's conservative ceiling; the *real* ceiling is
  the underlying model's context window, which this port cannot see —
  set `.max_state_chars` to match whatever the tiers are wired to.
- Errors map one-to-one from `TextModelError`: `NotConfigured` (the tier
  is unwired — how "no classifier vendor wired" surfaces honestly),
  `Rejected`, `Transient { retry_after }` with the back-off preserved,
  and `Transport`. Provider text only ever rides inside variants whose
  `Display` scrubs it.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
