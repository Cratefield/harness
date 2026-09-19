# cratefield-adapter-workers-ai

`Classifier` port over the Cloudflare Workers AI binding for the Cratefield
harness (issue #456). The model is reached through `env.AI.run(...)` — a
platform binding, **no API key at all** — so this adapter only exists on the
Workers runtime, and it bills through the venture's Cloudflare account rather
than to a vendor key.

This is a convenience for ventures already on Workers, explicitly **not** the
primary way in: bring-your-own-key via `cratefield-adapter-typesafe` is the
default `Classifier`, because it runs on every runtime through the `HttpClient`
port. This adapter's `profile()` still reports `Calibration::Classifier` — it
is the same purpose-trained model (`typesafe/jev`) behind a different
transport, so its numbers are the same family as the direct adapter's, and a
threshold tuned on either holds on both (unlike the
`adapter-classifier-llm` family; see `CLASSIFIER.md`).

## Usage

```rust,ignore
use cratefield_adapter_workers_ai::WorkersAi;

// `AI` is the conventional binding name; a missing or wrong-typed binding
// yields `None`, meaning the runtime simply does not provide the port.
// Never a panic.
if let Some(classifier) = WorkersAi::from_env(&env, "AI") {
    runtime = runtime.classifier(classifier);
}
```

The model id defaults to `typesafe/jev`; override it (and the state ceiling)
with `WorkersAi::from_env_with_model` or `WorkersAi::with_runner`.

## The context window

Workers AI documents a **32,000-token context window** for this model. At the
port's conservative ~4 chars/token that is about 128,000 chars, but the
questions share the window too, so the default state ceiling is core's
`DEFAULT_MAX_STATE_CHARS` (96,000 chars, roughly 24,000 tokens), leaving
roughly a quarter of the window for the question set. The ceiling is
overridable per constructor through a `ClassifierProfile`.

## The wire format

The request and response documents are this crate's *assumption*, not
something this repository's vendors document: the same model as the direct
`adapter-typesafe` adapter, so the same documents travel, one level down in
the binding instead of in an HTTP body.

- Input: `{"state": "...", "questions": [{"id", "kind", "instructions",
  "criteria" (choice), "levels" (score)}]}` — all questions of the call in
  **one** `run()`.
- Output: `{"answers": [{"id", "value", "probabilities"}]}` where `value` is
  a criterion label, a number on the scale, or `true`/`false`.

## What is refused, what is retryable

The adapter never invents an answer: a missing question id, a label the
question never offered, or a distribution that is not normalisable is
`ClassifierError::Rejected`. Probabilities that do not sum to one are
normalised (the model's softmax is not obliged to land exactly on one);
non-finite or non-positive totals are refused.

There is no key here, so there is nothing to leak — but a Workers AI binding
error can echo platform identifiers (account ids, binding names), so error
text only ever travels inside `ClassifierError` (whose `Display` scrubs) and
this crate's log lines carry outcome labels, never raw binding text.
