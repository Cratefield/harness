# TextModel: structured output you can rely on

The `TextModel` port answers prose. `TextModelExt` (issue #580) is the sibling
that answers a **value**: ask for JSON conforming to a schema, and get a value
that conforms or an error — never a half-parsed one. It is an extension trait
blanket-implemented for every `TextModel`, so an adapter cannot override it,
and cannot skip the validation inside it. Import the trait to call it:

```rust
use cratefield_core::TextModelExt;

// A value conforming to a schema you built yourself.
let value: serde_json::Value = model.complete_json(prompt, &schema).await?;

// Or the typed form: T's own schema is the constraint.
let quote: Quote = model.complete_as(prompt).await?;
```

`complete_json` takes the `prompt` **by value** — it holds the conversation it
will extend for a repair retry — and a `&schemars::Schema`. `complete_as::<T>`
generates that schema from `T` with `schema_for` (draft 2020-12, subschemas
inlined, the same generator the surfaces use).

## Native output, the fallback, and the guarantee

The adapters already do native structured output —
`cratefield-adapter-anthropic` forces a synthetic `respond` tool and
`cratefield-adapter-openai-compatible` sets `response_format: json_schema` —
and fill `Completion::json`. `complete_json` uses that when it is there, and
otherwise parses `Completion::text` with a markdown code fence stripped — the
fallback for a provider, or a server that ignored `response_format`, that
answered in prose.

Every answer is validated before it is returned. One that does not conform
gets **exactly one** repair retry: its reply quoted back, then a user turn
naming what was wrong and asking for only the JSON. A second failure is
`TextModelError::SchemaViolation`, carrying only the schema path and reason,
**never the model's output**, which may hold the personal data the schema was
there to structure. An error from `complete` itself (`Transient`, `Rejected`,
`Transport`) propagates unchanged, with no retry.

A schema the validator cannot honour — an unsupported keyword, or a root that
is not an object — is `TextModelError::InvalidSchema`, and the model is
**never called**: the schema is the caller's, so it is not the model's to pay
for.

## The supported schema subset

The validator is the one `run_tool_loop` already uses for tool arguments
(`crates/core/src/tool_loop.rs`), not a second implementation: one answer in
this crate to "which JSON Schema keywords are honoured". It is a deliberately
**narrow, fail-closed** subset — `type`, `properties`, `required`,
`additionalProperties` (including `false`, which `#[serde(deny_unknown_fields)]`
emits), `items`, `enum`, `const`, numeric and length bounds, and
`anyOf`/`oneOf`/`allOf` — plus the annotation keywords `title`, `description`,
`default`, `examples`, `$schema`, `$id`, `$comment` and `format`. Anything else
— a `$ref`, a `pattern`, an `if` — is refused up front with `InvalidSchema`
rather than silently unchecked. A struct deriving `JsonSchema` over numbers,
strings, `Vec`, `Option`, enums and nested objects stays inside the subset.

## Size and time

Each call is one `complete`, bounded like any other by the `HttpClient` port:
a response over `MAX_RESPONSE_BYTES` (4 MiB) or one that outlives
`MAX_RESPONSE_TIMEOUT` (30 s) fails. Because `complete_json` makes **at most
two** calls — the answer and the one repair — its worst case is roughly twice
that: two timeouts, two response sizes.

The reply must fit in `Prompt::max_tokens` (default `DEFAULT_MAX_TOKENS`,
1024). Set it so the schema's JSON fits: an answer truncated at that ceiling is
`TextModelError::Rejected` from the adapter — a bigger ceiling, not a re-ask,
is the fix — and `complete_json` propagates it unchanged, with no repair
retry. A value is never returned with its tail cut off.

## Worked example: a quote from a hotel's email reply

A module holds a guest's emailed reply and wants the offer as a value it can
compare and store. It writes the type it wants, derives `JsonSchema`, and
asks for it:

```rust
use cratefield_core::{ModelTier, Prompt, TextModelExt};
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct Quote {
    price: f64,
    currency: String,
    check_in: String,
    check_out: String,
    room: String,
    conditions: Vec<String>,
    valid_until: Option<String>,
}

let prompt = Prompt::new(ModelTier::Fast)
    .system("Extract the hotel's offer as JSON. Do not invent fields.")
    .user(email_body)
    .max_tokens(512);
let quote: Quote = model.complete_as(prompt).await?;
```

`deny_unknown_fields` puts `additionalProperties: false` in the generated
schema, so a model that invents a field is a violation, not a quiet extra key.
`Option<String>` becomes a nullable field, absent or null; `Vec<String>` an
array of strings. A model that answers with a string where `price` needs a
number is caught and given the one repair retry; if it still cannot, the caller
gets `SchemaViolation` naming `price` — and no `Quote`, so nothing downstream
can act on a guess. This is the shape `crates/core/tests/structured_output.rs`
exercises end to end.

## Not in the port

No streaming, for the same reason `TextModel` has none. No repair budget a
caller can raise: one retry is the guarantee, and a caller that wants another
attempt loops `complete_json` itself. And no schema migration — the validator
subset is the contract, and a schema outside it is a caller bug to fix, not a
silently grown capability.
