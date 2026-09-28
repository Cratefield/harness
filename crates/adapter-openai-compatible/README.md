<p align="center">
  <a href="https://crates.io/crates/cratefield-adapter-openai-compatible"><img src="https://img.shields.io/crates/v/cratefield-adapter-openai-compatible.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-adapter-openai-compatible on crates.io"></a>
  <a href="https://docs.rs/cratefield-adapter-openai-compatible"><img src="https://img.shields.io/docsrs/cratefield-adapter-openai-compatible?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-adapter-openai-compatible documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-adapter-openai-compatible

[`TextModel`] port over the [chat-completions wire](https://platform.openai.com/docs/api-reference/chat)
for the Cratefield harness (issue #560) — one adapter for every server that
answers that wire, because the base URL is a constructor argument, not a
constant: `OpenAI` itself, Workers AI's `OpenAI`-compatible endpoint, `OpenRouter`,
and local servers like `vLLM`, llama.cpp and Ollama. Uses the runtime's
`HttpClient` port — no `reqwest`, no vendor SDK — so it runs unchanged on
Workers (`worker::Fetch`) and natively, and inherits that port's destination
vetting, deadline and response-size caps.

## Usage

```rust,ignore
use std::sync::Arc;
use cratefield_adapter_openai_compatible::OpenAiCompatible;
use cratefield_core::{Prompt, TextModel};
use cratefield_runtime_cloudflare::{FetchClient, WorkersClock};

// OpenAI itself (the default base URL):
let model = OpenAiCompatible::new(
    Arc::new(FetchClient),
    Arc::new(WorkersClock),
    Some(key),
    "gpt-4o-mini",
);
// A compatible server instead — a trailing slash is harmless:
let local = model.with_base_url("http://127.0.0.1:11434/v1");
// Without a key (degraded mode): complete() -> Err(NotConfigured), with
// no network call. A keyless local server takes any placeholder — the
// adapter always sends `Authorization: Bearer <key>`, and a server that
// never checks it ignores it.
let completion = model
    .complete(Prompt::new(cratefield_core::ModelTier::Fast).user("Summarise this in one line"))
    .await?;
```

`OpenAiCompatible::from_env(http, clock)` reads `OPENAI_API_KEY`,
`OPENAI_MODEL` (default `gpt-4o-mini`) and `OPENAI_BASE_URL` (default
`https://api.openai.com/v1`) from the process environment
(native/self-hosted). On Workers, read the secrets from the venture's `Env`
and call `OpenAiCompatible::new`. The `Clock` is what lets the adapter read
the HTTP-date form of `Retry-After` (issue #278); without it a date-form 429
would read as "retry now".

The request carries `max_tokens`, the length cap the broadest set of
compatible servers accepts. One caveat on `OpenAI`'s own API: the GPT-5 and
o-series models refuse `max_tokens` (they take `max_completion_tokens`,
which most compatible servers do not speak), so a first-party key wants a
model that still takes `max_tokens`. With `Prompt::json_schema` set, the
request adds a `response_format: {type: "json_schema", …}` — with
`strict: false`, because the port allows any draft 2020-12 schema and
`OpenAI`'s strict mode rejects an ordinary one (it wants
`additionalProperties: false` with every property required). A caller who
wants strict-mode guarantees supplies a strict-compatible schema and keeps
their own check on the parsed answer. The server's JSON answer parses into
[`Completion::json`], and a `finish_reason` of `length` — the answer cut
off before the JSON was whole — is a `Rejected` error, not a fragment
handed back as a success. Without a schema no `response_format` is sent
and `json` stays `None`.

Two refusals arrive inside an otherwise successful response: the model's
own `refusal` (the assistant message carries it with `content: null`) and
a `finish_reason` of `content_filter`. Both are `Rejected` in the
adapter's own words — the provider's refusal text goes to the log, never
into the error the caller matches on.

Every completion reports token usage: `input_tokens` and `output_tokens`
from the wire's `usage` block, and `cached_input_tokens` from
`usage.prompt_tokens_details.cached_tokens` where the server reports it —
`None` when it does not (a server without caching), `Some(0)` on a cache
miss from one that does. `input_tokens` is the total the server processed;
the cached count is the subset served from the server's prompt cache. A
server that omits the `usage` block altogether completes with 0/0 counts
and a warning in the log — a missing report never silently reads as a
free completion.

Error mapping (to `cratefield_core::TextModelError`): 429 →
`Transient { retry_after }` (from the `Retry-After` header, both RFC 9110
forms), any 5xx → `Transient { retry_after: None }`, 400/422 → `Rejected`
(malformed request, filtered content), 401/403 → `Rejected` (a bad key is
not worth retrying), any other 4xx → `Rejected`. Everything that stops the
call from completing maps to `Transport`: timeout, blocked destination, a
body over the response cap, a success body that does not parse, a schema
call whose answer is not JSON. The adapter never puts the API key in an
error, and neither the prompt nor the completion text is ever logged — a
prompt is user content. Provider-supplied error messages do pass through
in `Rejected` details, the same convention as the Anthropic adapter.

## The caps are the design

The adapter attaches the port's widest `HttpPolicy` to every request: a
30 s deadline — the `HttpClient` ceiling, up from that port's 10 s default,
because a model call's normal case sits past it — and the port's 4 MiB
response cap, which `HttpPolicy::clamped` lets a caller tighten but never
raise. What that implies for a caller: keep `max_tokens` modest (an
oversized completion is refused as `Transport`, not truncated), make one
model call per pipeline stage, and let a timeout surface as `Transport`
for the caller to judge — never a retry inside the adapter.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
