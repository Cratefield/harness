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

## Tools

The wire speaks [function calling](https://platform.openai.com/docs/guides/function-calling),
so the adapter carries it by default (issue #665). With `Prompt::tools`
set, the request adds a `tools` array of
`{"type": "function", "function": {name, description, parameters}}`, and
`Prompt::tool_choice` steers the choice: `Auto` → `"auto"`, `None` →
`"none"`, `Required` → `"required"`, `Tool(name)` →
`{"type": "function", "function": {"name": "..."}}`. A `response_format`
and tools may be combined. A prompt with no tools serialises exactly as it
did before tools existed — no `tools`, no `tool_choice` — so a caller that
never asks for a tool sees no change.

The answer's `message.tool_calls` parse into `Completion::tool_calls`; the
arguments arrive as a JSON **string**, and the adapter parses them into an
object. A string that does not parse is kept as-is (a `Value::String`), so
`run_tool_loop` refuses the call — tool arguments must be a JSON object —
and feeds the error back to the model rather than the whole response
failing. `content` may be `null` on a call-only answer; that is not an
error. A `finish_reason` of `length` beside tool calls is `Rejected` —
truncated arguments must never reach an executor.

A conversation that quotes a tool call and its result goes back out as an
assistant message carrying `tool_calls` (`content` `null` when the turn
has no text, `arguments` re-serialised as a JSON string, or replayed
verbatim when it is the raw text of a call that did not parse) followed by
one `{"role": "tool", "tool_call_id", "content"}` message per result. The
wire has no `is_error` field on a tool message, so a failed result's text
is prefixed with `Error: ` for the model to read.

**Not every server behind this wire speaks tools.** A model that does not
may ignore the array or reject the request, so
`OpenAiCompatible::without_tools()` turns the capability off for one
deployment: `TextModel::supports` then reports `false` for
`Capability::Tools`, and a tools-bearing prompt is refused with
`TextModelError::Unsupported` before any request — never a completion that
silently ignored the tools. Use it for a server or model behind the wire
that does not do function calling. The default leaves tools on.

## Images

A turn built with `Prompt::user_parts` serialises its ordered parts as a
`content` array — each `{"type": "text", "text": …}` or
`{"type": "image_url", "image_url": {"url": "data:<media-type>;base64,…"}}`
— the image inline as a base64 `data:` URL. A text-only turn still
serialises `content` as a plain string, byte for byte as before images
existed.

**Not every model behind this wire has vision**, so image input is
**opt-in** — the mirror of `without_tools`. `OpenAiCompatible::with_images()`
turns it on; `TextModel::supports` then reports `Capability::Images`, and an
image-bearing prompt to a deployment that did not opt in is refused with
`TextModelError::Unsupported` before any request.

Bounds are enforced locally first: `Prompt::check_images` refuses more than
`MAX_PROMPT_IMAGES` images, one over `MAX_IMAGE_ENCODED_BYTES`, or a total
over `MAX_PROMPT_IMAGE_ENCODED_BYTES`, each with `TextModelError::ImageLimit`.

## Streaming

`TextModel::stream` (issue #859) speaks the wire natively: the request
`complete` builds plus `stream: true` and
`stream_options: {include_usage: true}`, its Server-Sent Events decoded by
core's shared SSE decoder into `TextDelta`s — answer text as it arrives,
`delta.reasoning_content` (and the `reasoning` alias some servers ship) as
`Reasoning`, each tool call started / grown argument fragment by fragment /
finished with the arguments reassembled by exactly the parser `complete`
uses, the trailing usage chunk as `Usage`, and one `Finish`. The head maps
errors identically to `complete` (bounded body included); an error payload
inside the stream ends it with `Transport`, and a stream that ends without
a `finish_reason` or `[DONE]` never passes as a success. Dropping the
returned stream drops the response body, which cancels the upstream
exchange — a disconnecting caller stops the spend.

Two prompts do not stream natively. One carrying `Prompt::json_schema` falls
back to one buffered `complete` round trip decomposed by
`completion_deltas` — structured output is a buffered feature
(`Completion::json` needs the whole answer). And a `finish_reason` of
`length` beside tool calls ends the stream with the same `Rejected` error
the buffered path returns: a call truncated mid-arguments never reaches an
executor either way.

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
