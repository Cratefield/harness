<p align="center">
  <a href="https://crates.io/crates/cratefield-adapter-anthropic"><img src="https://img.shields.io/crates/v/cratefield-adapter-anthropic.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-adapter-anthropic on crates.io"></a>
  <a href="https://docs.rs/cratefield-adapter-anthropic"><img src="https://img.shields.io/docsrs/cratefield-adapter-anthropic?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-adapter-anthropic documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-adapter-anthropic

[`TextModel`] port over the [Anthropic Messages API](https://docs.claude.com/en/api/messages)
for the Cratefield harness — the first text-model adapter (issue #430).
Uses the runtime's `HttpClient` port — no `reqwest`, no vendor SDK — so it
runs unchanged on Workers (`worker::Fetch`) and natively, and inherits
that port's destination vetting, deadline and response-size caps.

## Usage

```rust,ignore
use std::sync::Arc;
use cratefield_adapter_anthropic::Anthropic;
use cratefield_core::{Prompt, TextModel};
use cratefield_runtime_cloudflare::{FetchClient, WorkersClock};

// With a key:
let model = Anthropic::new(
    Arc::new(FetchClient),
    Arc::new(WorkersClock),
    Some(key),
    "claude-opus-5",
);
// Without a key (degraded mode): complete() -> Err(NotConfigured), with
// no network call. One call per complete() — no streaming, no retries
// inside the adapter:
let completion = model
    .complete(Prompt::user("Summarise this in one line", 256))
    .await?;
```

`Anthropic::from_env(http, clock)` reads `ANTHROPIC_API_KEY` and
`ANTHROPIC_MODEL` (default `claude-opus-5`) from the process environment
(native/self-hosted). On Workers, read the secret from the venture's
`Env` and call `Anthropic::new`. The `Clock` is what lets the adapter
read the HTTP-date form of `Retry-After` (issue #278); without it a
date-form 429 would read as "retry now".

With `Prompt::json_schema` set, the request declares a single tool whose
input schema is the caller's schema and forces it with
`tool_choice: {type: "tool"}`; the tool input comes back as
[`Completion::json`]. Without it, no tools are sent and `json` stays
`None`.

Error mapping (to `cratefield_core::TextModelError`): 429 →
`Transient { retry_after }` (from the `Retry-After` header, both RFC 9110
forms), any 5xx — including Anthropic's 529 `overloaded_error` →
`Transient { retry_after: None }`, 400/422 → `Rejected` (malformed
request, filtered content), 401/403 → `Rejected` (a bad key is not worth
retrying), any other 4xx → `Rejected`. Everything that stops the call
from completing maps to `Transport`: timeout, blocked destination, a body
over the response cap, a success body that does not parse, a forced JSON
call that comes back without its tool block. No error `Display` ever
includes the API key, and neither the prompt nor the completion text is
ever logged — a prompt is user content.

## The caps are the design

The adapter attaches the port's widest `HttpPolicy` to every request: a
30 s deadline — the `HttpClient` ceiling, up from that port's 10 s
default, because a model call's normal case sits past it — and the port's
4 MiB response cap, which `HttpPolicy::clamped` lets a caller tighten but
never raise. What that implies for a caller: keep `max_tokens` modest
(an oversized completion is refused as `Transport`, not truncated), make
one model call per pipeline stage, and let a timeout surface as
`Transport` for the caller to judge — never a retry inside the adapter.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
