<p align="center">
  <a href="https://crates.io/crates/cratefield-adapter-owlpost"><img src="https://img.shields.io/crates/v/cratefield-adapter-owlpost.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-adapter-owlpost on crates.io"></a>
  <a href="https://docs.rs/cratefield-adapter-owlpost"><img src="https://img.shields.io/docsrs/cratefield-adapter-owlpost?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-adapter-owlpost documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-adapter-owlpost

[`Mailer`] port over the [Owlpost](https://owlpost.to) REST API for the
Cratefield harness (issue #591). Uses the runtime's `HttpClient` port — no
`reqwest`, no vendor SDK — so it runs unchanged on Workers (`worker::Fetch`)
and natively. It is the second mail provider alongside `adapter-resend`, and
speaks the same Resend-compatible `POST {base}/v1/emails` wire.

## Usage

```rust,ignore
use std::sync::Arc;
use cratefield_adapter_owlpost::Owlpost;
use cratefield_runtime_cloudflare::{FetchClient, WorkersClock};

// With a key:
let mailer = Owlpost::new(
    Arc::new(FetchClient),
    Arc::new(WorkersClock),
    Some(key),
    "Acme <no-reply@send.example.com>",
    None,
);
// Without a key (degraded mode): send() -> Ok(SendOutcome::NotConfigured),
// no network call. Wire it into the runtime:
let runtime = Cloudflare::new().db("DB").mailer(mailer);
```

`Owlpost::from_env(http, clock)` reads `OWLPOST_API_KEY`, `OWLPOST_BASE_URL`
(default `DEFAULT_BASE_URL`, `https://api.owlpost.to`), `MAIL_FROM` and
`MAIL_REPLY_TO`. A blank key or base URL reads as unset. On Workers, read the
secrets from the venture's `Env` and call `Owlpost::new`. A self-hosted
deployment or proxy points the adapter at its own host with
`Owlpost::with_base_url` or `OWLPOST_BASE_URL`. The `Clock` is what lets the
adapter read the HTTP-date form of `Retry-After` (issue #278); without it a
date-form 429 would read as "retry now".

## Operations

Beyond the [`Mailer`] port (one message at `POST {base}/v1/emails`), each
call delegates to `OwlpostClient`, which owns the wire:

| Operation | Endpoint |
|---|---|
| `Owlpost::send_with(message, SendOptions)` — adds `stream`, `topic`, `cc`, `bcc`, `scheduled_at` | `POST {base}/v1/emails` |
| `Owlpost::batch(emails, idempotency_key)` — ≤ `MAX_BATCH` (100), the key is the batch's `Idempotency-Key`, returns the ids in order | `POST {base}/v1/emails/batch` |
| `Owlpost::get_email(id)` — returns an `Email`; `id` is validated to `[A-Za-z0-9_-]` first | `GET {base}/v1/emails/{id}` |

`SendOptions` and `Stream` are `#[non_exhaustive]`: build with
`SendOptions::default()` and set fields, not a struct literal. Unset fields
are omitted, so a plain `send` body is unchanged. A `topic` with
`Stream::Transactional`, an empty or oversized batch, and an empty or
path-like id are refused locally, with no request — the refusals are checked
before the key, so a programming error surfaces even in keyless dev.

## Error mapping

Owlpost answers RFC 9457 `application/problem+json`. `OwlpostError` is
either `NotConfigured` or a wrapped `cratefield_core::MailError`, so the
[`Mailer`] port and the extra operations share one mapping:

| Status | Variant |
|---|---|
| *(no API key)* | `OwlpostError::NotConfigured`; `Mailer::send` reports `Ok(SendOutcome::NotConfigured)` instead |
| *(local refusal)* | `MailError::Invalid { detail }` — empty/oversized batch, topic on a transactional message, bad id |
| 401 | `MailError::Unauthorized` |
| 403 (domain/verify wording) | `MailError::DomainNotVerified { domain }` |
| 403 (otherwise) | `MailError::Unauthorized` |
| 400, 404, 422, other 4xx | `MailError::Invalid { detail }` |
| 429 | `MailError::RateLimited { retry_after }` from the `Retry-After` header |
| 5xx | `MailError::Upstream(detail)`, with the `Retry-After` hint appended when present |

No error `Display` or `Debug` ever includes the API key: provider and
transport text is key-redacted when the error is built, and `Display`
additionally runs it through `cratefield_core::scrub_text`. `text` is always
sent alongside `html`; the `Idempotency-Key` header is set from
`Message::idempotency_key` (for a batch, from the batch's own key).

## Keys

`op_test_…` keys never reach a provider; `op_live_…` keys do. Use a test key
in development and the venture's live key in production, set with
`wrangler secret put OWLPOST_API_KEY`.

## The request fixture

`tests/fixtures/owlpost-send-email-request.schema.json` is the request schema
the contract test validates every recorded body against. Its canonical source
is `Owlpost-to/backend:crates/owlpost-core`, a private repository unreachable
from this one, so the fixture is authored from the Resend-compatible shape
Owlpost speaks and carries the provenance in a `$comment`. Refresh it from a
local checkout with `scripts/refresh-fixture.sh`.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
