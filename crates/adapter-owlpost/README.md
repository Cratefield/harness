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

## Error mapping

Owlpost answers RFC 9457 `application/problem+json` (`type`, `title`,
`status`, `detail`). Mapped to `cratefield_core::MailError`:

| Status | Variant |
|---|---|
| 401 | `Unauthorized` |
| 403 (domain/verify wording) | `DomainNotVerified { domain }` |
| 403 (otherwise) | `Unauthorized` |
| 400, 422, other 4xx | `Invalid { detail }` (`title: detail`) |
| 429 | `RateLimited { retry_after }` from the `Retry-After` header |
| 5xx | `Upstream(detail)`, with the `Retry-After` hint appended when present |

No error `Display` or `Debug` ever includes the API key. `text` is always
sent alongside `html`; the `Idempotency-Key` header is set from
`Message::idempotency_key`.

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
