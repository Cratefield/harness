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

## Webhooks

`webhook` verifies and parses Owlpost's inbound events. Owlpost signs
Stripe-style — `Cratefield-Signature: t=<unix>,v1=<hex HMAC-SHA256 of
"{t}.{body}">` — at core's ±300 s tolerance, widened with
`verifier().tolerance_secs(n)`. `parse_verified` verifies the **raw body
bytes first** and returns `WebhookError::Signature` without parsing them
when that fails, so an unverified delivery is never read.

The 13 event types (`email.sent`/`delivered`/`delivery_delayed`/`bounced`/
`soft_bounced`/`complained`/`unsubscribed`/`rejected`/`opened`/`clicked`/
`failed`, `message.received`/`held`) each parse into a typed `OwlpostEvent`
variant. A type this crate does not know becomes
`OwlpostEvent::Unknown(type_string)` — carried, not an error, so a handler
can ignore it.

**Deduplicate on `Envelope::id`, not on the header.** The signature covers
`t` and the body only, so `Cratefield-Event-Id` is unauthenticated: a
captured delivery replayed with a fresh id header still verifies and would
slip past a header-keyed ledger. `event_id(headers)` reads that header for
correlation and logging — reading it before verification, for instance —
and nothing more.

```rust,ignore
use cratefield_adapter_owlpost::webhook::{OwlpostEvent, event_id, parse_verified, verifier};

let envelope = parse_verified(&verifier(), secret, &headers, body, now_unix)?;
// `envelope.id` is inside the signed body — this is the dedup key.
let seen = inbox.claim(&envelope.id)?;
let _correlation = event_id(&headers); // logging only
match &envelope.data {
    OwlpostEvent::EmailBounced(b) => log(&format!("bounce {}", b.code.clone().unwrap_or_default())),
    OwlpostEvent::Unknown(t) => log(&format!("unhandled event {t}")),
    _ => {}
}
```

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

## Inbound

Owlpost also receives: the `/v1/inbound/messages` API (issue #682). Reads need
the `inbound:read` scope, writes `inbound:manage`.

| Operation | Endpoint |
|---|---|
| `Owlpost::list_messages(&MessageQuery)` — `inbox`, `thread`, `q`, `limit`, `before`, `held`, all optional | `GET {base}/v1/inbound/messages` |
| `Owlpost::list_held(inbox, before)` — `list_messages` with `status=held` | `GET {base}/v1/inbound/messages` |
| `Owlpost::get_message(id)` — with the body, as a `MessageDetail` | `GET {base}/v1/inbound/messages/{id}` |
| `Owlpost::raw_message(id)` — the RFC 822 source, as a `String` | `GET {base}/v1/inbound/messages/{id}/raw` |
| `Owlpost::reply(id, message)` — sends `to`, `subject`, `text`, `html` (Owlpost takes the sender from the inbox), returns the reply's id | `POST {base}/v1/inbound/messages/{id}/reply` |
| `Owlpost::release(id)` — stops holding the message | `POST {base}/v1/inbound/messages/{id}/release` |

A held message's body is never part of a listing: the page item `MessageSummary`
has no body field, so a held body is readable only through `get_message` or
`raw_message`, and `raw_message` returns the source verbatim. `MessageQuery` is
`#[non_exhaustive]` — build it with
`MessageQuery::default()` and set fields. Listings are cursor-paged:
`MessagePage::next` is the cursor to pass back as `MessageQuery::before`, and is
`None` on the last page. Message ids are validated to `[A-Za-z0-9_-]` before any
request, as outbound ids are. Inboxes, threads and routes follow.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
