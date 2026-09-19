<p align="center">
  <a href="https://crates.io/crates/cratefield-adapter-webhook-tracker"><img src="https://img.shields.io/crates/v/cratefield-adapter-webhook-tracker.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-adapter-webhook-tracker on crates.io"></a>
  <a href="https://docs.rs/cratefield-adapter-webhook-tracker"><img src="https://docs.rs/cratefield-adapter-webhook-tracker?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-adapter-webhook-tracker documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-adapter-webhook-tracker

The [`Tracker`](https://docs.rs/cratefield-core) port over a
tenant-configured webhook for the Cratefield harness (issue #432). It POSTs
the ticket as a JSON document signed with HMAC-SHA256, through the runtime's
`HttpClient` port — no vendor SDK, no `reqwest` — so the same adapter runs
unchanged on Cloudflare Workers and natively (ADR 0002: the port is core's,
the vendor client is this crate's).

## Usage

```rust,ignore
use std::sync::Arc;
use cratefield_adapter_webhook_tracker::WebhookTracker;
use cratefield_core::{Destination, TicketDraft};
use cratefield_runtime_cloudflare::{FetchClient, WorkersClock};

let tracker = WebhookTracker::new(Arc::new(FetchClient), Arc::new(WorkersClock), signing_secret);
let filed = tracker
    .file(
        &TicketDraft::new(
            "Outbox: refund failed",
            "The refund webhook failed twice.",
            Destination::Webhook {
                url: "https://ops.example.test/hooks/tickets".into(),
            },
            "01JFILED000000000000000000",
        )
        .labels(["from-outbox"]),
    )
    .await?;
```

The `Clock` is a constructor argument rather than a builder default so a
deployment that forgets it fails to compile — it is what stamps both the
payload and the signature, so the two cannot disagree.

## The signature

Every delivery carries one header, Stripe-style:

```text
Cratefield-Signature: t=<unix seconds>,v1=<lowercase hex>
```

The MAC is HMAC-SHA256 under the shared secret, computed over the bytes
`{t}.{raw_body}` — the timestamp is bound **into** the signature, so a
captured delivery cannot be replayed with a fresh timestamp: re-stamping
invalidates the MAC. That is the reason for this scheme over a separate,
unsigned timestamp header. The body is built once, signed, and sent — the
signed bytes are the wire bytes.

## Idempotency is delegated

A webhook cannot be searched the way the sibling
`cratefield-adapter-github-issues` searches a repository, so the *receiver*
dedupes: the payload carries the draft's `idempotency_key`, and a repeat
delivery with the same key is answered once. There is no tracker-side id to
learn back, so the returned `Filed` reports the idempotency key as its id
and `deduplicated: false`.

## Error mapping

To `cratefield_core::TrackerError`: 401/403 → `Unauthorized`, 404 →
`Rejected`, 422 → `Rejected`, 429/5xx → `Transient { retry_after }`
(`Retry-After`, both the seconds and the HTTP-date form), any other 4xx →
`Rejected`. A destination the `HttpClient` port's SSRF vetting refuses —
the URL comes from tenant config, so it is never fetched directly — is
`Rejected`: a config error, not weather a retry fixes. No error `Display`
ever includes the signing secret. A draft whose destination is not
`Destination::Webhook` is `Rejected` before any network call.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
