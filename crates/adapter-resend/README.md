<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/readme-banner.png" alt="Cratefield Harness. The open-source core. Modules are crates, compiled into one stateless Worker with its own database." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-adapter-resend"><img src="https://img.shields.io/crates/v/cratefield-adapter-resend.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-adapter-resend on crates.io"></a>
  <a href="https://docs.rs/cratefield-adapter-resend"><img src="https://img.shields.io/docsrs/cratefield-adapter-resend?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-adapter-resend documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-adapter-resend

[`Mailer`] port over the [Resend](https://resend.com) REST API for the
Cratefield harness. Uses the runtime's `HttpClient` port — no `reqwest`,
no vendor SDK — so it runs unchanged on Workers (`worker::Fetch`) and
natively.

## Usage

```rust,ignore
use std::sync::Arc;
use cratefield_adapter_resend::Resend;
use cratefield_runtime_cloudflare::{FetchClient, WorkersClock};

// With a key:
let mailer = Resend::new(
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

`Resend::from_env(http, clock)` reads `RESEND_API_KEY`, `MAIL_FROM`,
`MAIL_REPLY_TO` from the process environment (native/self-hosted). On
Workers, read the secrets from the venture's `Env` and call `Resend::new`.
The `Clock` is what lets the adapter read the HTTP-date form of
`Retry-After` (issue #278); without it a date-form 429 would read as
"retry now".

Error mapping (to `cratefield_core::MailError`): 401/403 →
`Unauthorized`/`DomainNotVerified { domain }` (domain parsed from Resend's
message), 422 → `Invalid { detail }`, 429 → `RateLimited { retry_after }`
(from the `Retry-After` header), 5xx → `Upstream`. No error `Display` ever
includes the API key. `text` is always sent alongside `html`; the
`Idempotency-Key` header is set from `Message::idempotency_key`.

## Verify a sending subdomain (not the apex)

The Resend account has **no verified domain yet**; until it does, real
sends 403 with "Domain ... is not verified" and this adapter maps that to
`MailError::DomainNotVerified`. Until then, forms run in the degraded
`NotConfigured`/503 mode.

When verifying:

1. In the Resend dashboard add a **subdomain**, e.g. `send.example.com`,
   not the apex.
2. Add the DKIM/SPF records Resend shows to the subdomain's DNS zone.
3. Wait for "Verified", then set `MAIL_FROM` to an address on that
   subdomain (e.g. `Acme <no-reply@send.example.com>`).

**Why not the apex?** The apex domain (e.g. `example.com`) carries the
inbound Email Routing MX records. Adding Resend's outbound DKIM/SPF to the
apex would mix inbound routing and outbound sending policy on the same
name and can break delivered mail and future provider moves. A dedicated
`send.` subdomain keeps them isolated, and lets inbound routing stay
untouched if the outbound provider ever changes.

## Probing the key

Until a domain is verified, the key is send-only. Probe it with a real
send (expect 403 `DomainNotVerified`, which proves the key itself is
valid):

```sh
curl -s -X POST https://api.resend.com/emails \
  -H "authorization: Bearer $RESEND_API_KEY" \
  -H "content-type: application/json" \
  -d '{"from":"probe@send.example.com","to":"you@example.com","subject":"probe","text":"probe"}'
```

A 401 means the key is bad; 403 with the domain message means the key
works but the domain is unverified.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
