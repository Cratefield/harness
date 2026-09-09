<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/readme-banner.png" alt="Cratefield Harness. The open-source core. Modules are crates, compiled into one stateless Worker with its own database." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-adapter-apns"><img src="https://img.shields.io/crates/v/cratefield-adapter-apns.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-adapter-apns on crates.io"></a>
  <a href="https://docs.rs/cratefield-adapter-apns"><img src="https://img.shields.io/docsrs/cratefield-adapter-apns?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-adapter-apns documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-adapter-apns

The [`Push`](https://docs.rs/cratefield-core) port over Apple Push Notification
service (APNs), for the Factory Zero / Cratefield harness (issue #104).

It talks HTTP/2 to `api.push.apple.com` (or the sandbox) through the runtime's
`HttpClient` port, so the one adapter runs unchanged on Cloudflare Workers and
on the native runtime — no vendor SDK, no `reqwest`, no OpenSSL.

## Recipients

It serves `Recipient::Apns` and answers `PushError::Rejected("unsupported
recipient…")` for `Fcm` and `WebPush`. A venture that speaks more than one
transport puts `cratefield_core::RoutingPush` in front, which dispatches by
variant (ADR 0015), so venture code holds one `Arc<dyn Push>`.

`Notification` is transport-neutral, so some fields are mapped and some are
dropped, deliberately:

| Field | APNs |
|---|---|
| `ttl` | `apns-expiration`, which is an **absolute** epoch: the adapter sends `now + ttl`, and `0` for a zero TTL ("deliver now or drop") |
| `silent` | `apns-push-type: background` + `aps.content-available`, and priority `5` whatever the caller asked — Apple rejects a background push at `10` |
| `badge` | `aps.badge` |
| `url` | a top-level `url` in the payload, next to `aps`; APNs has no click target of its own |
| `loc` | `aps.alert.title-loc-key` / `title-loc-args` / `loc-key` / `loc-args`, with `title`/`body` left as the fallback |
| `collapse_id` | `apns-collapse-id` |
| `priority` | `apns-priority` `10` / `5` |
| `icon` | **dropped** — an iOS notification takes its icon from the app bundle |

## Authentication

APNs uses a provider **JWT** signed ES256 with the `.p8` key from the Apple
developer portal. Signing and the mint-once cache live in
`cratefield-push-auth`, shared with the VAPID and Google signers. The adapter
mints the token once and reuses it for 50 minutes (`JWT_TTL`): Apple rejects
regenerating it more than once per ~20 minutes and accepts it for up to 60.
Signing is pure-Rust P-256 ECDSA with a deterministic RFC6979 nonce, so it
needs no RNG on a Workers isolate.

## Usage

```rust,ignore
use std::sync::Arc;
use cratefield_adapter_apns::{Apns, ApnsCredentials, ApnsHost};

// On Workers: read the secrets from `env`, and use the runtime's ports.
let http = Arc::new(cratefield_runtime_cloudflare::FetchClient);
let clock = Arc::new(cratefield_runtime_cloudflare::WorkersClock);

let push: Arc<dyn cratefield_core::Push> = match env.secret("APNS_KEY_P8").ok() {
    Some(p8) => Arc::new(Apns::new(http, clock, ApnsCredentials {
        key_p8_pem: p8.to_string(),
        key_id: env.secret("APNS_KEY_ID")?.to_string(),
        team_id: env.secret("APNS_TEAM_ID")?.to_string(),
        topic: env.secret("APNS_TOPIC")?.to_string(), // the app bundle id
        host: ApnsHost::parse(&env.secret("APNS_HOST")?.to_string())
            .unwrap_or(ApnsHost::Sandbox),
    })?),
    // No credentials set: reports NotConfigured, never touches the network.
    None => Arc::new(Apns::not_configured()),
};

// One transport: hand the adapter straight to the runtime. With more than
// one, wrap them: RoutingPush::new().apns(push).web_push(web).
let runtime = cratefield_runtime_cloudflare::Cloudflare::new().push_arc(push);

// Sending names the transport, not a bare string:
// push.send(&Recipient::apns(device_token), &notification).await?;
```

## Failure contract

`send` returns:

- `PushOutcome::Delivered { id }` on `200` (the `apns-id`).
- `PushError::Unregistered` on `410` — the device token is dead; **delete it**.
- `PushError::Transient { retry_after }` on `429`, `5xx`, a transport error, or
  an expired provider token (the JWT cache is dropped so the next send
  re-signs) — retry, and not before `retry_after` where Apple sent a
  delta-seconds `Retry-After`.
- `PushError::Rejected(..)` on any other `4xx` (a bad payload, wrong topic), and
  for a recipient this adapter does not serve — not retryable without a change.

## Verification

Signing and payload construction are unit-tested. The live path against Apple's
sandbox is **needs-human**: it requires a real `.p8`, bundle id, and device
token, which do not live in the repo.
