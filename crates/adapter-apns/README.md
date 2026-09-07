# cratefield-adapter-apns

The [`Push`](https://docs.rs/cratefield-core) port over Apple Push Notification
service (APNs), for the Factory Zero / Cratefield harness (issue #104).

It talks HTTP/2 to `api.push.apple.com` (or the sandbox) through the runtime's
`HttpClient` port, so the one adapter runs unchanged on Cloudflare Workers and
on the native runtime — no vendor SDK, no `reqwest`, no OpenSSL.

## Authentication

APNs uses a provider **JWT** signed ES256 with the `.p8` key from the Apple
developer portal. The adapter mints the token once and reuses it for 50 minutes
(`JWT_TTL`): Apple rejects regenerating it more than once per ~20 minutes and
accepts it for up to 60. Signing is pure-Rust P-256 ECDSA with a deterministic
RFC6979 nonce, so it needs no RNG on a Workers isolate.

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

let runtime = cratefield_runtime_cloudflare::Cloudflare::new().push_arc(push);
```

## Failure contract

`send` returns:

- `PushOutcome::Delivered { id }` on `200` (the `apns-id`).
- `PushError::Unregistered` on `410` — the device token is dead; **delete it**.
- `PushError::Transient(..)` on `5xx`, a transport error, or an expired
  provider token (the JWT cache is dropped so the next send re-signs) — retry.
- `PushError::Rejected(..)` on any other `4xx` (a bad payload, wrong topic) —
  not retryable without a change.

## Verification

Signing and payload construction are unit-tested. The live path against Apple's
sandbox is **needs-human**: it requires a real `.p8`, bundle id, and device
token, which do not live in the repo.
