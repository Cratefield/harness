<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/readme-banner.png" alt="Cratefield Harness. The open-source core. Modules are crates, compiled into one stateless Worker with its own database." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-adapter-webpush

The [`Push`](https://docs.rs/cratefield-core) port over **Web Push**, for the
Factory Zero / Cratefield harness (issue #180): RFC 8030 delivery, RFC 8188 /
RFC 8291 `aes128gcm` payload encryption, RFC 8292 VAPID authentication.

It POSTs to the subscription's endpoint through the runtime's `HttpClient`
port, so the one adapter runs unchanged on Cloudflare Workers and on the
native runtime — no vendor SDK, no `reqwest`, no OpenSSL. All the crypto is
pure Rust (`p256`, `hkdf`, `sha2`, `aes-gcm`) and builds for
`wasm32-unknown-unknown`.

## One adapter, browsers and Google-free Android

A browser subscription and a **UnifiedPush** endpoint are the same protocol.
A UnifiedPush distributor on Android (ntfy, `NextPush`, Sunup) hands the app an
endpoint that accepts exactly the RFC 8030 request a browser push service
accepts, so this adapter serves de-Googled Android as well as Chrome,
Firefox, Edge and Safari 16+/iOS 16.4+ PWAs. Nothing in it knows which it is
talking to — the transport is a fact about the recipient, not about the
device (ADR 0015).

> A note for anyone probing this by hand: publishing to a UnifiedPush topic
> on the **public** `ntfy.sh` answers `507 "cannot publish to UnifiedPush
> topic without previously active subscriber"`, because that instance runs
> with `visitor-subscriber-rate-limiting` on. It defaults to `false` on a
> self-hosted server, which is what the CI leg in issue #181 uses. A 507 is
> a configuration signal from ntfy, **not** a "subscription gone", and it is
> not mapped to `Unregistered`.

## Recipients

It serves `Recipient::WebPush` and answers `PushError::Rejected("unsupported
recipient…")` for `Apns` and `Fcm` — including when it is not configured,
which is a fact about the credentials and not about the transports it
carries. A venture that speaks more than one transport puts
`cratefield_core::RoutingPush` in front, which dispatches by variant, so
venture code holds one `Arc<dyn Push>`.

`Notification` is transport-neutral, so some fields are mapped and some are
dropped, deliberately:

| Field | Web Push |
|---|---|
| `title` / `body` | payload `title` / `body` |
| `icon` | payload `icon` |
| `url` | payload `url` — the click target a service worker opens |
| `thread_id` | payload `tag`: notifications sharing one replace each other in the shade |
| `silent` | payload `silent` (always present) |
| `data` | payload `data`, **nested** — not merged at the top level as the APNs adapter does, because `showNotification` takes a `data` member of its own and nesting means a caller's key can never collide with the adapter's |
| `ttl` | the `TTL` header, whole seconds; **24 hours** when unset, because RFC 8030 §5.2 makes the header mandatory and there is no "unset" on the wire. `0` is passed through as the deliberate "deliver only if online now"; a sub-second TTL rounds **up** to one second, never down to `0` |
| `priority` | the `Urgency` header: `Immediate` → `high`, `Conserve` → `normal` (not `low`, which can mean "hold until the screen is next on") |
| `collapse_id` | the `Topic` header. RFC 8030 §5.4 allows at most 32 URL-safe base64 characters, which the port's field need not respect, so a value that does not fit is replaced by the first 32 base64url characters of its SHA-256. Equal ids still collapse, different ids still do not — and a topic that might carry a user identifier stops being readable by the push service |
| `badge` | **dropped** — the port's `badge` is the iOS app-icon *count*, the web `Notification.badge` is an icon *URL*; a number there would be silently wrong |
| `category`, `loc` | **dropped** — neither has a counterpart in the web Notification API. There is no OS-side string catalogue to look a loc key up in, so localisation on the web happens before this point |

## Encryption

Every message gets a fresh P-256 key pair and a fresh 16-byte salt. The
ephemeral private key is combined with the subscription's `p256dh` by ECDH,
mixed with its `auth` secret by HKDF-SHA256 (RFC 8291 §3.3), and the result
is the input keying material for one AES-128-GCM record (RFC 8188). The push
service sees ciphertext; only the browser that created the subscription holds
the key to open it.

**The payload limit is computed, not remembered.** RFC 8188 §2 puts the
content at "any length up to `rs-17`" — one padding delimiter and one
16-octet tag — and the 86-octet header sits *outside* that budget. So the
default record size is derived from the 4096 octets a push service is
required to accept (RFC 8030 §7.2): `4096 - 86 = 4010`, giving
`4010 - 17 = 3993` octets of payload, which is exactly the number RFC 8291 §4
arrives at by the same arithmetic. An oversize payload is
`PushError::Rejected("payload too large: …")` **before** any request is made.
`WebPush::max_payload()` reports the limit and
`WebPush::with_record_size(..)` raises it, for a venture whose subscribers are
all on services that accept more than the minimum.

The folklore numbers — 4078, 4079, 3052 — come from setting `rs` to 4096 and
forgetting that the header is *added* to it, which produces a 4182-octet body
that a service capping at 4096 answers `413` to.

Verification: the RFC 8291 Appendix A example is reproduced byte for byte
(every published intermediate value, the 86-octet header, the ciphertext, and
the whole §5 body), the RFC 8188 §3.1 vector covers the content coding on its
own, and `tests/rfc8291.rs` runs an independent **decryptor** — the browser's
half, written from the RFC text — over arbitrary payloads, so a regression
cannot pass by matching a vector alone.

## Authentication (VAPID)

The `Authorization` header is `vapid t=<jwt>, k=<base64url public key>`
(RFC 8292 §3). The JWT is ES256 with `aud` = the push service's **origin**,
`sub` = the contact URI, `exp` = 12 hours out; signing and the mint-once
cache are `cratefield-push-auth`'s, shared with the APNs signer.

The token is cached **per push-service origin**, because `aud` is part of the
signed claims: Mozilla's token is not Google's. `aud` is the origin and never
the path — a push endpoint's path is the subscription's bearer capability, so
signing over it mints one token per subscriber and earns a `401` from every
service that checks strictly.

The legacy `Crypto-Key: p256ecdsa=` header is deliberately not sent. It
belongs to the pre-RFC draft; every current push service accepts RFC 8292 §3.

### Keys

Two secrets: `VAPID_PRIVATE_KEY` and `VAPID_SUBJECT` (a `mailto:` or `https:`
contact URI). The **public** key is derived from the private one and never
configured separately, so the pair cannot drift.

The private key is accepted in both forms that circulate: a PKCS#8 PEM, and
the bare 32-byte P-256 scalar base64url-encoded (what the JavaScript tooling
calls a VAPID private key).

`fz push vapid keygen` is the intended way to generate one; it lands with the
`fz push` CLI in **issue #184 and does not exist yet**. Until then:

```sh
openssl ecparam -genkey -name prime256v1 -noout \
  | openssl pkcs8 -topk8 -nocrypt          # -> VAPID_PRIVATE_KEY (PKCS#8 PEM)
```

The matching `applicationServerKey` for the browser is
`WebPush::public_key()` — serve it to the client rather than writing it down
twice.

## Usage

```rust,ignore
use std::sync::Arc;
use cratefield_adapter_webpush::{WebPush, vapid::VapidKeys};

// On Workers: read the secrets from `env`, and use the runtime's ports.
let http = Arc::new(cratefield_runtime_cloudflare::FetchClient);
let clock = Arc::new(cratefield_runtime_cloudflare::WorkersClock);

let push: Arc<dyn cratefield_core::Push> = match env.secret("VAPID_PRIVATE_KEY").ok() {
    Some(key) => Arc::new(WebPush::new(
        http,
        clock,
        VapidKeys {
            private_key: key.to_string(),
            // "mailto:ops@example.test"
            subject: env.secret("VAPID_SUBJECT")?.to_string(),
        },
    )?),
    // No key set: reports NotConfigured, never touches the network.
    None => Arc::new(WebPush::not_configured()),
};

// One transport: hand the adapter straight to the runtime. With more than
// one, wrap them: RoutingPush::new().web_push(push).apns(apns).
let runtime = cratefield_runtime_cloudflare::Cloudflare::new().push_arc(push);

// Sending names the transport, not a bare string. The three parts are what
// `PushSubscription.toJSON()` hands the client:
// push.send(
//     &Recipient::web_push(endpoint, p256dh, auth),
//     &notification,
// ).await?;
```

The browser side — `pushManager.subscribe({ applicationServerKey })` and the
service worker that reads this payload — is issue #183.

## Failure contract

`send` returns:

- `PushOutcome::Delivered { id }` on any `2xx`. RFC 8030 specifies `201
  Created` with a `Location` naming the push message resource, which becomes
  the `id`; `200` and `202` are accepted too, because ntfy answers `200` to a
  UnifiedPush publish and refusing that would fail a delivery that succeeded.
- `PushError::Unregistered` on `404` and `410` — the subscription is gone;
  **delete it**. Mozilla answers `410`, others `404` once the capability URL
  stops resolving, and both mean the same thing to the caller.
- `PushError::Transient { retry_after }` on `429`, any `5xx`, and a transport
  error — retry, and not before `retry_after`. Both forms of that header are
  read: delta-seconds and the HTTP-date form, the latter resolved against the
  `Clock` port.
- `PushError::Rejected(..)` on any other `4xx` (`400` malformed, `401`/`403`
  the token was refused, `413` body too large), for a recipient this adapter
  does not serve, and — before any request is made — for a malformed
  subscription, an endpoint that is not an absolute `http`/`https` URL, and
  an oversize payload. On a `401`/`403` the cached token for that origin is
  dropped, so a stale token re-signs on the next send and a genuinely wrong
  `aud` repeats its error instead of being masked by a cache hit.

## Verification

The RFC vectors, the decrypt-side round trip, the VAPID header (verified with
`p256`'s own verifier under a fixed key and a fixed clock) and every status
mapping are unit-tested here. The live path against a real push server is the
sibling issue #181, which stands up a self-hosted UnifiedPush distributor in
CI; the three vendor-live browser proofs are `needs-human` (issue #186).
