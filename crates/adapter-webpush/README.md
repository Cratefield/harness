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
> not mapped to `Unregistered` — nor to `Transient`, despite being a 5xx,
> because an operator state does not clear on its own and retrying it is
> retrying forever. It is `Rejected`, with `visitor-subscriber-rate-limiting`
> named in the message so the log line says what to change.

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

Every secret in that chain — the ECDH secret, the IKM, the CEK, the nonce,
the subscription's `auth` and the per-message private scalar — is cleared on
drop (`zeroize`, the workspace convention `crates/kms`, `crates/secrets` and
`module-linkedin` follow), and `aes-gcm` carries the same feature so the
cipher clears its expanded round keys too. `p256`'s `SharedSecret` already
zeroizes, so a copy taken out of it that did not would be the worst of both.

The subscription's two keys are read in **base64url or standard base64,
padded or not**. Browsers hand them over as unpadded base64url, but a
subscription is routinely stored and shipped by something that is not the
browser that made it, and the standard alphabet (`+` and `/`) comes back from
any encoder that was not asked for the URL-safe one. The alphabets do not
overlap, so accepting both is unambiguous — and refusing one meant a `p256dh`
containing a `+` could never be pushed to, permanently, since only the browser
can re-subscribe.

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

`fz push vapid keygen` is the way to generate one (issue #184):

```sh
fz push vapid keygen --file vapid.key   # prints the public key; writes the private one
wrangler secret put VAPID_PRIVATE_KEY < vapid.key
```

It prints the public key in the form the browser wants and refuses to
overwrite an existing key without `--force`, because rotating one
invalidates every existing subscription. `openssl ecparam -genkey -name
prime256v1 -noout | openssl pkcs8 -topk8 -nocrypt` produces the same thing
in the PKCS#8 form, which this adapter also accepts.

The matching `applicationServerKey` for the browser is
`WebPush::public_key()` — serve it to the client rather than writing it down
twice. `fz push inspect-subscription` reports the `aud` this adapter will
sign for a subscription, which is the first thing to check on a `401`.

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
- `PushError::Unregistered` on `410` — **and on nothing else**. See below.
- `PushError::Transient { retry_after }` on `429`, `5xx` other than `507`,
  `3xx`, `404`, `401`/`403`, and a transport error — retry, and not before
  `retry_after`. Both forms of that header are read: delta-seconds and the
  HTTP-date form, the latter resolved against the `Clock` port.
  - On `401`/`403` the cached token for that origin is dropped **and** the
    send stays retryable: a clock a few minutes out or a token that aged past
    its `exp` in flight is exactly this case, and the re-sign the rejection
    just arranged is what fixes it. A genuinely wrong `aud` repeats the error
    instead of being masked by a cache hit, bounded by the caller's own
    attempt budget.
  - `3xx` is not followed. The VAPID token is signed over the original
    origin, so replaying the POST at the `Location` earns a `401` from any
    service that checks `aud`; a distributor that moved is at worst
    temporary. The `Location` is never quoted back — it is a push endpoint.
- `PushError::Rejected(..)` on `400` (malformed) and `413` (body too large),
  on `507` (below), for a recipient this adapter does not serve, and — before
  any request is made — for a malformed subscription, an endpoint that is not
  an absolute `http`/`https` URL, and an oversize payload.

Error messages carry at most 200 characters of the service's response body,
control characters dropped and **everything URL- or path-shaped replaced with
`[redacted]`**. A Web Push endpoint is a bearer capability — whoever holds it
can push to that browser — and ntfy, nginx and CDN error pages all echo the
request path, which for this protocol *is* the subscription.

### `Unregistered` is a delete instruction

`PushError::Unregistered` does not mean "this send failed". It is the one
error in the port that tells the caller to **destroy** the recipient, and it
is easy to over-apply: this adapter and its FCM sibling each mapped an extra
status onto it independently, before either was reviewed.

It costs more here than anywhere else in the port. An APNs device token or an
FCM registration token is re-registered by the app on its next launch,
unattended; a Web Push subscription can be recreated **only** by the browser
calling `pushManager.subscribe()` again, which needs the user back on the site
with notification permission still granted. Pruning a live subscription is not
a lost message, it is a lost subscriber.

So the bar is a status whose only meaning is "gone". RFC 8030 §5 defines
exactly one — `410 Gone` — and that is the only one mapped. In particular
`404` is **not**: a self-hosted UnifiedPush distributor behind a proxy that
came back without its routes, or an edited ingress rule, answers `404` for
every path, so pruning on it deletes a venture's whole Web Push register in
one pass. It is retried instead. The trade is visible and deliberate: a
subscription that really is gone behind a service that only ever says `404`
is retried until the caller's attempt budget gives up, and lingers in the
register. Wasted sends against lost subscribers beats deleting live ones.

## Verification

The RFC vectors, the decrypt-side round trip, the VAPID header (verified with
`p256`'s own verifier under a fixed key and a fixed clock) and every status
mapping are unit-tested here. The three vendor-live browser proofs are
`needs-human` (issue #186).

### The interop leg: a real ntfy server (issue #181)

Everything above is this crate talking to itself, and two consistent
misreadings of one RFC paragraph agree with each other perfectly.
`tests/ntfy_live.rs` is the leg that cannot: it generates a subscription the
way a browser does, sends through the adapter over the **native runtime's
`HttpClient`** to a real ntfy server, reads the stored body back out of
ntfy's own JSON API, and opens it with the private key it generated. A
server that is not ours accepted the request, held ciphertext it could not
read, and what came back out is the notification.

CI runs it as the `web push conformance against a real ntfy server` job,
against a digest-pinned `binwiederhier/ntfy` container. Locally:

```sh
docker run --rm -p 8090:80 \
  -e NTFY_VISITOR_SUBSCRIBER_RATE_LIMITING=false \
  binwiederhier/ntfy:v2.28.0 serve

NTFY_URL=http://127.0.0.1:8090 cargo test -p cratefield-adapter-webpush \
  --test ntfy_live -- --nocapture
```

Without `NTFY_URL` the test skips and prints that recipe, so
`cargo test --workspace` stays green with no Docker.

Three things that recipe is deliberate about:

- **`127.0.0.1`, never `localhost`.** The native runtime's `HttpClient`
  refuses loopback *names* outright, before any resolver is consulted, so
  that the answer can never depend on `/etc/hosts`. The address form is
  admitted by `OutboundOptions::allow_loopback`, which the test sets and a
  deployment does not.
- **`visitor-subscriber-rate-limiting` pinned off.** With it on, as the
  public `ntfy.sh` runs it, a UnifiedPush publish answers the `507` quoted
  above even with a subscriber stream held open. It is already the
  self-hosted default; pinning it stops an upstream default change from
  turning the leg into a silent no-op, and the test fails loudly on a 507
  rather than skipping.
- **An `up`-prefixed 14-character topic**, the shape a distributor's own
  topics have — the shape ntfy's subscriber rate limiting is eligible for.
  A differently-shaped topic would walk past that trap and prove less.

What the leg does **not** prove: `Unregistered`. ntfy's "nobody is
listening" signal is that `507`, not the `410` RFC 8030 defines as gone, and
no real server produces a `410` on demand — so that mapping stays a unit
test. And ntfy reads none of `TTL`, `Urgency` or `Topic` from the request
(only `Content-Encoding`, which alone marks a publish as UnifiedPush, and
its own `X-*` headers), so the leg proves a real distributor **accepts** the
full RFC 8030 header set, not that it acts on it. A browser push service
acts on all three.
