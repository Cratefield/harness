<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/readme-banner.png" alt="Cratefield Harness. The open-source core. Modules are crates, compiled into one stateless Worker with its own database." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-adapter-fcm"><img src="https://img.shields.io/crates/v/cratefield-adapter-fcm.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-adapter-fcm on crates.io"></a>
  <a href="https://docs.rs/cratefield-adapter-fcm"><img src="https://img.shields.io/docsrs/cratefield-adapter-fcm?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-adapter-fcm documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-adapter-fcm

The [`Push`](https://docs.rs/cratefield-core) port over Firebase Cloud
Messaging, for the Cratefield harness (issue #179).

It speaks the **HTTP v1** API —
`POST https://fcm.googleapis.com/v1/projects/{project_id}/messages:send` — to
`fcm.googleapis.com` through the runtime's `HttpClient` port, so the one
adapter runs unchanged on Cloudflare Workers and on the native runtime: no
Firebase Admin SDK (there is none for Rust and none is needed), no `reqwest`,
no OpenSSL.

Legacy `fcm/send` is not an option: Google shut it down in June 2024. v1 with
an OAuth 2.0 bearer token is the only supported server path.

## Recipients

It serves `Recipient::Fcm` and answers `PushError::Rejected("unsupported
recipient…")` for `Apns` and `WebPush` — including when it is not configured,
which is a fact about the credentials and not about the transports it carries.
A venture that speaks more than one transport puts `cratefield_core::RoutingPush`
in front, which dispatches by variant (ADR 0015), so venture code holds one
`Arc<dyn Push>`.

Google-free Android is **not** this adapter. A handset without Play services
reaches its app over UnifiedPush, which is Web Push (RFC 8030) and is served by
`cratefield-adapter-webpush`.

`Notification` is transport-neutral, so some fields are mapped and some are
dropped, deliberately:

| Field | FCM HTTP v1 |
|---|---|
| `title` / `body` | `message.notification.title` / `.body` — the whole block is **absent** on a silent message |
| `data` | `message.data`, with **every value stringified** (see below) |
| `silent` | a **data-only** message: no `message.notification` and no `message.android.notification`, which is what makes Android hand the payload to the app instead of drawing it. Unlike APNs, the priority the caller asked for is kept — `HIGH` on a data message is how an Android app is woken |
| `priority` | `message.android.priority` `HIGH` / `NORMAL` |
| `ttl` | `message.android.ttl` as a duration string (`"3600s"`), not the absolute epoch APNs takes. A sub-second TTL rounds **up** to `"1s"`, never down to `"0s"` ("deliver now or drop") |
| `collapse_id` | `message.android.collapse_key` |
| `category` | `message.android.notification.channel_id` — the Android notification channel is what a category names on this platform |
| `thread_id` | **dropped** — the port means "group these in the UI", which APNs and the web Notification API both do. FCM HTTP v1 has no grouping field: `android.notification.tag` *replaces* the notification already in the drawer, so mapping `thread_id` to it would show five notifications in a thread as one, four destroyed. Android grouping is a client-side call (`NotificationCompat.Builder.setGroup`); use `collapse_id` if coalescing is what you meant |
| `url` | `message.android.notification.click_action`, **and** a `"url"` key in `message.data`: a silent message has no notification block to hold `click_action`, and the data key is what the APNs and Web Push adapters use too. The typed field wins over a `"url"` in `data`; with no `url` set, `data`'s own `url` is left alone |
| `icon` | a URL (`https://…`) is `message.notification.image`, which the device downloads; anything else is `message.android.notification.icon`, which names a drawable resource **inside the app**. Putting either in the other's place shows nothing at all |
| `loc` | `message.android.notification.title_loc_key` / `title_loc_args` / `body_loc_key` / `body_loc_args`. Args are only emitted alongside their key — they are substitutions for it |
| `badge` | **dropped** — FCM has no badge field; Android badges are the launcher's own count |

### `data` values are strings

FCM rejects a message whose `data` holds anything but strings. So the adapter
stringifies rather than dropping or failing: a string passes through as itself,
and anything else is **serialised as JSON** for the app to parse back.

```text
{ "room_id": "42", "seats": 3, "room": { "id": 42 } }
        ->  { "room_id": "42", "seats": "3", "room": "{\"id\":42}" }
```

A `data` that is not a JSON object (an array, a bare string) has no keys to
flatten into the map, so it is left out entirely.

FCM reserves some data keys of its own — `from`, `message_type`,
`notification`, and anything beginning `google` or `gcm` — and rejects a
message that uses one. The adapter passes your keys through untouched rather
than silently renaming them, so pick names outside that set.

## Authentication

FCM v1 takes an **OAuth 2.0 bearer token** minted from a Google service
account:

1. sign an RS256 assertion —
   `{iss: client_email, scope: https://www.googleapis.com/auth/firebase.messaging,
   aud: token_uri, iat, exp: +1h}` — with the service account's private key;
2. `POST https://oauth2.googleapis.com/token` with
   `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`;
3. use the returned `access_token` as `Authorization: Bearer …`.

Signing is `Rs256Signer` and the token lives in a `CachedToken`, both from
`cratefield-push-auth` — this crate re-implements no JWT. The bearer token is
cached for the lifetime Google states less a five-minute margin, capped at
`ACCESS_TOKEN_TTL` (55 minutes), so a token is always re-exchanged with
minutes to spare. A `401` that is not `THIRD_PARTY_AUTH_ERROR` drops the
cached token and retries the send **once**, mirroring the APNs
expired-provider-token path.

RSA PKCS#1 v1.5 signing is deterministic and needs no RNG, which is what lets
this run on a Workers isolate.

## Secrets

`FCM_SERVICE_ACCOUNT_JSON` — the service-account file Firebase hands over,
whole, which is the simplest thing to paste into a secret.
`FcmCredentials::from_service_account_json` reads `client_email`,
`private_key`, `project_id` and `token_uri` out of it, so there is no second
secret to keep in step.

## Usage

```rust,ignore
use std::sync::Arc;
use cratefield_adapter_fcm::Fcm;

// On Workers: read the secret from `env`, and use the runtime's ports.
let http = Arc::new(cratefield_runtime_cloudflare::FetchClient);
let clock = Arc::new(cratefield_runtime_cloudflare::WorkersClock);

let push: Arc<dyn cratefield_core::Push> = match env.secret("FCM_SERVICE_ACCOUNT_JSON").ok() {
    Some(json) => Arc::new(Fcm::from_service_account_json(http, clock, &json.to_string())?),
    // No credentials set: reports NotConfigured, never touches the network.
    None => Arc::new(Fcm::not_configured()),
};

// One transport: hand the adapter straight to the runtime. With more than
// one, wrap them: RoutingPush::new().fcm(push).apns(apns).
let runtime = cratefield_runtime_cloudflare::Cloudflare::new().push_arc(push);

// Sending names the transport, not a bare string:
// push.send(&Recipient::fcm(registration_token), &notification).await?;
```

## Failure contract

`send` returns:

- `PushOutcome::Delivered { id }` on `200` — the `name` FCM assigned
  (`projects/*/messages/*`).
- `PushError::Unregistered` **only** on the explicit `UNREGISTERED` code
  (`404`) — the registration token is dead; **delete it**.
- `PushError::Rejected(..)` on `INVALID_ARGUMENT` (`400`), `SENDER_ID_MISMATCH`
  (`403`) and `THIRD_PARTY_AUTH_ERROR` (`401` — the Firebase project's own APNs
  credential is missing or bad, which re-minting our token cannot fix), on a
  token exchange that answers `invalid_grant` or `unauthorized_client` (a
  revoked key or a service account without the grant: no amount of retrying
  fixes either), on any other `4xx` including a `404` with no `UNREGISTERED`
  code, for a recipient this adapter does not serve, and for an empty
  registration token — not retryable without a change.
- `PushError::Transient { retry_after }` on `QUOTA_EXCEEDED` (`429`),
  `UNAVAILABLE` (`503`), `INTERNAL` (`500`), a transport error, a token
  exchange that failed for any other reason, and a `401` that survives one
  re-exchange — retry, and not before `retry_after` where Google sent one.
  `Retry-After` is read in **both** RFC 9110 forms: delta-seconds, and the
  HTTP-date form some CDNs emit (resolved against the `Clock` port; a date
  already past means "retry now").

The mapping keys off `error.details[].errorCode` (the
`google.firebase.fcm.v1.FcmError` detail) rather than the HTTP status, because
the status alone is ambiguous: a `404` is a dead token *or* a project that does
not exist, and `THIRD_PARTY_AUTH_ERROR` arrives as a `401`, which is otherwise
the adapter's own bearer token being refused. The status is the fallback for a
body with no recognisable detail — a proxy, a load balancer, an outage.

That ambiguity is resolved in the **non-destructive** direction: `Unregistered`
instructs the caller to delete a device token, so only the explicit
`UNREGISTERED` code produces it. Point `FCM_SERVICE_ACCOUNT_JSON` at a deleted
or mistyped project and FCM answers a plain `404` to *every* send — pruning on
that would delete a venture's whole device registry, one send at a time, from a
configuration typo.

## Verification

The token exchange, its cache, the 401 re-mint, the payload (a golden JSON
assertion) and every error code are unit-tested against a scripted
`HttpClient`.

The live path — a real Firebase project, a real service-account key and a real
Android handset — is **needs-human** and tracked as issue #186. It is
deliberately **not** a blocker for merging this crate: none of those three
things live in the repo, and nothing in CI can stand in for a handset that
actually rings.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
