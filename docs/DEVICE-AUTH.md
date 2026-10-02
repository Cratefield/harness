# Device authorization

`cratefield-module-device-auth` (issue #587) implements the OAuth 2.0
**device authorization grant**, [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628),
for a Cratefield venture. It is the flow for a client that has no browser and
no keyboard: a CLI, a TV app, a terminal in an SSH session, an appliance.

Most OAuth flows hand a browser a redirect. This one cannot — there is no
browser to redirect — so it hands the client a **pair of codes** and a URL:

- a long, secret `device_code` the client presents when it polls, and
- a short `user_code` the person reads off the screen and types into a page
  they open on any device with a browser.

The module owns the three things the RFC leaves to the server: the code pair,
the polling state machine, and the approval page. It owns **neither** of the
two things only a venture can answer — who may approve, and what a credential
is — and each of those is a hook set on the builder.

## The flow

```
  client (no browser)              venture                       person (browser)
  ───────────────────              ───────                       ────────────────
  1. POST /code  ─────────────────▶ mint a code pair
     ◀────────────── device_code, user_code, verification_uri
  2. show the code and URL  ─────────────────────────────────▶ reads them
  3. POST /token (poll)  ─────────▶ pending  → authorization_pending
                                    │           slow_down (polls too fast)
  4.                               │◀── GET /v1/device-auth?user_code=…
                                    │    signs in, sees the request
                                    │◀── POST /approve  (or /deny)
  5. POST /token (poll)  ─────────▶ approved → consume, Issuer called once
     ◀────────────── the credential (200), or expired_token / access_denied
```

1. The client posts to `/v1/device-auth/code` with its `client_id`, the
   scopes it wants and an optional device `name`.
2. It shows the person the `user_code` and the
   `verification_uri_complete` URL.
3. It polls `/v1/device-auth/token` at the `interval` the response named,
   and keeps polling until the answer is neither `authorization_pending`
   nor `slow_down`.
4. The person opens the URL — possibly on a different device — signs in, and
   presses Approve or Deny.
5. The next poll that has waited out its interval receives the credential the
   venture's issuer minted.

## The endpoints

| Route | Who calls it | What it answers |
|---|---|---|
| `POST /v1/device-auth/code` | the client | `device_code`, `user_code`, `verification_uri`, `verification_uri_complete`, `expires_in`, `interval` |
| `POST /v1/device-auth/token` | the client | the credential as a 200, or an OAuth 2.0 error |
| `GET /v1/device-auth` | the browser | the code form, or the Approve/Deny page for a code |
| `POST /v1/device-auth/approve` | the browser | records the approval and renders a confirmation page |
| `POST /v1/device-auth/deny` | the browser | records the denial and renders a confirmation page |

The two machine routes take their parameters **either** as a JSON body or as
an `application/x-www-form-urlencoded` form — an RFC 8628 client posts a
form, an API tool posts JSON — and they answer the OAuth 2.0 error shape of
[RFC 6749 §5.2](https://www.rfc-editor.org/rfc/rfc6749#section-5.2) with a
`400`:

```json
{"error": "authorization_pending", "error_description": "the person has not approved this device yet"}
```

That is a different dialect from the RFC 9457 `application/problem+json`
everywhere else in the harness, and deliberately so: these two routes are
called by OAuth clients that already parse `error` / `error_description`, and
`slow_down` and `authorization_pending` are normal steps of the flow rather
than failures.

The errors this module answers with:

| `error` | When |
|---|---|
| `invalid_client` | `client_id` is missing or names a client the venture has not declared |
| `invalid_scope` | the request asked for a scope the client does not declare |
| `invalid_request` | a required field is missing, or `name` is longer than 100 characters |
| `unsupported_grant_type` | `grant_type` is not `urn:ietf:params:oauth:grant-type:device_code` |
| `invalid_grant` | the device code is unknown, or was issued to another client |
| `authorization_pending` | nobody has approved the device yet |
| `slow_down` | the poll arrived before the interval elapsed; the interval grew by five seconds |
| `access_denied` | the person denied the request |
| `expired_token` | the code expired, or has already been used to mint a credential |

The browser routes answer HTML. `/approve` and `/deny` carry only the user
code in the form body; the approver comes from the session, never from the
body.

## The two hooks

Both are set on the builder and both are object-safe, so a venture can hold
them behind its own abstraction.

### `Approver` — who is asking to approve

```rust
#[async_trait::async_trait]
pub trait Approver: Send + Sync {
    async fn approve(&self, headers: &HeaderMap, return_to: &str)
        -> Result<Approval, ApproverError>;
}

pub enum Approval {
    /// Signed in, as this subject. It becomes the credential's subject.
    Subject(String),
    /// Not signed in; send the browser here to sign in and come back.
    SignIn { location: String },
}
```

`return_to` is the same-site path and query of the page the person is on
(never an absolute URL, which a sign-in flow refuses as an open redirect),
including the `user_code` query, so a sign-in flow can return them straight to
the decision. `headers` is the whole browser request's headers — a session
cookie lives there and nowhere else.

Left unset, the module uses **`CallerApprover`**, the stock implementation
over the `Auth` port: a verified caller is a subject, an anonymous one is
sent to `sign_in_url` (default `/login`) with `return_to` appended. A venture
with its own session scheme implements `Approver` directly and does not need
the `Auth` port.

### `Issuer` — what credential the client gets

```rust
#[async_trait::async_trait]
pub trait Issuer: Send + Sync {
    async fn issue(&self, request: IssueRequest)
        -> Result<serde_json::Value, IssuerError>;
}
```

The returned `serde_json::Value` is the response body the client receives,
byte for byte — the module adds `Cache-Control: no-store` and nothing else,
so the venture decides the credential's shape entirely.

## At most once, and what that costs

The poll that wins a guarded `approved` → `consumed` update calls the
`Issuer` **exactly once**. Two polls that race after an approval cannot both
receive a credential: the winner gets the JSON, and the loser is told
`expired_token`.

If the `Issuer` **fails**, the row stays `consumed` and the credential is
lost — the client must run the flow again. This is a deliberate trade: a
credential minted twice is worse than one that has to be asked for again, and
an issuer that is not idempotent cannot be trusted to "retry" safely. An
issuer that wants to survive a transient failure should make its own mint
idempotent under the request it is given, not ask the module to keep the row
open.

## Abuse controls

The `/code` and `/token` routes are public and unauthenticated, so the
controls are the point rather than an afterthought:

- **Both codes are stored only as SHA-256 hashes.** There is no clear-text
  column in `device_auth_codes`, so a dump, a backup or a query log holds
  nothing that can be replayed. The device code is 32 random bytes from the
  builder's `RandomBytes` (the harness carries no CSPRNG of its own, ADR
  0002); the user code is eight characters from a twenty-letter alphabet with
  no look-alikes — `B` not `8`, `F` not `E`.
- **The `RateLimiter` port is required, not optional.** Production readiness
  refuses a composition that declares the module and mounts no limiter (issue
  #562): the public routes would otherwise be an open write path. `/code`
  fails *open* on a limiter transport error (issuing a code is cheap); the
  decision forms fail *closed*, because the limiter is the only thing between
  an approver and a brute-force budget over the user-code space.
- **A per-approver wrong-entry allowance.** After `max_wrong_entries` (five
  by default) wrong codes, the decision routes answer
  `device-auth/too-many-attempts` with a `Retry-After`. The allowance is
  encoded into the limiter key (`device-auth:guess:<allowance>:<subject>`) so
  a deployment's per-key policy can read it, the same way the D1 limiter's
  documentation encodes a plan in the key.
- **Same-origin on the decision forms.** A request the browser reports as
  cross-site — `sec-fetch-site` other than `same-origin`/`none`, or an
  `Origin` that is not this venture's own — is refused before the body is
  trusted, under `device-auth/cross-site-request`.
- **A scheduled purge.** Rows past their expiry are deleted on the module's
  own cron, so an abandoned request does not sit in the table forever; an
  erasure keyed on the approver's subject deletes their rows immediately
  ([PRIVACY.md](PRIVACY.md)).

The user code is guessable in a way the device code is not — eight characters
over a twenty-letter alphabet is roughly 34 bits, and a person has to be able
to type it. The same-origin guard, the per-approver allowance and the short
expiry are what make that acceptable; the device code, not the user code, is
the secret the polling client holds.

## Worked example: an issuer over `ApiKeys`

The common case is a venture whose own API keys are already managed by
core's `ApiKeys` (the namespace/mode/prefix store behind
`ApiKeyMode::Live`). The issuer is then a thin wrapper: it hands
`ApiKeys::issue` the subject that approved, the scopes that were granted, and
returns the token exactly once.

```rust,ignore
use std::sync::Arc;
use async_trait::async_trait;
use cratefield_core::{ApiKeyMode, ApiKeys, Subject};
use cratefield_module_device_auth::{DeviceAuth, DeviceClient, IssueRequest, Issuer, IssuerError};

struct VentureKeys {
    keys: Arc<ApiKeys>,
    namespace: String,
}

#[async_trait]
impl Issuer for VentureKeys {
    async fn issue(&self, request: IssueRequest) -> Result<serde_json::Value, IssuerError> {
        // `request.subject` approved the device; `request.scopes` are the
        // granted scopes, each checked against the client's declaration by
        // the time this runs. `request.name` is the device label.
        let scopes: Vec<&str> = request.scopes.iter().map(String::as_str).collect();
        let issued = self
            .keys
            .issue(&self.namespace, &request.subject, &scopes, ApiKeyMode::Live)
            .await
            .map_err(|err| IssuerError::new(err.to_string()))?;
        Ok(serde_json::json!({
            // The token is shown once and never stored in the clear.
            "api_key": issued.token,
            "prefix": issued.prefix,
            "token_type": "api_key",
        }))
    }
}

let module = DeviceAuth::builder()
    .client(DeviceClient::new("sealb-cli").scopes(["read", "write"]))
    .issuer(VentureKeys {
        keys: Arc::new(ApiKeys::new(db.clone(), clock.clone(), rng.clone(), "api_keys")),
        namespace: "sealb".to_owned(),
    })
    .random(rng)              // RandomBytes, e.g. over `getrandom`
    .sign_in_url("/login")    // where CallerApprover sends anonymous visitors
    .expires_in(time::Duration::seconds(600))
    .interval(time::Duration::seconds(5))
    .build();
```

The credential the client receives is then, for example:

```json
{"api_key": "sealb_live_9f2c…_…", "prefix": "sealb_live_9f2c…", "token_type": "api_key"}
```

An issuer backing AWS, a database of its own, or a signed JWT looks the same:
one `issue` call, one JSON body, called once.

## Storage

One table, `device_auth_codes`, created by the migration at
`crates/module-device-auth/migrations/sqlite/0001_init.sql`. The table is
declared in `Module::tables()` and its rows are declared as personal data
(`approver_subject`, erased on request), so export and erasure reach them
like any other table. Ports: `Database` and `RateLimiter` required; `Clock`
and `Auth` optional.

## The client side

`cratefield_oauth_client::device` is the client half of this flow: it fetches
the code pair, shows the code, and runs the poll loop, handling
`authorization_pending` and growing the interval on `slow_down` on its own.
A client that already speaks to the OAuth client crate gets the device grant
by turning that helper on.
