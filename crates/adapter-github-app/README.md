<p align="center">
  <a href="https://crates.io/crates/cratefield-adapter-github-app"><img src="https://img.shields.io/crates/v/cratefield-adapter-github-app.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-adapter-github-app on crates.io"></a>
  <a href="https://docs.rs/cratefield-adapter-github-app"><img src="https://img.shields.io/docsrs/cratefield-adapter-github-app?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-adapter-github-app documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-adapter-github-app

GitHub App authentication for the Cratefield harness (issue #623). It turns
an App's private key into the credentials the GitHub REST API accepts, over
the runtime's `HttpClient` and `Clock` ports — no vendor SDK, no `reqwest`,
no `tokio`, no `std::time` — so the same client runs on Cloudflare Workers
and natively (ADR 0002: the ports are core's, the vendor client is this
crate's). Signing reuses `cratefield-push-auth`'s `Rs256Signer` and its keyed
`CachedToken`, the same verified stack the push adapters present.

## Usage

```rust,ignore
use std::sync::Arc;
use cratefield_adapter_github_app::{GithubApp, DEFAULT_API_BASE};
use cratefield_runtime_cloudflare::{FetchClient, WorkersClock};

let app = GithubApp::new(
    app_id,
    Some(private_key_pem),       // the App's .pem; None => NotConfigured
    Arc::new(FetchClient),
    Arc::new(WorkersClock),
    DEFAULT_API_BASE,
);

// An installation token, cached and single-flighted per installation+scope.
let token = app.installation_token(installation_id, None, None).await?;
let response = app
    .request(installation_id, http::Request::get("/repos/acme/widgets/issues").body(bytes::Bytes::new())?)
    .await?;
```

## The three credentials

| What | Where it comes from | Lifetime |
|---|---|---|
| App JWT | `app_jwt()`: RS256 over `{iss: <app id>, iat: now-60, exp: now+540}` | 9 minutes, minted per call |
| Installation token (`ghs_…`) | `installation_token()`: the JWT exchanged at `POST /app/installations/{id}/access_tokens` | 1 hour; cached 55 minutes |
| User token (`ghu_…`) | `exchange_user_code()`: the user-to-server OAuth code traded at `/login/oauth/access_token` | as GitHub states |

`iss` is the **App ID as a decimal string**, which is what GitHub's docs
show for the client id and what the numeric app id renders to.

## Requests, caching and single flight

`request()` authenticates with an installation token and sets `Accept`,
`X-GitHub-Api-Version: 2022-11-28` and a `User-Agent` — GitHub rejects a
request without one — unless the caller already set them. Pass your own
`Authorization` and no installation token is minted at all.

The request's URI may be absolute or relative; a relative one is resolved
against the client's API base, so a `Link` URL (absolute) is followed as-is.

Installation tokens are cached in a `CachedToken` keyed by
`(installation_id, scope)`, where the scope is the requested permissions and
repositories in canonical order — a token scoped to one repository is never
handed to a call scoped to another. An absent scope and a present-but-empty
one get different entries: `Some(&empty)` sends `"permissions": {}` ("grant
nothing") where `None` omits the field ("narrow nothing"). Concurrent cold
calls for one scope make **one** HTTP exchange for the whole client: one
app-wide async mutex is held across check-cache → exchange → store, so a
second caller arriving mid-flight waits and then reads the token the first
stored. A token minted already inside the five-minute safety margin is
returned but not cached. A `401` on a request this client authenticated drops
the cached token, mints a fresh one and replays **exactly once**; a second
`401` is returned to the caller.

`GithubResponse` carries the response **and** GitHub's rate-limit headers
(`X-RateLimit-Remaining`, `X-RateLimit-Reset`, `Retry-After`). Non-2xx
statuses are returned rather than classified, so the caller decides; `304 Not
Modified` is the normal outcome of a conditional `GET` sent with `with_etag`,
and `GithubResponse::not_modified()` recognises it.

## Pagination

`next_page(headers)` reads the `rel="next"` URL out of a `Link` header
(several comma-separated links, quoted `rel`, commas inside a URL left
alone), and `paginate(installation_id, first_url, max_pages)` follows it up
to the cap.

A `next` link is followed only when it names the same origin — scheme, host
and port — as the API base. The next page is fetched with the installation
token in `Authorization`, and a `Link` header is the one part of a response
an upstream gets to choose, so a cross-origin link ends the walk instead.
`user_can_access_installation` applies the same rule and answers `false`
when it meets one: the call exists to grant access, so an unverifiable walk
fails closed.

`request` (and so `paginate`'s first URL) holds the same line for every
request it authenticates: an absolute URL on another origin is refused with
`GithubAppError::ForeignOrigin` before a token is minted. A caller that sets
its own `Authorization` is not minted a token, so the check does not apply.

## User-to-server

`exchange_user_code(client_id, client_secret, code, redirect_uri)` posts to
`{web_base}/login/oauth/access_token` (GitHub's **web** host, not the API
host — `with_web_base` overrides it for GitHub Enterprise Server). GitHub
answers `200` with `{"error": …}` on failure, so the body decides: the error
becomes `GithubAppError::OAuth` carrying GitHub's error *code* only, never the
body. A non-2xx without an `error` field is a plain `GithubAppError::Status`
carrying the status and the rate-limit headers, whether or not the body is
JSON — a gateway's HTML page is not a decode failure.
`user_can_access_installation(user_token, installation_id)` walks
`GET /user/installations?per_page=100` (following `Link` pages, capped) and
reports whether the user authorised that installation — the check to run
before linking an installation to an account.

Both take their credential from the caller: the code exchange uses the client
id and secret, and the access check uses the user's own token, so neither
needs the app's private key.

## Nothing leaks

The `Debug` impls of `GithubApp`, `InstallationToken` and `UserToken` redact
the key and every token; no error `Display` carries key material, a token, a
client secret or a JWT; and `tracing` calls emit metadata only (the
installation id, the status). The one message this crate does not write is
`GithubAppError::Decode`, which carries the JSON parser's own words about a
body — diagnostic text, so a caller that prints it is printing something a
response chose. A key that is absent or empty makes **every operation that
needs it** — `app_jwt`, `installation_token`, `request`, `paginate` — answer
`GithubAppError::NotConfigured` without touching the network; the
user-to-server pair above runs without a key.

## Setting up the GitHub App (needs a human, per venture)

Creating the App is a one-time, human, per-venture step — nothing here can do
it for you.

1. **Create the App.** GitHub → *Settings* → *Developer settings* → *GitHub
   Apps* → *New GitHub App*. Give it a name and a homepage URL.
2. **Set the webhook.** Under *Webhook*, set the payload URL to the venture's
   inbound route and set a **webhook secret**. Choose the events the venture
   cares about.
3. **Choose permissions.** Under *Permissions & events*, grant only what the
   venture needs (e.g. *Contents: read*, *Issues: read and write*). The
   installation token mints down to these; there is no path to more.
4. **Note the App ID and client ID.** The App ID is `iss` in the JWT; the
   client ID is what the user-to-server flow sends.
5. **Generate a client secret** (*Client secrets* → *Generate*) if the
   venture does the user-to-server flow. Store it in the venture's secrets —
   it is only ever sent to `github.com`, never logged.
6. **Download the private key** (*Private keys* → *Generate a private key*).
   GitHub sends a `.pem` in the PKCS#1 form; store it in the venture's
   secrets and hand it to `GithubApp::new`.
7. **Install the App** on the repositories the venture should reach, then
   record the installation id (`GET /app/installations`).

### Receiving its webhooks

GitHub signs every delivery with `X-Hub-Signature-256` (HMAC-SHA256 over the
raw body), which core verifies with the named `cratefield_core::Github`
scheme:

```rust,ignore
use cratefield_core::{Github, WebhookVerifier};

let verifier = WebhookVerifier::new(Github);
if !verifier.verify(&webhook_secret, request.headers(), &raw_body, now_unix) {
    return Err(/* 401 */);
}
```

That scheme carries **no timestamp** — only the HMAC — so it offers no replay
protection of its own. A replayed delivery is rejected by claiming the
`X-GitHub-Delivery` id through the `Inbox` dedup ledger, which is what makes
each delivery apply its effects exactly once:

```rust,ignore
use cratefield_core::Inbox;

let inbox = Inbox::new("github_app_inbox");
// `seen_at` is an RFC 3339 timestamp read from the Clock port.
if !inbox.claim(db, delivery_id, &seen_at).await? {
    return Ok(/* already handled */);
}
```

The body must be the **raw bytes** GitHub sent — verify before any JSON
parsing, or the canonical form will not match.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
