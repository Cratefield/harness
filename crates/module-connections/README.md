# cratefield-module-connections

Per-subject third-party OAuth connections for a Cratefield venture: a person
authorizes an account at a provider, both tokens are sealed at rest, and the
venture can hand out a live access token, refresh it before it lapses, or
revoke the whole connection.

Mounted at `/v1/connections`. One migration, two tables, one route. The OAuth
protocol itself — authorize URLs, PKCE, `state`, code exchange, refresh,
revoke, the token sealer — lives in `cratefield-oauth-client`; this module is
the venture-facing storage and lifecycle around it.

## Composing it

```rust
use cratefield_module_connections::{Connections, presets};

let connections = Connections::builder()
    .provider(presets::x())
    .provider(presets::gitlab())
    // A self-managed GitLab substitutes its own host:
    .provider(presets::gitlab_at("https://gitlab.example.com"))
    .allowed_origin("https://app.example.com")
    .refresh_lead(time::Duration::minutes(5))
    .build();
```

Configuration keys (all prefixed `CONNECTIONS_`):

| key | meaning |
| --- | --- |
| `CONNECTIONS_TOKEN_KEY` | 32 random bytes, base64. Seals every token and PKCE verifier. **Secret.** |
| `CONNECTIONS_TOKEN_KEY_ID` | Key-ring id for rotation (default `1`). |
| `CONNECTIONS_<KEY>_CLIENT_ID` | The client id the provider issued. |
| `CONNECTIONS_<KEY>_CLIENT_SECRET` | The client secret. **Secret.** |
| `CONNECTIONS_API_BASE` | The public base the callback is built from (default `https://api.<venture domain>`). |

`<KEY>` is the provider key upper-cased with non-alphanumerics turned into
`_`, so `presets::x()` reads `CONNECTIONS_X_CLIENT_ID` and
`presets::gitlab_at(..)` reads `CONNECTIONS_GITLAB_CLIENT_ID`. The redirect
URI is `<API_BASE>/v1/connections/callback/<key>`; register exactly that with
the provider. It is built from configuration, never from a `Host` header.

## Driving the flow

Your own route authenticates the person and calls the handle:

```rust,ignore
// GET /connect/{provider}?return_to=https://app.example.com/settings
let subject = /* your session */;
let authorize = connections.api().start(&subject, provider, return_to).await?;
// 303 the browser to authorize.url
```

The provider sends the browser back to `GET /v1/connections/callback/<provider>`
with `state` and `code`. The module spends the state (single-use), exchanges
the code, stores the connection and 303-redirects to the `return_to` that was
recorded on the state — with `connection=<id>` on success, or `error=<slug>`
on failure. A state that is unknown, spent or expired answers an RFC 9457
problem; the callback never redirects to a URL the venture did not vouch for.

Reading a token, from anywhere in the venture:

```rust,ignore
let token = connections.api().access_token(&connection_id).await?;
// token.expose() for one call, or hand the whole thing to
// cratefield_oauth_client::send_with_refresh, which retries once on a 401.
```

`send_with_refresh` takes an `AccessToken` and a call, retries it once with a
freshly-issued token on a 401, and reports `SendWithRefreshError` when the
provider has rejected the refresh — the case where a person must reconnect.

## The API

| method | what it does |
| --- | --- |
| `start(subject, provider, return_to)` | Writes a state and returns the authorize URL. Refuses a `return_to` off the allowed origins. |
| `complete(state, code)` | Spends the state and exchanges the code. One caller per state wins. |
| `list(subject)` / `get(connection_id)` | Reads connections. **Never** a token. |
| `access_token(connection_id)` | A live token, refreshed first when due. |
| `revoke(connection_id)` | Best-effort provider revoke, then clears the tokens locally. |
| `mark_needs_reconnect(connection_id, reason)` | Flags a connection a person must re-authorize. |
| `set_account(connection_id, external_account_id, display_name)` | Records the provider-side account identity. |

Every method names its subject or connection explicitly. No route in this
module picks the subject for you, so one person's connection cannot be reached
by another's request.

## Status and events

A connection is `active`, `needs_reconnect` (the provider refused the refresh
token) or `revoked`. Events, all carrying the connection id, subject and
provider only:

- `connections.connected`
- `connections.refreshed`
- `connections.revoked`
- `connections.needs_reconnect`

A scheduled pass purges spent and expired states and refreshes the active
connections due within `refresh_lead`, spending one unit of the invocation
budget per connection (ADR 0023).

## Presets

Each preset is verified against the provider's own documentation, cited in a
comment beside it.

| preset | authorize | client auth | scopes | refresh | PKCE |
| --- | --- | --- | --- | --- | --- |
| `x()` | `x.com/i/oauth2/authorize` | Basic | `tweet.read users.read offline.access` | **rotates** | required |
| `google()` | `accounts.google.com/o/oauth2/v2/auth` | Basic | `openid email profile` (+`access_type=offline`, `prompt=consent`) | stable | S256 |
| `linkedin()` | `www.linkedin.com/oauth/v2/authorization` | Post | `openid profile email` | stable | — |
| `vercel()` | `vercel.com/oauth/authorize` | Post | `openid email profile` | **rotates** | required |
| `gitlab()` / `gitlab_at(base)` | `<base>/oauth/authorize` | Post | `read_user` | **rotates** | S256 |
| `linear()` | `linear.app/oauth/authorize` | Post | `read,write` (comma-separated) | **rotates** | S256 |

A provider the presets do not carry is a `Provider::new(..)` with the same
`with_*` knobs. None of them holds a secret.

## Storage

`connection` — one row per connected account: the subject, the provider, the
provider-side account id and display name, the granted scopes, the status, and
the two tokens. Both tokens are stored **only** as XChaCha20-Poly1305
ciphertext, each bound by its AAD to `connections/connection/<id>/<column>`, so
a blob copied into another row or column fails to open (ADR 0102). Indexed by
`subject`, and by `(status, access_expires_at)` for the refresh scan.

`connection_state` — one row per attempt in flight, keyed by the **SHA-256
hash** of the state, holding the `return_to`, the sealed PKCE verifier, a
ten-minute deadline and the `spent_at` stamp that makes the state single-use.
Purged on the scheduled pass.

## Security

No token — access, refresh, code, PKCE verifier or client secret — is ever
written to a log line, a response body or a response header. A failure talking
to a provider is logged and recorded on the connection as structured facts
only: the problem slug, the HTTP status and the OAuth `error` code, and only
when that code is short, ASCII token-ish text — anything else becomes
`other`. The provider's own `error_description` is never stored or echoed:
LinkedIn and others put text an attacker chose there, so reflecting it would
be a reflected XSS on this venture's own domain. For the same reason the
`error` parameter on a callback redirect is sanitised before it is logged.

The callback is public, so the only thing standing between a stranger and a
stolen code is the state: a 256-bit value this module generated, stored as
its SHA-256 hash, single-use via one guarded `UPDATE`, and expiring in ten
minutes. Spending it is one statement whose affected-row count decides the
winner, so two callbacks racing on one state cannot both redeem the code.

Every `Problem` this module answers with comes from a `ProblemDef` whose slug
starts `connections-`.

## Personal data (ADR 0015)

Two tables hold personal data, declared through `Module::personal_data`:

| table | subject | kind | disposition | redacted |
| --- | --- | --- | --- | --- |
| `connection` | `subject` | identifier | erase | `access_token_sealed`, `refresh_token_sealed` |
| `connection_state` | `subject` | identifier | erase | `state_hash`, `verifier_sealed` |

The `connection` row is a connected third-party account — the provider, the
account id and name it gave us, the scopes and the status — with both tokens
held only as ciphertext. The `connection_state` row is one attempt in flight,
deleted once spent or ten minutes old.

## Ports

Requires `Db` and `HttpClient`; optionally uses `Clock`, `IdGen` and `Defer`.
