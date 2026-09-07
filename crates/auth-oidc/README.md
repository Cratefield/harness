# auth-oidc

OpenID Connect login (issue #15). Google is the first provider; the flow is
written against a provider descriptor, so Apple (#16) and anything else
compliant arrive as data rather than as a second copy of the flow.

Mounted at `/v1/auth-oidc`.

## Routes

| Route | What it does |
|---|---|
| `GET /{provider}/start?return_to=/path` | Builds the authorization URL with PKCE, seals the flow into a signed cookie, redirects |
| `GET /{provider}/callback?code&state` | Verifies the flow, exchanges the code, verifies the ID token, applies the linking rules, issues a session |

Both are public. An unknown provider is a 404; a known one whose credentials
are not configured says so rather than failing obscurely.

## Configuration

| Key | Required | Notes |
|---|---|---|
| `AUTH_OIDC_REDIRECT_BASE` | yes | The public origin. The redirect URI is `<base>/v1/auth-oidc/<provider>/callback` and must match what the provider has registered, exactly |
| `AUTH_OIDC_GOOGLE_CLIENT_ID` | per provider | |
| `AUTH_OIDC_GOOGLE_CLIENT_SECRET` | per provider | A Worker secret |
| `AUTH_OIDC_DEFAULT_RETURN_TO` | no | Defaults to `/` |

Half a credential is a configuration error rather than a runtime surprise:
a provider with an id and no secret would answer 503 with nothing to say why.

## What guards what

**The flow cookie is the only thing that makes a callback ours.** It is
signed, `__Host-` prefixed, and holds the `state` to compare, the `nonce` the
ID token must echo, the PKCE verifier and where to go afterwards. A callback
without it, with a tampered one, with one issued for another provider, or
with one older than ten minutes is refused before anything is exchanged.

It is `SameSite=Lax` rather than `Strict` deliberately: the callback arrives
as a top-level navigation from the provider, and `Strict` would withhold the
cookie on exactly that request.

**The expiry lives in the signed payload**, not in the signer's own `exp`,
because `Signer::verify` compares against the wall clock rather than the
`Clock` port. Putting it in the payload is what makes it testable and what
keeps it agreeing with a test clock.

**`return_to` may only be a path on this service.** An absolute URL, a
protocol-relative `//`, or a backslash a browser may normalise into one would
each turn a login endpoint into an open redirect, which is how a login flow
becomes a phishing laundry.

**Nothing from the provider is rendered.** A provider can put anything in
`error_description`; it is logged and never echoed.

## Discovery

Cached per isolate for an hour, because it is two network calls that would
otherwise run on every login. The cache holds signing keys, so an ID token
naming a key the cached JWKS has never seen triggers exactly one forced
refresh: a provider rotating keys must not lock everyone out until the
isolate recycles. That path is only reachable after a genuine token
exchange, and it is throttled so a provider that is simply broken cannot
turn every login into a discovery request.

## What this module does not decide

Which account an identity belongs to. `auth-core::linking` owns those rules
(#22) — they are the same for every method that arrives with an email — and
this module carries out what they return:

- a known identity signs in;
- a verified address on both sides links to the existing account, and an
  event carries the address that should be told;
- an address only one side has verified is **not** guessed: the person is
  told to sign in the way they already can and link from there;
- otherwise a new account, recording exactly what the provider vouched for.
  An unverified address is stored unverified, because storing it as verified
  would let the next provider auto-link a stranger's account to this one.

Confirming a link while signed in (`Outcome::ConfirmLink`) needs a page that
does not exist yet; the callback says so plainly rather than guessing.

## Known gaps

- The login chooser at `/v1/auth-core/authorize` does not offer this yet:
  `enabled_login_methods()` still returns nothing, and wiring it needs a
  decision about the methods that need a page rather than a link.
- No manual run against real Google yet. Everything here is exercised
  against a fake provider that mints real RS256 ID tokens, which covers the
  verification path but not Google's own quirks.
