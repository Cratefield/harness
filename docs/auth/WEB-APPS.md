# @cratefield/auth — web apps

`@cratefield/auth` is the framework-neutral TypeScript client for a Cratefield
auth-core issuer: the TypeScript counterpart of the Rust `cratefield-auth-client`
crate. It runs on Workers-style runtimes and Node 20+, uses only Web-standard
APIs (WebCrypto, Fetch, URL, TextEncoder/TextDecoder, atob/btoa, AbortSignal),
has no runtime dependencies, and exports the PKCE helpers for a
browser-only client. It implements authorization code with PKCE, a sealed state
cookie, local ES256 verification against the JWKS, and single-flight refresh
rotation ([README.md](README.md), [ARCHITECTURE.md](ARCHITECTURE.md)).

## Register the client

Register the app as a client the way a venture backend is (see
[README.md](README.md), "How a venture uses it"): an id, a secret and an
**exact** list of redirect URIs, no wildcards. Register the callback URL *and* the
post-logout URL; the IdP refuses a post-logout URL it does not hold, and `redirectUri` must match byte for byte.

## Setup

```ts
import { createAuth } from '@cratefield/auth';

// One per isolate, at module scope: the JWKS cache and refresh single-flight live here.
const auth = createAuth({
  issuer: 'https://auth.factory0.ventures', // exact, and no trailing slash
  clientId: 'client_abc',
  redirectUri: 'https://app.example/auth/callback',
  cookieSecret: env.COOKIE_SECRET, // >= 32 chars; keep it in a secret store
  postLogoutRedirectUri: 'https://app.example/',
});
```

`cookieSecret` must be at least 32 characters and is hashed to the AES-256-GCM
key that seals the state cookie (one value per deployment); `createAuth` throws
at startup otherwise. `issuer` must be the exact base URL with no trailing slash:
the authorize, token, logout and JWKS endpoints are derived from it
(`/v1/auth-core/…`, `/.well-known/jwks.json`), not fetched, so a spoofed
discovery response cannot move them or swap keys. `clientSecret` is only needed
for a confidential client.

## The flow

Plain `Request`/`Response` handlers; nothing here knows about a framework.

**Sign-in.** `startSignIn` builds the authorize URL and returns the `Set-Cookie`
for the state cookie; reuse that `Headers` object for the redirect.

```ts
if (url.pathname === '/auth/sign-in') {
  const { url: authorizeUrl, headers } = await auth.startSignIn({
    returnTo: url.searchParams.get('next') ?? undefined,
  });
  headers.set('Location', authorizeUrl);
  headers.set('Cache-Control', 'no-store');
  return new Response(null, { status: 302, headers });
}
```

**Callback.** `handleCallback` checks the sealed state, redeems the code,
verifies the token and sets the session cookies; it never throws for IdP trouble
— a refused, forged or expired state or a refused code is a generic 400, an
unreachable, timing-out or nonsensical IdP a 502. Every outcome deletes the state
cookie, so a spent code can never be replayed.

```ts
if (url.pathname === '/auth/callback') return auth.handleCallback(request);
```

**Protected routes.** `verify` returns the claims or `null`. On `null`, try
`refresh` first and apply its `Set-Cookie` headers, so a rotated token is stored.

```ts
let claims = await auth.verify(request); // the cookie, or `Authorization: Bearer`
if (!claims) {
  const refreshed = await auth.refresh(request);
  if (!refreshed.claims) return new Response('Unauthorized', { status: 401, headers: refreshed.headers });
  claims = refreshed.claims;
  return new Response(`Hello ${claims.sub}`, { headers: refreshed.headers });
}
return new Response(`Hello ${claims.sub}`);
```

**Sign-out.** Make it a `POST` (see "CSRF and redirects"). `signOut` clears the
app's cookies and redirects to `end_session_endpoint`, where the IdP ends the browser's session.
When the user still has a live IdP session, the IdP's `GET /logout` shows a
"Sign out of this device?" confirmation page and only revokes the session after
the user confirms, then redirects to the registered `post_logout_redirect_uri`
(`crates/auth-core/src/authorize.rs:569-591`).

```ts
if (url.pathname === '/auth/sign-out' && request.method === 'POST') {
  return auth.signOut();
}
```

## Cookies

Every cookie is `__Host-` prefixed (HTTPS-only, whole-origin, no `Domain`), so a
sibling subdomain can neither set nor shadow it. Attributes: `Path=/; Secure; HttpOnly; SameSite=Lax`.

| Cookie | Holds | Lifetime |
|---|---|---|
| `__Host-cf_state` | AES-256-GCM sealed `{ state, PKCE verifier, returnTo, exp }` | 600 s |
| `__Host-cf_at` | the ES256 access token | `min(expires_in, 3600)` s |
| `__Host-cf_rt` | the opaque refresh token | 30 days |

The state cookie is single-use, deleted at the callback — or sign-out — on every
outcome. Its value hides the PKCE verifier, a secret until the code is redeemed,
and the AEAD tag makes a forged `state` or `verifier` impossible to inject.

## Verification

- **ES256 only**, and `alg` is checked *before* any key is looked up, so `none`
  and the HMAC families never reach the key set.
- `iss` must equal the configured issuer exactly; `aud` must equal `clientId`
  (an array-form `aud` is refused, not searched).
- `exp`, `iat` and `nbf` allow 60 seconds of clock leeway.
- The JWKS cache honours the response's `Cache-Control` (clamped to 24 hours). A
  token naming an unknown `kid` triggers one forced refetch, at most once a
  minute, and a failed refetch keeps the previous key set — so invented key ids
  cannot drive outbound traffic, or an unreachable issuer invalidate every live
  session.

## Refresh

Refresh tokens are single-use and reuse revokes the session they were bound to
(`crates/auth-core/src/tokens.rs`, reuse detection). Inside one isolate, concurrent
refreshes with the same token share one call, and a success is remembered for 10
seconds under the *old* token — requests sent before the browser stored the rotated
cookie still carry it, and replaying it would revoke the session.

The grace is a deliberate trade: within the window anyone presenting the old
token gets the rotated pair, suppressing reuse detection for that long — kept short
so the blind spot is smaller than the round trip it covers. Cross-isolate races
are not handled here; only the IdP sees both, and CF13 handles them server-side.

A **4xx** refusal clears the cookies and signs the user out; a **transport error
or 5xx** throws — never sign a user out over an IdP blip, the next request retries.
Every IdP fetch has a 10-second timeout so a hung issuer cannot hold refresh forever.

## CSRF and redirects

`SameSite=Lax` stops a cross-site `POST` carrying the session cookies, but the
consumer must also check `Origin` on every mutating route — including sign-out,
which is why it should be a `POST` and not a link: a cross-site `GET` would
otherwise end the session (login CSRF).

`returnTo` is sanitised to a same-origin relative path and re-checked after
normalisation, so `/foo/..//evil.com` collapses to `/`. Anything that is not a
single-leading-slash path, or that contains a backslash or control character,
also collapses. The callback can never be an open redirect.

## What the IdP does not do

The client does not either, because the issuer does not:

- **No `nonce`, no `id_token`.** The access token is the only token and no nonce is sent.
- **`ui_locales` is forwarded, but the login UI does not use it yet.**
- **No "sign out everywhere".** `signOut` ends the current IdP session through
  `end_session_endpoint` only; `/logout-all` takes the IdP's own cookie, which a
  cross-origin app cannot send — tracked separately.
- **A revoked session's access token stays valid until `exp`** — refreshing
  stops immediately, but local verification is good for up to 10 minutes, the
  gap ADR [0201](../adr/0201-token-issuing.md) accepts so apps stay up when the IdP is down.

Next.js route helpers and a runnable example app are out of scope (CF12).

## Publishing

`@cratefield/auth` is published from `packages/auth-ts` by
`.github/workflows/publish-auth-ts.yml`: a tag `auth-ts-v<version>` publishes
with npm trusted publishing (GitHub OIDC, no `NPM_TOKEN`), and the same workflow
runs the typecheck, tests and a `--dry-run` publish on every pull request that
touches the package.
