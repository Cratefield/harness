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

Register the app as a client of **its own** auth instance, the way a
venture backend is (see [README.md](README.md), "How an app uses it", and
[MANAGED-INSTANCES.md](MANAGED-INSTANCES.md) step 10): an id, a secret and an
**exact** list of redirect URIs, no wildcards. Register the callback URL *and* the
post-logout URL; the IdP refuses a post-logout URL it does not hold, and `redirectUri` must match byte for byte.

## Setup

```ts
import { createAuth } from '@cratefield/auth';

// One per isolate, at module scope: the JWKS cache and refresh single-flight live here.
const auth = createAuth({
  issuer: 'https://auth.example.com', // your app's own instance: exact, no trailing slash
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
(`logout` and `logout_confirm` in `crates/auth-core/src/authorize.rs`).

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

## Next.js

The `@cratefield/auth/next` subpath adapts the client to the Next.js app
router. `next` is an optional peer dependency (`>=14`): an app that imports
only `@cratefield/auth` never installs it. The middleware and the route
handlers take and return the Web `Request`/`Response` types — nothing in the
subpath imports `next/server`, and a middleware may return a `Response` or
`undefined` to continue. The subpath does statically import `next/headers` (for
`getSession()`), so it loads only inside a Next.js app — but under any Next
runtime: `next dev`, `next start`, and OpenNext on Cloudflare Workers.

```ts
// lib/auth.ts — one per process, at module scope: the JWKS cache and the
// refresh single-flight live on this object.
import { createNextAuth } from '@cratefield/auth/next';

export const nextAuth = createNextAuth({
  issuer: 'https://auth.factory0.ventures', // exact, no trailing slash
  clientId: 'client_abc',
  redirectUri: 'https://app.example/api/auth/callback',
  cookieSecret: process.env.COOKIE_SECRET!, // >= 32 chars
  postLogoutRedirectUri: 'https://app.example/',
});
```

Pass an existing `createAuth(...)` instead of the config if the app already has
one; `createNextAuth` accepts either.

**`middleware.ts`.**

```ts
import { nextAuth } from '@/lib/auth';

export const middleware = nextAuth.authMiddleware({
  protect: ['/dashboard'],
  signInPath: '/api/auth/start',
});

// Let the route handlers through untouched; only app pages are guarded.
export const config = { matcher: ['/((?!api/auth).*)'] };
```

`protect` is a list of path prefixes. A prefix matches itself and its children
only: `/app` covers `/app` and `/app/x` but not `/apple`; a trailing slash is
normalised away, and `/` covers everything. `signInPath` must not fall under
any prefix — the middleware always lets that exact path through, so listing it
cannot create a redirect loop.

For a protected path the middleware verifies the access cookie at the edge. A
valid session continues. If the access cookie is gone or expired but the
refresh cookie is present and the method is `GET` or `HEAD`, it renews the
session in place: a `307` back to the same URL carrying the rotated
`Set-Cookie` headers, so the browser's next request is already authenticated (a
form `POST` is never replayed against a fresh session this way). Otherwise it
`302`s to `signInPath` with the original path and query as `return_to`.

**Route handlers.** Four files, one line each, under `app/api/auth/`:

```ts
// app/api/auth/start/route.ts — 302 to the IdP, sets the sealed state cookie.
export const GET = nextAuth.handlers.start;
// app/api/auth/callback/route.ts — redeems the code, sets the session cookies.
export const GET = nextAuth.handlers.callback;
// app/api/auth/refresh/route.ts — 204 rotated / 401 ended / 403 / 502.
export const POST = nextAuth.handlers.refresh;
// app/api/auth/logout/route.ts — ends the browser's session.
export const POST = nextAuth.handlers.logout;
```

`return_to` is sanitised before it is sealed into the state cookie, so only a
same-site relative path survives. `sanitizeReturnTo` keeps a value only if it
starts with a single `/` (never `//` or `/\`), contains no backslash and no
control character or whitespace, and — after `new URL` has resolved any dot
segments — still starts with a single `/`. `/foo/..//evil.com`, an absolute
`https://evil.com`, `//evil.com`, `javascript:…` and a leading space all
collapse to `/`; the callback can never be an open redirect.

**Same-origin.** `refresh` and `logout` are state-changing, so each checks the
origin before touching cookies (`isSameOrigin`). When the request carries an
`Origin`, it must equal the request's own origin — or the `origin` passed to
`createNextAuth(auth, { origin })`, for a proxy that rewrites the host. With no
`Origin`, only `Sec-Fetch-Site: same-origin` is accepted; anything else is
`403`. Set `origin` behind a proxy or OpenNext, where
`new URL(request.url).origin` is the internal host, not the public one; it is
used only by this check. The middleware's redirects (the in-place-refresh `307`
and the sign-in `302`) use a `Location` absolute and same-origin with the
request — Next rejects a relative one — which Next rewrites to a
request-relative location on the wire, so the browser stays on whatever origin
it used.

**Responses.** `refresh` answers `204` on rotation, `401` with cookie-clearing
headers when the refresh token is refused or absent, `403` cross-origin, and
`502` when the IdP is unreachable (it never clears the session over an outage).
`logout` returns `signOut()`'s response — a `302` that clears the app's cookies
and sends the browser to the IdP's `end_session_endpoint`. Because it is a
`POST`, drive it with a plain `<form method="post" action="/api/auth/logout">`
rather than a link, so a cross-site `GET` cannot end the session.

**`getSession()`.** In server components and route handlers it returns the
verified access-token claims or `null`. It reads the cookie through
`next/headers` and verifies it. A server component cannot set cookies, so an
expired access token is not refreshed there — renewal happens in the middleware
(for `GET`/`HEAD`) or through `POST /api/auth/refresh`.

[`examples/next-auth/`](../../examples/next-auth/) is a minimal app (a home
page, a protected page, sign-in and sign-out) run end to end in CI by a
Playwright test (`.github/workflows/next-auth-e2e.yml`) against a local
auth-worker under `wrangler dev`. Register the client as `kind: "public"` (no
secret) for the `http://localhost` redirect URIs, and register
`http://localhost:3000/` as a post-logout redirect URI too: the IdP refuses a
post-logout URL it does not hold.

## Publishing

`@cratefield/auth` is published from `packages/auth-ts` by
`.github/workflows/publish-auth-ts.yml`: a tag `auth-ts-v<version>` publishes
with npm trusted publishing (GitHub OIDC, no `NPM_TOKEN`), and the same workflow
runs the typecheck, tests and a `--dry-run` publish on every pull request that
touches the package.
