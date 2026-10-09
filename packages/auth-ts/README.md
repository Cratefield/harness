# @cratefield/auth

Sign-in, token verification and session refresh for a **Cratefield auth-core**
issuer, for web apps on Workers-style runtimes (Cloudflare Workers, Deno,
browsers) and Node 20+. It is the TypeScript counterpart of the Rust
`auth-client` crate: an authorization-code + PKCE flow with a sealed state
cookie, ES256 access-token verification against the issuer's JWKS, and
single-flight refresh-token rotation.

It has no runtime dependencies and uses only Web-standard APIs (WebCrypto,
Fetch, URL, TextEncoder/TextDecoder, atob/btoa, AbortSignal).

## Install

```sh
npm install @cratefield/auth
```

## Usage

```ts
import { createAuth } from '@cratefield/auth';

// Create once per isolate, at module scope: it holds the JWKS cache and the
// refresh in-flight maps. Endpoints are derived from `issuer` (auth-core pins
// them under /v1/auth-core), so nothing is fetched to discover them.
const auth = createAuth({
  issuer: 'https://auth.example',
  clientId: 'client_abc',
  redirectUri: 'https://app.example/auth/callback',
  cookieSecret: env.COOKIE_SECRET, // >= 32 chars
  postLogoutRedirectUri: 'https://app.example/',
});

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === '/auth/sign-in') {
      const { url: authorizeUrl, headers } = await auth.startSignIn({ returnTo: url.searchParams.get('next') ?? undefined });
      headers.set('Location', authorizeUrl); // startSignIn sets the state cookie
      headers.set('Cache-Control', 'no-store');
      return new Response(null, { status: 302, headers });
    }
    if (url.pathname === '/auth/callback') return auth.handleCallback(request); // verifies, sets session cookies, redirects
    if (url.pathname === '/auth/sign-out') return auth.signOut();

    const claims = await auth.verify(request); // the cookie, or `Authorization: Bearer`
    if (!claims) return new Response('Unauthorized', { status: 401 });
    return new Response(`Hello ${claims.sub}`);
  },
};
```

`verify` returns the token's claims or `null`; `refresh(request)` returns fresh
claims and the `Set-Cookie` headers for a rotated session; `signOut()` returns
a redirect that ends the browser's one session (there is no "sign out
everywhere" browser flow yet).

## Next.js

The `@cratefield/auth/next` subpath adapts the same client to the app router:
route handlers for `start` / `callback` / `refresh` / `logout`, an
`authMiddleware({ protect, signInPath })` for `middleware.ts`, and a
`getSession()` for server components. `next` is an optional peer dependency.

```ts
import { createNextAuth } from '@cratefield/auth/next';

const nextAuth = createNextAuth(auth); // same `auth` as above

// middleware.ts
export const middleware = nextAuth.authMiddleware({ protect: ['/app'], signInPath: '/auth/start' });

// app/api/auth/start/route.ts
export const GET = nextAuth.handlers.start;
```

See [`docs/auth/WEB-APPS.md#nextjs`](../../docs/auth/WEB-APPS.md#nextjs) for the
full integration guide, the cookie layout and the security model.

## Passkey PRF

For browser clients, `getPrfKey` evaluates the WebAuthn `prf` extension over a
set of enrolled passkeys and derives a non-extractable AES-GCM key from the
output — a key the user holds and the server never sees. The enrolled
passkeys come from `GET /v1/auth-passkeys/passkeys/prf`, which returns
`{ passkeys: [{ credentialId, prf, prfSalt }] }` for the signed-in account.
The raw output is
validated (present, 32 bytes — provider support claims are ignored) and
consumed by an HKDF-SHA256 step keyed on a per-purpose `info` string;
`redactPrfResults` turns a ceremony's `clientExtensionResults` into the
`{ prf: { enabled } }` form the server accepts (anything still carrying
`prf.results` is refused with `400`, `auth/passkey-prf-output-rejected`), and
`PrfUnavailableError`
signals an authenticator that could not evaluate.

```ts
import { getPrfKey, hasPrfCapablePasskey } from '@cratefield/auth';

if (hasPrfCapablePasskey(passkeys)) {
  const key = await getPrfKey(
    passkeys.map((p) => p.credentialId),
    passkeys.map((p) => p.prfSalt),
    { info: 'cratefield:sealed-notes:v1' },
  );
}
```

**Always enrol two unlock methods before sealing data**: losing the only
PRF-capable authenticator loses the data, and the server cannot help. See
[`docs/auth/PASSKEYS-PRF.md`](../../docs/auth/PASSKEYS-PRF.md) for the flow,
the capability states and the 2026 provider support matrix.

## License

MIT
