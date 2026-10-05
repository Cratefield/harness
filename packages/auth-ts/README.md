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

## License

MIT
