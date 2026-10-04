// @cratefield/auth/next: the Next.js (app-router) glue over the
// framework-agnostic AuthClient.
//
// Nothing here imports `next/server`. The middleware and the route handlers
// work on the Web `Request`/`Response` types — a `NextRequest` *is* a
// `Request`, and a middleware may return a `Response` or `undefined` to
// continue. The only Next-specific piece is `getSession`, which reads the
// access cookie through `next/headers`.
//
// `next` is an optional peer dependency (see package.json), so an app that
// only uses the core entry point never pulls it in.

import { createAuth, type Auth, type AuthConfig, type RefreshResult } from './client.js';
import { ACCESS_COOKIE, REFRESH_COOKIE, readCookie } from './cookies.js';
import type { Claims } from './jwt.js';
import { sanitizeReturnTo } from './util.js';
import { cookies } from 'next/headers';

/** Options for {@link createNextAuth}. */
export interface NextAuthOptions {
  /**
   * The app's public origin, when it differs from `new URL(request.url).origin`
   * — the usual case behind a proxy or tunnel that rewrites the request host.
   * Used only by the same-origin check on the state-changing handlers.
   */
  origin?: string;
}

/** Route handlers, shaped to hand straight to app-router route files. */
export interface NextAuthHandlers {
  /** `GET`: begin a sign-in, redirecting to the IdP. Reads `return_to`. */
  start(request: Request): Promise<Response>;
  /** `GET`: exchange the code and start the session. */
  callback(request: Request): Promise<Response>;
  /** `POST`: rotate the session cookies. Same-origin only. */
  refresh(request: Request): Promise<Response>;
  /** `POST`: end the browser's session. Same-origin only. */
  logout(request: Request): Promise<Response>;
}

/** The Next.js helpers bound to one {@link Auth}. */
export interface NextAuth {
  /**
   * Build the middleware. Returns `undefined` to let a request continue, or a
   * redirect to protect it.
   *
   * `signInPath` must NOT appear under any `protect` prefix: the middleware
   * always lets that exact path through, so a caller who lists it anyway
   * cannot create a redirect loop. `protect: ['/']` protects everything else.
   */
  authMiddleware(options: {
    protect: readonly string[];
    signInPath: string;
  }): (request: Request) => Promise<Response | undefined>;
  /** The verified access-token claims, or `null` when there is no session. */
  getSession(): Promise<Claims | null>;
  handlers: NextAuthHandlers;
}

/**
 * Create the Next.js helpers for an app.
 *
 * Pass the module-scoped {@link Auth} you already built, or an
 * {@link AuthConfig} to build one here (which throws on a configuration
 * error, same as `createAuth`).
 */
export function createNextAuth(authOrConfig: Auth | AuthConfig, options: NextAuthOptions = {}): NextAuth {
  const auth: Auth = isAuth(authOrConfig) ? authOrConfig : createAuth(authOrConfig);

  function authMiddleware({
    protect,
    signInPath,
  }: {
    protect: readonly string[];
    signInPath: string;
  }): (request: Request) => Promise<Response | undefined> {
    return async (request: Request): Promise<Response | undefined> => {
      const url = new URL(request.url);
      if (!isProtected(url.pathname, protect)) return undefined;
      // Never guard the sign-in route itself: redirecting to it from itself
      // is a loop. Resolve `signInPath` (which may be relative) first, then
      // compare as exact paths, tolerating a trailing slash on either side.
      if (isSamePath(url.pathname, new URL(signInPath, url).pathname)) return undefined;

      const claims = await auth.verify(request);
      if (claims) return undefined;

      // An expired *access* token with a live refresh cookie is a routine
      // continuation, not a sign-out. Only safe methods are renewed in place,
      // so a form POST is never silently replayed against a fresh session.
      const method = request.method.toUpperCase();
      if ((method === 'GET' || method === 'HEAD') && readCookie(request, REFRESH_COOKIE) !== undefined) {
        let renewed: RefreshResult | null = null;
        try {
          renewed = await auth.refresh(request);
        } catch {
          // IdP outage: fall through to the sign-in redirect rather than
          // failing the request with a 500.
          renewed = null;
        }
        if (renewed?.claims) {
          // Bounce back to the same URL with the rotated cookies attached, so
          // the browser's very next request is already authenticated. The
          // Location is absolute because Next's middleware adapter rejects a
          // relative one ("Please use only absolute URLs"); it is built from
          // the request's own URL, so Next rewrites it to a request-relative
          // location on the wire and the browser stays on whatever origin it
          // used — echoing a *configured* origin is what would leak the
          // internal host behind a proxy.
          // If the browser does not store the rotated cookies this repeats
          // until its redirect cap (~20) or the IdP's refresh-reuse detection
          // ends the session.
          const headers = new Headers();
          copySetCookies(renewed.headers, headers);
          headers.set('Location', request.url);
          headers.set('Cache-Control', 'no-store');
          return new Response(null, { status: 307, headers });
        }
      }

      return signInRedirect(request, signInPath);
    };
  }

  const handlers: NextAuthHandlers = {
    start: async (request: Request): Promise<Response> => {
      const url = new URL(request.url);
      const returnTo = sanitizeReturnTo(url.searchParams.get('return_to'));
      const { url: authorizeUrl, headers } = await auth.startSignIn({ returnTo });
      headers.set('Location', authorizeUrl);
      headers.set('Cache-Control', 'no-store');
      return new Response(null, { status: 302, headers });
    },
    callback: (request: Request): Promise<Response> => auth.handleCallback(request),
    refresh: async (request: Request): Promise<Response> => {
      if (!isSameOrigin(request, options.origin)) return forbidden();
      let result;
      try {
        result = await auth.refresh(request);
      } catch {
        // 5xx from the IdP: do not clear the session over an outage.
        return new Response(null, { status: 502 });
      }
      // On success the rotation cookies ride along; on a refusal (or no
      // cookie at all) any cookie-clearing headers ride along and the status
      // tells the client the session is over.
      const headers = new Headers();
      copySetCookies(result.headers, headers);
      return new Response(null, { status: result.claims ? 204 : 401, headers });
    },
    logout: async (request: Request): Promise<Response> => {
      if (!isSameOrigin(request, options.origin)) return forbidden();
      return auth.signOut();
    },
  };

  return {
    authMiddleware,
    async getSession(): Promise<Claims | null> {
      // `cookies()` is sync on Next 14 and async on Next 15; `await` covers
      // both. Verify the cookie's value — an access token we cannot verify is
      // not a session.
      const store = await cookies();
      const value = store.get(ACCESS_COOKIE)?.value;
      if (!value) return null;
      return auth.verify(value);
    },
    handlers,
  };
}

/**
 * Is `pathname` inside any of the `protect` prefixes?
 *
 * A prefix matches itself and its children only: `/app` protects `/app` and
 * `/app/x`, never `/apple`. A trailing slash on a prefix is normalised away,
 * and `/` protects everything. Empty entries are ignored.
 */
export function isProtected(pathname: string, protect: readonly string[]): boolean {
  for (const entry of protect) {
    const prefix = normalisePrefix(entry);
    if (prefix === null) continue;
    if (prefix === '/') return true;
    if (pathname === prefix || pathname.startsWith(`${prefix}/`)) return true;
  }
  return false;
}

/** A usable prefix, or `null` for a blank entry. `'/app/'` becomes `'/app'`. */
function normalisePrefix(entry: string): string | null {
  const trimmed = entry.trim();
  if (trimmed === '') return null;
  const prefixed = trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
  return normaliseTrailingSlash(prefixed);
}

/**
 * Two absolute paths are the same route ignoring a trailing slash on either
 * side: `/sign-in` matches `/sign-in/`. Never collapses `/` itself.
 */
function isSamePath(a: string, b: string): boolean {
  return normaliseTrailingSlash(a) === normaliseTrailingSlash(b);
}

/** Strip one trailing slash, keeping `'/'` as-is. */
function normaliseTrailingSlash(path: string): string {
  return path.length > 1 && path.endsWith('/') ? path.slice(0, -1) : path;
}

/**
 * The same-origin check the state-changing handlers (`refresh`, `logout`)
 * apply before touching cookies.
 *
 * Allowed when the `Origin` header equals the request's origin — or the
 * configured `allowedOrigin`, for a proxy where the request host differs.
 * Requests with no `Origin` (some same-origin GETs, older browsers) are
 * allowed only when `Sec-Fetch-Site: same-origin`; anything else is refused.
 */
export function isSameOrigin(request: Request, allowedOrigin?: string): boolean {
  const origin = request.headers.get('Origin');
  if (origin !== null) {
    const expected = allowedOrigin ?? new URL(request.url).origin;
    return origin === (expected.endsWith('/') ? expected.slice(0, -1) : expected);
  }
  return request.headers.get('Sec-Fetch-Site') === 'same-origin';
}

/** The `return_to` value for a request: its path and query, never its origin. */
export function returnToFor(request: Request): string {
  const url = new URL(request.url);
  return `${url.pathname}${url.search}`;
}

/**
 * A 302 to the app's sign-in route, carrying where to come back to.
 *
 * The `Location` is absolute: Next's middleware adapter rejects a relative one
 * ("Please use only absolute URLs") before the response reaches the browser.
 * It is built from the request's own URL, so Next rewrites the header to a
 * request-relative location on the wire, which keeps the browser on whatever
 * origin it used behind a host-rewriting proxy. If `signInPath` carries its
 * own query it is preserved, with `return_to` merged in alongside it.
 */
function signInRedirect(request: Request, signInPath: string): Response {
  const target = new URL(signInPath, request.url);
  target.searchParams.set('return_to', returnToFor(request));
  const headers = new Headers();
  headers.set('Location', target.toString());
  headers.set('Cache-Control', 'no-store');
  return new Response(null, { status: 302, headers });
}

/** The one refusal a cross-origin refresh/logout gets. */
function forbidden(): Response {
  return new Response('Cross-origin request refused.', { status: 403 });
}

/** Copy every `Set-Cookie` from one header set to another. */
function copySetCookies(from: Headers, to: Headers): void {
  for (const cookie of setCookieValues(from)) to.append('Set-Cookie', cookie);
}

/**
 * Read the `Set-Cookie` values out of a `Headers`, portably. `getSetCookie()`
 * exists in Node and workerd; the fallback splits the joined value, which is
 * safe because every cookie this package sets starts with `__Host-`.
 */
function setCookieValues(headers: Headers): string[] {
  const extended = headers as unknown as { getSetCookie?: () => string[] };
  if (typeof extended.getSetCookie === 'function') return extended.getSetCookie();
  const raw = headers.get('Set-Cookie');
  return raw ? raw.split(/,\s*(?=__Host-)/) : [];
}

function isAuth(value: Auth | AuthConfig): value is Auth {
  return typeof (value as Auth).startSignIn === 'function';
}
