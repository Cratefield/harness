import { describe, expect, it } from 'vitest';
import { createNextAuth, isProtected, isSameOrigin, returnToFor } from '../src/next.js';
import { createHarness, type Harness } from './fake-idp.js';
import { cookieAttributes, cookieValue, requestWithCookies } from './http-helpers.js';
import { setStubCookies } from './next-headers-stub.js';

const APP = 'https://app.example';
const AT = '__Host-cf_at';
const RT = '__Host-cf_rt';
const STATE = '__Host-cf_state';

/** A harness plus a NextAuth and the middleware under test. */
async function setup(): Promise<Harness & { next: ReturnType<typeof createNextAuth>; middleware: (r: Request) => Promise<Response | undefined> }> {
  const harness = await createHarness();
  const next = createNextAuth(harness.auth);
  const middleware = next.authMiddleware({ protect: ['/app'], signInPath: '/sign-in' });
  return { ...harness, next, middleware };
}

/** POST with explicit headers, so Origin/Sec-Fetch-Site/Cookie can be set. */
function post(path: string, headers: Record<string, string>): Request {
  return new Request(`${APP}${path}`, { method: 'POST', headers });
}

describe('isProtected', () => {
  it('matches a prefix and its children, not a bare-word sibling', () => {
    expect(isProtected('/app', ['/app'])).toBe(true);
    expect(isProtected('/app/x', ['/app'])).toBe(true);
    expect(isProtected('/app/x/deep', ['/app'])).toBe(true);
    expect(isProtected('/apple', ['/app'])).toBe(false);
    expect(isProtected('/applesauce', ['/app'])).toBe(false);
    expect(isProtected('/', ['/app'])).toBe(false);
  });

  it('normalises a trailing slash on a prefix', () => {
    expect(isProtected('/app', ['/app/'])).toBe(true);
    expect(isProtected('/app/x', ['/app/'])).toBe(true);
    expect(isProtected('/apple', ['/app/'])).toBe(false);
  });

  it("'/' protects everything", () => {
    expect(isProtected('/', ['/'])).toBe(true);
    expect(isProtected('/anything', ['/'])).toBe(true);
  });

  it('returns false for no prefixes and ignores blank entries', () => {
    expect(isProtected('/app', [])).toBe(false);
    expect(isProtected('/app', ['', '  '])).toBe(false);
  });
});

describe('isSameOrigin', () => {
  const url = `${APP}/auth/refresh`;

  it('accepts a matching Origin header and refuses a cross-origin one', () => {
    expect(isSameOrigin(new Request(url, { headers: { Origin: APP } }))).toBe(true);
    expect(isSameOrigin(new Request(url, { headers: { Origin: 'https://evil.example' } }))).toBe(false);
  });

  it('accepts a configured origin when the request host differs', () => {
    const req = new Request('https://internal.example/auth/refresh', { headers: { Origin: APP } });
    expect(isSameOrigin(req, APP)).toBe(true);
    expect(isSameOrigin(req)).toBe(false);
  });

  it('allows a missing Origin only with Sec-Fetch-Site: same-origin', () => {
    expect(isSameOrigin(new Request(url, { headers: { 'Sec-Fetch-Site': 'same-origin' } }))).toBe(true);
    expect(isSameOrigin(new Request(url))).toBe(false);
    expect(isSameOrigin(new Request(url, { headers: { 'Sec-Fetch-Site': 'cross-site' } }))).toBe(false);
  });
});

describe('returnToFor', () => {
  it('keeps the path and query but drops the origin', () => {
    expect(returnToFor(new Request(`${APP}/app/x?y=1`))).toBe('/app/x?y=1');
    expect(returnToFor(new Request(`${APP}/`))).toBe('/');
  });
});

describe('authMiddleware', () => {
  it('lets an unprotected path through', async () => {
    const { middleware } = await setup();
    expect(await middleware(new Request(`${APP}/public`))).toBeUndefined();
  });

  it('lets a request with a valid session through', async () => {
    const { middleware, idp } = await setup();
    const token = await idp.mintAccessToken();
    const req = requestWithCookies(`${APP}/app/x`, { [AT]: token });
    expect(await middleware(req)).toBeUndefined();
  });

  it('redirects a protected path to sign-in with an encoded return_to', async () => {
    const { middleware } = await setup();
    const response = await middleware(new Request(`${APP}/app/x?y=1`));
    expect(response!.status).toBe(302);
    // Absolute (Next's middleware adapter rejects a relative Location); built
    // from the request's own origin, which Next rewrites to a request-relative
    // location on the wire, so a host-rewriting proxy is not an issue.
    const location = new URL(response!.headers.get('Location')!);
    expect(`${location.origin}${location.pathname}`).toBe(`${APP}/sign-in`);
    expect(location.searchParams.get('return_to')).toBe('/app/x?y=1');
    expect(response!.headers.get('Cache-Control')).toBe('no-store');
  });

  it('merges return_to into a signInPath that already has a query', async () => {
    const { auth } = await setup();
    const middleware = createNextAuth(auth).authMiddleware({
      protect: ['/app'],
      signInPath: '/sign-in?tenant=acme',
    });
    const response = await middleware(new Request(`${APP}/app/x?y=1`));
    expect(response!.status).toBe(302);
    const location = new URL(response!.headers.get('Location')!);
    expect(`${location.origin}${location.pathname}`).toBe(`${APP}/sign-in`);
    expect(location.searchParams.get('tenant')).toBe('acme');
    expect(location.searchParams.get('return_to')).toBe('/app/x?y=1');
  });

  it('refreshes an expired access token in place for a GET', async () => {
    const { middleware } = await setup();
    const req = requestWithCookies(`${APP}/app/x?y=1`, { [RT]: 'rt_old' });
    const response = await middleware(req);
    expect(response!.status).toBe(307);
    // Absolute (Next requires it) and same-origin with the request, so Next
    // rewrites it to a request-relative location on the wire: behind a proxy
    // that rewrites the host the browser still stays on its own origin.
    expect(response!.headers.get('Location')).toBe(`${APP}/app/x?y=1`);
    expect(response!.headers.get('Cache-Control')).toBe('no-store');
    // The rotated cookies ride back, so the next request is authenticated.
    expect(cookieAttributes(response!.headers, AT)['Max-Age']).toBe('600');
    expect(cookieValue(response!.headers, RT)).toBe('rt_1');
  });

  it('does not renew in place for a POST, redirecting to sign-in instead', async () => {
    const { middleware } = await setup();
    const req = new Request(`${APP}/app/x`, { method: 'POST', headers: { Cookie: `${RT}=rt_old` } });
    const response = await middleware(req);
    expect(response!.status).toBe(302);
    expect(new URL(response!.headers.get('Location')!).pathname).toBe('/sign-in');
  });

  it('redirects to sign-in when there is no refresh cookie', async () => {
    const { middleware } = await setup();
    const response = await middleware(new Request(`${APP}/app/x`));
    expect(response!.status).toBe(302);
  });

  it('falls back to sign-in when the refresh call itself fails', async () => {
    const { middleware, idp } = await setup();
    idp.tokenStatus = 503;
    const req = requestWithCookies(`${APP}/app/x`, { [RT]: 'rt_old' });
    const response = await middleware(req);
    expect(response!.status).toBe(302);
    expect(new URL(response!.headers.get('Location')!).pathname).toBe('/sign-in');
  });

  it('never guards the sign-in path, even under a "/" prefix', async () => {
    const { auth } = await setup();
    const middleware = createNextAuth(auth).authMiddleware({ protect: ['/'], signInPath: '/sign-in' });
    expect(await middleware(new Request(`${APP}/sign-in`))).toBeUndefined();
    expect((await middleware(new Request(`${APP}/other`)))!.status).toBe(302);
  });

  it('exempts the sign-in path tolerating a trailing slash on either side', async () => {
    const { auth } = await setup();
    // Configured with a trailing slash...
    const trailing = createNextAuth(auth).authMiddleware({ protect: ['/'], signInPath: '/sign-in/' });
    expect(await trailing(new Request(`${APP}/sign-in`))).toBeUndefined();
    expect(await trailing(new Request(`${APP}/sign-in/`))).toBeUndefined();
    // ...and requested with one, against a slashless config.
    const plain = createNextAuth(auth).authMiddleware({ protect: ['/'], signInPath: '/sign-in' });
    expect(await plain(new Request(`${APP}/sign-in/`))).toBeUndefined();
  });
});

describe('handlers.start', () => {
  it('redirects to the IdP with the state cookie set', async () => {
    const { next, idp } = await setup();
    const response = await next.handlers.start(new Request(`${APP}/auth/start`));
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get('Location')!);
    expect(`${location.origin}${location.pathname}`).toBe(idp.authorizeUrl);
    expect(location.searchParams.get('response_type')).toBe('code');
    expect(cookieAttributes(response.headers, STATE)['Max-Age']).toBe('600');
    expect(response.headers.get('Cache-Control')).toBe('no-store');
  });

  /** Run `start`, then replay the sealed state through the callback. */
  async function startThenCallback(returnTo: string | undefined): Promise<Response> {
    const { next, idp } = await setup();
    const url = new URL(`${APP}/auth/start`);
    if (returnTo !== undefined) url.searchParams.set('return_to', returnTo);
    const started = await next.handlers.start(new Request(url));
    const state = new URL(started.headers.get('Location')!).searchParams.get('state')!;
    const sealed = cookieValue(started.headers, STATE)!;
    return next.handlers.callback(
      new Request(`${idp.issuer}/auth/callback?code=the-code&state=${state}`, {
        headers: { Cookie: `${STATE}=${sealed}` },
      }),
    );
  }

  it('carries a relative return_to through the sealed state', async () => {
    const done = await startThenCallback('/dashboard?tab=1');
    expect(done.status).toBe(302);
    expect(done.headers.get('Location')).toBe('/dashboard?tab=1');
  });

  it.each([
    ['an absolute URL', 'https://evil.example/x'],
    ['a protocol-relative URL', '//evil.example'],
    ['a backslash', '/\\evil.example'],
    ['a javascript: URL', 'javascript:alert(1)'],
  ])('sanitises %s in return_to to "/"', async (_label, hostile) => {
    const done = await startThenCallback(hostile);
    expect(done.status).toBe(302);
    expect(done.headers.get('Location')).toBe('/');
  });
});

describe('handlers.callback', () => {
  it('delegates to the client and refuses without a state cookie', async () => {
    const { next, idp } = await setup();
    const response = await next.handlers.callback(
      new Request(`${idp.issuer}/auth/callback?code=c&state=x`),
    );
    expect(response.status).toBe(400);
  });
});

describe('handlers.refresh', () => {
  const url = '/auth/refresh';

  it('refuses a cross-origin request', async () => {
    const { next } = await setup();
    const response = await next.handlers.refresh(
      post(url, { Origin: 'https://evil.example', Cookie: `${RT}=rt_old` }),
    );
    expect(response.status).toBe(403);
    expect(response.headers.get('Set-Cookie')).toBeNull();
  });

  it('refuses a request with no Origin and no same-origin fetch metadata', async () => {
    const { next } = await setup();
    const response = await next.handlers.refresh(post(url, { Cookie: `${RT}=rt_old` }));
    expect(response.status).toBe(403);
  });

  it('accepts a same-origin request and rotates the cookies (204)', async () => {
    const { next } = await setup();
    const response = await next.handlers.refresh(post(url, { Origin: APP, Cookie: `${RT}=rt_old` }));
    expect(response.status).toBe(204);
    expect(cookieAttributes(response.headers, AT)['Max-Age']).toBe('600');
    expect(cookieValue(response.headers, RT)).toBe('rt_1');
  });

  it('accepts Sec-Fetch-Site: same-origin without an Origin header', async () => {
    const { next } = await setup();
    const response = await next.handlers.refresh(
      post(url, { 'Sec-Fetch-Site': 'same-origin', Cookie: `${RT}=rt_old` }),
    );
    expect(response.status).toBe(204);
  });

  it('answers 401 with cleared cookies when the refresh is refused', async () => {
    const { next, idp } = await setup();
    idp.refuseRefresh = true;
    const response = await next.handlers.refresh(post(url, { Origin: APP, Cookie: `${RT}=rt_dead` }));
    expect(response.status).toBe(401);
    expect(cookieAttributes(response.headers, AT)['Max-Age']).toBe('0');
    expect(cookieAttributes(response.headers, RT)['Max-Age']).toBe('0');
  });

  it('answers 401 without cookies when there is nothing to refresh', async () => {
    const { next } = await setup();
    const response = await next.handlers.refresh(post(url, { Origin: APP }));
    expect(response.status).toBe(401);
    expect(response.headers.get('Set-Cookie')).toBeNull();
  });

  it('answers 502 on an IdP outage without clearing the session', async () => {
    const { next, idp } = await setup();
    idp.tokenStatus = 503;
    const response = await next.handlers.refresh(post(url, { Origin: APP, Cookie: `${RT}=rt_old` }));
    expect(response.status).toBe(502);
    expect(response.headers.get('Set-Cookie')).toBeNull();
  });
});

describe('handlers.logout', () => {
  it('refuses a cross-origin request', async () => {
    const { next } = await setup();
    const response = await next.handlers.logout(post('/auth/logout', { Origin: 'https://evil.example' }));
    expect(response.status).toBe(403);
  });

  it('ends the session for a same-origin request', async () => {
    const { next, idp } = await setup();
    const response = await next.handlers.logout(post('/auth/logout', { Origin: APP }));
    expect(response.status).toBe(302);
    expect(new URL(response.headers.get('Location')!).origin + new URL(response.headers.get('Location')!).pathname).toBe(
      idp.logoutUrl,
    );
    expect(cookieAttributes(response.headers, AT)['Max-Age']).toBe('0');
  });
});

describe('getSession', () => {
  it('verifies the access cookie read through next/headers', async () => {
    const { next, idp } = await setup();
    setStubCookies({ [AT]: await idp.mintAccessToken() });
    expect(await next.getSession()).toMatchObject({ sub: 'user_1', sid: 'sess_1' });
  });

  it('returns null without a cookie or with an unverifiable one', async () => {
    const { next } = await setup();
    setStubCookies({});
    expect(await next.getSession()).toBeNull();
    setStubCookies({ [AT]: 'not-a-jwt' });
    expect(await next.getSession()).toBeNull();
  });

  it('accepts an AuthConfig and builds the client itself', async () => {
    const { config, idp } = await createHarness();
    const next = createNextAuth(config);
    setStubCookies({ [AT]: await idp.mintAccessToken() });
    expect(await next.getSession()).toMatchObject({ sub: 'user_1' });
  });
});
