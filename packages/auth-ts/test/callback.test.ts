import { afterEach, describe, expect, it, vi } from 'vitest';
import { createAuth, type Auth } from '../src/index.js';
import { FakeIdp, createHarness } from './fake-idp.js';
import { cookieAttributes, cookieValue, requestWithCookies } from './http-helpers.js';

/** Run startSignIn and hand back the pieces the callback needs. */
async function begin(auth: Auth, returnTo?: string) {
  const { url, headers } = await auth.startSignIn(returnTo ? { returnTo } : undefined);
  return {
    state: new URL(url).searchParams.get('state')!,
    sealed: cookieValue(headers, '__Host-cf_state')!,
  };
}

function callbackRequest(idp: FakeIdp, params: Record<string, string>, cookies: Record<string, string | undefined>) {
  const url = new URL(`${idp.issuer}/auth/callback`);
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
  return requestWithCookies(url.toString(), cookies);
}

afterEach(() => {
  vi.useRealTimers();
});

describe('handleCallback', () => {
  it('exchanges the code, verifies the token and starts the session', async () => {
    const { auth, idp, config } = await createHarness({ config: { clientSecret: 'shh' } });
    const { state, sealed } = await begin(auth, '/welcome?x=1');

    const response = await auth.handleCallback(
      callbackRequest(idp, { code: 'the-code', state }, { '__Host-cf_state': sealed }),
    );

    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe('/welcome?x=1');
    expect(response.headers.get('Cache-Control')).toBe('no-store');

    const access = cookieAttributes(response.headers, '__Host-cf_at');
    expect(access['Max-Age']).toBe('600');
    expect(access['Path']).toBe('/');
    expect(access).toHaveProperty('Secure');
    expect(access).toHaveProperty('HttpOnly');
    expect(access['SameSite']).toBe('Lax');
    expect(cookieAttributes(response.headers, '__Host-cf_rt')['Max-Age']).toBe(String(30 * 24 * 60 * 60));
    // The one-shot state cookie is cleared in the same response.
    expect(cookieAttributes(response.headers, '__Host-cf_state')['Max-Age']).toBe('0');

    const body = idp.lastTokenParams()!;
    expect(body.get('grant_type')).toBe('authorization_code');
    expect(body.get('code')).toBe('the-code');
    expect(body.get('redirect_uri')).toBe(config.redirectUri);
    expect(body.get('client_id')).toBe(config.clientId);
    expect(body.get('client_secret')).toBe('shh');
    expect(body.get('code_verifier')).toHaveLength(43);
  });

  it('omits client_secret for a public client', async () => {
    const { auth, idp } = await createHarness();
    const { state, sealed } = await begin(auth);
    await auth.handleCallback(callbackRequest(idp, { code: 'c', state }, { '__Host-cf_state': sealed }));
    expect(idp.lastTokenParams()!.has('client_secret')).toBe(false);
  });

  it.each([
    ['a tampered cookie', 'TAMPER'],
    ['a missing cookie', undefined],
  ])('refuses %s without calling the IdP', async (_label, kind) => {
    const { auth, idp } = await createHarness();
    const { state, sealed } = await begin(auth);
    const before = idp.calls.length;
    const cookie = kind === 'TAMPER' ? `${sealed[0] === 'A' ? 'B' : 'A'}${sealed.slice(1)}` : undefined;

    const response = await auth.handleCallback(
      callbackRequest(idp, { code: 'c', state }, { '__Host-cf_state': cookie }),
    );

    expect(response.status).toBe(400);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(await response.text()).toBe('Sign-in could not be completed. Please try again.');
    expect(idp.calls.length).toBe(before);
    // The bad state cookie is cleared.
    expect(cookieAttributes(response.headers, '__Host-cf_state')['Max-Age']).toBe('0');
  });

  it('refuses a mismatched state', async () => {
    const { auth, idp } = await createHarness();
    const { sealed } = await begin(auth);
    const response = await auth.handleCallback(
      callbackRequest(idp, { code: 'c', state: 'not-the-state' }, { '__Host-cf_state': sealed }),
    );
    expect(response.status).toBe(400);
  });

  it('refuses an expired state cookie', async () => {
    const { auth, idp } = await createHarness();
    const { state, sealed } = await begin(auth);
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 601_000);
    const response = await auth.handleCallback(
      callbackRequest(idp, { code: 'c', state }, { '__Host-cf_state': sealed }),
    );
    expect(response.status).toBe(400);
  });

  it('refuses a replay: a second callback with no state cookie', async () => {
    const { auth, idp } = await createHarness();
    const { state, sealed } = await begin(auth);
    const first = await auth.handleCallback(
      callbackRequest(idp, { code: 'c', state }, { '__Host-cf_state': sealed }),
    );
    expect(first.status).toBe(302);
    // The first response deleted the cookie, so the browser sends none.
    const second = await auth.handleCallback(callbackRequest(idp, { code: 'c', state }, {}));
    expect(second.status).toBe(400);
  });

  it('refuses state sealed under a different cookie secret', async () => {
    const { auth, idp, config } = await createHarness();
    const { state, sealed } = await begin(auth);
    const stranger = createAuth({ ...config, cookieSecret: 'a-different-cookie-secret-long-enough' });
    const response = await stranger.handleCallback(
      callbackRequest(idp, { code: 'c', state }, { '__Host-cf_state': sealed }),
    );
    expect(response.status).toBe(400);
  });

  it('refuses an IdP error response', async () => {
    const { auth, idp } = await createHarness();
    const { state, sealed } = await begin(auth);
    const response = await auth.handleCallback(
      callbackRequest(idp, { error: 'access_denied', state }, { '__Host-cf_state': sealed }),
    );
    expect(response.status).toBe(400);
  });

  it('turns an IdP 400 refusal into the same generic 400', async () => {
    const { auth, idp } = await createHarness();
    idp.refuseCode = true;
    const { state, sealed } = await begin(auth);
    const response = await auth.handleCallback(
      callbackRequest(idp, { code: 'c', state }, { '__Host-cf_state': sealed }),
    );
    expect(response.status).toBe(400);
    expect(cookieAttributes(response.headers, '__Host-cf_state')['Max-Age']).toBe('0');
  });

  it('answers 502 on an IdP 5xx and still clears the state cookie', async () => {
    const { auth, idp } = await createHarness();
    idp.tokenStatus = 503;
    const { state, sealed } = await begin(auth);
    const response = await auth.handleCallback(
      callbackRequest(idp, { code: 'c', state }, { '__Host-cf_state': sealed }),
    );
    expect(response.status).toBe(502);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(cookieAttributes(response.headers, '__Host-cf_state')['Max-Age']).toBe('0');
  });

  it('answers 502 on a malformed token response', async () => {
    const { auth, idp } = await createHarness();
    idp.tokenBodyOverride = { access_token: 'has a space' };
    const { state, sealed } = await begin(auth);
    const response = await auth.handleCallback(
      callbackRequest(idp, { code: 'c', state }, { '__Host-cf_state': sealed }),
    );
    expect(response.status).toBe(502);
    expect(cookieAttributes(response.headers, '__Host-cf_state')['Max-Age']).toBe('0');
  });

  it('clamps a long expires_in to one hour', async () => {
    const { auth, idp } = await createHarness();
    idp.accessExpiresIn = 999_999;
    const { state, sealed } = await begin(auth);
    const response = await auth.handleCallback(
      callbackRequest(idp, { code: 'c', state }, { '__Host-cf_state': sealed }),
    );
    expect(response.status).toBe(302);
    expect(cookieAttributes(response.headers, '__Host-cf_at')['Max-Age']).toBe('3600');
  });

  it('refuses a token the IdP signs for another audience', async () => {
    const { auth, idp } = await createHarness();
    idp.accessClaims = { aud: 'someone-else' };
    const { state, sealed } = await begin(auth);
    const response = await auth.handleCallback(
      callbackRequest(idp, { code: 'c', state }, { '__Host-cf_state': sealed }),
    );
    expect(response.status).toBe(400);
    expect(response.headers.get('Set-Cookie')).toBeDefined();
  });
});
