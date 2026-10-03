import { afterEach, describe, expect, it, vi } from 'vitest';
import { createHarness } from './fake-idp.js';
import { cookieAttributes, cookieValue, requestWithCookies } from './http-helpers.js';

const REFRESH_COOKIE = '__Host-cf_rt';

function refreshRequest(refreshToken: string) {
  return requestWithCookies('https://app.example/', { [REFRESH_COOKIE]: refreshToken });
}

function tokenCalls(idp: { calls: Array<{ url: string }>; tokenUrl: string }): number {
  return idp.calls.filter((call) => call.url === idp.tokenUrl).length;
}

afterEach(() => {
  vi.useRealTimers();
});

describe('refresh', () => {
  it('returns nothing usable when there is no refresh cookie', async () => {
    const { auth } = await createHarness();
    const result = await auth.refresh(new Request('https://app.example/'));
    expect(result.claims).toBeNull();
    expect(result.accessToken).toBeUndefined();
    expect(result.headers.get('Set-Cookie')).toBeNull();
  });

  it('rotates the cookies on success', async () => {
    const { auth, idp, config } = await createHarness({ config: { clientSecret: 'shh' } });
    const result = await auth.refresh(refreshRequest('rt_old'));

    expect(result.claims).toMatchObject({ sub: 'user_1', sid: 'sess_1' });
    expect(result.accessToken).toBe(cookieValue(result.headers, '__Host-cf_at'));
    expect(cookieAttributes(result.headers, '__Host-cf_at')['Max-Age']).toBe('600');
    expect(cookieValue(result.headers, REFRESH_COOKIE)).toBe('rt_1');
    expect(cookieAttributes(result.headers, REFRESH_COOKIE)['Max-Age']).toBe(String(30 * 24 * 60 * 60));

    const body = idp.lastTokenParams()!;
    expect(body.get('grant_type')).toBe('refresh_token');
    expect(body.get('refresh_token')).toBe('rt_old');
    expect(body.get('client_id')).toBe(config.clientId);
    expect(body.get('client_secret')).toBe('shh');
  });

  it('single-flights N concurrent refreshes of the same token', async () => {
    const { auth, idp } = await createHarness();
    const results = await Promise.all(
      Array.from({ length: 20 }, () => auth.refresh(refreshRequest('rt_old'))),
    );
    expect(tokenCalls(idp)).toBe(1);
    for (const result of results) {
      expect(result.claims?.sub).toBe('user_1');
      expect(cookieValue(result.headers, REFRESH_COOKIE)).toBe('rt_1');
    }
  });

  it('reuses a recent success within the grace window', async () => {
    const { auth, idp } = await createHarness();
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
    await auth.refresh(refreshRequest('rt_old'));
    expect(tokenCalls(idp)).toBe(1);

    // 9s later a request the browser sent before it saw the new cookie still
    // carries the old token; it must not be replayed to the IdP.
    vi.setSystemTime(new Date('2026-01-01T00:00:09Z'));
    const late = await auth.refresh(refreshRequest('rt_old'));
    expect(late.claims?.sub).toBe('user_1');
    expect(tokenCalls(idp)).toBe(1);
  });

  it('calls the IdP again after the grace window', async () => {
    const { auth, idp } = await createHarness();
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
    await auth.refresh(refreshRequest('rt_old'));
    vi.setSystemTime(new Date('2026-01-01T00:00:11Z'));
    await auth.refresh(refreshRequest('rt_old'));
    expect(tokenCalls(idp)).toBe(2);
  });

  it('clears the session cookies on a 400 refusal', async () => {
    const { auth, idp } = await createHarness();
    idp.refuseRefresh = true;
    const result = await auth.refresh(refreshRequest('rt_dead'));

    expect(result.claims).toBeNull();
    expect(cookieAttributes(result.headers, '__Host-cf_at')['Max-Age']).toBe('0');
    expect(cookieAttributes(result.headers, REFRESH_COOKIE)['Max-Age']).toBe('0');
  });

  it('does not cache a refusal, so the next call retries', async () => {
    const { auth, idp } = await createHarness();
    idp.refuseRefresh = true;
    await auth.refresh(refreshRequest('rt_dead'));
    await auth.refresh(refreshRequest('rt_dead'));
    expect(tokenCalls(idp)).toBe(2);
  });

  it('throws on a 5xx and retries on the next call', async () => {
    const { auth, idp } = await createHarness();
    idp.tokenStatus = 503;
    await expect(auth.refresh(refreshRequest('rt_old'))).rejects.toThrow(/503/);
    idp.tokenStatus = 200;
    const result = await auth.refresh(refreshRequest('rt_old'));
    expect(result.claims).not.toBeNull();
    expect(tokenCalls(idp)).toBe(2);
  });

  it('throws on a token response whose cookies would be unsafe to set', async () => {
    const { auth, idp } = await createHarness();
    idp.tokenBodyOverride = { refresh_token: 'bad token; x=y' };
    await expect(auth.refresh(refreshRequest('rt_old'))).rejects.toThrow(/usable token/);
  });

  it('clears the cookies when the new access token fails verification', async () => {
    const { auth, idp } = await createHarness();
    idp.accessClaims = { aud: 'someone-else' };
    const result = await auth.refresh(refreshRequest('rt_old'));
    expect(result.claims).toBeNull();
    expect(cookieAttributes(result.headers, '__Host-cf_at')['Max-Age']).toBe('0');
  });
});
