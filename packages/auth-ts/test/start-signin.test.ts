import { describe, expect, it } from 'vitest';
import { createAuth } from '../src/index.js';
import { createHarness } from './fake-idp.js';
import { cookieAttributes, cookieValue } from './http-helpers.js';

describe('startSignIn', () => {
  it('builds an authorize URL with exactly the code-flow parameters', async () => {
    const { auth, idp, config } = await createHarness();
    const { url, headers } = await auth.startSignIn();

    const parsed = new URL(url);
    expect(`${parsed.origin}${parsed.pathname}`).toBe(idp.authorizeUrl);
    expect(parsed.searchParams.get('response_type')).toBe('code');
    expect(parsed.searchParams.get('client_id')).toBe(config.clientId);
    expect(parsed.searchParams.get('redirect_uri')).toBe(config.redirectUri);
    expect(parsed.searchParams.get('code_challenge')).toHaveLength(43);
    expect(parsed.searchParams.get('code_challenge_method')).toBe('S256');
    expect(parsed.searchParams.get('state')).toHaveLength(43);
    // The IdP has no nonce and no id_token; sending one would be wrong.
    expect(parsed.searchParams.has('nonce')).toBe(false);

    const attributes = cookieAttributes(headers, '__Host-cf_state');
    expect(attributes['Path']).toBe('/');
    expect(attributes['Max-Age']).toBe('600');
    expect(attributes['SameSite']).toBe('Lax');
    expect(attributes).toHaveProperty('Secure');
    expect(attributes).toHaveProperty('HttpOnly');
    expect(attributes).not.toHaveProperty('Domain');
  });

  it('seals the state cookie so the verifier is not readable', async () => {
    const { auth } = await createHarness();
    const { headers } = await auth.startSignIn();
    const value = cookieValue(headers, '__Host-cf_state')!;
    expect(value).not.toContain('verifier');
    expect(value).not.toContain('returnTo');
  });

  it('forwards ui_locales only when asked', async () => {
    const { auth } = await createHarness();
    const withLocales = new URL((await auth.startSignIn({ uiLocales: 'fr-CA' })).url);
    expect(withLocales.searchParams.get('ui_locales')).toBe('fr-CA');
    const without = new URL((await auth.startSignIn()).url);
    expect(without.searchParams.has('ui_locales')).toBe(false);
  });

  it('carries a sanitised returnTo into the state cookie', async () => {
    const { auth, idp } = await createHarness();
    const { url, headers } = await auth.startSignIn({ returnTo: '/dashboard?tab=1' });
    const state = new URL(url).searchParams.get('state')!;

    // Replay the sealed cookie through the callback and check where it lands.
    const sealed = cookieValue(headers, '__Host-cf_state')!;
    const callbackUrl = `${idp.issuer}/auth/callback?code=the-code&state=${encodeURIComponent(state)}`;
    const response = await auth.handleCallback(
      new Request(callbackUrl, { headers: { Cookie: `__Host-cf_state=${sealed}` } }),
    );
    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe('/dashboard?tab=1');
  });

  it('sanitises a hostile returnTo at sign-in time', async () => {
    const { auth, idp } = await createHarness();
    const { url, headers } = await auth.startSignIn({ returnTo: '//evil.com' });
    const state = new URL(url).searchParams.get('state')!;
    const sealed = cookieValue(headers, '__Host-cf_state')!;
    const response = await auth.handleCallback(
      new Request(`${idp.issuer}/cb?code=c&state=${state}`, {
        headers: { Cookie: `__Host-cf_state=${sealed}` },
      }),
    );
    expect(response.headers.get('Location')).toBe('/');
  });

  it('derives the authorize endpoint from the issuer without any discovery fetch', async () => {
    const { auth, idp } = await createHarness();
    await auth.startSignIn();
    expect(idp.calls.map((call) => call.url)).toEqual([]);
  });

  it('refuses a cookie secret shorter than 32 characters', async () => {
    const { config } = await createHarness();
    expect(() => createAuth({ ...config, cookieSecret: 'too-short' })).toThrow(/32/);
  });

  it('refuses an issuer that is not an http(s) URL or ends with a slash', async () => {
    const { config } = await createHarness();
    expect(() => createAuth({ ...config, issuer: 'auth.example' })).toThrow(/http\(s\)/);
    expect(() => createAuth({ ...config, issuer: 'ftp://auth.example' })).toThrow(/http\(s\)/);
    expect(() => createAuth({ ...config, issuer: 'https://auth.example/' })).toThrow(/slash/);
  });
});
