// The same public API, exercised inside workerd. This is the leg that proves
// the package actually runs where it ships: no Node globals, WebCrypto and
// Fetch only, and a real ES256 verification.
import { describe, expect, it } from 'vitest';
import {
  createAuth,
  codeChallengeS256,
  createCodeVerifier,
  derivePrfKey,
  getPrfKey,
  sanitizeReturnTo,
  type CredentialsContainerLike,
} from '../../src/index.js';
import { FakeIdp } from '../fake-idp.js';
import { cookieValue } from '../http-helpers.js';

describe('workerd runtime', () => {
  it('runs the PKCE and returnTo helpers on WebCrypto', async () => {
    const verifier = createCodeVerifier();
    expect(verifier).toHaveLength(43);
    expect(await codeChallengeS256(verifier)).toHaveLength(43);
    expect(sanitizeReturnTo('//evil.com')).toBe('/');
  });

  it('runs the full sign-in and verify flow', async () => {
    const idp = await FakeIdp.create();
    const auth = createAuth({
      issuer: idp.issuer,
      clientId: idp.clientId,
      redirectUri: 'https://app.example/auth/callback',
      cookieSecret: 'a-cookie-secret-long-enough-for-workerd',
      fetch: idp.fetch,
    });

    const { url, headers } = await auth.startSignIn({ returnTo: '/home' });
    const state = new URL(url).searchParams.get('state')!;
    const sealed = cookieValue(headers, '__Host-cf_state')!;

    const response = await auth.handleCallback(
      new Request(`${idp.issuer}/auth/callback?code=code-1&state=${state}`, {
        headers: { Cookie: `__Host-cf_state=${sealed}` },
      }),
    );
    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe('/home');

    const accessToken = cookieValue(response.headers, '__Host-cf_at')!;
    const claims = await auth.verify(accessToken);
    expect(claims).toMatchObject({ sub: 'user_1', aud: idp.clientId, iss: idp.issuer });
  });

  it('derives a passkey PRF key on WebCrypto', async () => {
    // The ceremony faked; the HKDF derivation below is the real workerd one.
    const prfOutput = crypto.getRandomValues(new Uint8Array(32));
    const credentialId = 'AAA';
    const container: CredentialsContainerLike = {
      async get() {
        return { rawId: new ArrayBuffer(0), getClientExtensionResults: () => ({ prf: { results: { first: prfOutput.buffer } } }) };
      },
    };
    const salt = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    const key = await getPrfKey([credentialId], [salt], { info: 'cratefield:workerd:v1', credentials: container });
    expect(key.extractable).toBe(false);

    const same = await derivePrfKey(prfOutput, 'cratefield:workerd:v1');
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new Uint8Array([1, 2]));
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, same, ciphertext);
    expect([...new Uint8Array(plaintext)]).toEqual([1, 2]);
  });
});
