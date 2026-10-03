import { afterEach, describe, expect, it, vi } from 'vitest';
import { b64urlDecode, b64urlEncode, utf8Encode } from '../src/base64url.js';
import type { FakeIdp } from './fake-idp.js';
import { createHarness } from './fake-idp.js';

/** An HS256 token whose "key" is the public JWK's x coordinate — the classic
 *  algorithm-confusion attack: if verification honoured the header's alg, the
 *  public key we just fetched would be used as an HMAC secret. */
async function hs256Confusion(idp: FakeIdp, kid: string): Promise<string> {
  const header = b64urlEncode(utf8Encode(JSON.stringify({ alg: 'HS256', kid })));
  const payload = b64urlEncode(utf8Encode(JSON.stringify(idp.defaultClaims())));
  const key = await crypto.subtle.importKey(
    'raw',
    b64urlDecode(idp.publicJwk.x!),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, utf8Encode(`${header}.${payload}`)));
  return `${header}.${payload}.${b64urlEncode(signature)}`;
}

afterEach(() => {
  vi.useRealTimers();
});

describe('verify', () => {
  it('accepts a valid token from a string', async () => {
    const { auth, idp } = await createHarness();
    const claims = await auth.verify(await idp.mintAccessToken());
    expect(claims).toMatchObject({ sub: 'user_1', aud: idp.clientId, iss: idp.issuer, sid: 'sess_1' });
  });

  it('reads the access-token cookie from a request', async () => {
    const { auth, idp } = await createHarness();
    const token = await idp.mintAccessToken();
    const request = new Request('https://app.example/', { headers: { Cookie: `__Host-cf_at=${token}` } });
    expect(await auth.verify(request)).not.toBeNull();
  });

  it('falls back to the Authorization header', async () => {
    const { auth, idp } = await createHarness();
    const token = await idp.mintAccessToken();
    const request = new Request('https://app.example/', { headers: { Authorization: `Bearer ${token}` } });
    expect(await auth.verify(request)).not.toBeNull();
  });

  it('returns null when there is no token at all', async () => {
    const { auth } = await createHarness();
    expect(await auth.verify(new Request('https://app.example/'))).toBeNull();
    expect(await auth.verify('')).toBeNull();
  });

  it('refuses a token expired beyond the leeway and accepts one within it', async () => {
    const { auth, idp } = await createHarness();
    const now = Math.floor(Date.now() / 1000);
    expect(await auth.verify(await idp.mintAccessToken({ exp: now - 61 }))).toBeNull();
    expect(await auth.verify(await idp.mintAccessToken({ exp: now - 30 }))).not.toBeNull();
  });

  it('refuses a token issued in the future', async () => {
    const { auth, idp } = await createHarness();
    const now = Math.floor(Date.now() / 1000);
    expect(await auth.verify(await idp.mintAccessToken({ iat: now + 61 }))).toBeNull();
    expect(await auth.verify(await idp.mintAccessToken({ iat: now + 30 }))).not.toBeNull();
  });

  it('refuses a signature forged by another key under the same kid', async () => {
    const { auth, idp } = await createHarness();
    const other = await createHarness({ idp: { kid: idp.kid, issuer: idp.issuer, clientId: idp.clientId } });
    expect(await auth.verify(await other.idp.mintAccessToken())).toBeNull();
  });

  it("refuses alg: none", async () => {
    const { auth, idp } = await createHarness();
    const header = b64urlEncode(utf8Encode(JSON.stringify({ alg: 'none', kid: idp.kid })));
    const payload = b64urlEncode(utf8Encode(JSON.stringify(idp.defaultClaims())));
    expect(await auth.verify(`${header}.${payload}.`)).toBeNull();
  });

  it('refuses an HS256 token signed with the public key', async () => {
    const { auth, idp } = await createHarness();
    expect(await auth.verify(await hs256Confusion(idp, idp.kid))).toBeNull();
  });

  it('refuses the wrong audience and the wrong issuer', async () => {
    const { auth, idp } = await createHarness();
    expect(await auth.verify(await idp.mintAccessToken({ aud: 'other-client' }))).toBeNull();
    expect(await auth.verify(await idp.mintAccessToken({ iss: 'https://other.example' }))).toBeNull();
  });

  it('refuses malformed tokens without throwing', async () => {
    const { auth } = await createHarness();
    for (const token of ['', 'not-a-token', 'only.two', 'a.b.c.d', '!!!.@@@.###']) {
      await expect(auth.verify(token)).resolves.toBeNull();
    }
  });

  it('refetches the JWKS when a token names a new kid, and verifies it', async () => {
    const { auth, idp } = await createHarness();
    expect(await auth.verify(await idp.mintAccessToken())).not.toBeNull();
    await idp.rotate('key-2');
    expect(await auth.verify(await idp.mintAccessToken())).not.toBeNull();
    expect(idp.jwksFetches()).toBeGreaterThanOrEqual(2);
  });

  it('rate-limits the unknown-kid refetch to once per minute', async () => {
    const { auth, idp } = await createHarness();
    await auth.verify(await idp.mintAccessToken()); // warm the cache (fetch 1)
    const ghost = await idp.sign(idp.defaultClaims(), { kid: 'ghost' });
    expect(await auth.verify(ghost)).toBeNull(); // forces a refetch (fetch 2)
    const afterFirst = idp.jwksFetches();

    expect(await auth.verify(ghost)).toBeNull();
    expect(idp.jwksFetches()).toBe(afterFirst); // within the minute: no fetch

    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 61_000);
    expect(await auth.verify(ghost)).toBeNull();
    expect(idp.jwksFetches()).toBe(afterFirst + 1);
  });

  it('returns null for an unknown kid when the key set was never fetched', async () => {
    const { auth, idp } = await createHarness();
    idp.jwksStatus = 500;
    expect(await auth.verify(await idp.mintAccessToken())).toBeNull();
  });

  it('honours the JWKS Cache-Control max-age', async () => {
    const { auth, idp } = await createHarness();
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
    idp.jwksCacheControl = 'public, max-age=2';
    const token = await idp.mintAccessToken();
    expect(await auth.verify(token)).not.toBeNull();
    expect(await auth.verify(token)).not.toBeNull();
    expect(idp.jwksFetches()).toBe(1); // still inside the 2s TTL
    vi.setSystemTime(new Date('2026-01-01T00:00:03Z'));
    expect(await auth.verify(token)).not.toBeNull();
    expect(idp.jwksFetches()).toBe(2);
  });

  it('keeps serving the previous key set when a refetch fails', async () => {
    const { auth, idp } = await createHarness();
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
    const token = await idp.mintAccessToken();
    expect(await auth.verify(token)).not.toBeNull();
    // Past the TTL, but the endpoint is now down: the old keys must still work.
    idp.jwksStatus = 500;
    vi.setSystemTime(new Date('2026-01-01T00:06:00Z'));
    expect(await auth.verify(token)).not.toBeNull();
  });

  it('shares one cold JWKS fetch across concurrent verifications', async () => {
    const { auth, idp } = await createHarness();
    const token = await idp.mintAccessToken();
    await Promise.all(Array.from({ length: 8 }, () => auth.verify(token)));
    expect(idp.jwksFetches()).toBe(1);
  });
});
