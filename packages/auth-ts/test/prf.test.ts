import { hkdfSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  PrfUnavailableError,
  derivePrfKey,
  getPrfKey,
  hasPrfCapablePasskey,
  redactPrfResults,
  type CredentialsContainerLike,
  type PrfClientExtensionResults,
  type PublicKeyCredentialRequestOptionsLike,
} from '../src/index.js';
import { b64urlDecode, b64urlEncode, utf8Encode } from '../src/base64url.js';

/** Bytes of a BufferSource, whatever view or buffer the fake (or a browser) produced. */
function bytes(source: BufferSource): Uint8Array {
  return ArrayBuffer.isView(source)
    ? new Uint8Array(source.buffer, source.byteOffset, source.byteLength)
    : new Uint8Array(source);
}

function b64(bytesIn: Uint8Array): string {
  return b64urlEncode(bytesIn);
}

/** 0x00..0x1f, 32 bytes — the fixed PRF output of the fake authenticator. */
const PRF_OUTPUT = Uint8Array.from({ length: 32 }, (_byte, i) => i);

const ID_1 = b64(Uint8Array.from({ length: 32 }, (_byte, i) => i + 1));
const ID_2_BYTES = Uint8Array.from({ length: 32 }, (_byte, i) => i + 33);
const ID_2 = b64(ID_2_BYTES);
// Padded on purpose: the helper must normalise evalByCredential keys to unpadded base64url.
// (42 unpadded chars + '==' is decodable; a 43-char id with padding would not be.)
const ID_3_BYTES = Uint8Array.from({ length: 31 }, (_byte, i) => i + 65);
const ID_3_PADDED = `${b64(ID_3_BYTES)}==`;
const SALT_1 = b64(Uint8Array.from({ length: 32 }, () => 0xab));
const SALT_2 = b64(Uint8Array.from({ length: 32 }, () => 0xcd));
const SALT_SHORT = b64(Uint8Array.from({ length: 16 }, () => 0));

/** A credentials container that records the `publicKey` options and answers with fixed extension results. */
function fakeContainer(clientExtensionResults: PrfClientExtensionResults | null) {
  const requests: Array<{
    challenge: Uint8Array;
    userVerification?: string;
    rpId?: string;
    timeout?: number;
    allowCredentials: Array<{ type: string; id: Uint8Array }>;
    extensions: NonNullable<PublicKeyCredentialRequestOptionsLike['extensions']>;
  }> = [];
  const container: CredentialsContainerLike = {
    async get(options) {
      const publicKey = options.publicKey!;
      requests.push({
        challenge: bytes(publicKey.challenge),
        userVerification: publicKey.userVerification,
        rpId: publicKey.rpId,
        timeout: publicKey.timeout,
        allowCredentials: (publicKey.allowCredentials ?? []).map((credential) => ({
          type: credential.type,
          id: bytes(credential.id),
        })),
        extensions: publicKey.extensions!,
      });
      if (!clientExtensionResults) return null;
      return { rawId: new ArrayBuffer(0), getClientExtensionResults: () => clientExtensionResults };
    },
  };
  return { container, requests };
}

function resultsWith(first: Uint8Array | undefined): PrfClientExtensionResults {
  return { prf: { enabled: true, ...(first && { results: { first: first.slice().buffer } }) } };
}

describe('getPrfKey', () => {
  it('sends eval.first for one credential, requires verification, and derives a working key', async () => {
    const { container, requests } = fakeContainer(resultsWith(PRF_OUTPUT));
    const key = await getPrfKey([ID_1], [SALT_1], {
      info: 'cratefield:test:v1',
      rpId: 'example.com',
      timeout: 60_000,
      credentials: container,
    });

    expect(requests).toHaveLength(1);
    const request = requests[0]!;
    expect(request.challenge).toHaveLength(32);
    expect(request.userVerification).toBe('required');
    expect(request.rpId).toBe('example.com');
    expect(request.timeout).toBe(60_000);
    expect(request.allowCredentials).toEqual([{ type: 'public-key', id: b64urlDecode(ID_1) }]);
    expect(bytes(request.extensions!.prf!.eval!.first)).toEqual(b64urlDecode(SALT_1));
    expect(request.extensions!.prf!.evalByCredential).toBeUndefined();

    expect(key.extractable).toBe(false);
    expect(key).toMatchObject({ type: 'secret', algorithm: { name: 'AES-GCM', length: 256 }, usages: ['encrypt', 'decrypt'] });
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new Uint8Array([1, 2, 3]));
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    expect([...new Uint8Array(plaintext)]).toEqual([1, 2, 3]);
  });

  it('sends evalByCredential keyed by unpadded b64url id for several credentials', async () => {
    const { container, requests } = fakeContainer(resultsWith(PRF_OUTPUT));
    await getPrfKey([ID_1, ID_2, ID_3_PADDED], [SALT_1, SALT_2, SALT_1], {
      info: 'cratefield:test:v1',
      credentials: container,
    });

    const prf = requests[0]!.extensions!.prf!;
    expect(prf.eval).toBeUndefined();
    expect(Object.keys(prf.evalByCredential!).sort()).toEqual([ID_1, ID_2, b64(ID_3_BYTES)].sort());
    expect(bytes(prf.evalByCredential![ID_1]!.first)).toEqual(b64urlDecode(SALT_1));
    expect(bytes(prf.evalByCredential![ID_2]!.first)).toEqual(b64urlDecode(SALT_2));
    expect(bytes(prf.evalByCredential![b64(ID_3_BYTES)]!.first)).toEqual(b64urlDecode(SALT_1));
    expect(requests[0]!.allowCredentials.map((credential) => credential.id)).toEqual([
      b64urlDecode(ID_1),
      ID_2_BYTES,
      ID_3_BYTES,
    ]);
  });

  it('draws a fresh challenge for every ceremony', async () => {
    const { container, requests } = fakeContainer(resultsWith(PRF_OUTPUT));
    await getPrfKey([ID_1], [SALT_1], { info: 'cratefield:test:v1', credentials: container });
    await getPrfKey([ID_1], [SALT_1], { info: 'cratefield:test:v1', credentials: container });
    expect(requests[0]!.challenge).not.toEqual(requests[1]!.challenge);
  });

  it('derives the same key from the same output and info', async () => {
    const first = fakeContainer(resultsWith(PRF_OUTPUT));
    const second = fakeContainer(resultsWith(PRF_OUTPUT));
    const key1 = await getPrfKey([ID_1], [SALT_1], { info: 'cratefield:test:v1', credentials: first.container });
    const key2 = await getPrfKey([ID_1], [SALT_1], { info: 'cratefield:test:v1', credentials: second.container });
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key1, new Uint8Array([4, 5, 6]));
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key2, ciphertext);
    expect([...new Uint8Array(plaintext)]).toEqual([4, 5, 6]);
  });

  it('derives a different key for a different info', async () => {
    const key1 = await getPrfKey([ID_1], [SALT_1], {
      info: 'cratefield:purpose-a:v1',
      credentials: fakeContainer(resultsWith(PRF_OUTPUT)).container,
    });
    const key2 = await getPrfKey([ID_1], [SALT_1], {
      info: 'cratefield:purpose-b:v1',
      credentials: fakeContainer(resultsWith(PRF_OUTPUT)).container,
    });
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key1, new Uint8Array([7, 8, 9]));
    await expect(crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key2, ciphertext)).rejects.toThrow();
  });

  it.each([
    ['no prf member at all', {}],
    ['enabled claimed without results', { prf: { enabled: true } }],
    ['an empty result', { prf: { enabled: true, results: { first: new ArrayBuffer(0) } } }],
    ['a wrong-length result', { prf: { enabled: true, results: { first: new ArrayBuffer(31) } } }],
  ])('rejects %s with PrfUnavailableError', async (_label, clientExtensionResults) => {
    const { container } = fakeContainer(clientExtensionResults as PrfClientExtensionResults);
    await expect(getPrfKey([ID_1], [SALT_1], { info: 'cratefield:test:v1', credentials: container })).rejects.toThrow(
      PrfUnavailableError,
    );
  });

  it('rejects with PrfUnavailableError when the ceremony returns no credential', async () => {
    const { container } = fakeContainer(null);
    await expect(getPrfKey([ID_1], [SALT_1], { info: 'cratefield:test:v1', credentials: container })).rejects.toThrow(
      PrfUnavailableError,
    );
  });

  it('rejects with PrfUnavailableError when WebAuthn is not available', async () => {
    // No injected container and no navigator.credentials under Node.
    await expect(getPrfKey([ID_1], [SALT_1], { info: 'cratefield:test:v1' })).rejects.toThrow(PrfUnavailableError);
  });

  it.each([
    ['mismatched lengths', [ID_1], [SALT_1, SALT_2], /same length/],
    ['no credentials', [], [], /must not be empty/],
    ['an empty id', [''], [SALT_1], /is empty/],
    ['a duplicate id', [ID_1, ID_1], [SALT_1, SALT_2], /unique/],
    ['a short salt', [ID_1], [SALT_SHORT], /32 bytes/],
    ['a non-base64url salt', [ID_1], ['not a salt!'], /not valid base64url/],
  ])('validates before the ceremony: %s', async (_label, ids, salts, message) => {
    const { container, requests } = fakeContainer(resultsWith(PRF_OUTPUT));
    await expect(
      getPrfKey(ids as string[], salts as string[], { info: 'cratefield:test:v1', credentials: container }),
    ).rejects.toThrow(message as string);
    expect(requests).toHaveLength(0); // nothing reached the authenticator
  });

  it('validates the info before the ceremony', async () => {
    const { container, requests } = fakeContainer(resultsWith(PRF_OUTPUT));
    await expect(getPrfKey([ID_1], [SALT_1], { info: '', credentials: container })).rejects.toThrow(
      /non-empty purpose string/,
    );
    expect(requests).toHaveLength(0);
  });
});

describe('derivePrfKey', () => {
  it('matches an independent HKDF-SHA256 computation (Node crypto.hkdfSync)', async () => {
    const info = 'cratefield:kat:v1';
    const expected = new Uint8Array(hkdfSync('sha256', PRF_OUTPUT, Buffer.alloc(0), Buffer.from(info), 32));

    // The params derivePrfKey uses, exercised directly: same HKDF-SHA256, empty salt, utf8 info.
    const material = await crypto.subtle.importKey('raw', PRF_OUTPUT, 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8Encode(info) },
      material,
      256,
    );
    expect(new Uint8Array(bits)).toEqual(expected);

    // And the key derivePrfKey returns is exactly that HKDF output, proven by
    // decrypting with the independently computed bytes.
    const key = await derivePrfKey(PRF_OUTPUT, info);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new Uint8Array([9, 9, 9]));
    const reference = await crypto.subtle.importKey('raw', expected, 'AES-GCM', false, ['decrypt']);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, reference, ciphertext);
    expect([...new Uint8Array(plaintext)]).toEqual([9, 9, 9]);
  });

  it('is deterministic and does not expose the input', async () => {
    const key1 = await derivePrfKey(PRF_OUTPUT, 'cratefield:test:v1');
    const key2 = await derivePrfKey(PRF_OUTPUT, 'cratefield:test:v1');
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key1, new Uint8Array([1]));
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key2, ciphertext);
    expect([...new Uint8Array(plaintext)]).toEqual([1]);
    expect(key1.extractable).toBe(false);
  });

  it('accepts an algorithm and usages override', async () => {
    const key = await derivePrfKey(PRF_OUTPUT, 'cratefield:test:v1', {
      algorithm: { name: 'AES-GCM', length: 128 },
      keyUsages: ['encrypt'],
    });
    expect(key).toMatchObject({ algorithm: { name: 'AES-GCM', length: 128 }, usages: ['encrypt'] });
  });

  it('rejects an empty info and empty output', async () => {
    await expect(derivePrfKey(PRF_OUTPUT, '')).rejects.toThrow(/non-empty purpose string/);
    await expect(derivePrfKey(new ArrayBuffer(0), 'cratefield:test:v1')).rejects.toThrow(/must not be empty/);
  });
});

describe('redactPrfResults', () => {
  it('replaces prf.results with enabled:true and copies other extensions', () => {
    const other = { 'credentialProtectionPolicy': 3 };
    const input: PrfClientExtensionResults = { ...other, prf: { enabled: true, results: { first: PRF_OUTPUT.buffer } } };
    const redacted = redactPrfResults(input);
    expect(redacted).toEqual({ credentialProtectionPolicy: 3, prf: { enabled: true } });
    expect(redacted.prf).not.toHaveProperty('results');
    // The input is untouched, and the raw bytes are not referenced by the copy.
    expect(input.prf!.results!.first).toBe(PRF_OUTPUT.buffer);
    expect(JSON.parse(JSON.stringify(redacted))).toEqual(redacted);
  });

  it('reports enabled:false from the presence of results, never the enabled claim', () => {
    expect(redactPrfResults({ prf: { enabled: true } }).prf).toEqual({ enabled: false });
    expect(redactPrfResults({ prf: { enabled: false, results: { first: PRF_OUTPUT.buffer } } }).prf).toEqual({
      enabled: true,
    });
    expect(redactPrfResults({}).prf).toEqual({ enabled: false });
  });
});

describe('hasPrfCapablePasskey', () => {
  it('requires at least one supported passkey', () => {
    expect(hasPrfCapablePasskey([{ credentialId: ID_1, prf: 'supported', prfSalt: SALT_1 }])).toBe(true);
    expect(hasPrfCapablePasskey([{ credentialId: ID_1, prf: 'unknown', prfSalt: SALT_1 }])).toBe(false);
    expect(
      hasPrfCapablePasskey([
        { credentialId: ID_1, prf: 'unsupported', prfSalt: SALT_1 },
        { credentialId: ID_2, prf: 'unknown', prfSalt: SALT_2 },
      ]),
    ).toBe(false);
    expect(hasPrfCapablePasskey([])).toBe(false);
  });
});
