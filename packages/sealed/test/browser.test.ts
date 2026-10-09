// Browser leg: one seal → open round trip in real Chromium — once through a
// simulated PRF output, once through a recovery code — plus the wrong-AAD
// tamper failure. Node 24 runs the same WebCrypto, so the node suite covers
// the rest (see vitest.config.ts); this file only proves the package works
// when the runtime is actually a browser (btoa/atob, WebCrypto, ESM loading).

import { describe, expect, it } from 'vitest';
import { newBlobId, newPrfSalt, open, seal } from '../src/index.js';

const SUBJECT = 'did:web:browser.example';
const PURPOSE = 'vault.browser';
const CREDENTIAL = 'YnJvd3Nlci10ZXN0LWNyZWRlbnRpYWw';
const PLAINTEXT = 'opened in a real browser';

const utf8 = (value: string): Uint8Array => new TextEncoder().encode(value);

describe('sealed in Chromium', () => {
  it('seals and opens through a PRF output and a recovery code', async () => {
    const prfOutput = crypto.getRandomValues(new Uint8Array(32));
    const created = await seal({
      subject: SUBJECT,
      blobId: newBlobId(),
      purpose: PURPOSE,
      plaintext: utf8(PLAINTEXT),
      unlocks: [
        { kind: 'prf', credentialId: CREDENTIAL, prfOutput, prfSalt: newPrfSalt() },
        { kind: 'recovery', code: 'AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH' },
      ],
      createdByCredential: CREDENTIAL,
    });
    const record = { ...created, subject: SUBJECT, created_at: '', updated_at: '' };

    expect(new TextDecoder().decode(await open(record, { kind: 'prf', credentialId: CREDENTIAL, prfOutput }))).toBe(PLAINTEXT);
    expect(
      new TextDecoder().decode(await open(record, { kind: 'recovery', code: 'aaaa bbbb cccc dddd eeee ffff gggg hhhh' })),
    ).toBe(PLAINTEXT);
  });

  it('fails to open a record whose AAD fields were changed', async () => {
    const prfOutput = crypto.getRandomValues(new Uint8Array(32));
    const created = await seal({
      subject: SUBJECT,
      blobId: newBlobId(),
      purpose: PURPOSE,
      plaintext: utf8(PLAINTEXT),
      unlocks: [
        { kind: 'prf', credentialId: CREDENTIAL, prfOutput, prfSalt: newPrfSalt() },
        { kind: 'recovery', code: 'AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH' },
      ],
      createdByCredential: CREDENTIAL,
    });
    // The same unlocks cannot open a record moved to another purpose: the AAD
    // no longer verifies, so AES-GCM refuses instead of returning plaintext.
    await expect(
      open({ ...created, subject: SUBJECT, created_at: '', updated_at: '', purpose: 'vault.other' }, { kind: 'prf', credentialId: CREDENTIAL, prfOutput }),
    ).rejects.toMatchObject({ code: 'decrypt_failed' });
  });
});
