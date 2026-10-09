// Node suite. Node 24 ships the same WebCrypto the browser gets, so the only
// difference under `test:browser` is the real Chromium runtime — the browser
// file keeps to a single seal/open round trip for that reason. Recovery-code
// tests share fixtures: each Argon2id derivation (64 MiB x 3) costs about a
// second.

import { beforeEach, describe, expect, it } from 'vitest';
import {
  addWrap,
  aad,
  generateRecoveryCode,
  newBlobId,
  newPrfSalt,
  normalizeRecoveryCode,
  open,
  removeWrap,
  rotateContentKey,
  rotateWraps,
  seal,
  RECOVERY_ARGON2_PARAMS,
  RECOVERY_PARAMS_FLOOR,
  SealedError,
} from '../src/index.js';
import { recoverContentKey } from '../src/wrap.js';
import type { BlobRecord } from '../src/index.js';

const SUBJECT = 'did:web:alice.example';
const PURPOSE = 'vault.notes';
const CREDENTIAL = 'dGVzdC1jcmVkZW50aWFsLWlk';
const PLAINTEXT = new TextEncoder().encode('attack at dawn');
const NOW = '2026-10-09T00:00:00Z';

const utf8 = (value: string): Uint8Array => new TextEncoder().encode(value);

interface Fixture {
  record: BlobRecord;
  prfOutput: Uint8Array;
  code: string;
}

let fixture: Fixture;

/** One seal (one Argon2id derivation for the recovery wrap) shared by most tests. */
beforeEach(async () => {
  const prfOutput = crypto.getRandomValues(new Uint8Array(32));
  const code = generateRecoveryCode();
  const created = await seal({
    subject: SUBJECT,
    blobId: newBlobId(),
    purpose: PURPOSE,
    plaintext: PLAINTEXT,
    unlocks: [
      { kind: 'prf', credentialId: CREDENTIAL, prfOutput, prfSalt: newPrfSalt() },
      { kind: 'recovery', code },
    ],
    createdByCredential: CREDENTIAL,
  });
  fixture = { record: { ...created, subject: SUBJECT, created_at: NOW, updated_at: NOW }, prfOutput, code };
});

const prfUnlock = (f: Fixture = fixture) => ({ kind: 'prf' as const, credentialId: CREDENTIAL, prfOutput: f.prfOutput });

describe('aad', () => {
  it('binds subject, blob id, version and purpose with pipes', () => {
    expect(Buffer.from(aad('sub', 'blob', 3, 'notes')).equals(utf8('sub|blob|3|notes'))).toBe(true);
  });

  it('refuses any part containing the separator', () => {
    for (const parts of [
      ['a|b', 'blob', 1, 'notes'],
      ['sub', 'blo|b', 1, 'notes'],
      ['sub', 'blob', 1, 'no|tes'],
    ] as const) {
      expect(() => aad(...parts), JSON.stringify(parts)).toThrowError(SealedError);
    }
  });
});

describe('seal', () => {
  it('produces the wire shape', () => {
    const { record } = fixture;
    expect(record.version).toBe(1);
    expect(record.alg).toBe('A256GCM');
    expect(record.blob_id).toMatch(/^[A-Za-z0-9_-]{1,64}$/);
    expect(record.created_by_credential).toBe(CREDENTIAL);
    // Unpadded base64url in every binary field (the `alg` names themselves
    // carry `+`, so the check is per field, not on the whole JSON).
    for (const value of [record.ciphertext, ...record.wraps.flatMap((w) => [w.salt, w.wrapped_key])]) {
      expect(value).not.toMatch(/[+=/]/);
    }

    const [prf, recovery] = record.wraps;
    expect(prf!.kind).toBe('prf');
    expect(prf!.alg).toBe('HKDF-SHA256+A256KW');
    expect(prf!.id).toBe(CREDENTIAL);
    expect(prf!.params).toBeUndefined();
    expect(Buffer.from(Buffer.from(prf!.salt, 'base64url')).length).toBe(32);
    expect(recovery!.kind).toBe('recovery');
    expect(recovery!.alg).toBe('ARGON2ID+A256KW');
    expect(recovery!.id).toMatch(/^recovery-\d+$/);
    expect(recovery!.params).toEqual(RECOVERY_ARGON2_PARAMS);
    expect(recovery!.params!.m_kib).toBeGreaterThanOrEqual(RECOVERY_PARAMS_FLOOR.m_kib);
    expect(Buffer.from(recovery!.salt, 'base64url').length).toBe(16);
    for (const wrap of record.wraps) {
      expect(Buffer.from(wrap.wrapped_key, 'base64url').length).toBe(40);
    }
  });

  it('refuses fewer than two unlocks', async () => {
    await expect(
      seal({ subject: SUBJECT, blobId: newBlobId(), purpose: PURPOSE, plaintext: PLAINTEXT, unlocks: [prfUnlock()], createdByCredential: CREDENTIAL }),
    ).rejects.toMatchObject({ code: 'too_few_unlocks' });
  });

  it('refuses a duplicate credential or a bad salt', async () => {
    const base = { subject: SUBJECT, blobId: newBlobId(), purpose: PURPOSE, plaintext: PLAINTEXT, createdByCredential: CREDENTIAL };
    await expect(seal({ ...base, unlocks: [prfUnlock(), prfUnlock()] })).rejects.toMatchObject({ code: 'duplicate_wrap' });
    await expect(
      seal({ ...base, unlocks: [{ kind: 'prf', credentialId: CREDENTIAL, prfOutput: crypto.getRandomValues(new Uint8Array(32)), prfSalt: new Uint8Array(8) }, { kind: 'recovery', code: fixture.code }] }),
    ).rejects.toMatchObject({ code: 'bad_input' });
  });

  it('generates distinct blob ids', () => {
    expect(newBlobId()).not.toBe(newBlobId());
  });
});

describe('open', () => {
  it('round trips through the PRF unlock', async () => {
    const plaintext = await open(fixture.record, prfUnlock());
    expect(Buffer.from(plaintext).equals(Buffer.from(PLAINTEXT))).toBe(true);
  });

  it('round trips through the recovery unlock, normalising the typed code', async () => {
    for (const typed of [fixture.code, fixture.code.toLowerCase(), fixture.code.replaceAll('-', ' '), ' ' + fixture.code]) {
      const plaintext = await open(fixture.record, { kind: 'recovery', code: typed });
      expect(Buffer.from(plaintext).equals(Buffer.from(PLAINTEXT)), JSON.stringify(typed)).toBe(true);
    }
  });

  it('folds Crockford look-alikes when normalising', () => {
    // Dashes are stripped (seal and open both normalise, so both sides agree).
    expect(normalizeRecoveryCode('i1l-o0')).toBe('11100');
  });

  it('fails a wrong recovery code', async () => {
    await expect(open(fixture.record, { kind: 'recovery', code: 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA' })).rejects.toMatchObject({
      code: 'unwrap_failed',
    });
  });

  it('fails a wrong PRF output', async () => {
    await expect(
      open(fixture.record, { kind: 'prf', credentialId: CREDENTIAL, prfOutput: crypto.getRandomValues(new Uint8Array(32)) }),
    ).rejects.toMatchObject({ code: 'unwrap_failed' });
  });

  it('fails a PRF credential with no wrap', async () => {
    await expect(open(fixture.record, { kind: 'prf', credentialId: 'other-credential', prfOutput: fixture.prfOutput })).rejects.toMatchObject({
      code: 'wrap_not_found',
    });
  });

  it('refuses a record below two wraps', async () => {
    const { record } = fixture;
    await expect(open({ ...record, wraps: [record.wraps[0]!] }, prfUnlock())).rejects.toMatchObject({
      code: 'bad_record',
    });
  });
});

describe('tamper', () => {
  it('fails with a changed purpose', async () => {
    await expect(open({ ...fixture.record, purpose: 'vault.other' }, prfUnlock())).rejects.toMatchObject({ code: 'decrypt_failed' });
  });

  it('fails with a changed version', async () => {
    await expect(open({ ...fixture.record, version: 2 }, prfUnlock())).rejects.toMatchObject({ code: 'decrypt_failed' });
  });

  it('fails with a changed subject', async () => {
    // The prf KEK binds subject and blob id (HKDF info, see prf.ts), so a
    // moved record fails one step earlier than the payload AAD — at unwrap.
    await expect(open({ ...fixture.record, subject: 'did:web:mallory.example' }, prfUnlock())).rejects.toMatchObject({ code: 'unwrap_failed' });
  });

  it('fails with a changed blob id', async () => {
    const moved = { ...fixture.record, blob_id: newBlobId() };
    await expect(open(moved, prfUnlock())).rejects.toMatchObject({ code: 'unwrap_failed' });
  });

  it('fails with a changed subject under a recovery unlock at the payload AAD', async () => {
    // The recovery KEK does not bind the subject, so the same tamper is
    // caught by the AES-GCM AAD instead.
    await expect(open({ ...fixture.record, subject: 'did:web:mallory.example' }, { kind: 'recovery', code: fixture.code })).rejects.toMatchObject({
      code: 'decrypt_failed',
    });
  });

  it('fails a flipped ciphertext bit', async () => {
    const bytes = Buffer.from(fixture.record.ciphertext, 'base64url');
    bytes[bytes.length - 1]! ^= 1; // flip inside the tag
    await expect(open({ ...fixture.record, ciphertext: bytes.toString('base64url') }, prfUnlock())).rejects.toMatchObject({
      code: 'decrypt_failed',
    });
  });

  it('fails a tampered wrapped key', async () => {
    const bytes = Buffer.from(fixture.record.wraps[0]!.wrapped_key, 'base64url');
    bytes[0]! ^= 1;
    const tampered = {
      ...fixture.record,
      wraps: fixture.record.wraps.map((w) => (w.kind === 'prf' ? { ...w, wrapped_key: bytes.toString('base64url') } : w)),
    };
    await expect(open(tampered, prfUnlock())).rejects.toMatchObject({ code: 'unwrap_failed' });
  });
});

describe('downgrade protection', () => {
  it('refuses a recovery wrap below the Argon2id floor, even when opening via the healthy wrap', async () => {
    const weak = { ...fixture.record, wraps: fixture.record.wraps.map((w) => (w.kind === 'recovery' ? { ...w, params: { m_kib: 1024, t: 3, p: 1 } } : w)) };
    await expect(open(weak, prfUnlock())).rejects.toMatchObject({ code: 'weak_params' });

    const fast = { ...fixture.record, wraps: fixture.record.wraps.map((w) => (w.kind === 'recovery' ? { ...w, params: { ...RECOVERY_PARAMS_FLOOR, t: 1 } } : w)) };
    await expect(open(fast, prfUnlock())).rejects.toMatchObject({ code: 'weak_params' });
  });

  it('refuses a recovery wrap with no params', async () => {
    const stripped = {
      ...fixture.record,
      wraps: fixture.record.wraps.map((w) => {
        const { params, ...rest } = w;
        return w.kind === 'recovery' ? rest : w;
      }),
    };
    await expect(open(stripped, prfUnlock())).rejects.toMatchObject({ code: 'bad_wrap' });
  });

  it('refuses malformed wraps on the record', async () => {
    const [prf] = fixture.record.wraps;
    const short = { ...fixture.record, wraps: [prf!, { ...fixture.record.wraps[1]!, wrapped_key: prf!.wrapped_key.slice(0, -4) }] };
    await expect(open(short, prfUnlock())).rejects.toMatchObject({ code: 'bad_wrap' });

    const withParams = { ...fixture.record, wraps: [prf!.params !== undefined ? prf! : { ...prf!, params: { m_kib: 1, t: 1, p: 1 } }, fixture.record.wraps[1]!] };
    await expect(open(withParams, prfUnlock())).rejects.toMatchObject({ code: 'bad_wrap' });
  });
});

describe('wrap edits keep the payload byte-identical', () => {
  it('addWrap wraps the same key for a new unlock', async () => {
    const before = fixture.record.ciphertext;
    const newCode = generateRecoveryCode();
    const edit = await addWrap(fixture.record, prfUnlock(), { kind: 'recovery', id: 'recovery-paper', code: newCode });

    expect(edit.version).toBe(fixture.record.version);
    expect(edit.wraps).toHaveLength(3);
    expect(fixture.record.ciphertext).toBe(before);
    expect(edit.wraps.map((w) => w.id)).toEqual([CREDENTIAL, fixture.record.wraps[1]!.id, 'recovery-paper']);

    const applied = { ...fixture.record, wraps: edit.wraps };
    expect(Buffer.from(await open(applied, { kind: 'recovery', id: 'recovery-paper', code: newCode })).equals(Buffer.from(PLAINTEXT))).toBe(true);
    expect(Buffer.from(await open(applied, prfUnlock())).equals(Buffer.from(PLAINTEXT))).toBe(true);
  });

  it('removeWrap drops a wrap but never below two', async () => {
    const applied = { ...fixture.record };
    const withThree = await addWrap(applied, prfUnlock(), { kind: 'recovery', id: 'recovery-paper', code: fixture.code });
    const record3 = { ...applied, wraps: withThree.wraps };

    const edit = removeWrap(record3, record3.wraps[0]!.id);
    expect(edit.wraps).toHaveLength(2);
    expect(fixture.record.ciphertext).toBe(edit.version === record3.version ? fixture.record.ciphertext : 'moved');

    const record2 = { ...record3, wraps: edit.wraps };
    expect(Buffer.from(await open(record2, { kind: 'recovery', id: 'recovery-paper', code: fixture.code })).equals(Buffer.from(PLAINTEXT))).toBe(true);

    expect(() => removeWrap(record2, record2.wraps[0]!.id)).toThrowError(/at least 2/);
    expect(() => removeWrap(record2, 'recovery-nowhere')).toThrowError(/no wrap/);
  });

  it('rotateWraps rewraps the same key under fresh wraps', async () => {
    const newPrf = crypto.getRandomValues(new Uint8Array(32));
    const newCode = generateRecoveryCode();
    const edit = await rotateWraps(fixture.record, prfUnlock(), [
      { kind: 'prf', credentialId: 'new-credential', prfOutput: newPrf },
      { kind: 'recovery', code: newCode },
    ]);

    expect(edit.version).toBe(fixture.record.version);
    expect(fixture.record.ciphertext).toBe(edit ? fixture.record.ciphertext : 'moved');
    expect(edit.wraps.map((w) => w.id)).not.toContain(CREDENTIAL);

    const applied = { ...fixture.record, wraps: edit.wraps };
    expect(Buffer.from(await open(applied, { kind: 'prf', credentialId: 'new-credential', prfOutput: newPrf })).equals(Buffer.from(PLAINTEXT))).toBe(true);
    await expect(open(applied, prfUnlock())).rejects.toMatchObject({ code: 'wrap_not_found' });
  });
});

describe('rotateContentKey', () => {
  it('re-encrypts under a new key, bumps the version, and retires old unlocks', async () => {
    const { record } = fixture;
    const oldCiphertext = record.ciphertext;
    const newCode = generateRecoveryCode();
    const newPrfOutput = crypto.getRandomValues(new Uint8Array(32));

    const next = await rotateContentKey(record, prfUnlock(), [
      { kind: 'prf', credentialId: 'new-credential', prfOutput: newPrfOutput },
      { kind: 'recovery', code: newCode },
    ]);

    expect(next.blob_id).toBe(record.blob_id);
    expect(next.version).toBe(record.version + 1);
    expect(next.ciphertext).not.toBe(oldCiphertext);
    expect(next.created_by_credential).toBe(record.created_by_credential);

    const applied: BlobRecord = { ...next, subject: record.subject, created_at: record.created_at, updated_at: NOW };
    expect(Buffer.from(await open(applied, { kind: 'prf', credentialId: 'new-credential', prfOutput: newPrfOutput })).equals(Buffer.from(PLAINTEXT))).toBe(true);
    expect(Buffer.from(await open(applied, { kind: 'recovery', code: newCode })).equals(Buffer.from(PLAINTEXT))).toBe(true);

    await expect(open(record, prfUnlock())).resolves; // the old record still opens on its own version
    await expect(open({ ...applied, version: record.version }, { kind: 'prf', credentialId: 'new-credential', prfOutput: newPrfOutput })).rejects.toMatchObject({
      code: 'decrypt_failed',
    });
  });

  it('refuses fewer than two new unlocks', async () => {
    await expect(rotateContentKey(fixture.record, prfUnlock(), [prfUnlock({ ...fixture })])).rejects.toMatchObject({ code: 'too_few_unlocks' });
  });
});

// `recoverContentKey` is the internal function `open` decrypts through; the
// extractability flag is asserted here rather than on `open`'s return value so
// the public API stays key-free.
describe('content key extractability', () => {
  it('recovers a non-extractable key for decrypt-only callers, extractable for re-wrap callers', async () => {
    const forOpen = await recoverContentKey(fixture.record, prfUnlock(), { extractable: false });
    expect(forOpen.extractable).toBe(false);
    expect(forOpen.usages).toEqual(['encrypt', 'decrypt']);

    const forRewrap = await recoverContentKey(fixture.record, prfUnlock(), { extractable: true });
    expect(forRewrap.extractable).toBe(true);
  });

  it('is WebCrypto-enforced: the decrypt-only key cannot be wrapped again', async () => {
    const forOpen = await recoverContentKey(fixture.record, prfUnlock(), { extractable: false });
    const kek = await crypto.subtle.importKey('raw', crypto.getRandomValues(new Uint8Array(32)), 'AES-KW', true, ['wrapKey']);
    await expect(crypto.subtle.wrapKey('raw', forOpen, kek, { name: 'AES-KW' })).rejects.toThrow();
  });
});
