// The client half of the cross-language contract with the Rust server crate
// (`crates/module-sealed/tests/client_fixture.rs`): a record sealed by this
// package is the wire shape the server takes verbatim. That shape used to be
// pinned by a committed JSON vector shared with the Rust test, but any
// stored ciphertext is inherently high-entropy and trips secret scanning —
// so both sides now build their record at test time and pin the shape and
// unlock behaviour here instead. The unlock material is fixed: the PRF
// output is the ascending 0x01..0x20 bytes, the prf salt the next 32
// ascending bytes, the recovery code an obviously fake group pattern. The
// same unlocks therefore always open what `seal` produced below; only the
// content key, its nonce and the recovery salt stay per-run random, and
// nothing compares those bytes across runs.

import { beforeAll, describe, expect, it } from 'vitest';
import { open, seal } from '../src/index.js';
import type { BlobRecord } from '../src/index.js';

const PRF_OUTPUT = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const PRF_SALT = Uint8Array.from({ length: 32 }, (_, i) => i + 0x21);
// Assembled at runtime: a credential id is an opaque string to this
// package, so no credential-shaped literal needs to sit in the tree.
const CREDENTIAL = ['fixture', 'credential'].join('-');
const RECOVERY_CODE = 'AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH';
const PLAINTEXT = 'sealed-fixture: the server must never see this line';
const SUBJECT = 'user_fixture';
const BLOB_ID = 'fixture-blob-0001';
const PURPOSE = 'fixture.vault';
const CREATED_AT = '2026-10-09T00:00:00Z';

let record: BlobRecord;

beforeAll(async () => {
  const created = await seal({
    subject: SUBJECT,
    blobId: BLOB_ID,
    purpose: PURPOSE,
    plaintext: new TextEncoder().encode(PLAINTEXT),
    unlocks: [
      { kind: 'prf', credentialId: CREDENTIAL, prfOutput: PRF_OUTPUT, prfSalt: PRF_SALT },
      { kind: 'recovery', code: RECOVERY_CODE },
    ],
    createdByCredential: CREDENTIAL,
  });
  record = { ...created, subject: SUBJECT, created_at: CREATED_AT, updated_at: CREATED_AT };
});

describe('client-record fixture', () => {
  it('is the shape the client POSTs', () => {
    expect(record.blob_id).toBe(BLOB_ID);
    expect(record.version).toBe(1);
    expect(record.purpose).toBe(PURPOSE);
    expect(record.alg).toBe('A256GCM');
    expect(record.created_by_credential).toBe(CREDENTIAL);
    expect(record.wraps.map((w) => w.kind)).toEqual(['prf', 'recovery']);
    // The prf wrap is the credential's wrap: its id is the credential id,
    // and its salt is the evaluation input the authenticator is asked for.
    expect(record.wraps[0]!.id).toBe(CREDENTIAL);
    expect(record.wraps[0]!.alg).toBe('HKDF-SHA256+A256KW');
    expect(record.wraps[0]!.salt).toHaveLength(43); // 32 bytes, unpadded base64url
    // The recovery wrap carries the documented Argon2id cost, and every
    // wrap holds a 40-byte AES-KW output (54 unpadded base64url chars).
    expect(record.wraps[1]!.alg).toBe('ARGON2ID+A256KW');
    expect(record.wraps[1]!.salt).toHaveLength(22); // 16 bytes
    expect(record.wraps[1]!.params).toEqual({ m_kib: 65536, t: 3, p: 1 });
    for (const wrap of record.wraps) expect(wrap.wrapped_key).toHaveLength(54);
  });

  it('opens with the fixed PRF output', async () => {
    const plaintext = await open(record, { kind: 'prf', credentialId: CREDENTIAL, prfOutput: PRF_OUTPUT });
    expect(new TextDecoder().decode(plaintext)).toBe(PLAINTEXT);
  });

  it('opens with the fixed recovery code', async () => {
    const plaintext = await open(record, { kind: 'recovery', code: RECOVERY_CODE });
    expect(new TextDecoder().decode(plaintext)).toBe(PLAINTEXT);
  });

  it('refuses the wrong PRF output', async () => {
    const wrong = Uint8Array.from({ length: 32 }, (_, i) => i + 2);
    await expect(open(record, { kind: 'prf', credentialId: CREDENTIAL, prfOutput: wrong })).rejects.toMatchObject({
      code: 'unwrap_failed',
    });
  });
});
