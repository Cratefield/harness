// Cross-language fixture: the same file the Rust server crate exercises
// (`crates/module-sealed/tests/fixtures/client-record.json`), opened here to
// prove what the client POSTs is what both sides agree on. The constants
// below are the test-only unlock material that produced it; the record
// itself is public (it is, after all, what the server stores).

// Vite serves JSON imports natively, so no Node built-ins are needed here.
import fixture from '../../crates/module-sealed/tests/fixtures/client-record.json';
import { describe, expect, it } from 'vitest';
import { open } from '../src/index.js';
import type { BlobRecord, CreateBlob } from '../src/index.js';

// The unlocks the fixture was sealed under (see the generator run that wrote
// the file): a fixed 32-byte PRF output, 0x01..0x20, for credential
// `Zml4dHVyZS1jcmVkZW50aWFs`, and the recovery code below.
const PRF_OUTPUT = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const CREDENTIAL = 'Zml4dHVyZS1jcmVkZW50aWFs';
const RECOVERY_CODE = 'AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH';
const PLAINTEXT = 'sealed-fixture: the server must never see this line';
const SUBJECT = 'user_fixture';

const record: BlobRecord = {
  ...(fixture as CreateBlob),
  subject: SUBJECT,
  created_at: '2026-10-09T00:00:00Z',
  updated_at: '2026-10-09T00:00:00Z',
};

describe('client-record fixture', () => {
  it('is the shape the client POSTs', () => {
    expect(record.blob_id).toBe('fixture-blob-0001');
    expect(record.version).toBe(1);
    expect(record.purpose).toBe('fixture.vault');
    expect(record.alg).toBe('A256GCM');
    expect(record.created_by_credential).toBe(CREDENTIAL);
    expect(record.wraps.map((w) => w.kind)).toEqual(['prf', 'recovery']);
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
