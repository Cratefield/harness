// `open` — recover the content key through one unlock and decrypt.

import { aad, assertRecordShape } from './aad.js';
import { decryptPayload } from './keys.js';
import { recoverContentKey } from './wrap.js';
import type { BlobRecord, Unlock } from './types.js';

/**
 * Open a server record with one of its unlocks.
 *
 * The record is fully validated first (algorithm, version, at least two
 * wraps, every wrap's shape and KDF parameters — see `assertRecordShape`), so
 * a record carrying a downgraded recovery wrap is refused before any key
 * material is derived. The AAD is recomputed from the record's own
 * `subject` / `blob_id` / `version` / `purpose`, so a record moved between
 * subjects, renamed or re-versioned without re-encryption fails verification
 * instead of returning tampered plaintext.
 *
 * @returns the plaintext bytes.
 * @throws `SealedError` — `weak_params` / `bad_wrap` for a tampered record,
 * `wrap_not_found` when `unlock` matches nothing, `unwrap_failed` for wrong
 * key material, `decrypt_failed` when the payload fails AES-GCM verification.
 */
export async function open(record: BlobRecord, unlock: Unlock): Promise<Uint8Array<ArrayBuffer>> {
  assertRecordShape(record);
  // Decrypt-only: the recovered key is non-extractable, so nothing downstream
  // of `open` can move it anywhere — including back into a wrap.
  const contentKey = await recoverContentKey(record, unlock, { extractable: false });
  return decryptPayload(contentKey, record.ciphertext, aad(record.subject, record.blob_id, record.version, record.purpose));
}
