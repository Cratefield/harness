// Wrap management: change how the content key is locked without ever
// re-encrypting the payload. `addWrap`, `removeWrap` and `rotateWraps`
// return the body for `PUT /blobs/{id}/wraps` — `{version, wraps}` — and
// leave the payload, its nonce and the record's version untouched.

import { aad, assertRecordShape } from './aad.js';
import { b64urlEncode } from './base64url.js';
import { SealedError } from './errors.js';
import { encryptPayload, newContentKey } from './keys.js';
import { open } from './open.js';
import { buildWrap, buildWraps, recoverContentKey } from './wrap.js';
import { PAYLOAD_ALG, type BlobRecord, type CreateBlob, type Unlock, type WrapEdit } from './types.js';

/**
 * Add a wrap for `newUnlock`, keeping the same content key. The existing
 * unlock recovers the key; the new unlock wraps it again. Refuses a wrap id
 * that is already on the record.
 */
export async function addWrap(record: BlobRecord, existingUnlock: Unlock, newUnlock: Unlock): Promise<WrapEdit> {
  assertRecordShape(record);
  // Extractable: the key is about to be re-wrapped under the new unlock.
  const contentKey = await recoverContentKey(record, existingUnlock, { extractable: true });
  const added = await buildWrap(contentKey, newUnlock, record.subject, record.blob_id, new Set(record.wraps.map((w) => w.id)));
  return { version: record.version, wraps: [...record.wraps, added] };
}

/**
 * Remove the wrap `wrapId`. Needs no unlock — deleting a wrap cannot expose
 * anything — but refuses to leave the record with fewer than two.
 */
export function removeWrap(record: BlobRecord, wrapId: string): WrapEdit {
  assertRecordShape(record);
  const wraps = record.wraps.filter((w) => w.id !== wrapId);
  if (wraps.length === record.wraps.length) {
    throw new SealedError('wrap_not_found', `no wrap ${JSON.stringify(wrapId)} on this record`);
  }
  if (wraps.length < 2) {
    throw new SealedError('too_few_unlocks', `removing ${JSON.stringify(wrapId)} would leave ${wraps.length} unlocks; at least 2 are required`);
  }
  return { version: record.version, wraps };
}

/**
 * Rebuild the whole wrap set under `newUnlocks` (at least two), keeping the
 * same content key and payload. Old unlocks stop working; fresh salts are
 * drawn for every wrap. Use when an unlock *identifier* must be retired but
 * the content key is not suspected.
 */
export async function rotateWraps(record: BlobRecord, existingUnlock: Unlock, newUnlocks: readonly Unlock[]): Promise<WrapEdit> {
  assertRecordShape(record);
  if (newUnlocks.length < 2) {
    throw new SealedError('too_few_unlocks', `at least 2 unlocks are required, got ${newUnlocks.length}`);
  }
  const contentKey = await recoverContentKey(record, existingUnlock, { extractable: true });
  const wraps = await buildWraps(contentKey, newUnlocks, record.subject, record.blob_id);
  return { version: record.version, wraps };
}

/**
 * Rotate the content key itself: decrypt the payload, re-encrypt it under a
 * fresh key with a fresh nonce and AAD bound to `version + 1`, and wrap the
 * new key under `newUnlocks` (at least two). Use when an unlock may have
 * leaked: a wrapped-key-only leak dies with `rotateWraps`, a plaintext or
 * content-key leak needs this. Returns the full `CreateBlob` body for
 * `PUT /blobs/{id}`; `version` is bumped by one so the server can reject
 * lost updates.
 */
export async function rotateContentKey(
  record: BlobRecord,
  existingUnlock: Unlock,
  newUnlocks: readonly Unlock[],
): Promise<CreateBlob> {
  assertRecordShape(record);
  if (newUnlocks.length < 2) {
    throw new SealedError('too_few_unlocks', `at least 2 unlocks are required, got ${newUnlocks.length}`);
  }
  const plaintext = await open(record, existingUnlock);
  const contentKey = await newContentKey();
  const wraps = await buildWraps(contentKey, newUnlocks, record.subject, record.blob_id);
  const version = record.version + 1;
  const ciphertext = await encryptPayload(contentKey, plaintext, aad(record.subject, record.blob_id, version, record.purpose));
  return {
    blob_id: record.blob_id,
    version,
    purpose: record.purpose,
    alg: PAYLOAD_ALG,
    ciphertext: b64urlEncode(ciphertext),
    wraps,
    created_by_credential: record.created_by_credential,
  };
}
