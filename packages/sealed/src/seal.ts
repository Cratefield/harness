// `seal` — create a blob: one fresh content key, one AES-GCM payload, one
// wrap per unlock.

import { aad, assertBlobId, assertPurpose } from './aad.js';
import { b64urlEncode } from './base64url.js';
import { SealedError } from './errors.js';
import { encryptPayload, newContentKey } from './keys.js';
import { buildWraps } from './wrap.js';
import { PAYLOAD_ALG, type CreateBlob, type Unlock } from './types.js';

const random = crypto.getRandomValues.bind(crypto);

/**
 * A fresh client-generated blob id: 128 bits of randomness, base64url (43
 * chars of `[A-Za-z0-9_-]`, within the server's 1..=64). Client-generated
 * because it is bound into the AAD — the server never gets to name it.
 */
export function newBlobId(): string {
  return b64urlEncode(random(new Uint8Array(16)));
}

/**
 * Seal `plaintext` for later reopening by each of `unlocks`.
 *
 * A fresh non-extractable AES-256-GCM content key encrypts the plaintext
 * (12-byte random nonce, 16-byte tag, AAD from `aad`), then is wrapped once
 * per unlock. `unlocks` must carry at least two entries — a single unlock is
 * a single point of failure for data that has no other copy, so it is refused
 * at construction, not at the server.
 *
 * The content key itself never leaves this function: it exists only inside
 * the WebCrypto key store and in the wrapped form on the wire.
 */
export async function seal(input: {
  subject: string;
  blobId: string;
  purpose: string;
  plaintext: Uint8Array;
  unlocks: readonly Unlock[];
  createdByCredential: string;
}): Promise<CreateBlob> {
  const { subject, blobId, purpose, plaintext, unlocks, createdByCredential } = input;
  assertBlobId(blobId);
  assertPurpose(purpose);
  if (subject.length === 0) throw new SealedError('bad_input', 'subject must be non-empty');
  if (createdByCredential.length === 0) throw new SealedError('bad_input', 'createdByCredential must be non-empty');
  if (unlocks.length < 2) {
    throw new SealedError('too_few_unlocks', `at least 2 unlocks are required, got ${unlocks.length}`);
  }

  const contentKey = await newContentKey();
  const wraps = await buildWraps(contentKey, unlocks, subject, blobId);
  const ciphertext = await encryptPayload(contentKey, plaintext, aad(subject, blobId, 1, purpose));
  return {
    blob_id: blobId,
    version: 1,
    purpose,
    alg: PAYLOAD_ALG,
    ciphertext: b64urlEncode(ciphertext),
    wraps,
    created_by_credential: createdByCredential,
  };
}
