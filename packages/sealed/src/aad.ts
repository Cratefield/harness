// Additional authenticated data and wire-field validation.
//
// The AAD binds every ciphertext to exactly one (subject, blob, version,
// purpose) tuple on the server: a record moved, renamed or re-versioned
// without re-encryption fails to decrypt. Because the blob id is
// client-generated and lives inside the AAD, `seal` never lets the server
// choose it.

import { utf8Encode } from './base64url.js';
import { SealedError } from './errors.js';
import { assertWrapShape } from './keys.js';
import type { BlobRecord } from './types.js';
import { PAYLOAD_ALG } from './types.js';

/**
 * Build the AES-GCM additional authenticated data:
 * `subject|blob_id|version|purpose`, UTF-8 encoded. Every part must be free
 * of `|`, the separator — otherwise `("a|b", "c")` and `("a", "b|c")` would
 * produce the same AAD and a blob could be replayed across fields.
 */
export function aad(subject: string, blobId: string, version: number, purpose: string): Uint8Array<ArrayBuffer> {
  assertNoPipe('subject', subject);
  assertNoPipe('blob id', blobId);
  assertNoPipe('purpose', purpose);
  return utf8Encode(`${subject}|${blobId}|${version}|${purpose}`);
}

/** Reject a blob id outside `1..=64` of `[A-Za-z0-9_-]` (the server's rule). */
export function assertBlobId(blobId: string): void {
  if (blobId.length < 1 || blobId.length > 64 || !/^[A-Za-z0-9_-]+$/.test(blobId)) {
    throw new SealedError('bad_input', `blob id must be 1-64 chars of [A-Za-z0-9_-], got ${JSON.stringify(blobId)}`);
  }
}

/** Reject a purpose outside `1..=64` of `[a-z0-9._-]` (the server's rule). */
export function assertPurpose(purpose: string): void {
  if (purpose.length < 1 || purpose.length > 64 || !/^[a-z0-9._-]+$/.test(purpose)) {
    throw new SealedError('bad_input', `purpose must be 1-64 chars of [a-z0-9._-], got ${JSON.stringify(purpose)}`);
  }
}

/** Reject a version below 1 or above the u32 range. */
export function assertVersion(version: number): void {
  if (!Number.isInteger(version) || version < 1 || version > 0xffff_ffff) {
    throw new SealedError('bad_input', `version must be a u32 >= 1, got ${version}`);
  }
}

function assertNoPipe(field: string, value: string): void {
  if (value.includes('|')) throw new SealedError('bad_input', `${field} must not contain '|'`);
}

/**
 * Check the parts of a server record this package trusts before touching
 * crypto: the payload algorithm, the version range, that at least two wraps
 * remain (the server's own invariant — a record below it is a bug or an
 * attack, not something to open), and every wrap's shape and KDF parameters.
 *
 * Wraps are all validated up front, not just the one being opened: a record
 * carrying *any* under-floor recovery wrap is one a thief could brute-force
 * offline, so the whole record is refused (downgrade protection).
 */
export function assertRecordShape(record: BlobRecord): void {
  if (record.alg !== PAYLOAD_ALG) {
    throw new SealedError('bad_record', `unsupported payload alg ${JSON.stringify(record.alg)}`);
  }
  assertVersion(record.version);
  assertBlobId(record.blob_id);
  assertPurpose(record.purpose);
  if (record.wraps.length < 2) {
    throw new SealedError('bad_record', `record has ${record.wraps.length} wraps; at least 2 are required`);
  }
  for (const wrap of record.wraps) assertWrapShape(wrap);
}
