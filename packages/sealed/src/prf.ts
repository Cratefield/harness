// Passkey-PRF unlocks.
//
// A WebAuthn credential with the `prf` extension returns 32 deterministic
// bytes when evaluated against a salt. Those bytes never leave the
// authenticator's origin, so they become the HKDF input keying material for
// this wrap's KEK. The same salt must be replayed to the authenticator on
// every unlock, so it is stored publicly in the wrap (`salt`).

import { b64urlDecode } from './base64url.js';
import { SealedError } from './errors.js';
import type { Wrap } from './types.js';

/** Length of the PRF evaluation input (`eval.first`). WebAuthn salts are 32 bytes by convention. */
export const PRF_SALT_LENGTH = 32;

const random = crypto.getRandomValues.bind(crypto);

/** A fresh 32-byte PRF evaluation input. Pass these bytes to `prf: {eval: {first}}` when creating the credential. */
export function newPrfSalt(): Uint8Array<ArrayBuffer> {
  return random(new Uint8Array(PRF_SALT_LENGTH));
}

/**
 * The bytes to pass to `navigator.credentials.get({extensions: {prf: {eval:
 * {first: bytes}}}})` when opening a record with this wrap.
 */
export function prfEvalInput(wrap: Wrap): Uint8Array<ArrayBuffer> {
  if (wrap.kind !== 'prf') throw new SealedError('bad_wrap', `wrap ${JSON.stringify(wrap.id)} is not a prf wrap`);
  const salt = b64urlDecode(wrap.salt);
  if (salt.length !== PRF_SALT_LENGTH) {
    throw new SealedError('bad_wrap', `prf salt must be ${PRF_SALT_LENGTH} bytes, got ${salt.length}`);
  }
  return salt;
}

/**
 * HKDF-SHA256 over the PRF output.
 *
 * `salt` = the wrap's `salt` — the same 32 bytes evaluated by the
 * authenticator. It is public (the server stores it), but HKDF salts are
 * meant to be public: pinning it here means two blobs wrapped under the same
 * PRF output still get independent KEKs once their eval inputs differ, and
 * rotating the eval input rotates the KEK without touching the PRF secret.
 *
 * `info` = `"cratefield/sealed/v1/prf|" + subject + "|" + blob_id`, which
 * domain-separates every blob: one PRF output cannot be audited into
 * unlocking two different records even by a caller who holds it.
 */
export async function derivePrfKek(
  prfOutput: Uint8Array,
  prfSalt: Uint8Array,
  subject: string,
  blobId: string,
): Promise<CryptoKey> {
  // Copied into a fresh view: `crypto.subtle` insists on an ArrayBuffer-backed
  // one, and `prfOutput` arrives as a plain `Uint8Array` of unknown buffer.
  const ikm = await crypto.subtle.importKey('raw', new Uint8Array(prfOutput), 'HKDF', false, ['deriveBits']);
  const info = utf8(`cratefield/sealed/v1/prf|${subject}|${blobId}`);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(prfSalt), info: new Uint8Array(info) },
    ikm,
    256,
  );
  return crypto.subtle.importKey('raw', bits, 'AES-KW', false, ['wrapKey', 'unwrapKey']);
}

function utf8(value: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(new TextEncoder().encode(value));
}
