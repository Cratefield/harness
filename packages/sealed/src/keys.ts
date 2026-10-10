// The content key (CK) and the KEKs that wrap it.
//
// One AES-256-GCM key encrypts the payload. It exists to encrypt/decrypt in
// place, and moves between machines exclusively as `wrapped_key` blobs under
// per-unlock KEKs (AES-KW, whose 40-byte output for a 256-bit key is the wire
// invariant the server checks). WebCrypto only lets `wrapKey`/`unwrapKey`
// move a key in `raw` form when the key itself is extractable, so the CK is
// created extractable — the wrap is its only road off the device, and no
// export path beyond `wrapKey` is ever offered.

import { b64urlDecode } from './base64url.js';
import { SealedError } from './errors.js';
import { derivePrfKek, PRF_SALT_LENGTH, prfEvalInput } from './prf.js';
import { assertRecoveryParams, deriveRecoveryKek, normalizeRecoveryCode, RECOVERY_SALT_LENGTH } from './recovery.js';
import { PAYLOAD_ALG, PRF_WRAP_ALG, RECOVERY_WRAP_ALG, type Unlock, type Wrap } from './types.js';

/** AES-KW output length for a 256-bit key. */
export const WRAPPED_KEY_LENGTH = 40;

/** AES-GCM nonce length: 96 bits, the size NIST recommends for random nonces. */
export const NONCE_LENGTH = 12;

/** AES-GCM tag length in bits. */
const TAG_LENGTH = 128;

/**
 * A fresh content key: AES-GCM 256, encrypt/decrypt only. Extractable because
 * `wrapKey('raw', …)` — the only way it ever leaves this device — refuses a
 * non-extractable key.
 */
export function newContentKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

/**
 * Validate a wrap read off a record against the wire-format invariants:
 * matching alg, salt length, and — for recovery — the Argon2id cost floor
 * (a below-floor wrap is a downgrade and refused before any key material is
 * derived).
 *
 * @throws `SealedError('bad_wrap' | 'weak_params')`.
 */
export function assertWrapShape(wrap: Wrap): void {
  const fail = (code: 'bad_wrap' | 'weak_params', message: string): never => {
    throw new SealedError(code, `wrap ${JSON.stringify(wrap.id)}: ${message}`);
  };
  if (wrap.kind !== 'prf' && wrap.kind !== 'recovery') return fail('bad_wrap', `unknown kind ${JSON.stringify(wrap.kind)}`);
  const wrapped = b64urlDecode(wrap.wrapped_key);
  if (wrapped.length !== WRAPPED_KEY_LENGTH) {
    return fail('bad_wrap', `wrapped_key must be ${WRAPPED_KEY_LENGTH} bytes, got ${wrapped.length}`);
  }
  if (wrap.kind === 'prf') {
    if (wrap.alg !== PRF_WRAP_ALG) return fail('bad_wrap', `alg must be ${PRF_WRAP_ALG}, got ${JSON.stringify(wrap.alg)}`);
    if (wrap.params !== undefined) return fail('bad_wrap', 'prf wraps carry no params');
    const salt = b64urlDecode(wrap.salt);
    if (salt.length !== PRF_SALT_LENGTH) {
      return fail('bad_wrap', `salt must be ${PRF_SALT_LENGTH} bytes, got ${salt.length}`);
    }
    return;
  }
  if (wrap.alg !== RECOVERY_WRAP_ALG) {
    return fail('bad_wrap', `alg must be ${RECOVERY_WRAP_ALG}, got ${JSON.stringify(wrap.alg)}`);
  }
  const salt = b64urlDecode(wrap.salt);
  if (salt.length !== RECOVERY_SALT_LENGTH) {
    return fail('bad_wrap', `salt must be ${RECOVERY_SALT_LENGTH} bytes, got ${salt.length}`);
  }
  assertRecoveryParams(wrap.params);
}

/**
 * Derive the KEK for `wrap` from `unlock` and unwrap the content key. An
 * AES-KW integrity failure (wrong code/PRF output, or a tampered
 * `wrapped_key`) throws `SealedError('unwrap_failed')` — AES-KW never
 * returns a plausible-looking key for a bad input.
 *
 * `opts.extractable` is the caller's call, and every caller must state it:
 * decrypt-only paths (`open`) take a non-extractable key so nothing downstream
 * can export it, while the re-wrap paths (`addWrap`, `rotateWraps`) need an
 * extractable one because AES-KW re-wrapping is a raw move.
 */
export async function unwrapContentKey(
  wrap: Wrap,
  unlock: Unlock,
  subject: string,
  blobId: string,
  opts: { extractable: boolean },
): Promise<CryptoKey> {
  assertWrapShape(wrap);
  const wrapped = b64urlDecode(wrap.wrapped_key);
  const kek = await (wrap.kind === 'prf'
    ? prfKek(wrap, unlock, subject, blobId)
    : deriveRecoveryKek(normalizeRecoveryCode(recoveryCode(unlock)), b64urlDecode(wrap.salt)));
  try {
    return await crypto.subtle.unwrapKey(
      'raw',
      wrapped,
      kek,
      { name: 'AES-KW' },
      { name: 'AES-GCM', length: 256 },
      opts.extractable,
      ['encrypt', 'decrypt'],
    );
  } catch (e) {
    throw new SealedError('unwrap_failed', `could not unwrap the content key with ${wrap.kind} wrap ${JSON.stringify(wrap.id)}`, { cause: e });
  }
}

async function prfKek(wrap: Wrap, unlock: Unlock, subject: string, blobId: string): Promise<CryptoKey> {
  if (unlock.kind !== 'prf' || unlock.credentialId !== wrap.id) {
    throw new SealedError('wrap_not_found', `no prf wrap for credential ${JSON.stringify(unlock.kind === 'prf' ? unlock.credentialId : '')}`);
  }
  return derivePrfKek(unlock.prfOutput, prfEvalInput(wrap), subject, blobId);
}

function recoveryCode(unlock: Unlock): string {
  if (unlock.kind !== 'recovery') throw new SealedError('wrap_not_found', 'expected a recovery unlock');
  return unlock.code;
}

/**
 * Encrypt `plaintext` under the content key with a fresh 12-byte nonce,
 * returning `nonce || ciphertext || tag` — the wire `ciphertext` layout.
 */
export async function encryptPayload(
  contentKey: CryptoKey,
  plaintext: Uint8Array,
  aadBytes: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: new Uint8Array(aadBytes), tagLength: TAG_LENGTH },
      contentKey,
      new Uint8Array(plaintext),
    ),
  );
  const out = new Uint8Array(NONCE_LENGTH + sealed.length);
  out.set(nonce, 0);
  out.set(sealed, NONCE_LENGTH);
  return out;
}

/**
 * Decrypt a wire `ciphertext` (`nonce || ciphertext || tag`, base64url) under
 * the content key, verifying the AAD.
 *
 * @throws `SealedError('decrypt_failed')` on any tamper — wrong AAD, flipped
 * ciphertext bit, truncated record — never a partial or garbage plaintext.
 */
export async function decryptPayload(
  contentKey: CryptoKey,
  ciphertext: string,
  aadBytes: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> {
  const bytes = b64urlDecode(ciphertext);
  if (bytes.length < NONCE_LENGTH + TAG_LENGTH / 8) {
    throw new SealedError('bad_record', `ciphertext must be at least ${NONCE_LENGTH + TAG_LENGTH / 8} bytes (nonce + tag), got ${bytes.length}`);
  }
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: bytes.slice(0, NONCE_LENGTH), additionalData: new Uint8Array(aadBytes), tagLength: TAG_LENGTH },
        contentKey,
        bytes.slice(NONCE_LENGTH),
      ),
    );
  } catch (e) {
    throw new SealedError('decrypt_failed', `${PAYLOAD_ALG} verification failed — the record was modified or does not match this unlock`, {
      cause: e,
    });
  }
}
