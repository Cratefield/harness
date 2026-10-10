/**
 * Every failure mode of this package throws a `SealedError`; the `code`
 * distinguishes them. Codes cover, in rough order of interest:
 *
 * - `decrypt_failed` / `unwrap_failed` — a wrap or the payload was tampered
 *   with, or the unlock material is wrong. Both are integrity failures:
 *   AES-GCM and AES-KW refuse to output plaintext/key material rather than
 *   garbage, so callers should treat these as "this record was modified" and
 *   never as data.
 * - `weak_params` — a recovery wrap read off a record asks for Argon2id
 *   below the floor we accept (downgrade protection).
 * - the rest are input/shape errors, safe to surface to the caller as-is.
 */
export type SealedErrorCode =
  | 'bad_input'
  | 'bad_record'
  | 'bad_wrap'
  | 'weak_params'
  | 'wrap_not_found'
  | 'too_few_unlocks'
  | 'duplicate_wrap'
  | 'unwrap_failed'
  | 'decrypt_failed';

export class SealedError extends Error {
  readonly code: SealedErrorCode;

  constructor(code: SealedErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'SealedError';
    this.code = code;
  }
}
