// Recovery-code unlocks: an offline-typed code stretched with Argon2id.
//
// The code is the user's break-glass unlock, used when the passkey is lost,
// so it must be typeable from paper. It is stretched with Argon2id at a cost
// floor the client enforces both when creating a wrap and when reading one
// back (downgrade protection, see `keys.ts`).

import { argon2id } from 'hash-wasm';
import { SealedError } from './errors.js';
import { RECOVERY_PARAMS_FLOOR, type RecoveryParams } from './types.js';

const random = crypto.getRandomValues.bind(crypto);

/** Crockford base32: no I, L, O, U — the letters that read as digits or each other. */
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/** Argon2id parameters used for every recovery wrap this package creates. */
export const RECOVERY_ARGON2_PARAMS: RecoveryParams = { m_kib: 65536, t: 3, p: 1 };

/** Argon2id salt length, per wrap. */
export const RECOVERY_SALT_LENGTH = 16;

/**
 * A fresh recovery code: 8 groups of 4 Crockford base32 characters
 * (`XXXX-XXXX-...`), 160 bits of entropy — above the 128-bit floor.
 */
export function generateRecoveryCode(): string {
  const bytes = random(new Uint8Array(32));
  let code = '';
  for (let i = 0; i < 32; i += 1) {
    if (i > 0 && i % 4 === 0) code += '-';
    code += CROCKFORD[bytes[i]! & 31];
  }
  return code;
}

/**
 * Normalise a typed code before hashing: strip spaces and dashes, uppercase,
 * then fold `I`/`L` to `1` and `O` to `0` (the Crockford look-alikes). So a
 * code read off paper survives casing and `l`-vs-`1` transcription slips.
 */
export function normalizeRecoveryCode(code: string): string {
  return code.replace(/[\s-]/g, '').toUpperCase().replace(/[ILO]/g, (c) => (c === 'I' || c === 'L' ? '1' : '0'));
}

/**
 * Argon2id over the normalised code: 64 MiB, 3 iterations, 1 lane, 32-byte
 * output (the server's minimum-accepted cost, and ours). Slower than a
 * password hash on purpose — a recovery code may sit in a desk drawer for
 * years.
 */
export async function deriveRecoveryKek(normalizedCode: string, salt: Uint8Array): Promise<CryptoKey> {
  const bits = await argon2id({
    password: normalizedCode,
    salt: new Uint8Array(salt),
    parallelism: RECOVERY_ARGON2_PARAMS.p,
    iterations: RECOVERY_ARGON2_PARAMS.t,
    memorySize: RECOVERY_ARGON2_PARAMS.m_kib,
    hashLength: 32,
    outputType: 'binary',
  });
  // Fresh view: hash-wasm returns a `Uint8Array` over an unknown buffer, and
  // `crypto.subtle` insists on an ArrayBuffer-backed one.
  return crypto.subtle.importKey('raw', new Uint8Array(bits), 'AES-KW', false, ['wrapKey', 'unwrapKey']);
}

/**
 * Enforce the Argon2id cost floor on params read off a record. A wrap
 * claiming `m_kib: 1024` would let whoever holds the code be brute-forced at
 * a thousandth of the intended cost — so below-floor params are a downgrade,
 * not a hint.
 *
 * @throws `SealedError('weak_params')` below the floor.
 */
export function assertRecoveryParams(params: RecoveryParams | undefined): RecoveryParams {
  if (!params) throw new SealedError('bad_wrap', 'recovery wrap is missing its params');
  const floor = RECOVERY_PARAMS_FLOOR;
  if (params.m_kib < floor.m_kib || params.t < floor.t || params.p < floor.p) {
    throw new SealedError(
      'weak_params',
      `recovery wrap params m_kib=${params.m_kib} t=${params.t} p=${params.p} are below the accepted floor ` +
        `m_kib>=${floor.m_kib} t>=${floor.t} p>=${floor.p} — refusing (downgrade protection)`,
    );
  }
  return params;
}
