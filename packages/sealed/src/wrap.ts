// Building wraps: one KEK per unlock, content key wrapped under each.
//
// Shared by `seal` (initial wraps) and `wraps.ts` (add/rotate) so every wrap
// this package produces — fresh or derived from an existing CK — has the
// same shape and parameters.

import { b64urlEncode } from './base64url.js';
import { SealedError } from './errors.js';
import { unwrapContentKey, WRAPPED_KEY_LENGTH } from './keys.js';
import { derivePrfKek, newPrfSalt, PRF_SALT_LENGTH } from './prf.js';
import {
  deriveRecoveryKek,
  normalizeRecoveryCode,
  RECOVERY_ARGON2_PARAMS,
  RECOVERY_SALT_LENGTH,
} from './recovery.js';
import { PRF_WRAP_ALG, RECOVERY_WRAP_ALG, type Unlock, type Wrap } from './types.js';

const random = crypto.getRandomValues.bind(crypto);

/**
 * Wrap `contentKey` under `unlock`, producing one wire wrap.
 *
 * - prf: `id` is the credential id; `salt` is `unlock.prfSalt` or a fresh
 *   32-byte one. KEK = HKDF-SHA256(PRF output, salt, info) — see `prf.ts`.
 * - recovery: `id` is `unlock.id` or the next free `recovery-<n>` from
 *   `usedIds`; KEK = Argon2id(normalised code, 16-byte random salt) at the
 *   documented cost.
 */
export async function buildWrap(
  contentKey: CryptoKey,
  unlock: Unlock,
  subject: string,
  blobId: string,
  usedIds: ReadonlySet<string>,
): Promise<Wrap> {
  return unlock.kind === 'prf' ? buildPrfWrap(contentKey, unlock, subject, blobId, usedIds) : buildRecoveryWrap(contentKey, unlock, usedIds);
}

async function buildPrfWrap(
  contentKey: CryptoKey,
  unlock: Extract<Unlock, { kind: 'prf' }>,
  subject: string,
  blobId: string,
  usedIds: ReadonlySet<string>,
): Promise<Wrap> {
  if (usedIds.has(unlock.credentialId)) {
    throw new SealedError('duplicate_wrap', `credential ${JSON.stringify(unlock.credentialId)} already has a wrap`);
  }
  const salt = unlock.prfSalt ?? newPrfSalt();
  if (salt.length !== PRF_SALT_LENGTH) {
    throw new SealedError('bad_input', `prf salt must be ${PRF_SALT_LENGTH} bytes, got ${salt.length}`);
  }
  const kek = await derivePrfKek(unlock.prfOutput, salt, subject, blobId);
  return {
    id: unlock.credentialId,
    kind: 'prf',
    alg: PRF_WRAP_ALG,
    salt: b64urlEncode(salt),
    wrapped_key: b64urlEncode(await wrapContentKey(kek, contentKey)),
  };
}

async function buildRecoveryWrap(
  contentKey: CryptoKey,
  unlock: Extract<Unlock, { kind: 'recovery' }>,
  usedIds: ReadonlySet<string>,
): Promise<Wrap> {
  const id = unlock.id ?? `recovery-${nextRecoveryNumber(usedIds)}`;
  if (usedIds.has(id)) throw new SealedError('duplicate_wrap', `wrap id ${JSON.stringify(id)} is already in use`);
  const salt = random(new Uint8Array(RECOVERY_SALT_LENGTH));
  const kek = await deriveRecoveryKek(normalizeRecoveryCode(unlock.code), salt);
  return {
    id,
    kind: 'recovery',
    alg: RECOVERY_WRAP_ALG,
    salt: b64urlEncode(salt),
    params: { ...RECOVERY_ARGON2_PARAMS },
    wrapped_key: b64urlEncode(await wrapContentKey(kek, contentKey)),
  };
}

/** `recovery-<n+1>` where `<n>` is the largest suffix already in `usedIds` (0 if none). */
export function nextRecoveryNumber(usedIds: ReadonlySet<string>): number {
  let max = 0;
  for (const id of usedIds) {
    const match = /^recovery-(\d+)$/.exec(id);
    if (match) max = Math.max(max, Number(match[1]));
  }
  return max + 1;
}

async function wrapContentKey(kek: CryptoKey, contentKey: CryptoKey): Promise<Uint8Array<ArrayBuffer>> {
  const wrapped = new Uint8Array(await crypto.subtle.wrapKey('raw', contentKey, kek, { name: 'AES-KW' }));
  if (wrapped.length !== WRAPPED_KEY_LENGTH) {
    throw new SealedError('bad_wrap', `AES-KW produced ${wrapped.length} bytes, expected ${WRAPPED_KEY_LENGTH}`);
  }
  return wrapped;
}

/**
 * Unwrap the content key of `record` with `unlock`. A prf unlock matches the
 * wrap whose id is the credential id; a recovery unlock matches `unlock.id`
 * if given, else tries every recovery wrap in order (an id-less unlock says
 * "open with my code", and older records may hold several recovery wraps).
 *
 * `opts.extractable` is passed to every unwrap: `false` for decrypt-only
 * callers (`open`), `true` only for callers about to re-wrap the key
 * (`addWrap`, `rotateWraps`).
 *
 * @throws `SealedError('wrap_not_found')` for no matching wrap, or
 * `SealedError('unwrap_failed')` if the material does not open any of them.
 */
export async function recoverContentKey(
  record: { subject: string; blob_id: string; wraps: Wrap[] },
  unlock: Unlock,
  opts: { extractable: boolean },
): Promise<CryptoKey> {
  const { subject, blob_id: blobId, wraps } = record;
  if (unlock.kind === 'prf') {
    const wrap = wraps.find((w) => w.kind === 'prf' && w.id === unlock.credentialId);
    if (!wrap) throw new SealedError('wrap_not_found', `no prf wrap for credential ${JSON.stringify(unlock.credentialId)}`);
    return unwrapContentKey(wrap, unlock, subject, blobId, opts);
  }
  const recovery = wraps.filter((w) => w.kind === 'recovery');
  if (unlock.id !== undefined) {
    const wrap = recovery.find((w) => w.id === unlock.id);
    if (!wrap) throw new SealedError('wrap_not_found', `no recovery wrap ${JSON.stringify(unlock.id)}`);
    return unwrapContentKey(wrap, unlock, subject, blobId, opts);
  }
  if (recovery.length === 0) throw new SealedError('wrap_not_found', 'record has no recovery wraps');
  let last: SealedError | undefined;
  for (const wrap of recovery) {
    try {
      return await unwrapContentKey(wrap, unlock, subject, blobId, opts);
    } catch (e) {
      if (!(e instanceof SealedError) || e.code !== 'unwrap_failed') throw e;
      last = e;
    }
  }
  throw last ?? new SealedError('unwrap_failed', 'recovery code opens no wrap on this record');
}

/** Build wraps for every unlock, rejecting duplicate ids across the set. */
export async function buildWraps(
  contentKey: CryptoKey,
  unlocks: readonly Unlock[],
  subject: string,
  blobId: string,
): Promise<Wrap[]> {
  const usedIds = new Set<string>();
  const wraps: Wrap[] = [];
  for (const unlock of unlocks) {
    const wrap = await buildWrap(contentKey, unlock, subject, blobId, usedIds);
    usedIds.add(wrap.id);
    wraps.push(wrap);
  }
  return wraps;
}
