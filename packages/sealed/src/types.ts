// Wire types shared with the Rust server crate (`module-sealed`). All JSON
// keys are snake_case; all binary fields are unpadded base64url. Keep this
// file in lockstep with the server's schema — it is the contract.

/** AES-256-GCM, 12-byte nonce prepended, 16-byte tag appended. */
export const PAYLOAD_ALG = 'A256GCM';

export const PRF_WRAP_ALG = 'HKDF-SHA256+A256KW';
export const RECOVERY_WRAP_ALG = 'ARGON2ID+A256KW';

/** Argon2id parameters for a recovery wrap (`m_kib` in KiB, `t` rounds, `p` lanes). */
export interface RecoveryParams {
  m_kib: number;
  t: number;
  p: number;
}

/** Lowest Argon2id cost a recovery wrap may carry — anything below is a downgrade and refused. */
export const RECOVERY_PARAMS_FLOOR: RecoveryParams = { m_kib: 65536, t: 3, p: 1 };

/**
 * One key wrap: the content key encrypted under one unlock's KEK.
 *
 * - `kind: "prf"` — `salt` is the 32-byte PRF evaluation input the app passes
 *   to `navigator.credentials.get({extensions: {prf: {eval: {first: salt}}}})`;
 *   `params` must be absent. `id` is the WebAuthn credential id (base64url).
 * - `kind: "recovery"` — `salt` is the 16-byte Argon2id salt; `params` is
 *   required. `id` is `recovery-<n>` or a client label.
 */
export interface Wrap {
  id: string;
  kind: 'prf' | 'recovery';
  alg: typeof PRF_WRAP_ALG | typeof RECOVERY_WRAP_ALG;
  salt: string;
  params?: RecoveryParams;
  wrapped_key: string;
}

/** Body for `POST /blobs` (also what `rotateContentKey` returns for `PUT /blobs/{id}`). */
export interface CreateBlob {
  blob_id: string;
  version: number;
  purpose: string;
  alg: typeof PAYLOAD_ALG;
  ciphertext: string;
  wraps: Wrap[];
  created_by_credential: string;
}

/** What the server returns from `GET /blobs/{id}`: a CreateBlob plus its metadata. */
export interface BlobRecord extends CreateBlob {
  subject: string;
  created_at: string;
  updated_at: string;
}

/** Body for `PUT /blobs/{id}/wraps`: wrap edits that never touch the payload. */
export interface WrapEdit {
  version: number;
  wraps: Wrap[];
}

/** Unlock via a passkey PRF output. `prfSalt` may be omitted on `seal` (a fresh one is generated). */
export interface UnlockPrf {
  kind: 'prf';
  /** WebAuthn credential id (base64url); becomes the wrap's `id`. */
  credentialId: string;
  /** The 32-byte `prf` extension output for `eval.first = prfSalt`. */
  prfOutput: Uint8Array;
  /** The 32-byte PRF evaluation input; also stored as the wrap's `salt`. */
  prfSalt?: Uint8Array;
}

/** Unlock via an Argon2id-derived recovery code. */
export interface UnlockRecovery {
  kind: 'recovery';
  /** Wrap id; defaults to the next free `recovery-<n>`. */
  id?: string;
  code: string;
}

export type Unlock = UnlockPrf | UnlockRecovery;
