// Public surface of @cratefield/sealed.

export { aad } from './aad.js';
export { newBlobId, seal } from './seal.js';
export { open } from './open.js';
export { addWrap, removeWrap, rotateContentKey, rotateWraps } from './wraps.js';
export { newPrfSalt, prfEvalInput } from './prf.js';
export { generateRecoveryCode, normalizeRecoveryCode, RECOVERY_ARGON2_PARAMS } from './recovery.js';
export { RECOVERY_PARAMS_FLOOR } from './types.js';
export { SealedError } from './errors.js';
export type { SealedErrorCode } from './errors.js';
export type {
  BlobRecord,
  CreateBlob,
  RecoveryParams,
  Unlock,
  UnlockPrf,
  UnlockRecovery,
  Wrap,
  WrapEdit,
} from './types.js';
