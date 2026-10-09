// Public surface of @cratefield/auth.

export { createAuth } from './client.js';
export type { Auth, AuthConfig, RefreshResult } from './client.js';
export type { Claims } from './jwt.js';
export { createCodeVerifier, codeChallengeS256 } from './pkce.js';
export {
  PrfUnavailableError,
  derivePrfKey,
  getPrfKey,
  hasPrfCapablePasskey,
  redactPrfResults,
} from './prf.js';
export type {
  CredentialsContainerLike,
  DerivePrfKeyOptions,
  GetPrfKeyOptions,
  PrfCapability,
  PrfClientExtensionResults,
  PrfExtensionOutputs,
  PrfPasskeyInfo,
  PublicKeyCredentialLike,
  PublicKeyCredentialRequestOptionsLike,
} from './prf.js';
export { sanitizeReturnTo } from './util.js';
