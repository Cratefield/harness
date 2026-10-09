// Client-side passkey PRF (WebAuthn `prf` extension) support: run a
// user-verification ceremony, take the raw PRF output the authenticator
// returns, and stretch it into a non-extractable WebCrypto key.
//
// The point of the extension is a key the *user* holds and the server never
// sees: the authenticator derives 32 deterministic bytes from the credential's
// secret plus a per-credential salt, and the salt is not secret — the server
// stores it so the client knows what to ask for. This module never sends the
// PRF output anywhere: ceremony output goes straight into HKDF and only the
// derived key (and a redacted `clientExtensionResults`) survive.

import { b64urlDecode, b64urlEncode, utf8Encode } from './base64url.js';

/**
 * The `prf` member of `getClientExtensionResults()`, and the form we accept in
 * {@link redactPrfResults}. Types are local rather than DOM: the package
 * compiles against the `WebWorker` lib, which has no WebAuthn interfaces.
 */
export interface PrfExtensionOutputs {
  /**
   * An authenticator's self-reported support claim. Deliberately ignored by
   * {@link getPrfKey}: several providers (Edge's Microsoft Password Manager,
   * Samsung Pass) report `enabled` without being able to evaluate, so only
   * the presence of real `results` counts.
   */
  enabled?: boolean;
  /** The evaluated secret(s); present only when `eval`/`evalByCredential` was asked for and answered. */
  results?: {
    /** 32 bytes derived from the credential secret and the `first` salt. */
    first?: ArrayBuffer;
    second?: ArrayBuffer;
  };
}

/** The subset of `getClientExtensionResults()` this module reads; other extensions pass through untouched. */
export interface PrfClientExtensionResults {
  prf?: PrfExtensionOutputs;
  [extension: string]: unknown;
}

/** A credential returned by a `credentials.get` ceremony, narrowed to what PRF needs. */
export interface PublicKeyCredentialLike {
  rawId: ArrayBuffer;
  getClientExtensionResults(): PrfClientExtensionResults;
}

/** The `navigator.credentials` surface, narrowed to `get` so tests can fake the ceremony. */
export interface CredentialsContainerLike {
  get(options: {
    publicKey?: PublicKeyCredentialRequestOptionsLike;
    signal?: AbortSignal;
  }): Promise<PublicKeyCredentialLike | null>;
}

/** The `publicKey` options of a `credentials.get` assertion, narrowed to what this module sends. */
export interface PublicKeyCredentialRequestOptionsLike {
  challenge: BufferSource;
  rpId?: string;
  timeout?: number;
  userVerification?: 'required' | 'preferred' | 'discouraged';
  allowCredentials?: Array<{ type: 'public-key'; id: BufferSource }>;
  extensions?: {
    prf?: {
      /** The single-salt form, used when exactly one credential is allowed. */
      eval?: { first: BufferSource };
      /** The per-credential form, keyed by *unpadded base64url* credential id; used for several. */
      evalByCredential?: Record<string, { first: BufferSource }>;
    };
    [extension: string]: unknown;
  };
}

/**
 * Whether a credential can produce PRF output, as recorded by the server at
 * registration (and revised after evaluations). `unknown` is the honest state
 * for credentials registered before the extension was requested, and for
 * providers like Samsung Pass that only report PRF on the `get` *after* the
 * one that first evaluated it.
 */
export type PrfCapability = 'supported' | 'unsupported' | 'unknown';

/** One entry of `GET /v1/auth-passkeys/passkeys/prf`'s `passkeys` array. */
export interface PrfPasskeyInfo {
  credentialId: string;
  prf: PrfCapability;
  /** The per-credential salt the server hands out; not secret, but required to derive. */
  prfSalt: string;
}

/** Options for {@link getPrfKey}. */
export interface GetPrfKeyOptions {
  /**
   * The HKDF `info` string binding the key to one purpose, e.g.
   * `cratefield:sealed-notes:v1`. Derivations for different purposes MUST use
   * different strings; see {@link derivePrfKey}.
   */
  info: string;
  /** The RP ID to request; defaults to the calling origin's effective domain. */
  rpId?: string;
  /** Ceremony timeout in ms; the browser applies its own default when omitted. */
  timeout?: number;
  /** Injectable for tests; defaults to `globalThis.navigator.credentials`. */
  credentials?: CredentialsContainerLike;
  /** Usages for the derived key; defaults to AES-GCM `encrypt`/`decrypt`. */
  keyUsages?: KeyUsage[];
  /** Target algorithm of the derived key; defaults to AES-GCM 256. */
  algorithm?: AesKeyAlgorithm;
}

/** Options for {@link derivePrfKey}, the pure WebCrypto half of {@link getPrfKey}. */
export interface DerivePrfKeyOptions {
  /** Usages for the derived key; defaults to AES-GCM `encrypt`/`decrypt`. */
  keyUsages?: KeyUsage[];
  /** Target algorithm of the derived key; defaults to AES-GCM 256. */
  algorithm?: AesKeyAlgorithm;
}

/**
 * Thrown when a ceremony completes but produces no usable PRF output, or
 * WebAuthn is not available at all. Distinguishing this from other failures
 * lets a caller flip the credential's recorded capability to `unsupported`
 * (post {@link redactPrfResults}'s output so the server does it) instead of
 * surfacing a raw error.
 */
export class PrfUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PrfUnavailableError';
  }
}

/** Bytes of randomness in a `get` challenge and in the salts the server stores. */
const PRF_BYTES = 32;

/** The PRF extension's fixed output size (WebAuthn L3 §5.8.3): `results.first` is always 32 bytes. */
const PRF_OUTPUT_BYTES = 32;

/**
 * The HKDF salt: deliberately zero-length and fixed.
 *
 * HKDF's salt exists to mix in independent randomness; the PRF output is
 * already uniform and secret, so a salt would add nothing. Pinning it (rather
 * than varying per key) is what makes the same `info` yield the same key on
 * every device and provider — the per-purpose separation comes entirely from
 * `info`, and per-credential separation from the authenticator itself.
 */
const HKDF_SALT = new Uint8Array(0);

/** Default target of {@link derivePrfKey}: a non-extractable AES-GCM 256 key. */
const DEFAULT_ALGORITHM: AesKeyAlgorithm = { name: 'AES-GCM', length: 256 };

/** Default usages of the derived key. */
const DEFAULT_KEY_USAGES: KeyUsage[] = ['encrypt', 'decrypt'];

/**
 * Run a PRF evaluation ceremony for the given credentials and derive a key.
 *
 * With one credential id the `eval` form is sent (the most compatible); with
 * several, `evalByCredential` keyed by unpadded base64url id, matching the
 * login options the server generates. A random challenge and
 * `userVerification: "required"` make the ceremony a real unlock, not a
 * silent read.
 *
 * The authenticator's support claims are never trusted — a browser that
 * returns `prf.enabled` without `prf.results` (or a short result) throws
 * {@link PrfUnavailableError}. The raw PRF bytes are consumed by the HKDF
 * import and not retained.
 *
 * @param credentialIds Unpadded base64url credential ids, from `GET /v1/auth-passkeys/passkeys/prf`.
 * @param salts The matching per-credential salts (base64url, 32 bytes each), same order.
 * @returns A non-extractable key, deterministic in (credential, salt, `info`).
 */
export async function getPrfKey(
  credentialIds: string[],
  salts: string[],
  options: GetPrfKeyOptions,
): Promise<CryptoKey> {
  if (credentialIds.length === 0) throw new Error('credentialIds must not be empty');
  if (credentialIds.length !== salts.length) throw new Error('credentialIds and salts must have the same length');
  if (typeof options.info !== 'string' || options.info === '') {
    throw new Error('info must be a non-empty purpose string');
  }
  const ids = new Set(credentialIds);
  if (ids.size !== credentialIds.length) throw new Error('credentialIds must be unique');

  const decoded = credentialIds.map((id, index) => {
    if (id === '') throw new Error(`credential id at index ${index} is empty`);
    let bytes: Uint8Array<ArrayBuffer>;
    try {
      bytes = b64urlDecode(id);
    } catch {
      throw new Error(`credential id at index ${index} is not valid base64url`);
    }
    return bytes;
  });
  const saltBytes = salts.map((salt, index) => {
    let bytes: Uint8Array<ArrayBuffer>;
    try {
      bytes = b64urlDecode(salt);
    } catch {
      throw new Error(`salt at index ${index} is not valid base64url`);
    }
    if (bytes.length !== PRF_BYTES) throw new Error(`salt at index ${index} must decode to ${PRF_BYTES} bytes`);
    return bytes;
  });

  // Re-encode so the `evalByCredential` keys are canonical unpadded base64url,
  // whatever padding or alphabet quirks the caller passed in.
  const normalizedIds = decoded.map(b64urlEncode);

  const extensions =
    salts.length === 1
      ? { prf: { eval: { first: saltBytes[0]! } } }
      : {
          prf: {
            evalByCredential: Object.fromEntries(normalizedIds.map((id, index) => [id, { first: saltBytes[index]! }])),
          },
        };

  const container = options.credentials ?? defaultCredentialsContainer();
  const credential = await container.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(PRF_BYTES)),
      userVerification: 'required',
      ...(options.rpId !== undefined && { rpId: options.rpId }),
      ...(options.timeout !== undefined && { timeout: options.timeout }),
      allowCredentials: decoded.map((id) => ({ type: 'public-key' as const, id })),
      extensions,
    },
  });
  if (!credential) throw new PrfUnavailableError('the ceremony returned no credential');

  const first = credential.getClientExtensionResults().prf?.results?.first;
  // The only proof of PRF support is the output itself; `byteLength` also
  // collapses a missing result (`undefined`) to a failure here.
  if (first === undefined || first.byteLength !== PRF_OUTPUT_BYTES) {
    throw new PrfUnavailableError(
      `the authenticator did not return a ${PRF_OUTPUT_BYTES}-byte PRF result for this credential`,
    );
  }
  return derivePrfKey(first, options.info, options);
}

/**
 * Stretch raw PRF output into a non-extractable key: HKDF-SHA256 over the
 * output with `info = utf8(info)` and the fixed empty salt.
 *
 * `info` is the whole key domain: derivations that must never meet (wallet
 * keys vs sealed notes vs API keys) use different strings, and any change to
 * a purpose's string changes every key ever derived for it. The PRF output is
 * copied before import and the copy is zeroed once WebCrypto has it —
 * best-effort, since `importKey` keeps its own internal copy until GC.
 *
 * @param prfOutput The `results.first` bytes from a PRF evaluation.
 * @returns A non-extractable key, deterministic in (prfOutput, `info`).
 */
export async function derivePrfKey(
  prfOutput: BufferSource,
  info: string,
  options: DerivePrfKeyOptions = {},
): Promise<CryptoKey> {
  if (typeof info !== 'string' || info === '') throw new Error('info must be a non-empty purpose string');
  if (prfOutput.byteLength === 0) throw new Error('prfOutput must not be empty');

  // `importKey` needs an ArrayBuffer-backed view (and must not detach the
  // caller's buffer), so work on a copy we can scrub.
  const source = ArrayBuffer.isView(prfOutput)
    ? new Uint8Array(prfOutput.buffer, prfOutput.byteOffset, prfOutput.byteLength)
    : new Uint8Array(prfOutput);
  const copy = source.slice();

  const material = await crypto.subtle.importKey('raw', copy, 'HKDF', false, ['deriveKey']);
  copy.fill(0);

  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info: utf8Encode(info) },
    material,
    options.algorithm ?? DEFAULT_ALGORITHM,
    false, // non-extractable: the derived key must not be readable out of `exportKey`
    options.keyUsages ?? DEFAULT_KEY_USAGES,
  );
}

/**
 * Post a ceremony's `clientExtensionResults` to the server without leaking
 * the PRF bytes.
 *
 * The server rejects any result that still carries `prf.results`; the redacted
 * form replaces the whole `prf` member with `{ enabled }` — `true` when the
 * ceremony actually produced a `first` result (so the server marks the
 * credential supported), `false` otherwise (empty counts as absent, matching
 * {@link getPrfKey}'s validation). Other extensions are copied through
 * unchanged.
 */
export function redactPrfResults(clientExtensionResults: PrfClientExtensionResults): {
  prf: { enabled: boolean };
  [extension: string]: unknown;
} {
  const enabled = (clientExtensionResults.prf?.results?.first?.byteLength ?? 0) > 0;
  return { ...clientExtensionResults, prf: { enabled } };
}

/** Whether at least one enrolled passkey is known PRF-capable. Require this before offering sealed storage. */
export function hasPrfCapablePasskey(passkeys: readonly PrfPasskeyInfo[]): boolean {
  return passkeys.some((passkey) => passkey.prf === 'supported');
}

/**
 * The ambient credential container, or nothing on a runtime without WebAuthn
 * (Workers, Node, tests that forgot to inject). Resolved lazily — `navigator`
 * does not exist as a WebAuthn container in most runtimes this package
 * compiles for.
 */
function defaultCredentialsContainer(): CredentialsContainerLike {
  const credentials = (globalThis as { navigator?: { credentials?: CredentialsContainerLike } }).navigator?.credentials;
  if (!credentials) throw new PrfUnavailableError('WebAuthn (navigator.credentials) is not available in this context');
  return credentials;
}
