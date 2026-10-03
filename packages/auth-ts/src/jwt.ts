// Access-token verification: header, signature, then claims — and the JWKS
// cache that feeds it.
//
// The order mirrors crates/auth-client/src/verify.rs, and it matters for the
// same reason: nothing in the payload is trusted until the signature proves
// it came from a key we hold, so `alg` is checked (and refused) before any
// key is looked up, and the claims are checked last.

import { b64urlDecode, utf8Decode, utf8Encode } from './base64url.js';
import { FETCH_TIMEOUT_MS } from './util.js';

/** The only signing algorithm accepted. Checked before key lookup. */
export const ALGORITHM = 'ES256';

/** Clock skew tolerated on `exp`, `iat` and `nbf`, seconds. */
const LEEWAY_SECS = 60;

/** JWKS cache TTL when the response carries no `Cache-Control`. */
const JWKS_DEFAULT_TTL_MS = 300_000;

/** Longest we will honour a `Cache-Control` `max-age`, whatever a server claims. */
const MAX_CACHE_TTL_MS = 24 * 60 * 60 * 1000;

/**
 * Parse a `Cache-Control` `max-age` in seconds into a millisecond TTL.
 *
 * Falls back to `fallbackMs` when absent or unparseable, and clamps to
 * `MAX_CACHE_TTL_MS` so a mistaken `max-age=999999999` cannot pin a stale key
 * set in place forever.
 */
function cacheTtlMs(header: string | null, fallbackMs: number): number {
  const match = header?.match(/(?:^|,)\s*max-age\s*=\s*(\d+)/i);
  if (!match?.[1]) return fallbackMs;
  const seconds = Number(match[1]);
  if (!Number.isFinite(seconds)) return fallbackMs;
  return Math.min(seconds * 1000, MAX_CACHE_TTL_MS);
}

/** Shortest gap between forced refetches of the key set, milliseconds. */
export const REFETCH_MIN_MS = 60_000;

/** A verified access token's claims. */
export interface Claims {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  sid: string;
  email?: string;
  email_verified?: boolean;
  amr?: string[];
}

/** Outcome of one verification attempt. */
type VerifyOutcome =
  | { ok: true; claims: Claims }
  | { ok: false; unknownKid?: string };

/**
 * Verify one token against the keys currently held.
 *
 * Returns `unknownKid` (rather than a bare failure) only so the caller can
 * decide whether a refetch is worth trying. Everything else — malformed
 * header, wrong `alg`, bad signature, bad claims — is a flat `false`.
 */
export async function verifyToken(
  token: string,
  keys: Map<string, CryptoKey>,
  issuer: string,
  audience: string,
  nowSecs: number,
): Promise<VerifyOutcome> {
  const firstDot = token.indexOf('.');
  const secondDot = token.indexOf('.', firstDot + 1);
  // Exactly three segments: a fourth dot means this is not a compact JWS.
  if (firstDot < 0 || secondDot < 0 || token.indexOf('.', secondDot + 1) >= 0) {
    return { ok: false };
  }
  const encodedHeader = token.slice(0, firstDot);
  const encodedPayload = token.slice(firstDot + 1, secondDot);
  const encodedSignature = token.slice(secondDot + 1);

  let header: { alg?: unknown; kid?: unknown };
  try {
    header = JSON.parse(utf8Decode(b64urlDecode(encodedHeader))) as typeof header;
  } catch {
    return { ok: false };
  }
  if (typeof header !== 'object' || header === null) return { ok: false };

  // Algorithm first, before a key is even looked up. `none` and the HMAC
  // families die here rather than deeper in, so a token asking to be
  // "verified" with the public key as a shared secret never gets the chance.
  if (header.alg !== ALGORITHM) return { ok: false };
  if (typeof header.kid !== 'string') return { ok: false };

  const key = keys.get(header.kid);
  if (!key) return { ok: false, unknownKid: header.kid };

  let signature: Uint8Array<ArrayBuffer>;
  try {
    signature = b64urlDecode(encodedSignature);
  } catch {
    return { ok: false };
  }
  // ECDSA P-256 is exactly r||s, 32 + 32 bytes; anything else is not a
  // signature WebCrypto will accept and is cheaper to reject here.
  if (signature.length !== 64) return { ok: false };

  const signingInput = utf8Encode(`${encodedHeader}.${encodedPayload}`);
  let valid: boolean;
  try {
    valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      signature,
      signingInput,
    );
  } catch {
    return { ok: false };
  }
  if (!valid) return { ok: false };

  // Only now is anything in the payload worth reading.
  const claims = parseClaims(encodedPayload, issuer, audience, nowSecs);
  return claims ? { ok: true, claims } : { ok: false };
}

/** Parse and validate the payload, or `null` if any check fails. */
function parseClaims(
  encodedPayload: string,
  issuer: string,
  audience: string,
  nowSecs: number,
): Claims | null {
  let raw: unknown;
  try {
    raw = JSON.parse(utf8Decode(b64urlDecode(encodedPayload)));
  } catch {
    return null;
  }
  if (typeof raw !== 'object' || raw === null) return null;
  const p = raw as Record<string, unknown>;

  const iss = p['iss'];
  const sub = p['sub'];
  const aud = p['aud'];
  const sid = p['sid'];
  const exp = p['exp'];
  const iat = p['iat'];
  if (
    typeof iss !== 'string' ||
    typeof sub !== 'string' ||
    // `aud` must be a string equal to our client id. An array form is
    // refused rather than searched: auth-core always mints a string, so an
    // array is either a bug or a probe.
    typeof aud !== 'string' ||
    typeof sid !== 'string' ||
    typeof exp !== 'number' ||
    typeof iat !== 'number' ||
    !Number.isFinite(exp) ||
    !Number.isFinite(iat)
  ) {
    return null;
  }

  // The check a hand-rolled verifier forgets: a token minted for another
  // client is signed by the same issuer with the same key and differs only
  // in a claim that is easy to skip.
  if (iss !== issuer) return null;
  if (aud !== audience) return null;
  if (nowSecs - LEEWAY_SECS >= exp) return null;
  if (iat - LEEWAY_SECS > nowSecs) return null;
  const nbf = p['nbf'];
  if (typeof nbf === 'number' && Number.isFinite(nbf) && nbf - LEEWAY_SECS > nowSecs) {
    return null;
  }

  const claims: Claims = { iss, sub, aud, exp, iat, sid };
  if (typeof p['email'] === 'string') claims.email = p['email'];
  if (typeof p['email_verified'] === 'boolean') claims.email_verified = p['email_verified'];
  if (Array.isArray(p['amr']) && p['amr'].every((m) => typeof m === 'string')) {
    claims.amr = p['amr'] as string[];
  }
  return claims;
}

/**
 * A cached JWKS for one issuer.
 *
 * Keys rotate, so a cache that never refreshes eventually rejects every
 * token; a cache that refetches on every request lets anyone drive traffic at
 * the issuer by presenting tokens naming keys that do not exist. Both are
 * bounded here: a TTL for the ordinary case, and a rate-limited forced
 * refetch when a token names an unknown key.
 *
 * A failed refetch keeps the previous key set. A momentarily unreachable
 * issuer must not invalidate every live session in a running app.
 */
export class JwksCache {
  private keys = new Map<string, CryptoKey>();
  private fetchedAtMs = 0;
  private ttlMs = JWKS_DEFAULT_TTL_MS;
  private lastForcedMs = 0;
  private everFetched = false;
  private inflight: Promise<void> | null = null;

  constructor(private readonly fetchImpl: typeof fetch) {}

  /** The current key map. Replaced wholesale on each successful fetch. */
  current(): Map<string, CryptoKey> {
    return this.keys;
  }

  /** Fetch if the TTL has lapsed (or nothing has been fetched yet). */
  async ensureFresh(jwksUri: string, nowMs: number): Promise<void> {
    if (this.everFetched && nowMs - this.fetchedAtMs < this.ttlMs) return;
    await this.fetchInto(jwksUri, nowMs);
  }

  /**
   * Force a fetch, at most once per {@link REFETCH_MIN_MS}.
   *
   * The rate limit is what stops an attacker inventing `kid`s from turning
   * every verification into an outbound request.
   */
  async refetch(jwksUri: string, nowMs: number): Promise<void> {
    if (nowMs - this.lastForcedMs < REFETCH_MIN_MS) return;
    this.lastForcedMs = nowMs;
    await this.fetchInto(jwksUri, nowMs);
  }

  private fetchInto(jwksUri: string, nowMs: number): Promise<void> {
    // Concurrent cold callers share one request rather than stampeding.
    this.inflight ??= this.fetchKeys(jwksUri, nowMs).finally(() => {
      this.inflight = null;
    });
    return this.inflight;
  }

  private async fetchKeys(jwksUri: string, nowMs: number): Promise<void> {
    try {
      const response = await this.fetchImpl(jwksUri, {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (!response.ok) return;
      const body = (await response.json()) as { keys?: unknown };
      const keys = new Map<string, CryptoKey>();
      if (Array.isArray(body.keys)) {
        for (const jwk of body.keys) {
          const imported = await importJwk(jwk);
          if (imported) keys.set(imported.kid, imported.key);
        }
      }
      this.keys = keys;
      this.fetchedAtMs = nowMs;
      this.ttlMs = cacheTtlMs(response.headers.get('Cache-Control'), JWKS_DEFAULT_TTL_MS);
      this.everFetched = true;
    } catch {
      // Keep the previous key set; see the class comment.
    }
  }
}

/**
 * Import one public JWK, or `null` if it is not a P-256 key we can verify
 * with.
 *
 * A key carrying `d` is a private key, which must never appear in a public
 * set; skipping it means an issuer bug cannot become a client vulnerability.
 */
async function importJwk(jwk: unknown): Promise<{ kid: string; key: CryptoKey } | null> {
  if (typeof jwk !== 'object' || jwk === null) return null;
  const { kty, crv, kid, x, y, alg, d } = jwk as Record<string, unknown>;
  if (d !== undefined) return null;
  if (kty !== 'EC' || crv !== 'P-256') return null;
  // `alg` may be omitted; when present it must name the algorithm we use.
  if (alg !== undefined && alg !== ALGORITHM) return null;
  if (typeof kid !== 'string' || typeof x !== 'string' || typeof y !== 'string') return null;
  try {
    const key = await crypto.subtle.importKey(
      'jwk',
      { kty: 'EC', crv: 'P-256', x, y, ext: true },
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    return { kid, key };
  } catch {
    return null;
  }
}
