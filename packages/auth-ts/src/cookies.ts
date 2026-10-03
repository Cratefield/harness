// Session cookies and the sealed OAuth state cookie.
//
// Every cookie is `__Host-` prefixed, which forces the browser to accept it
// only over HTTPS, only for the whole origin, and only without a `Domain`
// attribute — so a sibling subdomain (a takeover-prone deploy target, a
// shared host) can never set or shadow our session. The attributes below
// must therefore stay exactly as they are; `__Host-` is rejected outright if
// `Secure` is missing, `Path` is not `/`, or a `Domain` is present.

import { b64urlDecode, b64urlEncode, utf8Decode, utf8Encode } from './base64url.js';

/** Names of the three cookies the flow owns. */
export const STATE_COOKIE = '__Host-cf_state';
export const ACCESS_COOKIE = '__Host-cf_at';
export const REFRESH_COOKIE = '__Host-cf_rt';

/** The state cookie's lifetime, seconds — the sign-in round trip, not more. */
export const STATE_MAX_AGE_SECS = 600;

/**
 * The refresh cookie's lifetime, seconds.
 *
 * This mirrors auth-core's `REFRESH_TOKEN_DAYS` (30). It is a client-side
 * convenience only: the IdP decides the real expiry and will refuse a token
 * past it. Kept as a literal because the id is presented to the browser as a
 * number and there is nothing to negotiate.
 */
export const REFRESH_MAX_AGE_SECS = 30 * 24 * 60 * 60;

/** Read one cookie from a request, or `undefined` if it is absent. */
export function readCookie(request: Request, name: string): string | undefined {
  const header = request.headers.get('Cookie');
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return undefined;
}

/**
 * Serialise one session cookie with the attributes `__Host-` requires.
 *
 * No `Domain`, `Path=/`, `Secure`, `HttpOnly`, `SameSite=Lax`. `Lax` (not
 * `Strict`) because the callback is a top-level cross-site navigation from
 * the IdP and a `Strict` cookie would not be sent on it.
 */
export function serializeCookie(name: string, value: string, maxAgeSecs: number): string {
  return `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSecs}`;
}

/** Delete a cookie: identical attributes, empty value, `Max-Age=0`. */
export function deleteCookie(name: string): string {
  return `${name}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`;
}

/** Append a `Set-Cookie` to a header set without clobbering an earlier one. */
export function appendSetCookie(headers: Headers, cookie: string): void {
  headers.append('Set-Cookie', cookie);
}

/** What the sealed state cookie carries across the sign-in round trip. */
export interface StatePayload {
  /** CSRF token, compared against the query parameter. */
  state: string;
  /** The PKCE verifier; confidential, hence the AEAD below. */
  verifier: string;
  /** Sanitised post-sign-in destination. */
  returnTo: string;
  /** Expiry, Unix seconds. */
  exp: number;
}

/** Derive the AES-256-GCM key from the configured cookie secret. */
async function stateKey(cookieSecret: string): Promise<CryptoKey> {
  // SHA-256 rather than a KDF: the secret is a high-entropy application key,
  // not a password, and the hash fixes its length at the 32 bytes AES wants.
  const digest = await crypto.subtle.digest('SHA-256', utf8Encode(cookieSecret));
  return crypto.subtle.importKey('raw', digest, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/**
 * Seal the state payload into a single cookie value, `base64url(iv || ct)`.
 *
 * AES-256-GCM for two reasons: the tag makes the cookie tamper-evident (a
 * forged `state` or `verifier` cannot be injected), and the ciphertext hides
 * the PKCE verifier, which is a secret until the code is redeemed and has no
 * business sitting in the clear in a cookie the browser will replay.
 */
export async function sealState(payload: StatePayload, cookieSecret: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await stateKey(cookieSecret);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, utf8Encode(JSON.stringify(payload))),
  );
  const sealed = new Uint8Array(iv.length + ciphertext.length);
  sealed.set(iv, 0);
  sealed.set(ciphertext, iv.length);
  return b64urlEncode(sealed);
}

/**
 * Open a sealed state cookie, or `null` if it is malformed, forged, under a
 * different secret, or simply not one of ours.
 *
 * Never throws: every failure is the same "no usable state" to the caller.
 */
export async function unsealState(value: string, cookieSecret: string): Promise<StatePayload | null> {
  try {
    const sealed = b64urlDecode(value);
    // 12-byte IV plus at least the 16-byte GCM tag.
    if (sealed.length < 12 + 16) return null;
    const iv = sealed.slice(0, 12);
    const ciphertext = sealed.slice(12);
    const key = await stateKey(cookieSecret);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    const parsed: unknown = JSON.parse(utf8Decode(new Uint8Array(plaintext)));
    return isStatePayload(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function isStatePayload(value: unknown): value is StatePayload {
  if (typeof value !== 'object' || value === null) return false;
  const payload = value as Record<string, unknown>;
  return (
    typeof payload['state'] === 'string' &&
    typeof payload['verifier'] === 'string' &&
    typeof payload['returnTo'] === 'string' &&
    typeof payload['exp'] === 'number'
  );
}
