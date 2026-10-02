// PKCE (RFC 7636), S256 only. These are exported so a browser-only client
// (one that talks to the authorize endpoint itself) can reuse the same code
// the server-side flow uses.

import { b64urlEncode } from './base64url.js';

/** Bytes of entropy behind a verifier: 32 bytes → 43 base64url characters. */
const VERIFIER_BYTES = 32;

/**
 * A fresh PKCE code verifier.
 *
 * 32 random bytes render as 43 base64url characters, exactly the minimum
 * RFC 7636 §4.1 asks for; there is no reason to go lower, and the verifier is
 * the only thing standing between an intercepted code and a stolen session.
 */
export function createCodeVerifier(): string {
  return b64urlEncode(crypto.getRandomValues(new Uint8Array(VERIFIER_BYTES)));
}

/** The S256 challenge for a verifier: base64url(SHA-256(ASCII(verifier))). */
export async function codeChallengeS256(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return b64urlEncode(new Uint8Array(digest));
}
