// base64url (RFC 4648 §5, unpadded) over `btoa`/`atob`.
//
// A tiny hand-rolled codec rather than a Buffer/Node shim: the package has to
// run unchanged in workerd, the browser and Node 20+, and none of those share
// a byte encoding helper. Callers must treat a throw from `b64urlDecode` as
// "this input was not base64url" — it comes from the attacker-controllable
// `atob`.

const decoder = new TextDecoder();
const encoder = new TextEncoder();

/**
 * UTF-8 encode to bytes, without touching a Node-only global.
 *
 * The copy into a fresh `Uint8Array` is deliberate: `TextEncoder.encode` is
 * typed `Uint8Array<ArrayBufferLike>`, while `crypto.subtle` insists on an
 * `ArrayBuffer`-backed view. Returning exactly that type keeps the cast out of
 * every call site.
 */
export function utf8Encode(value: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(encoder.encode(value));
}

/** UTF-8 decode bytes to a string. */
export function utf8Decode(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

/** Encode bytes as unpadded base64url. */
export function b64urlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decode unpadded base64url to bytes.
 *
 * @throws if the input is not valid base64url.
 */
export function b64urlDecode(value: string): Uint8Array<ArrayBuffer> {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const remainder = padded.length % 4;
  if (remainder === 1) throw new Error('invalid base64url length');
  const binary = atob(remainder === 0 ? padded : padded + '='.repeat(4 - remainder));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
