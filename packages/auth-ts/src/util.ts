// Small primitives shared by the client: a constant-time string compare for
// the CSRF `state` check, and the open-redirect defence for `returnTo`.

/**
 * Compare two strings without leaking *where* they first differ.
 *
 * The values compared here (`state`) are not secrets, so a timing oracle is
 * not the threat; the point is to avoid a `===` whose early exit could, in
 * principle, help an attacker search for a matching state. Length is still
 * revealed, which is fine — the state is a fixed-width 32-byte b64url value.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  const left = new TextEncoder().encode(a);
  const right = new TextEncoder().encode(b);
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i += 1) diff |= left[i]! ^ right[i]!;
  return diff === 0;
}

/**
 * Seconds every outbound request to the IdP is allowed.
 *
 * Without a bound, one hung issuer connection holds its slot in the refresh
 * in-flight map forever, and every later request for that token waits on it.
 */
export const FETCH_TIMEOUT_MS = 10_000;

/**
 * The origin `returnTo` values are resolved against. It never appears in
 * output; it exists only so `new URL` can normalise a relative path.
 */
const DUMMY_ORIGIN = 'https://return.invalid';

/**
 * Reduce a caller-supplied post-sign-in destination to a same-origin relative
 * path — never an absolute URL and never a protocol-relative one.
 *
 * Anything suspicious collapses to `/`. The check is deliberately positive
 * (keep only a path that resolves against a dummy origin to that same dummy
 * origin) rather than a denylist, because denylists of URL forms are how
 * open redirects survive: `//evil.com`, `/\evil.com`, `\\evil.com`,
 * `https://evil.com`, `javascript:…` and a leading space all have to fail,
 * and most of them do not look alike.
 *
 * Control characters and whitespace are rejected outright; a browser strips
 * some of them when parsing a `Location`, which is exactly what turns
 * `/\t/evil.com` into an off-site redirect after our check has passed.
 *
 * The *output* is checked as well as the input: `new URL` resolves dot
 * segments, so `/foo/..//evil.com` and `/%2e%2e//evil.com` both normalise to
 * `//evil.com` — a protocol-relative URL that only becomes dangerous after
 * parsing, i.e. after the input checks above have already passed.
 */
export function sanitizeReturnTo(value: string | null | undefined): string {
  if (typeof value !== 'string' || value === '') return '/';
  // A single leading slash only. `//host` and `/\host` are protocol-relative.
  if (!value.startsWith('/') || value.startsWith('//')) return '/';
  // Backslashes anywhere: browsers treat `\` as `/` in URLs.
  if (value.includes('\\')) return '/';
  // Any C0/C1 control character or whitespace, including tab and newline.
  if (/[\u0000- \u007f-\u009f]/.test(value)) return '/';

  let url: URL;
  try {
    url = new URL(value, DUMMY_ORIGIN);
  } catch {
    return '/';
  }
  // Belt and braces: `new URL('https://evil.com', base)` ignores the base.
  if (url.origin !== DUMMY_ORIGIN) return '/';

  const out = url.pathname + url.search + url.hash;
  // Re-check the normalised result; dot-segment resolution above is the one
  // step that can turn a safe-looking input into `//host`.
  if (!out.startsWith('/') || out.startsWith('//') || out.includes('\\')) return '/';
  return out;
}
