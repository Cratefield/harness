// Reading `Set-Cookie` back out of a `Headers`, portably. `getSetCookie()`
// exists in Node and workerd; the fallback splits the joined value, which is
// safe here because every cookie this client sets starts with `__Host-`.

export function setCookieHeaders(headers: Headers): string[] {
  const extended = headers as unknown as { getSetCookie?: () => string[] };
  if (typeof extended.getSetCookie === 'function') return extended.getSetCookie();
  const raw = headers.get('Set-Cookie');
  return raw ? raw.split(/,\s*(?=__Host-)/) : [];
}

/** The full `name=value; attrs` string for one cookie, or `undefined`. */
export function cookieHeader(headers: Headers, name: string): string | undefined {
  return setCookieHeaders(headers).find((cookie) => cookie.startsWith(`${name}=`));
}

/** The value of one cookie. */
export function cookieValue(headers: Headers, name: string): string | undefined {
  const header = cookieHeader(headers, name);
  if (!header) return undefined;
  const pair = header.split(';')[0]!;
  return pair.slice(pair.indexOf('=') + 1);
}

/** The attributes of one cookie (`Path`, `Max-Age`, …) as they were set. */
export function cookieAttributes(headers: Headers, name: string): Record<string, string> {
  const header = cookieHeader(headers, name);
  const attrs: Record<string, string> = {};
  if (!header) return attrs;
  for (const part of header.split(';').slice(1)) {
    const trimmed = part.trim();
    const eq = trimmed.indexOf('=');
    if (eq < 0) attrs[trimmed] = '';
    else attrs[trimmed.slice(0, eq)] = trimmed.slice(eq + 1);
  }
  return attrs;
}

/** Build a request carrying the given cookies (values may be undefined). */
export function requestWithCookies(url: string, cookies: Record<string, string | undefined>): Request {
  const header = Object.entries(cookies)
    .filter((entry): entry is [string, string] => entry[1] !== undefined)
    .map(([name, value]) => `${name}=${value}`)
    .join('; ');
  return new Request(url, header ? { headers: { Cookie: header } } : undefined);
}
