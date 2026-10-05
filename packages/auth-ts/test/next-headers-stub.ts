// A stand-in for `next/headers`, aliased in vitest.config.ts. `next` is an
// optional peer dependency and is not installed here, so the Node test run
// needs something to resolve the import to. The value lives on `globalThis`
// (keyed by a well-known string) so setting it from the test and reading it
// from the aliased module cannot diverge on module identity.

const KEY = '__cratefield_auth_next_headers_stub__';

/** The cookies `cookies()` will report for the rest of this test. */
export function setStubCookies(values: Record<string, string | undefined>): void {
  (globalThis as Record<string, unknown>)[KEY] = values;
}

export function cookies(): { get(name: string): { value: string } | undefined } {
  const values = ((globalThis as Record<string, unknown>)[KEY] ?? {}) as Record<string, string | undefined>;
  return {
    get(name: string) {
      const value = values[name];
      return value === undefined ? undefined : { value };
    },
  };
}
