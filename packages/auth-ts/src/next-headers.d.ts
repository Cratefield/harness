// The one Next.js API `src/next.ts` calls: the app-router cookie store.
//
// `next` is an optional peer dependency and is deliberately not installed in
// this repo (it must not become a devDependency), so TypeScript has nothing to
// resolve `next/headers` to. This ambient declaration supplies exactly the
// surface we use and nothing more; a consumer's own project resolves the real
// types instead. It is not emitted to `dist/` (tsc does not copy input `.d.ts`
// files), and `dist/next.d.ts` never mentions `next/headers` — the import is
// used only inside `getSession`'s body, so declaration emit elides it.
//
// `cookies()` is synchronous in Next 14 and returns a Promise in Next 15. The
// union is what makes `await cookies()` correct on both.
declare module 'next/headers' {
  interface CookieStore {
    get(name: string): { value: string } | undefined;
  }
  export function cookies(): CookieStore | Promise<CookieStore>;
}
