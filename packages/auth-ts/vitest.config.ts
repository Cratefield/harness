// The bulk of the suite runs in Node (which has the same WebCrypto/Fetch
// globals) because it needs `node:fs` for the source guard test. The Workers
// runtime gets its own project, `vitest.workers.config.ts`.
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: {
      // `next` is an optional peer dependency, so the test run resolves the
      // one Next API `src/next.ts` calls to a local stub (see the file).
      'next/headers': fileURLToPath(new URL('./test/next-headers-stub.ts', import.meta.url)),
    },
  },
  test: {
    include: ['test/**/*.test.ts'],
    exclude: ['test/workers/**', 'node_modules/**', 'dist/**'],
  },
});
