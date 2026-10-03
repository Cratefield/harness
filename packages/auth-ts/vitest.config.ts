// The bulk of the suite runs in Node (which has the same WebCrypto/Fetch
// globals) because it needs `node:fs` for the source guard test. The Workers
// runtime gets its own project, `vitest.workers.config.ts`.
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    exclude: ['test/workers/**', 'node_modules/**', 'dist/**'],
  },
});
