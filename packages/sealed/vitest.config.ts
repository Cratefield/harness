// The bulk of the suite runs in Node (Node 24 ships the same WebCrypto the
// browser gets), so only the seal/open round trip that must prove the real
// Chromium runtime lives in `test/browser.test.ts` — that file gets its own
// project, `vitest.browser.config.ts`.
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    exclude: ['test/browser.test.ts', 'node_modules/**', 'dist/**'],
  },
});
