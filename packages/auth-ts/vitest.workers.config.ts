// The `workerd` leg: the same public API exercised inside the runtime it
// ships to, so a Node-only API or an accidental Node import cannot pass the
// Node suite and then fail on deploy.
//
// The pool moved from a `defineWorkersConfig()` helper to a Vite plugin in
// @cloudflare/vitest-pool-workers 0.22 (Vitest 4), hence `cloudflareTest`.
import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-pool-workers';

export default defineConfig({
  plugins: [cloudflareTest({ miniflare: { compatibilityDate: '2025-01-01' } })],
  test: {
    include: ['test/workers/**/*.test.ts'],
  },
});
