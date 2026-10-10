// The browser project: the same suite shape, but really executed inside a
// headless Chromium via the Playwright provider (`@vitest/browser-playwright`).
// Node's WebCrypto matches the browser's, so this leg exists to catch
// runtime-environment gaps (globals, module loading, btoa/atob), not
// crypto differences — hence the single round-trip file.
//
// `chromiumSandbox: false` because CI runners (and this package's sandboxed
// build environments) run as root, where Chrome's SUID sandbox cannot start;
// the test exercises crypto code, not the sandbox.
import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/browser.test.ts'],
    browser: {
      enabled: true,
      provider: playwright(),
      headless: true,
      instances: [{ browser: 'chromium' }],
      providerOptions: {
        launchOptions: { chromiumSandbox: false },
      },
    },
  },
});
