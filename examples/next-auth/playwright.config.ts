import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { defineConfig, devices } from '@playwright/test';

// Next loads `.env.local` for the server itself; the test runner and the spec
// must see the same values, so load it here too (without clobbering the real
// environment). `npm run setup` writes the file. Playwright runs from the
// project root, so a cwd-relative path is safe (and usable from a CJS-loaded
// config, where `import.meta` is not).
try {
  const text = readFileSync(resolve(process.cwd(), '.env.local'), 'utf8');
  for (const line of text.split('\n')) {
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    if (!(key in process.env)) process.env[key] = line.slice(eq + 1).trim();
  }
} catch {
  // No `.env.local` yet. The build and webServer will say so.
}

const APP_URL = process.env.APP_URL ?? 'http://localhost:3000';

export default defineConfig({
  testDir: './e2e',
  // One browser, one journey: the steps share a cookie jar.
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: APP_URL,
    trace: 'retain-on-failure',
  },
  projects: [
    // Chromium only: it accepts `__Host-`/Secure cookies on http://localhost,
    // which the session cookies require.
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
  webServer: {
    command: 'npm run start',
    url: APP_URL,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
