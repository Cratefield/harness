import { expect, test } from '@playwright/test';

// One serial journey through the whole flow, because every step shares the
// browser's cookie jar with the previous one. The IdP is started outside
// Playwright (see the README / CI step).
//
// Two things about this test that a reader should not have to reverse-engineer:
//
// 1. "Expiry" is simulated, not waited for. auth-core issues access tokens with
//    a fixed 600 s TTL; dropping the `__Host-cf_at` cookie reproduces exactly
//    what the browser does when the cookie's `Max-Age` lapses, while
//    `__Host-cf_rt` survives — the state the middleware renews in place.
//
// 2. `stripReferrerPolicy` below works around a defect in the IdP's own HTML
//    pages, not in anything this example — or `@cratefield/auth` — does. The
//    harness stamps every HTML response with `Referrer-Policy: no-referrer`
//    (crates/core/src/http.rs). In Chromium that makes a same-origin *form POST*
//    send `Origin: null`, and auth-core's CSRF guard refuses a literal `null`
//    origin (crates/auth-core/src/csrf.rs). So the IdP's password form and its
//    sign-out confirmation page both answer 403 to a real browser submission.
//    Stripping the header for the IdP's responses only restores the browser
//    behaviour the IdP was written against; the app-facing flow under test is
//    untouched. That IdP bug is tracked separately. See the README for more.

const IDP = new URL(process.env.AUTH_ISSUER ?? 'http://localhost:8787').origin;
const APP = process.env.APP_URL ?? 'http://localhost:3000';

/** Drop `Referrer-Policy` from the IdP's responses (see note 2 above). */
async function stripReferrerPolicy(context: import('@playwright/test').BrowserContext) {
  await context.route(`${IDP}/**`, async (route) => {
    const response = await route.fetch({ maxRedirects: 0 });
    const headers = { ...response.headers() };
    delete headers['referrer-policy'];
    await route.fulfill({ response, headers });
  });
}

test('sign in, refresh, and sign out through the IdP', async ({ page, context }) => {
  await stripReferrerPolicy(context);

  const email = process.env.E2E_EMAIL ?? 'next-auth-e2e@example.com';
  const password = process.env.E2E_PASSWORD ?? 'correct horse battery staple';

  await test.step('an anonymous /dashboard visit is redirected to the IdP', async () => {
    await page.goto('/dashboard');
    await expect(page).toHaveURL(/\/v1\/auth-core\/authorize/);
    await expect(page.locator('a.method[data-method="password"]')).toBeVisible();
  });

  await test.step('signing in with the password form lands back on /dashboard', async () => {
    await page.locator('a.method[data-method="password"]').click();
    await page.fill('#email', email);
    await page.fill('#password', password);
    await page.getByRole('button', { name: 'Sign in' }).click();

    await expect(page).toHaveURL(`${APP}/dashboard`);
    await expect(page.getByTestId('subject')).not.toBeEmpty();
    await expect(page.getByTestId('claims')).toContainText('"sub"');
  });

  await test.step('a dropped access cookie is refreshed in place', async () => {
    expect((await context.cookies()).some((c) => c.name === '__Host-cf_at')).toBe(true);
    await context.clearCookies({ name: '__Host-cf_at' });

    // Reload: the middleware finds a refresh cookie but no access cookie,
    // refreshes, and 307s back to this same URL with the new cookies.
    await page.goto('/dashboard');
    await expect(page).toHaveURL(`${APP}/dashboard`);
    await expect(page.getByTestId('subject')).not.toBeEmpty();

    const after = await context.cookies();
    expect(after.some((c) => c.name === '__Host-cf_at')).toBe(true);
    expect(after.some((c) => c.name === '__Host-cf_rt')).toBe(true);
  });

  await test.step('POST /api/auth/refresh: 204 same-origin, 403 cross-origin', async () => {
    const sameOrigin = await page.evaluate(async () => {
      const res = await fetch('/api/auth/refresh', { method: 'POST' });
      return res.status;
    });
    expect(sameOrigin).toBe(204);

    const crossOrigin = await context.request.post('/api/auth/refresh', {
      headers: { Origin: 'https://evil.example' },
    });
    expect(crossOrigin.status()).toBe(403);
  });

  await test.step('signing out clears the session and re-protects /dashboard', async () => {
    await page.getByRole('button', { name: 'Sign out' }).click();
    // The IdP shows a confirmation page before ending its own session.
    await expect(page).toHaveURL(/\/v1\/auth-core\/logout/);
    // This page arrived as the *target of the app's 302*, and Playwright does
    // not route a redirect target — only a fresh navigation — so navigate it
    // again to put it through `stripReferrerPolicy` before submitting.
    await page.goto(page.url());
    await page.getByRole('button', { name: 'Sign out' }).click();

    await expect(page).toHaveURL(`${APP}/`);
    const cookies = await context.cookies();
    expect(cookies.some((c) => c.name === '__Host-cf_at')).toBe(false);
    expect(cookies.some((c) => c.name === '__Host-cf_rt')).toBe(false);

    // And the protected page starts the sign-in again.
    await page.goto('/dashboard');
    await expect(page).toHaveURL(/\/v1\/auth-core\/authorize/);
  });
});
