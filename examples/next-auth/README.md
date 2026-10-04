# Next.js + Cratefield auth-core

A minimal Next.js (app-router) app that signs in through a Cratefield
auth-core IdP using [`@cratefield/auth/next`](../../packages/auth-ts), the
`authMiddleware` / `getSession` / route-handler glue over the framework-agnostic
`AuthClient`.

What it demonstrates:

- `middleware.ts` protects `/dashboard` and renews an expired access cookie from
  the refresh cookie in place (a `307` back to the same URL carrying the rotated
  `Set-Cookie`s) instead of bouncing the user to the IdP.
- `app/dashboard/page.tsx` is a server component reading the verified session
  with `getSession()`.
- `app/api/auth/{start,callback,refresh,logout}/route.ts` are one-liners around
  `nextAuth.handlers.*`. `refresh` and `logout` are `POST` and refuse a
  cross-origin caller with `403`.
- The session cookies (`__Host-cf_at`, `__Host-cf_rt`, `__Host-cf_state`) are
  `Secure; HttpOnly; SameSite=Lax`, so the example only works over
  `http://localhost` in Chromium (which accepts `__Host-` there).

## Run it locally

Prerequisites: Node 20+, a built `@cratefield/auth`, `worker-build` and
wrangler. From the repository root:

```sh
# 1. Build the library the example depends on.
npm ci
npm run build -w @cratefield/auth

# 2. Write crates/auth-worker/.dev.vars (generates the secrets + signing key).
cd examples/next-auth
npm ci
npm run idp

# 3. Build and start the local IdP on http://localhost:8787.
cd ../../crates/auth-worker
npx wrangler d1 migrations apply DB --local
npx wrangler dev --local --port 8787     # leave running

# 4. Register this app's client + test user, writing .env.local.
cd -
npm run setup

# 5. Build and run the app on http://localhost:3000.
npm run build
npm run start                             # leave running

# 6. Drive the whole journey in a headless Chromium.
npx playwright install --with-deps chromium   # once
npm run test:e2e
```

`npm run test:e2e` starts the app itself (Playwright's `webServer`) and reuses
an already-running `npm run start` when there is one. The IdP is started outside
Playwright, as above and in CI.

## The e2e test

`e2e/auth.spec.ts` runs one serial journey: an anonymous `/dashboard` visit is
sent to the IdP's chooser, signing in with the password form lands back on
`/dashboard`, a dropped access cookie is refreshed in place, `POST
/api/auth/refresh` answers `204` same-origin and `403` cross-origin, and signing
out (through the IdP's confirmation page) clears the session and re-protects
`/dashboard`. See the comments in the spec for why "expiry" is simulated and why
it strips one response header from the IdP.

## Known issue the spec works around

The harness stamps every HTML response with `Referrer-Policy: no-referrer`
(`crates/core/src/http.rs`). In Chromium that makes a same-origin **form POST**
send `Origin: null`, and auth-core's CSRF guard rejects a literal `null` origin
(`crates/auth-core/src/csrf.rs`). The IdP's password form and its sign-out
confirmation page therefore answer `403` to a real browser submission. The e2e
spec removes `Referrer-Policy` from the IdP's responses (and nowhere else) so
the browser behaves as the IdP was written for; the app-facing flow under test
is untouched. This is an IdP defect, not an `@cratefield/auth` one.
