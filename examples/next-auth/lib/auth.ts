// The one place the Next app builds its `@cratefield/auth/next` helpers.
//
// Everything is read lazily: `next build` imports the route files and the
// middleware, and the example has to build even before `npm run setup` has
// written `.env.local`. One `Auth` (with its JWKS cache) is shared for the
// life of the process.

import { createNextAuth, type NextAuth } from '@cratefield/auth/next';

/** An environment variable an auth flow cannot run without. */
function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is not set. Start the IdP and run \`npm run setup\`.`);
  }
  return value;
}

let cached: NextAuth | undefined;

/** The app's Next glue, built from the environment on first use. */
export function getNextAuth(): NextAuth {
  cached ??= createNextAuth({
    issuer: required('AUTH_ISSUER'),
    clientId: required('AUTH_CLIENT_ID'),
    redirectUri: required('AUTH_REDIRECT_URI'),
    cookieSecret: required('AUTH_COOKIE_SECRET'),
    // Optional: sign-out still works, it just stays on the IdP.
    postLogoutRedirectUri: process.env.AUTH_POST_LOGOUT_REDIRECT_URI,
  });
  return cached;
}

/** The verified session for the current request, or `null`. Server-only. */
export function getSession() {
  return getNextAuth().getSession();
}
