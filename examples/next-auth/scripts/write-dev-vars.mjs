// Write `idp/.dev.vars` for the local IdP (`idp/wrangler.toml`).
//
// Generates the two shared secrets and a fresh ES256 signing key, and points
// the Worker at this example. Run from the example root: `npm run idp`.
// `.dev.vars` is gitignored; re-running rotates the signing key (which
// invalidates existing tokens — fine for a local IdP).

import { randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const devVars = fileURLToPath(new URL('../idp/.dev.vars', import.meta.url));

const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
  'sign',
  'verify',
]);
const jwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);

/** An ES256 signing key in the JWKS shape auth-core expects. */
const signingKeys = [
  { kty: jwk.kty, crv: jwk.crv, kid: 'k', d: jwk.d, x: jwk.x, y: jwk.y },
];

const secret = () => randomBytes(32).toString('hex');

const lines = [
  `HARNESS_SECRET=${secret()}`,
  `ADMIN_TOKEN=${secret()}`,
  `AUTH_CORE_SIGNING_KEYS=${JSON.stringify(signingKeys)}`,
  'AUTH_CORE_SIGNING_KEY_ACTIVE=k',
  'ENV=development',
  'AUTH_PUBLIC_URL=http://localhost:8787',
  'AUTH_CORE_ISSUER=http://localhost:8787',
  'AUTH_VENTURE_NAME=next-auth-example-idp',
  'AUTH_BRAND_NAME=Next auth example',
  'AUTH_CORE_LOGIN_METHODS=password',
  'AUTH_CORS_ORIGINS=http://localhost:3000',
  // The captcha is deliberately off so the e2e run can drive the plain form.
  'AUTH_PASSWORD_BREACH_CHECK=false',
  '',
];

writeFileSync(devVars, lines.join('\n'));
console.log(`wrote ${devVars}`);
