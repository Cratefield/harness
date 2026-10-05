// Register the example's OAuth client and its test user against a running,
// migrated local IdP, then write `examples/next-auth/.env.local`.
//
// Run from the example root, after the IdP is up: `npm run setup`.

import { randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const IDP = process.env.IDP_URL ?? 'http://localhost:8787';
const APP = process.env.APP_URL ?? 'http://localhost:3000';
const EMAIL = process.env.E2E_EMAIL ?? 'next-auth-e2e@example.com';
const PASSWORD = process.env.E2E_PASSWORD ?? 'correct horse battery staple';

const devVarsPath = fileURLToPath(new URL('../idp/.dev.vars', import.meta.url));
const envLocalPath = fileURLToPath(new URL('../.env.local', import.meta.url));

/** `KEY=VALUE` lines as an object (enough for our own `.dev.vars`). */
function parseEnv(text) {
  const out = {};
  for (const line of text.split('\n')) {
    const eq = line.indexOf('=');
    if (eq > 0) out[line.slice(0, eq).trim()] = line.slice(eq + 1).trim();
  }
  return out;
}

let adminToken;
try {
  adminToken = parseEnv(readFileSync(devVarsPath, 'utf8')).ADMIN_TOKEN;
} catch {
  // Fall through to the shared error below.
}
if (!adminToken) {
  throw new Error(`no ADMIN_TOKEN in ${devVarsPath}. Run \`npm run idp\` first.`);
}

const redirectUri = `${APP}/api/auth/callback`;
const postLogoutRedirectUri = `${APP}/`;

/** POST JSON and return status + parsed body text. */
async function post(path, body, headers = {}) {
  const res = await fetch(`${IDP}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  return { status: res.status, text: await res.text() };
}

// 1. The OAuth client. `public` because an http://localhost redirect is only
//    accepted for public clients (no client secret).
const client = await post(
  '/v1/auth-core/admin/clients',
  { name: 'next-auth example', kind: 'public', redirect_uris: [redirectUri, postLogoutRedirectUri] },
  { Authorization: `Bearer ${adminToken}` },
);
if (client.status !== 201) {
  throw new Error(`client registration failed (${client.status}): ${client.text}`);
}
const clientId = JSON.parse(client.text).id;

// 2. The test user. 409 means a previous run already made it — fine.
const user = await post('/v1/auth-password/register', { email: EMAIL, password: PASSWORD });
if (user.status !== 202 && user.status !== 409) {
  throw new Error(`user registration failed (${user.status}): ${user.text}`);
}

writeFileSync(
  envLocalPath,
  [
    `AUTH_ISSUER=${IDP}`,
    `AUTH_CLIENT_ID=${clientId}`,
    `AUTH_REDIRECT_URI=${redirectUri}`,
    `AUTH_POST_LOGOUT_REDIRECT_URI=${postLogoutRedirectUri}`,
    `AUTH_COOKIE_SECRET=${randomBytes(32).toString('hex')}`,
    `E2E_EMAIL=${EMAIL}`,
    `E2E_PASSWORD=${PASSWORD}`,
    '',
  ].join('\n'),
);

console.log(`registered client ${clientId}; wrote ${envLocalPath}`);
