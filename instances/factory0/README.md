# Instance: factory0

Factory Zero's auth instance: hosted by Cratefield (a managed instance) on
factory0.ventures' own domain, with Factory Zero's branding. Nothing on its
pages, mail, cookies or tokens names Cratefield.

| | Staging | Production |
|---|---|---|
| Origin / issuer | `https://auth-staging.factory0.ventures` | `https://auth.factory0.ventures` |
| Passkey RP ID | `auth-staging.factory0.ventures` | `factory0.ventures` |
| D1 | `factory0-auth-staging` (Factory0 account) | `factory0-auth-production` (not created yet) |
| GitHub environment | `auth-factory0-staging` | `auth-factory0-production` |
| Mail | Owlpost, from `send.factory0.ventures` | same |
| Login methods | passkey, magic link | same |

The Worker is the unmodified `crates/auth-worker`; everything specific to
Factory Zero is in [`wrangler.toml`](wrangler.toml).

Consumers:

- The factory0.ventures website (Cloudflare Pages). Its Pages Functions run the
  authorization-code + PKCE flow against this instance and keep the session in
  `__Host-` cookies on factory0.ventures. The browser never sees a token.
- api.factory0.ventures (factory0-backend): verifies the access token it is
  sent (`Authorization: Bearer`) with `cratefield-auth-client` against
  `https://auth-staging.factory0.ventures` (production: `https://auth.factory0.ventures`),
  audience = the website's client id.

## Clients

Each consumer is a registered client of this instance (MANAGED-INSTANCES.md
step 10). The website is a **confidential-free public client** in the
registration sense (`"kind": "public"`, PKCE, no secret) because the Pages
Function, not the browser, runs the exchange and keeps the tokens in its own
`__Host-` cookies.

Redirect URIs (exact):

- `https://factory0.ventures/api/auth/callback` (production site)
- `https://staging.factory0.ventures/api/auth/callback` (if the staging site is used)
- `http://localhost:8788/api/auth/callback` (`wrangler pages dev`)

Post-logout redirect URIs: the same origins with `/enter/`.

Registration is an admin API call that needs the instance's `ADMIN_TOKEN`
secret on that environment. It is not done in this PR; see the owner
checklist in the PR description.

## Status

Staging: D1 created and migrated only once `wrangler d1 migrations apply` has
run; secrets not set. Production: no D1, no secrets, no deploy. The deploy
workflow skips production while its D1 id is the
`REPLACE_WITH_PRODUCTION_D1_ID` placeholder.
