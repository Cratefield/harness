# Instance: ledgers

Ledgers' auth instance: hosted by Cratefield (a managed instance) on
Ledgers' own domain, `ledgers.sh`, with Ledgers' branding. Nothing on its
pages, mail, cookies or tokens names Cratefield.

| | Staging | Production |
|---|---|---|
| Origin / issuer | `https://auth-staging.ledgers.sh` | `https://auth.ledgers.sh` |
| Passkey RP ID | `auth-staging.ledgers.sh` | `ledgers.sh` |
| Passkey origin | `https://auth-staging.ledgers.sh` | `https://auth.ledgers.sh` |
| D1 | `ledgers-auth-staging` (id `LEDGERS_AUTH_STAGING_D1_ID`, placeholder) | `ledgers-auth-production` (id `LEDGERS_AUTH_PROD_D1_ID`, placeholder) |
| Rate limiter namespaces | `1801` | `1802` |
| GitHub environment | `auth-ledgers-staging` | `auth-ledgers-production` |
| Mail | Owlpost, from `send.ledgers.sh` (staging sends real mail; no dev fallback) | same |
| Login methods | passkey (primary), magic link (recovery, first sign-in) | same |

The Worker is the unmodified `crates/auth-worker`; everything specific to
Ledgers is in [`wrangler.toml`](wrangler.toml).

**Passkey RP ID.** Production uses `ledgers.sh`, the registrable domain, so
production passkeys work on the auth host and on the app hosts
(`app.ledgers.sh`) if the app ever runs a WebAuthn ceremony on its own pages.
Staging uses its own host, `auth-staging.ledgers.sh`, matching factory0 and
yoginini, so staging passkeys never show up on production sign-in. A passkey
is bound to its RP ID for good, so both are fixed before any user enrols one.
Every passkey origin is the RP ID or a subdomain of it, as WebAuthn requires.

**Status:** not provisioned. Both D1 ids are placeholders, so
`deploy-auth.yml` skips this instance on every run. No D1, secrets, Owlpost
domain, Turnstile site or custom domains exist yet. Branding uses the
Ledgers logo (`https://ledgers.sh/assets/icon-512.png`), the Ledgers app's dark
palette (background `#0F1217`, surface `#151920`, line `#252B34`, text `#E4E7EB`,
muted `#B8C0CA`; the primary button is `#E4E7EB` with `#0F1217` text; the accent
`#7FA6C9` is for links and focus rings) and Source Sans 3 / Source Code Pro from
Google Fonts (`AUTH_BRAND_FONT_CSS_URL`).
Support address, privacy and terms URLs are not set yet (no pages exist), so
they are commented out (`needs-human` in `wrangler.toml`). Staging sends real
mail through Owlpost, so a first sign-in by magic link works there once
`OWLPOST_API_KEY` is set. Both environments allow registration by magic link
(`AUTH_MAGIC_LINK_ALLOW_REGISTRATION`); open sign-up is intended, since
Ledgers gates the books by the owner role.

## Consumers

- **Ledgers-sh/ledgers server** (`api-staging.ledgers.sh` / `api.ledgers.sh`):
  verifies access tokens. Set `LEDGERS_AUTH_ISSUER` to the instance URL
  (`https://auth-staging.ledgers.sh` / `https://auth.ledgers.sh`) and
  `LEDGERS_AUTH_CLIENT_ID` to the web app's client id (the token audience),
  and verify with `cratefield-auth-client`.
- **Ledgers web app** (`app-staging.ledgers.sh` / `app.ledgers.sh`): a
  **public** client (`"kind": "public"`, PKCE, no secret). Redirect URIs
  are exact:
  - staging: `https://api-staging.ledgers.sh/auth/callback`
  - production: `https://api.ledgers.sh/auth/callback`

  The web app's browser origins are the only CORS origins
  (`https://app-staging.ledgers.sh`, `https://app.ledgers.sh`). The
  client is registered with `roles_claim` on, so the access token carries
  the `roles` claim the server authorises against.

## Provisioning (owner steps)

Run from `instances/ledgers/` unless noted. Staging first, then production.
Full runbook: [`docs/auth/MANAGED-INSTANCES.md`](../../docs/auth/MANAGED-INSTANCES.md).

1. **D1.** Create both databases on the Cloudflare account that holds
   `ledgers.sh`, then replace the two placeholders in `wrangler.toml`:
   ```sh
   bunx wrangler d1 create ledgers-auth-staging
   bunx wrangler d1 create ledgers-auth-production
   ```
2. **Migrations.** The deploy workflow applies them before every deploy
   (`wrangler d1 migrations apply DB --remote`). To apply by hand:
   ```sh
   bunx wrangler d1 migrations apply DB --remote
   bunx wrangler d1 migrations apply DB --remote --env production
   ```
3. **Secrets**, by name only, per environment (never in git or a log):
   ```sh
   bunx wrangler secret put HARNESS_SECRET                 # 32+ random bytes
   bunx wrangler secret put ADMIN_TOKEN                    # 32+ random bytes
   bunx wrangler secret put AUTH_CORE_SIGNING_KEYS         # JSON array of P-256 private JWKs
   bunx wrangler secret put AUTH_CORE_SIGNING_KEY_ACTIVE   # the active signing kid
   bunx wrangler secret put OWLPOST_API_KEY                # Owlpost key scoped to send.ledgers.sh
   bunx wrangler secret put TURNSTILE_SECRET               # the Turnstile site's secret
   ```
   Add `--env production` for production. Do not reuse any value from
   another instance.
4. **Domains.** The first `wrangler deploy` creates the custom domains from
   the `route` entries. The `ledgers.sh` zone must be on the account that
   runs the Worker (or delegated to it).
5. **Turnstile.** Create a widget whose hostnames are `auth-staging.ledgers.sh`
   and `auth.ledgers.sh`. Put its site key in place of
   `LEDGERS_TURNSTILE_SITE_KEY` (both environments) and its secret in
   `TURNSTILE_SECRET`.
6. **Owlpost.** Verify the sending domain `send.ledgers.sh` in Owlpost, add
   the DNS records it shows to the `ledgers.sh` zone, and create the API key
   for `OWLPOST_API_KEY`. The senders in `wrangler.toml` must stay on that
   domain.
7. **GitHub environments.** In this repository create `auth-ledgers-staging`
   and `auth-ledgers-production`; add required reviewers to the production
   one. If the Cloudflare account is not the repository default, set
   `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` on both.
8. **Deploy and smoke.** Merge the PR; `main` deploys staging. Or:
   `gh workflow run deploy-auth.yml -f instance=ledgers -f environment=staging`.
   The workflow smoke-tests `https://auth-staging.ledgers.sh`.
9. **Register the web app client** on each environment, with the admin API
   (the `201` response returns `client_secret` only for confidential
   clients; this one is public, so none is returned):
   ```sh
   curl -fsS https://auth-staging.ledgers.sh/v1/auth-core/admin/clients \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H 'content-type: application/json' \
     -d '{"name":"Ledgers web","kind":"public",
          "redirect_uris":["https://api-staging.ledgers.sh/auth/callback"],
          "roles_claim":true}'
   ```
   Production is the same call against `https://auth.ledgers.sh` with
   `https://api.ledgers.sh/auth/callback`. Record the returned client id as
   `LEDGERS_AUTH_CLIENT_ID` for the server.
10. **Grant the owner role.** Once the owner has signed in once (so a `sub`
    exists), grant the owner role on each environment:
    ```sh
    curl -fsS -X POST https://auth-staging.ledgers.sh/v1/auth-core/admin/users/<sub>/role \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H 'content-type: application/json' \
      -d '{"role":"owner"}'
    ```
    Find `<sub>` with the admin API; do not guess it.
11. **Hand-over checklist.** Both D1 ids real and migrated; both hostnames
    pass the smoke test; secrets set in both environments; a magic link
    arrives from `send.ledgers.sh`; Turnstile lists both hosts; client
    registered with `roles_claim`; owner role granted; the server's
    `LEDGERS_AUTH_ISSUER` and `LEDGERS_AUTH_CLIENT_ID` set.
