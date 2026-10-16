# Instance: findsyou

FindsYou's auth instance: hosted by Cratefield (a managed instance) on
FindsYou's own domain, with FindsYou's branding. Nothing on its pages, mail,
cookies or tokens names Cratefield.

| | Staging | Production |
|---|---|---|
| Origin / issuer | `https://auth-staging.findsyou.work` | `https://auth.findsyou.work` |
| Passkey RP ID | `auth-staging.findsyou.work` | `findsyou.work` |
| D1 | `findsyou-auth-staging` | `findsyou-auth-production` |
| GitHub environment | `auth-findsyou-staging` | `auth-findsyou-production` |
| Mail | Owlpost, from `send.findsyou.work` | same |

The Worker is the unmodified `crates/auth-worker`; everything specific to
FindsYou is in [`wrangler.toml`](wrangler.toml). Login methods start as
passkey and magic link. CORS allows `api.findsyou.work` (the app Worker,
which serves the product UI) and the `findsyou.work` marketing site.

**Status:** both D1s exist on the Factory0 Cloudflare account, which holds
`findsyou.work`. Secrets, migrations and the first deploys follow the
steps in [`docs/auth/MANAGED-INSTANCES.md`](../../docs/auth/MANAGED-INSTANCES.md).
There is no privacy or terms page on `findsyou.work` yet, so
`AUTH_BRAND_PRIVACY_URL` and `AUTH_BRAND_TERMS_URL` stay commented out.

Consumer:

- The FindsYou app Worker (FindsYou-Work/app, `api.findsyou.work`): a
  **confidential** client with the redirect URI
  `https://api.findsyou.work/auth/callback`. It sets `AUTH_ISSUER` to the
  instance URL, `AUTH_CLIENT_ID` to the client id, `AUTH_REDIRECT_URI`, and
  the `AUTH_CLIENT_SECRET` Worker secret.
