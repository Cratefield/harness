# Instance: yoginini

Yoginini's auth instance: hosted by Cratefield (a managed instance) on
Yoginini's own domain, with Yoginini's branding. Nothing on its pages,
mail, cookies or tokens names Cratefield.

| | Staging | Production |
|---|---|---|
| Origin / issuer | `https://auth-staging.yoginini.us` | `https://auth.yoginini.us` |
| Passkey RP ID | `auth-staging.yoginini.us` | `yoginini.us` |
| D1 | `yoginini-auth-staging` | `yoginini-auth-production` |
| GitHub environment | `auth-yoginini-staging` | `auth-yoginini-production` |
| Mail | Owlpost, from `send.yoginini.us` | same |

The Worker is the unmodified `crates/auth-worker`; everything specific to
Yoginini is in [`wrangler.toml`](wrangler.toml). Login methods start as
passkey and magic link. CORS allows the two web origins, `yoginini.us` and
`www.yoginini.us`; the iOS app signs in through `ASWebAuthenticationSession`
and needs no CORS.

**Status:** both D1 databases exist on the Cloudflare account that holds
`yoginini.us`; staging is migrated, has its core secrets and answers at
`https://auth-staging.yoginini.us`. Production has no secrets, migrations or
deploy yet. Owlpost (`OWLPOST_API_KEY`) and Turnstile (`TURNSTILE_SECRET`)
are not set on staging yet, so staging sends no mail and shows no captcha.
There is no terms page on `yoginini.us` yet, so `AUTH_BRAND_TERMS_URL` stays
commented out. The steps are in
[`docs/auth/MANAGED-INSTANCES.md`](../../docs/auth/MANAGED-INSTANCES.md).

Consumers:

- Yoginini/ios: a **public** client (PKCE, no secret) with the redirect URI
  `us.yoginini.app://auth`; the app reads `YogAuthIssuer` and
  `YogAuthClientID`.
- Yoginini/yoginini-backend: sets `AUTH_ISSUER` to the instance URL and
  `AUTH_CLIENT_ID` to the same client id (the token audience), and verifies
  tokens with `cratefield-auth-client`.
