# Instance: keepshipping

Keep Shipping's auth instance: hosted by Cratefield (a managed instance) on
Keep Shipping's own domain, with Keep Shipping's branding. Nothing on its
pages, mail, cookies or tokens names Cratefield.

| | Staging | Production |
|---|---|---|
| Origin / issuer | `https://auth-staging.keepshipping.run` | `https://auth.keepshipping.run` |
| Passkey RP ID | `auth-staging.keepshipping.run` | `keepshipping.run` |
| D1 | `keepshipping-auth-staging` | `keepshipping-auth-production` |
| GitHub environment | `auth-keepshipping-staging` | `auth-keepshipping-production` |
| Mail | Owlpost, from `send.keepshipping.run` | same |

The Worker is the unmodified `crates/auth-worker`; everything specific to
Keep Shipping is in [`wrangler.toml`](wrangler.toml). Login methods start as
passkey and magic link. CORS allows the console's origin,
`console.keepshipping.run`, its only client so far.

**Status:** the staging D1 exists on the Cloudflare account that holds
`keepshipping.run`; staging is migrated, has its core secrets and answers at
`https://auth-staging.keepshipping.run`. Production has no D1 (its id is
still a placeholder, so the deploy workflow skips it), secrets, migrations
or deploy yet. Owlpost (`OWLPOST_API_KEY`) and Turnstile
(`TURNSTILE_SECRET`) are not set on staging yet, so staging sends no mail
and shows no captcha. There is no privacy or terms page on
`keepshipping.run` yet, so `AUTH_BRAND_PRIVACY_URL` and
`AUTH_BRAND_TERMS_URL` stay commented out. The steps are in
[`docs/auth/MANAGED-INSTANCES.md`](../../docs/auth/MANAGED-INSTANCES.md).

Consumer:

- The Keep Shipping console (`console.keepshipping.run`): a **public**
  client (PKCE, no secret) with the redirect URI
  `https://console.keepshipping.run/console/callback`. It sets
  `AUTH_ISSUER` to the instance URL and `AUTH_CLIENT_ID` to the client id
  (the token audience), and verifies tokens with `cratefield-auth-client`.
