# Instance: alphahunt

Alphahunt's auth instance: hosted by Cratefield (a managed instance) on
Alphahunt's own domain, with Alphahunt's branding. Nothing on its pages,
mail, cookies or tokens names Cratefield.

| | Staging | Production |
|---|---|---|
| Origin / issuer | `https://auth-staging.alphahunt.ing` | `https://auth.alphahunt.ing` |
| Passkey RP ID | `auth-staging.alphahunt.ing` | `alphahunt.ing` |
| D1 | `alphahunt-auth-staging` | `alphahunt-auth-production` |
| GitHub environment | `auth-alphahunt-staging` | `auth-alphahunt-production` |
| Mail | Owlpost, from `send.alphahunt.ing` | same |

The Worker is the unmodified `crates/auth-worker`; everything specific to
Alphahunt is in [`wrangler.toml`](wrangler.toml). Login methods start as
passkey and magic link.

**Status:** both D1 databases exist on the Cloudflare account that holds
`alphahunt.ing`; staging is migrated, has its core secrets and answers at
`https://auth-staging.alphahunt.ing`. Production has no secrets, migrations
or deploy yet. Owlpost (`OWLPOST_API_KEY`) and Turnstile (`TURNSTILE_SECRET`)
are not set on staging yet, so staging sends no mail and shows no captcha.
The steps are in
[`docs/auth/MANAGED-INSTANCES.md`](../../docs/auth/MANAGED-INSTANCES.md).
Alphahunt's logo, accent, support address and legal URLs are commented out
in `wrangler.toml` until Alphahunt confirms them.

Consumer side (after the first production deploy): Alphahunt-ing/backend
sets `AUTH_ISSUER=https://auth.alphahunt.ing` and verifies tokens with
`cratefield-auth-client`.
