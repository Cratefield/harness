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

**Status:** not provisioned. The D1 ids are placeholders, so the deploy
workflow skips this instance until they are filled in. The steps are in
[`docs/auth/MANAGED-INSTANCES.md`](../../docs/auth/MANAGED-INSTANCES.md).
Alphahunt's logo, accent, support address and legal URLs are commented out
in `wrangler.toml` until Alphahunt confirms them.

Consumer side (after the first production deploy): Alphahunt-ing/backend
sets `AUTH_ISSUER=https://auth.alphahunt.ing` and verifies tokens with
`cratefield-auth-client`.
