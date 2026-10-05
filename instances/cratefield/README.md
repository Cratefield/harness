# Instance: cratefield

Cratefield's own auth instance, operated by Cratefield.

| | Staging | Production |
|---|---|---|
| Origin / issuer | `https://auth-staging.cratefield.com` | `https://auth.cratefield.com` |
| Passkey RP ID | `auth-staging.cratefield.com` | `cratefield.com` |
| D1 | `cratefield-auth-staging` | `cratefield-auth-production` |
| GitHub environment | `auth-cratefield-staging` | `auth-cratefield-production` |
| Mail | Owlpost, from `send.cratefield.com` | same |

The Worker is the unmodified `crates/auth-worker`; everything specific to
Cratefield is in [`wrangler.toml`](wrangler.toml). Branding: display name
`Cratefield`, the Cratefield logo, accent `#3a5bef`. Login methods start as
passkey and magic link; Google, Apple and Meta are added to
`AUTH_CORE_LOGIN_METHODS` once their clients exist.

**Status:** not provisioned. The D1 ids are placeholders, so the deploy
workflow skips this instance until they are filled in. The steps, and the
secrets by name, are in
[`docs/auth/MANAGED-INSTANCES.md`](../../docs/auth/MANAGED-INSTANCES.md).
Confirm the support, privacy and terms URLs commented out in
`wrangler.toml` exist before enabling them.

Deploy one environment by hand: `gh workflow run deploy-auth.yml -f
instance=cratefield -f environment=staging`.
