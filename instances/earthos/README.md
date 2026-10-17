# Instance: earthos

EarthOS's auth instance: hosted by Cratefield (a managed instance) on
EarthOS's own domain, with EarthOS's branding. Nothing on its pages, mail,
cookies or tokens names Cratefield. Aura (`aura.earthos.world`) is served
from the same domain and is a browser origin allowed by CORS.

| | Staging | Production |
|---|---|---|
| Origin / issuer | `https://auth-staging.earthos.world` | `https://auth.earthos.world` |
| Passkey RP ID | `auth-staging.earthos.world` | `earthos.world` |
| D1 | `earthos-auth-staging` | `earthos-auth-production` |
| GitHub environment | `auth-earthos-staging` | `auth-earthos-production` |
| Mail | Owlpost, from `send.earthos.world` | same |

The Worker is the unmodified `crates/auth-worker`; everything specific to
EarthOS is in [`wrangler.toml`](wrangler.toml). Login methods start as
passkey and magic link. CORS allows the EarthOS origins
(`staging.earthos.world` on staging, `earthos.world` on production) and
`aura.earthos.world`.

**Cloudflare account:** the instance runs on the **Earth.OS** account, id
`9615fcc65730fceaccc02752e049b7fd`, which is not the Factory0 account. The
id is not in `wrangler.toml`; the deploy workflow reads it from the
`CLOUDFLARE_ACCOUNT_ID` secret of each `auth-earthos-<env>` GitHub
environment, as for the other instances. For local `wrangler` commands set
`CLOUDFLARE_ACCOUNT_ID` to the same value.

**Status:** both D1s exist on the Earth.OS account (created 2026-10-18).
Secrets, the GitHub environments, the custom domains, the Owlpost sender,
the Turnstile widget and the first deploys are still to do; the steps are in
[`docs/auth/MANAGED-INSTANCES.md`](../../docs/auth/MANAGED-INSTANCES.md).

Not set yet, so the instance sends no branded logo or links:
`AUTH_BRAND_LOGO_URL`, `AUTH_BRAND_ACCENT`, `AUTH_BRAND_SUPPORT_EMAIL`,
`AUTH_BRAND_PRIVACY_URL`, `AUTH_BRAND_TERMS_URL`. The app owner supplies
these (the privacy URL is required before any Meta provider is enabled).
Sign-up follows the module default: an address with no account gets no mail
on a magic-link request. Set `AUTH_MAGIC_LINK_ALLOW_REGISTRATION = "true"`
if EarthOS wants open sign-up, as FindsYou does.

Owlpost: `send.earthos.world` must be added and verified in Owlpost before
the senders work. The DNS records Owlpost shows go to the earthos.world zone.

Consumer:

- The EarthOS Worker (World-360/EarthOS.world): a **confidential** client.
  Its redirect URI is `https://earthos.world/api/auth/callback` on
  production and `https://staging.earthos.world/api/auth/callback` on
  staging. Each environment's client is registered separately through the
  instance's admin API (`docs/auth/MANAGED-INSTANCES.md` section 10). The
  app sets `AUTH_ISSUER` to the instance URL, `AUTH_CLIENT_ID`,
  `AUTH_REDIRECT_URI`, and the `AUTH_CLIENT_SECRET` Worker secret.
