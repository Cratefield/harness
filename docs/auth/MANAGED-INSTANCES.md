# Running a new auth instance

Auth runs as **one instance per app** (issue #777): the app's own domain,
D1, secrets, passkey relying party, sender and branding. This is the
runbook for adding one. It covers both ways an instance is run:

- **Self-hosted.** The app's team deploys and operates the instance, on
  their own Cloudflare account, from their own repository or a fork of this
  one. They follow every step below themselves.
- **Managed by Cratefield.** Cratefield operates the instance on the app's
  domain, from `instances/<app>/` in this repository and this repository's
  deploy workflow. The app's team owns the domain and the provider
  accounts (Google, Apple, Meta) and hands Cratefield the delegated pieces
  marked *(app owner)* below; Cratefield does the rest.

Nothing in the Worker names an app. If a step seems to need an app's name
in code, it belongs in the instance's `wrangler.toml` instead.

Throughout, `<app>` is the instance's short name (`alphahunt`), `<domain>`
the app's domain (`alphahunt.ing`) and `<host>` the instance's host
(`auth.<domain>`). Staging uses `auth-staging.<domain>` and its own
copies of every resource.

## 1. The instance directory

Copy `instances/cratefield/` to `instances/<app>/` and edit
`wrangler.toml`:

- `name = "<app>-auth"`.
- `route` (staging) and `[env.production] route`: the two hostnames, as
  `custom_domain = true`.
- `[[ratelimits]] namespace_id`: two ids not used by any other instance on
  the same Cloudflare account.
- `[vars]` and `[env.production.vars]` (wrangler does not inherit vars into
  an environment, so both carry the full set): `AUTH_PUBLIC_URL`,
  `AUTH_CORE_ISSUER` (equal to it), `AUTH_VENTURE_NAME = "<app>-auth"`,
  `AUTH_CORS_ORIGINS` (the app's own browser origins),
  `AUTH_BRAND_NAME` and the optional branding (`AUTH_BRAND_LOGO_URL`,
  `AUTH_BRAND_ACCENT`, `AUTH_BRAND_SUPPORT_EMAIL`, `AUTH_BRAND_FOOTER`,
  `AUTH_BRAND_PRIVACY_URL`, `AUTH_BRAND_TERMS_URL`),
  `AUTH_PASSKEYS_RP_ID` (production: `<domain>`; staging: its own host),
  `AUTH_PASSKEYS_ORIGINS`, the module bases (`AUTH_MAGIC_LINK_PUBLIC_BASE`,
  `AUTH_PASSWORD_PUBLIC_BASE`, `AUTH_OIDC_REDIRECT_BASE`,
  `AUTH_META_REDIRECT_BASE`) and the senders.

Every key is described in
[`crates/auth-worker/README.md`](../../crates/auth-worker/README.md).
`cargo test -p cratefield-auth-worker --test instances` boots every
instance's configuration in both environments and checks the route, issuer
and RP ID agree; run it before opening the PR.

Add a short `README.md` beside it saying who operates the instance.

**Choosing the passkey RP ID.** A passkey is bound to the RP ID for good.
Using the app's registrable domain (`<domain>`) rather than `<host>` keeps
the passkeys usable if the app later runs a ceremony on its own pages. Pick
it before the first user registers one; changing it later strands every
passkey.

## 2. D1

Per environment, on the Cloudflare account that will run the Worker:

```sh
npx wrangler d1 create <app>-auth-staging
npx wrangler d1 create <app>-auth-production
```

Paste the two ids in place of `REPLACE_WITH_STAGING_D1_ID` and
`REPLACE_WITH_PRODUCTION_D1_ID`. Until they are real ids, the deploy
workflow skips the instance with a notice. Migrations are applied by the
workflow before every deploy (`wrangler d1 migrations apply DB --remote`),
from `crates/auth-worker/migrations`.

## 3. Domain

- *(app owner)* The app's zone must be on Cloudflare, on the account that
  runs the Worker, or delegated to it. For a managed instance, the owner
  adds Cratefield's account or delegates `auth.<domain>` and
  `auth-staging.<domain>`.
- The custom domains are created by the first `wrangler deploy` from the
  `route` entries. Nothing else points at the Worker.

## 4. GitHub environments and Cloudflare credentials

For a managed instance, in this repository:

- Create the environments `auth-<app>-staging` and `auth-<app>-production`.
  Add required reviewers to the production one: it is the approval gate.
- If the instance's Cloudflare account differs from the repository's
  default, set `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` as
  environment secrets on both. The token needs Workers Scripts, D1 and
  Workers Routes edit on that account and zone.

A self-hosted instance does the same in its own repository, or deploys
with `wrangler deploy` by hand.

## 5. Secrets

Names only; values never go in `wrangler.toml`, a commit or a log. From
`instances/<app>/`, once per environment (`--env production` for
production):

| Secret | What |
|---|---|
| `HARNESS_SECRET` | At least 32 random bytes. `HARNESS_SECRET_PREVIOUS` only during a rotation |
| `ADMIN_TOKEN` | At least 32 random bytes; the admin API answers 401 without it |
| `AUTH_CORE_SIGNING_KEYS` | JSON array of P-256 private JWKs; with `AUTH_CORE_SIGNING_KEY_ACTIVE` naming the signing `kid` (rotation: `DEPLOYING.md`) |
| `OWLPOST_API_KEY` | The instance's Owlpost key (or `RESEND_API_KEY` with `AUTH_MAILER = "resend"`) |
| `TURNSTILE_SECRET` | The Turnstile site's secret |
| `AUTH_OIDC_GOOGLE_CLIENT_SECRET` | When Google is enabled |
| `AUTH_OIDC_APPLE_PRIVATE_KEY` | When Apple is enabled (with `AUTH_OIDC_APPLE_KEY_ID`/`_TEAM_ID` as vars) |
| `AUTH_META_CLIENT_SECRET` | When Meta is enabled |

```sh
npx wrangler secret put HARNESS_SECRET            # staging
npx wrangler secret put HARNESS_SECRET --env production
```

Each instance has its own values. Never reuse a secret or signing key
across instances: a key shared by two instances lets one instance's tokens
pass the other's verification.

## 6. Mail: the Owlpost sender domain

- In Owlpost, add and verify the sending domain the instance uses
  (`send.<domain>` in the committed instances). *(app owner)* adds the DNS
  records Owlpost shows (SPF, DKIM, return path) to the app's zone.
- Create an API key scoped to that domain and put it as `OWLPOST_API_KEY`.
- The senders in `wrangler.toml` (`MAIL_FROM`, `AUTH_MAGIC_LINK_MAIL_FROM`,
  `AUTH_PASSWORD_MAIL_FROM`) must be on the verified domain. The display
  name in them should be the app's.

Resend stays supported: verify the domain there instead, set
`AUTH_MAILER = "resend"` and the `RESEND_API_KEY` secret. Production
refuses to boot with no mailer.

## 7. Turnstile

Create a Turnstile widget whose hostnames are `<host>` and
`auth-staging.<domain>`. The secret becomes `TURNSTILE_SECRET`; the Worker
checks that every verdict names its own host (`AUTH_TURNSTILE_HOSTNAME`,
defaulting to the host of `AUTH_PUBLIC_URL`).

## 8. OIDC callbacks

Each provider is optional. Enable one by creating the client, setting its
variables and secret, and adding its slug to `AUTH_CORE_LOGIN_METHODS`
(`passkey,magic-link,password,google,apple,meta`). The redirect URIs must
match byte for byte; register staging's alongside production's.

| Provider | Register | Redirect / return URL |
|---|---|---|
| Google | *(app owner)* an OAuth client (Web application) in the app's Google Cloud project; consent screen in the app's name | `https://<host>/v1/auth-oidc/google/callback` |
| Apple | *(app owner)* a Services ID, a Sign in with Apple key; verify `<host>` on the Services ID first | `https://<host>/v1/auth-oidc/apple/callback` (Apple posts the form here) |
| Meta | *(app owner)* a Meta app with Facebook Login | `https://<host>/v1/auth-meta/callback`; plus the data deletion callback in [`META-APP-REVIEW.md`](META-APP-REVIEW.md) |

Google: `AUTH_OIDC_GOOGLE_CLIENT_ID` (var), `AUTH_OIDC_GOOGLE_CLIENT_SECRET`
(secret). Apple: `AUTH_OIDC_APPLE_CLIENT_ID` (the Services ID),
`AUTH_OIDC_APPLE_TEAM_ID`, `AUTH_OIDC_APPLE_KEY_ID` (vars),
`AUTH_OIDC_APPLE_PRIVATE_KEY` (secret). Meta: `AUTH_META_CLIENT_ID` (var),
`AUTH_META_CLIENT_SECRET` (secret). Each module's README has the details.

The provider consoles show the app's name and logo to the person signing
in, so they are created in the app's accounts, not Cratefield's, even for
a managed instance.

## 9. Deploy and smoke

Merge the PR that adds `instances/<app>/`. A push to `main` deploys every
provisioned instance's staging; deploy one by hand with:

```sh
gh workflow run deploy-auth.yml -f instance=<app> -f environment=staging
```

The workflow smoke-tests the instance's own URL
(`crates/auth-worker/smoke.sh <AUTH_PUBLIC_URL>`): `/__health`, the
discovery document and the JWKS answer 200, and the discovery document's
issuer is the instance itself. Production follows an `auth-v*` tag (or a
dispatch with `environment=production`) through the
`auth-<app>-production` approval.

## 10. Register the app as a client

The admin API is the instance's own; there is no shared registry.

```sh
curl -fsS https://<host>/v1/auth-core/admin/clients \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"<App>","kind":"confidential",
       "redirect_uris":["https://app.<domain>/auth/callback"]}'
```

The `201` body carries `client_secret` once; hand it to the app through its
own secret store. Redirect URIs are an exact-match allowlist. The app then
verifies tokens with `cratefield-auth-client` against issuer
`https://<host>` (for example, `AUTH_ISSUER=https://<host>`).

## 11. Hand-over checklist

- [ ] Both D1 ids filled in, migrations applied.
- [ ] Both hostnames answer the smoke test.
- [ ] Secrets set in both environments; none shared with another instance.
- [ ] Owlpost domain verified; a magic link arrives from the app's sender
      with the app's name in the subject.
- [ ] Turnstile hostnames include both hosts.
- [ ] Each enabled provider's callback registered for both hosts.
- [ ] Privacy and terms URLs set (Meta's review requires the privacy URL).
- [ ] The app's client registered; the app verifies tokens against its own
      issuer.
