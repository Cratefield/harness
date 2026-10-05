# Deploying the auth service

Auth is deployed as **one branded instance per app** (issue #777), never as
a shared service. Each instance is a directory
[`instances/<app>/`](../../instances) holding its `wrangler.toml`; every one
builds the same, unmodified `crates/auth-worker`. Standing up a new instance,
self-hosted or managed by Cratefield, is
[MANAGED-INSTANCES.md](MANAGED-INSTANCES.md). This page covers the deploy
workflow, the configuration surface, and the two rotations: signing keys and
client secrets.

## The deploy workflow

[`deploy-auth.yml`](../../.github/workflows/deploy-auth.yml) plans one job per
instance:

| Trigger | Deploys |
|---|---|
| push to `main` touching `crates/auth-*`, `instances/` or the workflow | every instance's staging (`[vars]`, top level of its `wrangler.toml`) |
| an `auth-v*` tag | every instance's production (`[env.production]`), each behind the `auth-<app>-production` environment's approval |
| `workflow_dispatch` (`instance`, `environment`) | one instance, or `all`, to the chosen environment |

Each job applies the D1 migrations, deploys from `instances/<app>/`, and runs
[`smoke.sh`](../../crates/auth-worker/smoke.sh) against that instance's own
`AUTH_PUBLIC_URL`: `/__health`, the discovery document and the JWKS must
answer `200` over TLS, and the discovery document's issuer must be the
instance itself. An instance whose D1 ids are still `REPLACE_WITH_*` is not
provisioned and is skipped with a notice. Cloudflare credentials are read per
GitHub environment (`auth-<app>-staging`, `auth-<app>-production`), falling
back to the repository's secrets, so instances can live on different
Cloudflare accounts. If `CLOUDFLARE_API_TOKEN` or `CLOUDFLARE_ACCOUNT_ID` is
missing for that environment, the job is skipped with a notice rather than
failing — set both as environment secrets as
[MANAGED-INSTANCES.md](MANAGED-INSTANCES.md) describes.

By hand, from an instance's directory:

```sh
npx wrangler d1 migrations apply DB --remote                     # staging
npx wrangler deploy
npx wrangler d1 migrations apply DB --env production --remote    # production
npx wrangler deploy --env production
../../crates/auth-worker/smoke.sh https://auth.<app-domain>
```

Migrations are collected from the module crates by `fz migrations collect`
and committed under
`crates/auth-worker/migrations/<GGGG>_<module>_<NNNN>_<name>.sql`, pinned by
`.harness-lock.json`; every instance's `migrations_dir` points there.

## Prerequisites, per instance

- **Workers Paid.** `auth-password` verifies with Argon2id at m=19456, t=2, p=1 —
  roughly 40 ms per hash or verify (ADR 0200), which the free tier's 10 ms CPU
  limit cannot fit. Password login is not a knob to tune down.
- The app's domain on Cloudflare (two `custom_domain` routes: staging and
  production) and a D1 database per environment.
- A Workers Rate Limiting namespace per environment (the `[[ratelimits]]`
  stanza, ids unique on the account); readiness refuses an instance whose
  limiter binding does not resolve (harness #437).
- A Turnstile site covering both hostnames, and a mail provider — Owlpost
  (recommended) or Resend — with the instance's **verified sender domain**.

## Self-hosting outside this repository

A self-hosted instance can live in the app's own repository: copy an
`instances/<app>/wrangler.toml`, point `main`, `[build] cwd` and
`migrations_dir` at a checkout of this repository's `crates/auth-worker`
(a submodule or a pinned clone), and deploy with `wrangler` or a copy of
`deploy-auth.yml`. `worker-build` compiles the package in its working
directory, which is why the instances set `[build] cwd` to the crate and
`main` to the shim it writes there.

### A wrapper crate, only for template overrides

To override templates (e.g. your own magic-link mail), wrap the crate: depend on
`cratefield-auth-worker` with `default-features = false` (dropping `entry`, so its
`#[event(fetch)]`/`#[event(scheduled)]` do not collide), serve from your handlers,
and read config with `AuthWorkerConfig::from_config(&EnvConfig(env))` (or
`validate_config` without building):

```rust
cratefield_auth_worker::serve_request(req, env, ctx, |w| w.templates(my_templates())).await
cratefield_auth_worker::serve_scheduled_request(event, env, ctx, |w| w.templates(my_templates())).await
```

Ids are `<module>/<template>` with `<id>@<locale>` variants; overrides are
registered after the module defaults, so they win (`crates/core/src/template.rs`).

## Configuration

All of these go in `[vars]` (staging) **and** `[env.production.vars]`
(production) of the instance's `wrangler.toml`: wrangler does not inherit
vars into an environment. A blank value reads as unset. There are no
defaults that name an app: the four identity values are required, and a
missing one is refused at boot with a message naming it. The full list,
branding included, is in
[`crates/auth-worker/README.md`](../../crates/auth-worker/README.md).

| Variable | Default | Meaning |
|---|---|---|
| `AUTH_PUBLIC_URL` | **required** | Issuer, the instance's public URL and the problem-type base (`<url>/problems/…`, issue #557). The venture domain is its host. Must be an absolute `https` origin; a bare trailing `/` is trimmed; `http` is allowed only for the loopback hosts `localhost`/`127.0.0.1`/`[::1]`. No path, query or fragment. |
| `AUTH_VENTURE_NAME` | **required** | The instance's id, e.g. `alphahunt-auth`. Must be kebab-case (`[a-z0-9]+`, parts joined by `-`). |
| `AUTH_CORS_ORIGINS` | **required** | The app's exact `scheme://host[:port]` origins for cross-origin `GET`s (discovery, JWKS). Must be `https` (`http` only for a loopback host); no wildcards, paths or trailing slash. At least one. |
| `AUTH_BRAND_NAME` | **required** | The display name on every page and in every mail subject. |
| `AUTH_BRAND_*` | none | Logo, accent, support address, footer, privacy and terms URLs. |
| `AUTH_PROBLEM_BASE` | `<AUTH_PUBLIC_URL>/problems/` | Overrides the problem-type base. |
| `AUTH_TURNSTILE_HOSTNAME` | host of `AUTH_PUBLIC_URL` | The bare hostname the Turnstile verdict must name (no scheme, port or path). (`TURNSTILE_SECRET` stays a secret.) |
| `MAIL_FROM` | `no-reply@<host of AUTH_PUBLIC_URL>` | The mailer's default `From`, for mail that sets none of its own: `addr@host` or `Name <addr@host>`, domain verified. Magic-link does not use it — see below. |
| `MAIL_REPLY_TO` | none | The mailer's default `Reply-To`, same address forms. |
| `AUTH_MAILER` | the provider whose key is set, Owlpost first | `owlpost`, `resend` or `none`. `owlpost` needs the `OWLPOST_API_KEY` secret (and an optional, `https`-only `OWLPOST_BASE_URL`); `resend` needs `RESEND_API_KEY`. Unset with both keys is refused as ambiguous. Under `ENV=production`, `none` and "no mailer at all" are refused. The committed instances set `owlpost`. |

`ENV` accepts only `production`, `staging` or `development`; anything else is a startup
error.

### Module settings

The runtime hands each module the raw `Env`, so these keys do **not** default from the Worker variables above — every instance sets them:

| Key | Notes |
|---|---|
| `AUTH_CORE_ISSUER` | Must equal `AUTH_PUBLIC_URL` (compared as origins). `auth-core` reads its issuer here, not from the Worker config. |
| `AUTH_MAGIC_LINK_PUBLIC_BASE` | Required. The origin the mailed link points at. |
| `AUTH_MAGIC_LINK_MAIL_FROM` | Required. Magic-link mail is sent **From this**, not `MAIL_FROM` — the module sets the message's own `From`, overriding the adapter default. Domain verified. |
| `AUTH_MAGIC_LINK_ALLOW_REGISTRATION` | Default `false`. When `true`, a magic-link request for an address with no account **creates one** — passwordless sign-up, open to anyone who can type an address. |
| `AUTH_CORE_SSO_TOKEN_KEY` | 32 bytes of base64 (standard or URL-safe, padded or not). Seals each enterprise SSO connection's OIDC client secret at rest; set it as a **secret**. Without it, creating a connection or rotating its secret answers `503 auth/sso-unconfigured`; the optional `AUTH_CORE_SSO_TOKEN_KEY_ID` (integer, default `1`) is the key id for rotation. See [SSO.md](SSO.md). |

## Rotating signing keys

Access tokens are ES256 JWTs signed with one configured key; the JWKS at
`/.well-known/jwks.json` publishes the public half of **every** configured key
(`crates/auth-core/src/tokens.rs`). Two variables hold the material:

- `AUTH_CORE_SIGNING_KEYS` — a JSON array of 1 to 16 private EC JWKs on P-256, each with a
  unique `kid` and the private scalar `d` (base64url, unpadded); `kty`, `crv`, `kid` are read,
  `x`/`y` are ignored and re-derived from `d`. Set it as a **secret** — private key material.
- `AUTH_CORE_SIGNING_KEY_ACTIVE` — the `kid` that signs; it must name one of the
  configured keys.

Access tokens live `ACCESS_TOKEN_SECS` = **600 s** — a constant, not configuration.

**Add a key, both are published, switch, retire:**

1. Generate a P-256 key with a new `kid` (any JWK tool, e.g. `step crypto jwk
   create --kty EC --crv P-256`). Add it to the array and put the secret,
   **leaving `AUTH_CORE_SIGNING_KEY_ACTIVE` on the old key**; the JWKS lists both.
2. **Wait for every verifier to refetch** — the JWKS carries
   `Cache-Control: max-age=300`, and `cratefield-auth-client` caches keys up to an
   hour (`JWKS_TTL_SECS = 3600`), never refetching sooner than 60 s. Existing
   tokens are unaffected — their key is still published.
3. **Switch.** Set `AUTH_CORE_SIGNING_KEY_ACTIVE` to the new `kid` and put the
   secret. New tokens carry the new `kid`.
4. **Wait longer than the access-token lifetime** — over 600 s — then **retire**:
   remove the old key and put the secret. Once it leaves the JWKS, an unexpired
   token it signed is unverifiable to a fresh fetch — do not skip the wait.

Steps 1, 3 and 4 re-put `AUTH_CORE_SIGNING_KEYS` (step 3, `…_ACTIVE` too); a secret
change publishes a new version and new isolates read it, so wait after each. There
is no admin route and no `fz` command for signing keys — rotation is these two
variables and a redeploy.

## Rotating a client secret

A client hashes its secret with Argon2id; the plaintext exists once, in the create
or rotate response. Rotation keeps **two** valid over an overlap window, so the
client can move without downtime:

```sh
curl -fsS -X POST \
  https://auth.<app-domain>/v1/auth-core/admin/clients/<client-id>/rotate-secret \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

The response is `{ "client_secret": "<new>", "previous_hash_expires_at": "<RFC 3339>" }`. The new
secret verifies at once; the previous one keeps verifying until `previous_hash_expires_at`,
**one hour** after the rotation by default (`AUTH_CORE_SECRET_OVERLAP_SECS` overrides it). Deploy
the new secret to the client before that instant; public clients have no secret — the route answers `400`.

## Troubleshooting a refused startup

An invalid configuration is a refused Worker: its reasons are logged once per
isolate (all together, not just the first), then every request answers `500` until
you fix the config and redeploy — confirm it is up with
`curl -fsS https://auth.<app-domain>/__health`.

| Log symptom | Fix |
|---|---|
| `… is required` | One of the four identity values (`AUTH_PUBLIC_URL`, `AUTH_VENTURE_NAME`, `AUTH_CORS_ORIGINS`, `AUTH_BRAND_NAME`) is missing from this environment's vars. Remember wrangler does not inherit `[vars]` into `[env.production.vars]`. |
| `AUTH_PUBLIC_URL` — not absolute / has a path / `http` off loopback | A bare `https` origin like `https://auth.example.com`; only `localhost`/`127.0.0.1`/`[::1]` may use `http`. A trailing `/` is fine. |
| `AUTH_BRAND_*` — malformed | The accent is `#rgb`/`#rrggbb`; URLs are absolute `https`; the support address is a bare `addr@host`; names and footers have no control characters. |
| `AUTH_CORS_ORIGINS` — wildcard, path, trailing slash, `http`, or no origins | Exact `https` `scheme://host[:port]` origins; set-but-empty is refused, at least one is required. |
| `AUTH_VENTURE_NAME` — must be kebab-case | `[a-z0-9]+` parts joined by `-`, e.g. `acme-auth`. |
| `AUTH_TURNSTILE_HOSTNAME` — must be a bare hostname | The host alone, e.g. `auth.example.com`; no scheme, port or path. |
| `AUTH_CORE_SIGNING_KEYS` / `…_KEY_ACTIVE` | A JSON array, not one object; each entry needs `kty: EC`, `crv: P-256`, a unique `kid`, `d`. The active `kid` must be in the array. |
| `AUTH_MAILER` — unknown / requires a key / ambiguous / production needs a mailer | Use `owlpost` or `resend` and set the key it needs; never `none`, or no key at all, under `ENV=production`. A blank value reads as unset. |
| `MAIL_FROM`/`MAIL_REPLY_TO` — not an address | `addr@host` or `Name <addr@host>`, no whitespace. |
