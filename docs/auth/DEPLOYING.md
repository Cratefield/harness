# Deploying the auth service

The shared instance is `auth.factory0.ventures`, deployed by
[`deploy-auth.yml`](../../.github/workflows/deploy-auth.yml) from `main` (staging)
and an `auth-v*` tag (production). This covers running the same Worker as your
venture's **own** instance, and its two rotations: signing keys and client secrets.

## You probably do not need your own

Register as a client of `auth.factory0.ventures` instead; run your own only when one of these is true:

- **Your pages call the JSON routes first-party.** `auth-password`'s sign-in routes
  refuse a request whose `sec-fetch-site` is not `same-origin`/`none`, or whose
  `Origin` names another site: `403 auth/cross-site-request`. `same-site` is refused
  too (`crates/auth-core/src/csrf.rs`), so `app.venture.com` posting to
  `auth.factory0.ventures` fails. Redirect flows (Google, Apple, magic link) are
  exempt; a password is not.
- **Your own sender, templates and data residency** — your verified domain, your
  From address, and users, sessions and clients in your own D1, with the cost and
  on-call that come with it.

## Prerequisites

- **Workers Paid.** `auth-password` verifies with Argon2id at m=19456, t=2, p=1 —
  roughly 40 ms per hash or verify (ADR 0200), which the free tier's 10 ms CPU
  limit cannot fit. Password login is not a knob to tune down.
- A domain on Cloudflare (a `custom_domain` route) and a D1 database per environment.
- A Workers Rate Limiting namespace (the `[[ratelimits]]` stanza); readiness
  refuses a venture whose limiter binding does not resolve (harness #437).
- A Turnstile site (site key on the page, secret to the Worker) and a mail
  provider — Resend or Owlpost — with a **verified sender domain** (production only).

## A separate deployment, step by step

1. **Your own wrangler config, the same crate.** A separate deployment is a Worker of its own:
   your `wrangler.toml` (a deployment repo, or `wrangler deploy -c path/to/wrangler.toml`) sets
   `name`, the production `route = { pattern = "<your-host>", custom_domain = true }`,
   `[[d1_databases]]` (`binding = "DB"`), a per-environment `[[ratelimits]]` `namespace_id`, and
   `[vars]` (below; secrets are not vars). It builds the **unmodified** `cratefield-auth-worker`
   crate — no copy, no fork. Note `worker-build` compiles the package in the config's directory
   (`main = "build/worker/shim.mjs"` is relative to it), so the config either sits beside the
   crate or sets `[build] command`/`main` to build it and point at the shim. Create a D1 per
   environment (`npx wrangler d1 create <name>`) first.
2. **Apply migrations.** Migrations are collected from the module crates by
   `fz migrations collect` and committed under
   `crates/auth-worker/migrations/<GGGG>_<module>_<NNNN>_<name>.sql`, pinned by
   `.harness-lock.json`. From the deployment directory:

   ```sh
   npx wrangler d1 migrations apply DB --remote                     # staging
   npx wrangler d1 migrations apply DB --env production --remote    # production
   ```

3. **Set the secrets** (never in `wrangler.toml`):

   ```sh
   wrangler secret put HARNESS_SECRET   --env production   # ≥ 32 bytes, also signs HMAC state
   wrangler secret put ADMIN_TOKEN      --env production   # ≥ 32 bytes; admin routes answer 401 without it
   wrangler secret put TURNSTILE_SECRET --env production
   wrangler secret put AUTH_CORE_SIGNING_KEYS --env production < keys.json
   # plus RESEND_API_KEY (mailer `resend`) or OWLPOST_API_KEY (mailer `owlpost`)
   ```

   Secrets and vars share one namespace and secrets win; `HARNESS_SECRET_PREVIOUS`
   only verifies during its rotation.

4. **Deploy and smoke.** `wrangler deploy` or `wrangler deploy --env production`;
   then `./smoke.sh https://<your-host>`, which requires `200` over TLS from
   `/__health`, `/.well-known/openid-configuration` and `/.well-known/jwks.json`.

5. **Register the first client** (there is no `fz` command for this). The admin
   API answers only once `ADMIN_TOKEN` is set; unset means every admin route is
   `401`:

   ```sh
   curl -fsS https://<your-host>/v1/auth-core/admin/clients \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H 'content-type: application/json' \
     -d '{"name":"My venture","kind":"confidential",
          "redirect_uris":["https://app.venture.com/auth/callback"]}'
   ```

   The `201` body carries `client_secret` **once** — only its Argon2id hash is
   stored; redirect URIs are an exact-match allowlist, no wildcards.

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

All of these go in `[vars]` (staging) and `[env.production.vars]` (production); a
blank value reads as unset, so the default applies.

| Variable | Default | Meaning |
|---|---|---|
| `AUTH_PUBLIC_URL` | `https://auth.factory0.ventures` | Issuer, the venture's public URL and the problem-type base (`<url>/problems/…`). The venture domain is its host. Must be an absolute `https` origin; a bare trailing `/` is trimmed; `http` is allowed only for the loopback hosts `localhost`/`127.0.0.1`/`[::1]`. No path, query or fragment. |
| `AUTH_VENTURE_NAME` | `factory0-auth` | The venture's name. Must be kebab-case (`[a-z0-9]+`, parts joined by `-`). |
| `AUTH_CORS_ORIGINS` | `https://app.cratefield.com,https://cratefield.com,https://yoginini.us` | Exact `scheme://host[:port]` origins for cross-origin `GET`s (discovery, JWKS). Must be `https` (`http` only for a loopback host); no wildcards, paths or trailing slash. **Set-but-empty is a startup error** — the harness requires at least one origin. |
| `AUTH_TURNSTILE_HOSTNAME` | host of `AUTH_PUBLIC_URL` | The bare hostname the Turnstile verdict must name (no scheme, port or path). (`TURNSTILE_SECRET` stays a secret.) |
| `MAIL_FROM` | `no-reply@<host of AUTH_PUBLIC_URL>` | The mailer's default `From`, for mail that sets none of its own: `addr@host` or `Name <addr@host>`, domain verified. Magic-link does not use it — see below. |
| `MAIL_REPLY_TO` | none | The mailer's default `Reply-To`, same address forms. |
| `AUTH_MAILER` | unset | `resend`, `owlpost` or `none`; unset **or blank** keeps the legacy behaviour — Resend when the `RESEND_API_KEY` secret is set, otherwise no mail. `resend` needs `RESEND_API_KEY`; `owlpost` needs `OWLPOST_API_KEY` (and an optional, `https`-only `OWLPOST_BASE_URL`). Under `ENV=production`, `AUTH_MAILER=none` is refused; set it explicitly in production so a mistyped key cannot silently degrade to no mail. |

`ENV` accepts only `production`, `staging` or `development`; anything else is a startup
error. The shared deployment needs no new variables — if it already sets
`MAIL_FROM`/`MAIL_REPLY_TO`, those now act as the adapter's default sender (previously ignored).

### Module settings

The runtime hands each module the raw `Env`, so these keys do **not** default from the Worker variables above — a separate deployment sets them too:

| Key | Notes |
|---|---|
| `AUTH_CORE_ISSUER` | Must equal `AUTH_PUBLIC_URL` (compared as origins); checked when `AUTH_PUBLIC_URL` is set explicitly. `auth-core` reads its issuer here, not from the Worker config. |
| `AUTH_MAGIC_LINK_PUBLIC_BASE` | Required. The origin the mailed link points at. |
| `AUTH_MAGIC_LINK_MAIL_FROM` | Required. Magic-link mail is sent **From this**, not `MAIL_FROM` — the module sets the message's own `From`, overriding the adapter default. Domain verified. |
| `AUTH_MAGIC_LINK_ALLOW_REGISTRATION` | Default `false`. When `true`, a magic-link request for an address with no account **creates one** — passwordless sign-up, open to anyone who can type an address. |

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
  https://<your-host>/v1/auth-core/admin/clients/<client-id>/rotate-secret \
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
`curl -fsS https://<your-host>/__health`.

| Log symptom | Fix |
|---|---|
| `AUTH_PUBLIC_URL` — not absolute / has a path / `http` off loopback | A bare `https` origin like `https://auth.venture.com`; only `localhost`/`127.0.0.1`/`[::1]` may use `http`. A trailing `/` is fine. |
| `AUTH_CORS_ORIGINS` — wildcard, path, trailing slash, `http`, or no origins | Exact `https` `scheme://host[:port]` origins; set-but-empty is refused, at least one is required. |
| `AUTH_VENTURE_NAME` — must be kebab-case | `[a-z0-9]+` parts joined by `-`, e.g. `acme-auth`. |
| `AUTH_TURNSTILE_HOSTNAME` — must be a bare hostname | The host alone, e.g. `auth.venture.com`; no scheme, port or path. |
| `AUTH_CORE_SIGNING_KEYS` / `…_KEY_ACTIVE` | A JSON array, not one object; each entry needs `kty: EC`, `crv: P-256`, a unique `kid`, `d`. The active `kid` must be in the array. |
| `AUTH_MAILER` — unknown / requires a key / `none` in production | Use `resend`, `owlpost` or `none`, set the key it needs, and never `none` under `ENV=production`. A blank value reads as unset. |
| `MAIL_FROM`/`MAIL_REPLY_TO` — not an address | `addr@host` or `Name <addr@host>`, no whitespace. |
