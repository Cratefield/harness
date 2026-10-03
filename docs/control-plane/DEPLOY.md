# Deploying the control plane

The hosted control plane (`crates/control-plane`) runs as one Worker
(`cratefield-control-plane`) and one D1 database (`cratefield-control-plane`)
at **https://console.cratefield.com**. It is deployed by
[`.github/workflows/deploy-control-plane.yml`](../../.github/workflows/deploy-control-plane.yml):

- **When:** every push to `main` that touches `crates/control-plane*/**` or
  the workflow, and on demand (`gh workflow run deploy-control-plane.yml`).
  A change to a shared crate (core, the Cloudflare runtime) is picked up by
  the next control-plane deploy or a manual run.
- **Until the Cloudflare secrets exist** the deploy job is skipped with a
  notice, so `main` stays green.
- **What a run does,** in order, inside the GitHub environment `production`
  (one deploy at a time, never cancelled half-way):
  1. resolves the D1 database `cratefield-control-plane` by name through the
     Cloudflare API, creating it on the first run, and writes its id into
     the runner's copy of `wrangler.toml` (no real id is committed — the
     file carries `REPLACED_AT_DEPLOY_BY_WORKFLOW`);
  2. applies `crates/control-plane/migrations/` to it (`wrangler d1
     migrations apply DB --env production --remote`);
  3. builds the wasm (`worker-build --release`) and runs `wrangler deploy
     --env production`, which attaches the Custom Domain
     `console.cratefield.com` (Cloudflare creates the DNS record and the
     certificate);
  4. generates `HARNESS_SECRET` and `ADMIN_TOKEN` **only if absent**
     (`openssl rand -hex 32` piped into `wrangler secret put`, never
     printed); an existing value — including one you set by hand — is never
     replaced;
  5. runs [`crates/control-plane/smoke.sh`](../../crates/control-plane/smoke.sh):
     `/__health`, `/__ready` (a `SELECT 1` through D1) and
     `/v1/console/login` must answer 200. The last one is the real check:
     a production deployment missing a readiness control answers every
     `/v1` route `503 not-production-ready` while `/__health` stays green.
     Each path is retried for up to five minutes, because a brand-new
     Custom Domain takes a moment to resolve and get its certificate.

## One-time owner steps

### 1. Cloudflare account

- The `cratefield.com` zone must be **active on the same account** as
  `CLOUDFLARE_ACCOUNT_ID`. A Custom Domain can only be attached in the
  account that owns the zone; if the zone lives elsewhere the deploy fails
  at the route step.
- No `console` DNS record should exist already: the Custom Domain creates
  its own proxied record and refuses to overwrite a conflicting one. Delete
  any placeholder `console.cratefield.com` record first.
- Workers and D1 work on the free plan (the gzipped Worker is about 1.3 MB,
  under the free 3 MB limit); a paid Workers plan is only needed for higher
  limits.

### 2. Cloudflare API token

Create a custom token (My Profile → API Tokens → Create Custom Token):

| Scope | Permission | Access |
|---|---|---|
| Account (the Cratefield account) | Workers Scripts | Edit |
| Account | D1 | Edit |
| Account | Account Settings | Read |
| Zone (`cratefield.com` only) | Workers Routes | Edit |
| Zone (`cratefield.com` only) | DNS | Edit |
| Zone (`cratefield.com` only) | Zone | Read |

*Zone Read* lets wrangler look up the zone the Custom Domain lives in; the
other five are the ones the deploy itself exercises. Limit Zone Resources
to `cratefield.com` rather than all zones.

### 3. GitHub repository secrets

The same names `deploy-auth.yml` uses:

```
gh secret set CLOUDFLARE_ACCOUNT_ID -R Cratefield/harness   # paste the account id
gh secret set CLOUDFLARE_API_TOKEN  -R Cratefield/harness   # paste the token
```

The GitHub environment `production` is created by the first run. Adding
required reviewers to it turns every deploy into an approval; leave it open
for deploy-on-merge.

### 4. Worker secrets

Set these on the Worker from a machine with wrangler authenticated against
the account (`export CLOUDFLARE_API_TOKEN=… CLOUDFLARE_ACCOUNT_ID=…`), from
`crates/control-plane/`, always with `--env production`. `wrangler secret
put` reads the value from a prompt or from stdin; never pass it as an
argument. A secret can be set before the first deploy only if the Worker
exists, so the simplest order is: add the GitHub secrets, let the first
deploy run, then set the rest — each `secret put` takes effect on the live
Worker immediately.

**Required (the workflow generates them if absent):**

| Secret | Purpose |
|---|---|
| `HARNESS_SECRET` | Signs sessions and links; at least 32 bytes. Rotate with `HARNESS_SECRET_PREVIOUS` (see `docs/ARCHITECTURE.md`, ADR 0014). |
| `ADMIN_TOKEN` | Bearer for the operator routes, notably the allowlist invite. Worker secrets are write-only, so the generated value cannot be read back — to use the admin routes, replace it with one you keep (below). |

**A way in — at least one, or nobody can sign in.** `CONSOLE_DEV_LOGIN` is
refused in production, and the console is invite-only, so you also need to
allowlist yourself (step 5).

| Sign-in | Secrets | Register this redirect URI with the provider |
|---|---|---|
| Magic link (needs no third party but mail) | `RESEND_API_KEY` (a Resend API key with sending access), `CONSOLE_MAGIC_LINK_FROM` (e.g. `Cratefield <signin@cratefield.com>` — the domain must be verified in Resend) | — |
| Google | `CONSOLE_GOOGLE_CLIENT_ID`, `CONSOLE_GOOGLE_CLIENT_SECRET` | `https://console.cratefield.com/v1/console/auth/callback` |
| Apple | `CONSOLE_APPLE_CLIENT_ID` (Services ID), `CONSOLE_APPLE_TEAM_ID`, `CONSOLE_APPLE_KEY_ID`, `CONSOLE_APPLE_PRIVATE_KEY` (the `.p8` contents) — all four or none | `https://console.cratefield.com/v1/console/auth/apple/callback` |
| Meta (Facebook) | `CONSOLE_META_CLIENT_ID`, `CONSOLE_META_CLIENT_SECRET`; optional `CONSOLE_META_GRAPH_VERSION` | `https://console.cratefield.com/v1/console/auth/meta/callback` |

The login page shows exactly the providers whose settings are complete and
names the missing settings of the rest, so it doubles as a checklist.

**Optional:**

| Setting | Default | Notes |
|---|---|---|
| `CONSOLE_MAGIC_LINK_TTL_SECS` | 900 | 60–86400, validated at boot |
| `DASHBOARD_KEY_MAX_AGE_DAYS`, `DASHBOARD_SECRET_MAX_AGE_DAYS` | module defaults | the secrets screen's rotation policy |

**Set in `wrangler.toml`, not as secrets:** `ENV=production` and
`CONSOLE_BASE_URL=https://console.cratefield.com` (`[env.production.vars]`).
**Never set in production:** `CONSOLE_DEV_LOGIN`, `DASHBOARD_DEV_KEK` — the
Worker refuses to boot with either.

Example, replacing the admin token with one you keep:

```
cd crates/control-plane
openssl rand -hex 32 > ~/.cratefield-admin-token   # or straight into a password manager
wrangler secret put ADMIN_TOKEN --env production < ~/.cratefield-admin-token
wrangler secret put RESEND_API_KEY --env production   # prompts for the value
```

### 5. Invite the first operator

```
curl -fsS -X POST https://console.cratefield.com/v1/console/admin/allowlist \
  -H "Authorization: Bearer $(cat ~/.cratefield-admin-token)" \
  -H 'Content-Type: application/json' \
  -d '{"value":"you@cratefield.com","kind":"email","note":"owner"}'
```

`kind` is `email` or `domain` (a domain admits every address on it). Then
sign in at https://console.cratefield.com/v1/console/login.

## Verifying a deploy

- The workflow's *Smoke production* step must be green.
- By hand: `./crates/control-plane/smoke.sh https://console.cratefield.com`.
- `curl -s https://console.cratefield.com/__health | jq '{env, mailer}'` —
  `env` must read `production`; `mailer` reads `configured` once
  `RESEND_API_KEY` is set.
- `wrangler deployments list --env production` shows what is live;
  Workers Logs (observability is enabled) shows the per-request summary.

## Rolling back

- **Code:** `wrangler rollback --env production` returns to the previous
  version (`wrangler deployments list --env production` lists them; pass a
  version id to pick one). Then revert the offending commit on `main`, or
  the next push redeploys it.
- **Database:** migrations only move forward. Undo a bad one with a new
  migration, or restore with D1 Time Travel:
  `wrangler d1 time-travel restore cratefield-control-plane --timestamp=<RFC 3339, before the deploy>`
  (keeps 30 days; take a bookmark first with `wrangler d1 time-travel info`).
- **Secrets:** `wrangler secret put <NAME> --env production` with the old
  value, or `wrangler secret delete` for an optional one. Deleting
  `HARNESS_SECRET` takes the console down; deleting `ADMIN_TOKEN` disables
  the admin routes, and the next deploy generates a new one.
- **Take it offline:** remove the Custom Domain in the dashboard (Workers →
  `cratefield-control-plane` → Settings → Domains & Routes); the Worker and
  its D1 stay intact.

## Migrations

`wrangler d1 migrations apply` reads `crates/control-plane/migrations/`,
not the modules, so every migration the console and the dashboard declare
must be collected there. The files are named
`<NNNN>_<module>_<id>_<name>.sql` and pinned in `.harness-lock.json` by
`fz migrations collect` (`docs/MODULE-AUTHORING.md`); locked files are never
renumbered or edited, new ones append. The control plane has no `fz` bin of
its own, so collect through a throwaway binary that composes the same
modules in the same order (`Chrome`, `Console`, `Dashboard`) and calls
`cratefield_cli::main_for`, then run
`migrations collect --out crates/control-plane/migrations`. The test
`every_module_migration_is_collected_for_wrangler` fails, naming the
migration, whenever a module adds one that is not collected or a collected
file drifts from the module's SQL.

## Local development is unchanged

The top level of `wrangler.toml` is the local shape (local D1, no route, no
`ENV`); only `[env.production]` is deployed. To try the production rules
locally, put `ENV=production`, a `HARNESS_SECRET` and
`CONSOLE_BASE_URL=http://127.0.0.1:8787` in `.dev.vars` (git-ignored), then
`wrangler d1 migrations apply DB --local && wrangler dev --local` and run
`./smoke.sh http://127.0.0.1:8787`.
