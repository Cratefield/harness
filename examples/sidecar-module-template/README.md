# sidecar-module-template

**Copy this repository and deploy it as your own Worker. The source never
has to leave your repository.** In the customer-account deployment mode
nobody but you ever compiles it: you build the Worker with your own
credentials, you deploy it to your own Cloudflare account next to your
host Worker, and the host mounts it over a service binding at the same
`/v1/<module name>` prefix it serves its own modules at — so no caller
can tell the difference ([ADR 0009](https://github.com/Cratefield/harness/blob/main/docs/adr/0009-sidecar-modules-over-service-bindings.md)).
In a hosted mode the honest line changes to **"build it yourself and hand
us the artifact"**: the source stays with you either way, only the deploy
step differs (issue #67 decides the hosted mechanism).

What is here:

```text
src/module.rs     the module — one table, one route pair, one cron purge. THE FILE YOU EDIT
src/harness.rs    the venture identity + wiring; the four values there must match your host Worker
src/lib.rs        the Worker entry points (fetch, scheduled) — usually never touched
src/fz_main.rs    the fz bin: migrations collect, doctor
migrations/       the collected migration stream this repo applies itself (see below)
wrangler.toml     deployment config; every non-obvious line has a why
tests/            the cratefield-testing conformance kit + route/cron behaviour
```

## Build, test, deploy

```sh
cargo test                                  # conformance kit + behaviour, no network
wrangler d1 migrations apply <db-name> --remote
wrangler secret put HARNESS_SECRET          # this Worker's OWN (see .dev.vars.example)
wrangler secret put ADMIN_TOKEN             # also its own
wrangler secret put SIDECAR_GATEWAY_SECRET  # the one shared value; host has it too
wrangler deploy
```

`cargo test` passes from a fresh clone with no edits, and so does
`worker-build --release` — the wasm artifact the deploy produces.

Before the first deploy, edit `src/harness.rs`: the venture name, domain,
`public_url` and CORS origins must **exactly match your host Worker's
`src/harness.rs`**. They decide where the module's links point and which
browser origins may call this Worker, and a mismatch is not an error
anywhere — it is a silent wrong redirect. A template cannot read your
host's source, so the values live in exactly one place, next to the
comment that says what drifting from them costs.

## The one line the operator adds on the host

The host Worker mounts the sidecar through configuration, not a rebuild:

```toml
# host wrangler.toml
[[services]]
binding = "NOTES"
service = "my-sidecar"          # the name this Worker was deployed under

[vars]
HARNESS_SIDECARS = '{"notes":"NOTES"}'
```

Mount and unmount are reversible at any time
([MOUNTING.md](https://github.com/Cratefield/harness/blob/main/docs/MOUNTING.md)):
the module crate can just as well be compiled into the host, and a
caller cannot tell which.

## The five things this template pins down

Each of these is silent if left to the reader, so the template decides
it.

1. **No public route.** `wrangler.toml` sets `workers_dev = false` and
   declares no `routes`. The host's rate limiting, captcha and
   request-id trust all key off the `cf-connecting-ip` the host resolves
   and forwards; a directly reachable sidecar would accept a
   client-supplied one and bypass all of it. The config comment says
   so next to the setting, because "why is this missing" is the question
   that leads someone to add it back.
2. **Its own secrets, not the host's.** This Worker never receives the
   host's `HARNESS_SECRET` or `ADMIN_TOKEN` — the first would let it
   forge the host's confirm and unsubscribe links, the second would open
   the host's admin plane. It signs and checks with its own, and the
   host's gateway stamp (`x-harness-gateway`) is what re-materializes
   this Worker's own admin token for admin paths, so no bearer ever
   crosses in either direction (issue #131).
3. **Its own cron trigger.** The host's `serve_scheduled` fans a cron
   out over the *host's* modules; nothing on the host fires this
   Worker's `scheduled()`. `wrangler.toml` declares `[triggers]` and
   `src/lib.rs` declares `#[event(scheduled)]`, and the module ships a
   real retention purge so the cron does real work — a purge that
   silently never runs is the exact failure mode.
4. **Its own migrations, against the shared database.** The D1 database
   is **yours** — the same `database_id` the host binds — but the
   migration *stream* is this repository's: `fz migrations collect`
   writes `migrations/` here, and you apply it with
   `wrangler d1 migrations apply` from this repo. Two streams share one
   database cleanly provided they are applied **one after the other,
   never in parallel**, and the file names are recorded in
   `migrations/.harness-lock.json` so a module can move between mounts
   without re-running its schema
   ([MIGRATION-STREAMS.md](https://github.com/Cratefield/harness/blob/main/docs/MIGRATION-STREAMS.md)).
5. **A duplicated `Venture`.** Name, domain, `public_url` and
   `cors_origins` — see above. One place, loud comment, and the README
   says why it cannot be generated across repositories.

## What a contract mismatch looks like

Every harness response carries `x-harness-api` and `x-harness-module`.
The host checks them on **every** forwarded response — not cached at
cold start, because an isolate can outlive a sidecar redeploy. If this
Worker is built against a different harness contract than the host
expects, the mounted prefix answers:

```text
503 sidecar-contract-mismatch
```

and the trail is findable through one `x-request-id` on both Workers'
logs. A missing service binding or a dead sidecar is the gentler
`503 sidecar-unavailable`. Either way every other module on the host
keeps serving.

## Making it yours

Change `src/module.rs` — rename the module, rewrite the route bodies,
add migrations under `migrations/sqlite/` and wire them into
`migrations()`. Run `cargo test`, then `fz migrations collect`, then
deploy. That is the whole loop; the issue's verification is exactly
that someone who has not read the harness does it and gets an answer
through a host that mounts it.

**Extracting the template.** While the harness crates live only in this
repository ([ADR 0013](https://github.com/Cratefield/harness/blob/main/docs/adr/0013-one-repository.md)),
the template sits inside it and its `Cargo.toml` inherits versions from
the workspace. When the crates reach crates.io (see
[RELEASING.md](https://github.com/Cratefield/harness/blob/main/docs/RELEASING.md)),
extraction is mechanical: copy the directory, drop the `workspace = true`
inheritance for explicit versions (or git dependencies until then), and
the `.github/workflows/ci.yml` shipped in the template takes over. Until
extraction day, this in-tree copy is kept honest by the harness CI's
conformance and wasm legs.

MIT, same as the harness. Multi-module sidecars are deliberately out of
scope: one sidecar carries one module until there is a reason for more.
