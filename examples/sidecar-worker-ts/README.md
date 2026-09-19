# sidecar-worker-ts

**The harness sidecar contract, in TypeScript, for people who do not write
Rust.** Copy this directory, deploy it as your own Worker, and the host
mounts it over a service binding at the same `/v1/<module name>` prefix it
serves its own modules at — no caller can tell the difference
([ADR 0009](https://github.com/Cratefield/harness/blob/main/docs/adr/0009-sidecar-modules-over-service-bindings.md)).
It is the Rust template's
([`examples/sidecar-module-template`](../sidecar-module-template)) smallest
honest sibling: same wire contract, no runtime dependencies, no build step
— `wrangler deploy` bundles `src/index.ts` directly.

What is here:

```text
src/module.ts      the module — its name, routes, tables, events. THE FILE YOU EDIT
src/index.ts       the Worker entry point: guard, then the three mount routes
src/gateway.ts     the gateway guard: token verification, fail-closed 503
src/surface.ts     the /__health and /__surface bodies + the venture identity
src/http.ts        the response envelope: the two stamps, the echoed request id
src/problems.ts    error answers in the host's problem shape
wrangler.toml      deployment config; every non-obvious line has a why
test/              bun tests that mint real gateway stamps with WebCrypto
```

## What this cannot do yet

Read this before planning a module around it.

1. **No data access.** The host's Tables HTTP contract exists (#153), but
   the generated typed client for it does not (#155). Until #155 lands,
   reaching data from TypeScript means hand-rolling calls against that
   contract — which this example deliberately does not do, because a
   stand-in client here would teach a shape that is about to change. The
   routes answer out of thin air on purpose, `wrangler.toml` declares no
   `[[d1_databases]]`, and `src/module.ts` declares zero tables as a
   positive decision. When #155 lands, data access arrives here.
2. **No conformance-kit parity.** The Rust template runs the
   cratefield-testing conformance kit; these bun tests pin the same wire
   contract from this side but are not that kit, and nothing proves the two
   stay in lockstep but the tests themselves.
3. **Invisible to `fz`.** The schema tooling (#66) walks Rust modules; a
   TypeScript sidecar's tables and events are declared in
   `src/module.ts` and read only by the host's `/__health` probe.

## Build, test, deploy

```sh
bun install
bun run typecheck
bun test
wrangler secret put SIDECAR_GATEWAY_SECRET   # the one shared value; host has it too
wrangler deploy
```

`bun test` passes from a fresh clone with no edits. Before the first
deploy, edit `src/surface.ts`: the venture name, public URL and
environment must **exactly match your host Worker's** — a mismatch is not
an error anywhere, it is a silent wrong answer to a renderer that asks.
In production also set `SIDECAR_REQUIRE_GATEWAY=1` — a `[vars]` line in
your `wrangler.toml`, beside the secret (`.dev.vars.example` shows both
for local dev) — without it the guard over `/v1/` and `/__surface` never
closes, and the token checks in item 7 below never run.

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
a caller cannot tell which half of the venture answered.

## The contract, in one place

Each of these is checked by the host on every request, so the example
decides each one visibly rather than leaving it to the reader.

1. **The prefix is not stripped.** The host forwards the caller's original
   URI, so this Worker serves its routes under its own
   `/v1/notes/...` — and `/v1/notes-nope/...` never reaches the module.
2. **Every answer is stamped.** `x-harness-api: 1` and
   `x-harness-module: notes`, and the caller's `x-request-id` echoed back
   so one trail reaches both Workers' logs. The envelope in `src/http.ts`
   does it once, so no route can forget.
3. **The host copies back only an allowlist of headers.** Anything else
   this Worker sets stops at the mount — `set-cookie` in particular is
   dropped, so there is no cookie jar across this boundary.
4. **`GET /__health` answers without a gateway token.** Probes must probe.
   The host reads the stamps and this body's `modules[*].tables` — where
   an explicit empty list is what makes the table-collision check a check
   and not a coin flip.
5. **`GET /__surface` declares exactly one module**, named exactly the
   mount name, within the caps (64 actions, 64 views, 256 KiB body). The
   host merges only the public subset and rejects the whole document on a
   contract disagreement.
6. **`POST /__events` answers `202` and runs handlers after the
   response**, in this Worker's own `waitUntil`. `202`, not `200`: the
   work has not happened yet, and a status that claimed it had would be
   the one lie this route cannot afford. Inbound only, delivered at most
   once, never retried, no queue.
7. **With `SIDECAR_REQUIRE_GATEWAY` set**, every guarded request carries a
   token the host minted with the shared `SIDECAR_GATEWAY_SECRET`
   (HMAC-SHA256 over the exact encoded payload bytes, at least a 32-byte
   secret, checked in constant time with WebCrypto). Bad or missing is a
   `401`; requiring the gateway without a usable secret is a broken deploy
   and answers a loud `503`, never a quiet `200`.

## How it differs from the Rust template

Same mount, same stamps, same guard — deliberately, or a caller could tell
the difference. What is actually different: no D1 binding and no migration
stream (there is no data access to migrate — see the first "cannot do
yet"), no cron trigger (the host fans its cron out over its own modules,
and a module with no data has nothing to purge), and no
`HARNESS_SECRET`/`ADMIN_TOKEN` — this Worker never receives the host's
secrets; the one value shared across the boundary is
`SIDECAR_GATEWAY_SECRET` (issue #131).

MIT, same as the harness. One sidecar carries one module until there is a
reason for more.
