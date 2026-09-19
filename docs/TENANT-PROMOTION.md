# Promoting a venture off D1 — the 10 GB cap as a threshold

Issue #154, part of epic #23. The cap should be a threshold a venture
crosses on a written path, not a wall it discovers. This is the path,
and the reason it is short.

> **Status: the machinery exists and is tested minus the Cloudflare
> leg; no promotion has ever been run.** The D1 runtime is
> single-tenant per Worker — one Worker, one venture, one D1 — so the
> tenant on D1 *is* the venture, and there is no per-tenant promotion
> to document. Promotion is a venture-level move onto the Postgres
> runtime ([TENANT-ROUTING.md](TENANT-ROUTING.md) §6), and every
> mechanical part of it already ships.
> [§6](#6-what-this-document-cannot-yet-claim) says what nothing here
> can claim.

## 1. What the cap is a cap on

[PRICING.md](control-plane/PRICING.md) states the number as a storage
row on Cloudflare's plans: 5 GB pooled across the account, and a
**10 GB/db hard cap** per database, billed at `$0.75 / GB-mo` past the
pool. The row is per database. [ROADMAP.md](control-plane/ROADMAP.md)
states the same number per tenant: "The 10 GB cap is per tenant."

Both are true in one sentence today, because on the Cloudflare path
the tenant, the database and the venture are the same thing.
[TENANT-ROUTING.md](TENANT-ROUTING.md) says it as premise — the
Cloudflare path has one venture per Worker and one D1 — and §6 makes
it mechanism: a runtime with no registry inserts a **single implicit
tenant**, the venture itself, status `active`, its handle the one
database binding. The code pins it twice:
`the_implicit_tenant_answers_for_every_host` in
`crates/core/src/tenant.rs`, and
`without_a_tenant_plane_every_host_is_the_implicit_tenant` in
`crates/core/tests/tenant_routing.rs`.

So "promote a tenant off D1" is a category error: there is no unit
smaller than the deployment to promote. The thing that outgrows the
cap is the venture, and the move is the venture's (§3). The per-tenant
lifecycle begins on the other side of it, once a tenant lives in its
own database under
[ADR 0008](adr/0008-native-runtime-is-multi-tenant-database-per-tenant.md)
— where the D1 figure does not follow, because it is a Cloudflare
allotment and this repo's design puts no cap on a tenant database. A
tenant's ceiling after promotion is its provider's, chosen when the
database is provisioned (§4), not D1's.

The number itself moves. PRICING carries its own banner — Cloudflare
pricing verified 2026-09-07, re-check before launch — and this
document inherits it rather than restating the price as timeless.

## 2. When to promote

Before you must. The cap is hard — PRICING's word — and nothing in the
path below goes faster for being started late: the move is a rehearsal
plus a cutover with a write freeze (§3, §5). Start when the trend says
the cap arrives within that horizon, not when a write meets the
ceiling. What D1 does at the ceiling is Cloudflare's behaviour, not
this repo's; the runbook's job is never to find out.

Nothing in the repository reports D1 usage. There is no `fz`
subcommand for it, and the control-plane metering PRICING's guards
assume is #7 and #11's to build and does not exist. The operator's
only answer is Cloudflare's own tooling — `wrangler` and the dashboard
— and neither is this repo's to document. The one measurement the
repo's own runbooks produce is the dump `wrangler d1 export` writes:
§3 needs one anyway, [ROLLBACK.md](ROLLBACK.md) §6 already requires a
nightly one, and its size on disk is a lower bound on the data. It is
not a meter. Until the control plane meters storage, the threshold is
a person reading Cloudflare's numbers — which is why this section is
prose and not a check.

## 3. The move

Two facts shape the runbook. First, `fz data export` reads a local
SQLite file only; it cannot read a live D1, so the wrangler leg is not
a convenience but the bridge. Second, both `fz` halves the path needs
— `data import`, and `migrations apply --dialect postgres` — sit
behind a cargo feature a stock `fz` does not have. Build with
`--features cratefield-cli/postgres`; both commands refuse with build
instructions otherwise. [DATA-MOVE.md](DATA-MOVE.md) names the feature
at its step 4, which is later than the first command that needs it;
this runbook says it once, here.

| # | Step | Who | Verified by |
| --: | :--- | :--- | :--- |
| 1 | Pull D1 into a local SQLite file: `wrangler d1 export <database-name> --remote --env production --output dump.sql`, then `sqlite3 venture-copy.db < dump.sql` | **operator** | the copy opens and `fz data export --plan` reads it; the one leg Cloudflare credentials gate and CI cannot cover |
| 2 | Stand up the target Postgres database: PITR on, retention **≥ 30 days**; an application role scoped to that database only | **operator** | the provider console; the retention floor is [ROLLBACK.md](ROLLBACK.md) §6 |
| 3 | Apply the venture's migrations to it: `fz migrations apply --dialect postgres --url postgres://user:pass@host:5432/<venture>` | harness | `harness_migrations` in the target; re-running applies only what is missing |
| 4 | Export the copy: `fz data export --db venture-copy.db --out data.jsonl` (`--plan` previews without writing) | harness | `export_writes_manifest_and_records_and_is_deterministic` — exporting twice is byte-identical |
| 5 | Dry-run the import: `fz data import --url postgres://user:pass@host:5432/<venture>-staging --plan data.jsonl` | harness | the plan prints tables, incoming rows, existing rows, refusal warnings |
| 6 | Import for real: `fz data import --url postgres://user:pass@host:5432/<venture>-staging data.jsonl` | harness | every table's sha256 is checked before anything is written (`tampered_file_fails_the_sha256_check`) and row counts are re-counted after; `round_trip_sqlite_to_postgres_matches_counts_and_checksum` is that round trip in CI |
| 7 | Smoke test: run the module suites with `FZ_TEST_POSTGRES_URL` at the target, then click the venture's critical paths | **operator** | the parity suite is the code path production runs |
| 8 | Freeze writes, then repeat steps 1–6 against the production target from a **fresh** `wrangler d1 export`, so nothing written after the rehearsal leaks in | **operator** | matching counts and checksums on the second round trip |
| 9 | Switch the venture's `src/lib.rs` runtime line to the native runtime with Postgres, build, deploy | **operator** | the diff is the one line [PORTABILITY.md](PORTABILITY.md) promises; no module code changes |

Four notes the table leans on:

- **Sidecars export separately.** `fz` sees only the modules compiled
  into it, so an export refuses to run when the mount table names
  sidecars —
  `export_refuses_a_venture_with_sidecars_until_the_omission_is_acknowledged`.
  Export those from the sidecar's own repository, then re-run here
  with `--without-sidecar-tables`, which records the omission in the
  manifest so the artifact says what it does not contain.
- **The artifact is the audit record.** Keep `data.jsonl`. The
  manifest binds it to the venture it was exported from, and an export
  from another venture is refused before anything touches the network
  (`a_foreign_export_file_is_refused_before_anything_touches_the_network`).
- **No `--append` here, on purpose.** The target is empty by
  construction, and import refuses a non-empty table without the flag
  — so a re-run against a half-filled target cannot merge silently.
- **The portable subset bounds what moves.** TEXT, INTEGER, REAL,
  BOOLEAN (ADR
  [0004](adr/0004-sea-query-and-portable-sql-migrations.md)); a BLOB
  column is refused at export rather than half-carried.

## 4. Landing on the multi-tenant runtime

Step 9 leaves the venture on Postgres in the shape every development
run already has: native without a registry, serving as the implicit
tenant. That is off D1 and off the cap, and it is not yet a registry
tenant — [TENANT-ROUTING.md](TENANT-ROUTING.md) §10 is explicit that
what remains for native *with* a control database is wiring a
`PoolRegistry` into `Ports.tenants`, and this document does not
pretend that has happened.

Becoming a registry tenant is
[TENANT-ONBOARDING.md](TENANT-ONBOARDING.md) §1, and the promotion has
already paid its first two steps: step 2 above is onboarding steps 1
and 2, provision with PITR and scope the app role. From step 3 on —
the DSN stored as a global secret the registry merely names — the
runbook is the onboarding runbook, not this one. Where that secret
lives is §6's unsettled question; this document does not decide it.

The mechanical half of onboarding, the registry writes, now has a
runtime-neutral home, and that is #154's code half: `TenantLifecycle`,
a port in `crates/core/src/tenant_lifecycle.rs` with `create`,
`status`, `tenants`, `set_status`, and `begin_erasure` /
`complete_erasure` for the offboarding half.
`cratefield-adapter-postgres` implements it over the writes that
already existed, `register_tenant` and `set_tenant_status`. [ADR
0019](adr/0019-the-tenant-lifecycle-is-a-port-in-core.md) records what
the port is deliberately not. It is not in the `Ports` struct, because
modules must never write the registry. It consumes the transition rule
where #361 put it, `TenantStatus::admits`, rather than restating it.
And it provisions and drops nothing: ADR 0008 scopes a tenant's app
role to its own database, so the harness holds no credential that
could create or drop one. Provisioning stays step 2 above, a person's;
the drop stays offboarding's, a person's, after the crypto-shred and
the retention hold.

One tenant at a time is still a plan-only affair:
`fz migrations apply --tenant <TENANT> --plan` prints one tenant's
reconcile, and `--tenant` without `--plan` is refused — fleet apply is
the runtime reconciler's job. Once a row exists and reconciliation has
flipped it to `active`, `only_active_serves` pins the rule that decides
who answers.

## 5. Cutover and rollback

DNS is the cutover, and the sentence is
[PORTABILITY.md](PORTABILITY.md)'s: "The Worker and the D1 database
still exist and still answer, so a bad cutover is a DNS revert, not a
restore." The order is DATA-MOVE §6's: freeze writes; repeat steps 1–6
from a fresh export; deploy the native build; point the domain at the
new host; watch `/__health` and `/__ready`; unfreeze.

The revert is cheap because nothing was destroyed to cut over: the
Worker still answers and D1 still holds the data. What a revert does
not do is rewind data — rows written to Postgres between cutover and
revert stay in Postgres, and bringing them home is a second
export-import run in reverse. A revert is a serving decision, not a
data merge, which is a reason to keep the frozen window and the
time-to-decision short.

After the cutover, [ROLLBACK.md](ROLLBACK.md) §6's floors attach to
the new database as ordinary tenant-database requirements: the PITR
floor was set in step 2, and the nightly export continues — the same
runbook covers both engines, which is the point of the floor.

## 6. What this document cannot yet claim

- **No promotion has been run.** Not the rehearsal, not the cutover,
  not by this document and not by any other. What CI proves is the
  round trip minus the wrangler leg —
  `round_trip_sqlite_to_postgres_matches_counts_and_checksum` in
  `crates/cli-acceptance/tests/data.rs`, gated on
  `FZ_TEST_POSTGRES_URL`. The wrangler leg cannot be covered by CI, so
  steps 1 and 8 are the parts only a person can prove.
- **No tenant database has ever been provisioned** (§4), so the
  landing described there has never happened either. The registry
  writes onboarding needs exist and are tested; no real tenant has
  exercised them.
- **runtime-native has no tenant wiring.** A promoted venture serves
  as the implicit tenant until a `PoolRegistry` reaches
  `Ports.tenants` ([TENANT-ROUTING.md](TENANT-ROUTING.md) §10).
  "Registry tenant" is a state this document describes, not one
  anything has served.
- **Where the DSN lives is unsettled.** The onboarding runbook stores
  it as a global secret the registry merely names; the shipped
  registry table carries a `dsn` column that can hold the string
  itself, and the code's own comment records the choice as a
  deployment's, deliberately open. Both exist; this document does not
  decide.
- **Registry cache lifetime is open**
  ([TENANT-ROUTING.md](TENANT-ROUTING.md) §13): how promptly a status
  change takes effect for a served tenant is unresolved, and §4's
  "confirm the tenant answers" inherits that uncertainty.
- **Nothing meters D1 storage** (§2). "When to promote" is a person
  reading Cloudflare's numbers until the control plane says otherwise.
