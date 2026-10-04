# Importing a Supabase project, step 1: inspect

`fz import supabase inspect` connects **read-only** to a Supabase project and
writes a migration report: everything in the project, each item classified
as **automatic**, **needs work** or a **blocker**, with the data size and a
rough transfer time. It is the first step of the Supabase importer that
[ADR 0026](../adr/0026-supabase-import.md) decides (issue #658), and it is
useful on its own: it tells a venture exactly what moves by itself and what
someone has to write or decide.

It never writes to the project, and nothing it produces contains a
credential, a password hash, an email or a row of data.

## What it reads

From the project's Postgres, in one `REPEATABLE READ READ ONLY` transaction:

- schemas, and the tables in them with estimated row counts and sizes;
- columns and types, constraints, indexes, sequences, enums, extensions
  (with their support status on the harness), functions, triggers and views;
- every **row-level-security policy**, per table and role, with its SQL;
- the number of `auth.users`, the providers in `auth.identities`, MFA
  factors and SSO providers — counts only;
- storage buckets with their object counts and total sizes, from
  `storage.buckets` and `storage.objects`;
- Realtime publications (`pg_publication`) and `pg_cron` jobs;
- grants to Supabase's API roles (`anon`, `authenticated`, `service_role`).

From the Supabase Management API, **only when a token is given**: the Edge
Functions, and which sign-in providers and MFA methods the auth
configuration enables. Without a token those are reported as *not
inspected* — unknown, not none. Only the configuration's `…_enabled`
booleans are read; its client secrets and SMTP password are never looked at.

## Read-only, twice

1. The session's default is read-only (set at connection and again with
   `SET`), and every read runs inside a `READ ONLY` transaction that is
   rolled back, never committed. Before the rollback, inspect checks that
   Postgres never assigned the transaction an id, which any write would
   have done, and records that in the report.
2. Connect as a role that cannot write at all. In the Supabase SQL editor,
   which runs as `postgres`:

```sql
create role cratefield_inspect login password '<a long random password>' bypassrls;
alter role cratefield_inspect set default_transaction_read_only = on;
grant pg_read_all_data to cratefield_inspect;
```

`pg_read_all_data` (Postgres 14+) is the whole role in one grant: `SELECT`
on every table, view and sequence, and `USAGE` on every schema, current and
future — `auth`, `storage`, `cron` and your own included — with no write.
The old `grant usage on schema auth` warned (`no privileges were granted`)
and granted nothing, because `postgres` does not own `auth`; this does not.
`BYPASSRLS` is needed too: Supabase enables row-level security on
`auth.users`, `auth.identities`, `storage.buckets`, `storage.objects` and
`cron.job`, and a role without it reads zero rows there — which inspect now
reports as `not_visible` (unknown, not zero), never as a silent `0`.
Supabase's `postgres` holds both attributes, so it can grant them.

If the grant is refused (an older image where `postgres` lacks admin on
`pg_read_all_data`), grant the pieces by hand: `grant usage on schema
public, storage, extensions, cron, <your schemas> to cratefield_inspect;`
and, the same way, `grant select on all tables in schema <...> to
cratefield_inspect;`. `auth` is the exception: its `USAGE` can only come
from its owner, `supabase_admin` — `psql
postgresql://supabase_admin:postgres@127.0.0.1:54322/postgres` on a local
CLI stack, and not available to you on a hosted project. Where `bypassrls`
is refused as well, the table's owner can instead run `create policy
cratefield_inspect_read on <table> for select to cratefield_inspect using
(true);` — which `postgres` cannot do on Supabase's managed tables.

The report's `read_only` block says what was observed: the read-only
transaction and session, the absence of a transaction id, and whether the
role holds any write privilege. A run as a superuser or as a role that can
write still works, with a warning. Writes are refused by privilege
(`permission denied for table …`), not only by the read-only GUC, which the
role could switch off itself — the grant is the guard that matters.

Any section the role cannot fully see — `auth`, `storage.buckets`,
`storage.objects`, `cron`, or a schema without `USAGE`/`SELECT` — is
reported as `coverage.sections[].coverage: not_visible` (unknown, not
zero), makes `ready: false`, and adds a blocker naming the grant or
`BYPASSRLS` it needs; the Markdown report prints a "Grants needed" SQL
block.

The role can read everything, including `auth` password hashes and storage
metadata, so drop it when the migration is done: `revoke pg_read_all_data
from cratefield_inspect; drop role cratefield_inspect;` (or `drop owned by
cratefield_inspect; drop role cratefield_inspect;` if you granted by hand).
The decommission checklist will say so too.

This was verified against Supabase's own init scripts and migrations on
Postgres 16 locally, not on a hosted project: the same roles and grants are
expected there, but if `grant pg_read_all_data` or `bypassrls` is refused,
use the fallback above and the report will name what is missing.

## Running it

The engine reads Postgres through sqlx, so it is behind a feature of the
`fz` binary (a venture's wasm build must never see sqlx):

```sh
cargo install cratefield-cli --features import-supabase
```

Then, with the connection string of the role above (Project Settings →
Database → Connection string, *session* mode or direct):

```sh
export SUPABASE_DB_URL='postgresql://cratefield_inspect:<password>@db.<ref>.supabase.co:5432/postgres'
export SUPABASE_ACCESS_TOKEN='sbp_…'   # optional: Edge Functions and auth config
cratefield-cli import supabase inspect --project <ref> --out report.md
cratefield-cli import supabase inspect --project <ref> --json --out report.json
```

- `--db-url` and `--management-token` work too, but put the secret in your
  shell history and the process list; `fz` says so on stderr.
- `fz` never prompts (ADR 0026, Decision 6): with no URL it refuses and
  names `SUPABASE_DB_URL`.
- `--md` (the default) or `--json`; without `--out` the report goes to
  stdout and nothing else does.
- `--transfer-mbps <n>` changes the throughput the transfer estimate
  assumes (default 100 Mbit/s).
- The exit code is non-zero only for a refused input, a connection error or
  a permission error (including a Management API token that is refused).
  **Blockers do not fail the command**: they are part of the report.

## Reading the report

The Markdown report opens with a summary — ready or not, counts per
classification, sizes and the transfer estimate — then lists the findings:

- **Blockers** stop a later step until resolved: an extension with no
  harness form (`dblink`, `postgres_fdw`, `plv8`, `timescaledb`, …), a
  foreign key from your tables into a Supabase table no phase recreates
  (`storage.objects`, `auth.identities`), or a schema named `app` beside
  `public` (which is imported as `app`).
- **Needs work** is moved or reported, but the venture writes or decides
  something: every RLS policy, functions that use `auth.*` or are
  `SECURITY DEFINER`, triggers on `auth.users` (the sign-up hook),
  views over `auth`, foreign keys into `auth.users` (dropped, values kept
  and checked), OAuth providers to configure, Edge Functions (→ Worker
  routes in a module), Realtime publications (→ the `Realtime` port),
  cron jobs (→ scheduled handlers), Supabase platform extensions, grants
  to `anon`/`authenticated`, objects over the Blob port's 10 MiB cap.
- **Automatic** moves with nothing to decide: tables, columns,
  constraints, indexes, sequences, enums, supported extensions, plain
  functions, triggers and views, auth users with their passwords, storage
  buckets into R2.

Every needs-work item needs a disposition before cutover — *covered* (with
the code or test that covers it) or *waived* (with a reason) — and RLS
policies one by one, never in bulk (ADR 0026, Decision 5). The
[Dispositions](#dispositions) section below covers the file, `inspect
--dispositions` and `dispositions init`.

[`supabase-report.md`](supabase-report.md) documents the JSON, field by
field; [`supabase-report.sample.md`](supabase-report.sample.md) is the
report of the test fixture.

### RLS policies: a pattern, a suggested check, a test stub

The harness has no row-level security (ADR 0008), and ADR 0026 rejects
translating policies automatically. So inspect does not translate them: it
labels each one so the person writing the replacement check starts in the
right place.

- **Rules first.** Common Supabase shapes are recognised from the policy's
  roles and SQL: owner-only (`auth.uid() = user_id`), tenant-scoped through
  a membership lookup, public read (`true`), public write, role- or
  claim-based (`auth.role()`, `auth.jwt()`), and service-role only. Then the
  shapes those miss: ownership through a parent row, tenancy through a parent
  row and a membership table, a filtered public read (a column predicate, no
  `auth.*`), deny-all (`false`), and an OR of recognised shapes as
  `composite`, listing each part. A rule match has confidence 1.0.
- **A classifier for the rest, if you want one.** With `--classify`, each
  policy no rule placed is asked one typed question — which access pattern
  is this? — through the harness's `Classifier` port: TypeSafe's calibrated
  judge, Jev, via `cratefield-adapter-typesafe` (it reads
  `TYPESAFE_API_KEY`). The top label is taken when its confidence reaches
  `--classify-threshold` (default 0.8); below it the policy stays
  `needs_review` and the report keeps the label it was given. The
  threshold is the adapter's number, so another adapter
  (`cratefield-adapter-classifier-llm`, through the library) needs its own.
  The classifier is sent the policy's SQL and the names of its table and
  columns — never a row.
- **Without `--classify`** every policy no rule placed is `needs_review`,
  so the report is deterministic.

Each policy in the JSON carries `pattern`, `confidence`, `source` (`rule`
or `classifier`), a `suggested_equivalent` (advice, not code), a failing
`test_stub` to turn into the test that proves the replacement, and a
`disposition` — `undecided` until a dispositions file covers or waives it.

## Dispositions

Inspect reports; it does not decide. Every item classified **needs work** or
**blocker** needs its own disposition before cutover (ADR 0026, Decision 5):
*covered*, with a reference to the code or test that replaces it, or
*waived*, with a reason. RLS policies are decided one by one, never in bulk.

The decisions live in a TOML file, `import/supabase-dispositions.toml` by
default, keyed by the finding `id` from the report verbatim:

```toml
[items."policy:public.posts.Anyone can read posts"]
status = "waived"
reason = "public feed by design"

[items."function:public.handle_new_user()"]
status = "covered"
ref = "src/auth/hooks.rs#on_signup"
```

- `status = "covered"` requires a `ref`; `status = "waived"` requires a
  `reason`. `status = "undecided"` is the placeholder `init` writes.
- The key is the finding `id` — spaces, dots and all. The file is refused,
  naming the entry, for a glob wildcard key (`*`), a key with no `kind:`
  prefix, a waived entry with no reason, or a covered entry with no `ref`.
  A `?` is a literal, not a wildcard: it can name a real policy.

Write a starting point, one `undecided` block per item that needs a
decision, each with the finding's kind and reason above it:

```sh
cratefield-cli import supabase dispositions init --project <ref>
# → import/supabase-dispositions.toml
```

`init` refuses to overwrite an existing file without `--force`, and
`--dispositions <FILE>` leaves out the items that file already decides.

Apply it:

```sh
cratefield-cli import supabase inspect --project <ref> \
  --dispositions import/supabase-dispositions.toml --json --out report.json
```

The report then carries each decision in `dispositions.decided`, the counts
per kind in `dispositions.by_kind`, and any entry that matched no item in
`dispositions.stale` — a renamed or removed item, delete it. `summary.decided`
and `summary.undecided` count the items; **cutover refuses while
`summary.undecided` is non-zero** (#661). A refused file is a non-zero exit
naming the offending entry, and no report is written.

### From a per-policy baseline

A list of accepted permissive policies — EarthOS keeps one in
`scripts/rls-baseline.json`, an array of `{ "table", "policy", "reason" }` —
becomes one `waived` entry per policy, no importer needed. Write that file
first (a `table` already containing a `.` is taken as schema-qualified,
otherwise schema `public` is assumed):

```sh
node -e '
for (const {table, policy, reason} of require("./scripts/rls-baseline.json")) {
  const key = table.includes(".") ? table : `public.${table}`;
  console.log(`[items.${JSON.stringify(`policy:${key}.${policy}`)}]\nstatus = "waived"\nreason = ${JSON.stringify(reason)}\n`);
}' > import/supabase-rls-baseline.toml
```

`JSON.stringify` escapes the policy name and the reason as TOML basic strings
(spaces, dots and quotes included), so a name like `Users update "own"
profile` lands in a valid key.

Then have `init` write the skeleton into a second file, leaving out the items
the baseline already decides (`--dispositions` omits them), and merge the two
— their keys are disjoint, so concatenating is enough:

```sh
cratefield-cli import supabase dispositions init --project <ref> \
  --dispositions import/supabase-rls-baseline.toml \
  --out import/supabase-dispositions.toml
cat import/supabase-rls-baseline.toml >> import/supabase-dispositions.toml
```

## Plan, dry run and apply

Inspect is step 1; the plan (issue #728, ADR 0026 Decision 3) is what ties a
run to the inspection it was written from and to the Postgres it is going
into. It is a document, not an action — nothing here writes to the target.

```sh
cratefield-cli import supabase --project <ref> --dir ./import
```

The bare `fz import supabase` (and its explicit `fz import supabase plan`)
inspects the source read-only, reads the target read-only, and writes three
files to `--dir` (default `.`):

- `report.json` and `report.md` — the inspection (as `inspect --out`).
- `plan.json` — the plan: `plan_version` (readers refuse one they do not
  know), `tool`, `project` (by ref), `inspection_hash` (`sha256:<hex>` over
  the report; a column add, drop or retype changes it, re-inspecting an
  unchanged source does not), `schema_mapping` (`public` -> `app`),
  `phases` in order (`auth_users`, `schema`, `data`, `storage`, `verify`),
  `target` (`null` when it was not checked), `extensions` (each source
  extension with its version and schema, what the target makes available,
  installed and default versions, schema), and `blockers`.

Flags: `--project` (the run's only required one), `--db-url`,
`--management-token` (prefer `SUPABASE_DB_URL` / `SUPABASE_ACCESS_TOKEN`),
`--target-env <VAR>` (the variable the target Postgres URL is read from;
default `DATABASE_URL`, the harness's own app-database variable), `--dir`,
`--transfer-mbps`, and the `--classify` / `--classify-threshold` pair.

**Blockers are in the plan, and the exit code is zero.** The codes are:

- `target_not_checked` — `--target-env`'s variable is unset, so the plan
  says what it could not check and how to supply it.
- `extension_missing` — the source has an extension the target cannot
  provide; names it and the source version.
- `extension_older` — the target's best version is older than the source's;
  names both.
- `extension_in_public` — the source installed an extension in `public`,
  which the target move makes `app`: the search path, the extension schema
  and the `public.<type>` remap.

Only the source's own extensions are checked; the platform's (and
`plpgsql`) are not.

### Applying a plan

```sh
cratefield-cli import supabase --project <ref> --apply --plan ./import/plan.json
```

Apply re-inspects the source and refuses, non-zero, unless the plan still
matches: an unknown `plan_version`, a different project, a hash that no
longer matches ("the source changed since the plan was written …
re-plan"), or a blocker the plan still carries. When it matches it prints
the hash and writes nothing to the target — the auth-users and data phases
land with #659/#660.

## What comes next

Inspect is step 1. The later steps read its JSON report:

2. **Auth users** (#659, after #650): users with their bcrypt hashes
   (verified and upgraded on next sign-in), verified flags and metadata,
   identities mapped to configured providers, and the id mapping the data
   step uses to rewrite `auth.users` foreign keys.
3. **Schema and data** (#660): the schema into `app`, rows copied with COPY
   in resumable chunks, then foreign keys validated, sequences set, and
   per-table counts and checksums compared with the source.
4. **Storage** (#661): buckets and objects into R2 under the same keys.
5. **Cutover and rollback** (#661): the switch, a rollback window and a
   decommission checklist, and the dashboard's "Migrate from Supabase"
   button over the same engine.
