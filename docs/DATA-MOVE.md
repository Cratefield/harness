# Moving a venture's data: D1 → Postgres

The rehearsal runbook for `fz data export` / `fz data import` (issue
#21), the data step of the self-hosting path in
[ARCHITECTURE.md](ARCHITECTURE.md) section 10. Every command runs from
the venture repo.

## What moves

The venture's module tables — the tables the harness's modules declare,
in lock order (`fz migrations collect` order). The `harness_migrations`
bookkeeping table is infrastructure and never travels: the target's own
`fz migrations apply` record is the truth there.

## 1. Stand up the target

A Postgres 16 database per venture (ADR 0008). For a rehearsal:

```sh
docker run -d --name <venture>-pg -e POSTGRES_PASSWORD=… -p 5432:5432 postgres:16
```

Apply the venture's migrations to it:

```sh
cargo run --bin fz -- migrations apply --dialect postgres \
  --url postgres://user:pass@host:5432/<venture>
```

## 2. Pull the D1 data into a local SQLite file

`fz data export` reads SQLite. D1 is SQLite; the Cloudflare-side step is
`wrangler d1 export`, which produces SQL, loaded into a scratch database
(yes, this step needs `sqlite3` installed — it is a rehearsal tool, not
a deployment dependency):

```sh
wrangler d1 export <database-name> --remote --env production --output dump.sql
sqlite3 venture-copy.db < dump.sql
```

This is the one leg that needs Cloudflare credentials and cannot be
covered by CI; everything after it is.

## 3. Export to the manifest + JSONL artifact

```sh
cargo run --bin fz -- data export --db venture-copy.db --out data.jsonl
```

The file's first line is the manifest — per-table row counts, the
column list and a sha256 over the table's record lines, tables in lock
order — followed by one `{"table","row"}` JSON record per row. Exporting
the same database twice is byte-identical. `--plan` prints the summary
without writing.

Keep the artifact: it is the audit record of exactly what moved.

## 4. Import into the rehearsal target

```sh
# dry run: prints tables, incoming rows, existing rows, refusal warnings
cargo run --bin fz -- data import --url postgres://user:pass@host:5432/<venture>-staging --plan data.jsonl

# the real thing
cargo run --bin fz -- data import --url postgres://user:pass@host:5432/<venture>-staging data.jsonl
```

Import verifies every table's sha256 against the manifest **before
writing** (a tampered file leaves the target untouched), refuses a
non-empty table without `--append`, inserts in one transaction per
table, and verifies row counts afterwards. Build the `fz` bin with
factory0-cli's `postgres` feature (`--features factory0-cli/postgres`).

## 5. Smoke test on Postgres

Run the venture's test suite with the Postgres parity leg against the
staging database (`FZ_TEST_POSTGRES_URL`, the module suites pick it up
automatically), then point a staging Worker or a local native runtime at
the database and click the venture's critical paths: join, confirm,
status, unsubscribe. The parity suite is the same code path the modules
run in production.

## 6. The cutover

1. Freeze writes (a maintenance notice on the forms, or a rate-limit
   rule returning `503`).
2. Repeat steps 2–4 against the **production** Postgres, from a fresh
   `wrangler d1 export` so nothing written after the rehearsal leaks in.
3. Switch `src/harness.rs` to the native runtime
   (`.runtime(Native::new().db(Postgres::from_env()))`), build, deploy.
4. Point `api.<domain>` at the new host, watch `/__health` and
   `/__ready`, unfreeze writes.

A cutover rehearsal is only done when a repeated round trip (fresh
export → fresh import into a second empty database → matching counts)
succeeds — the acceptance test in `crates/cli-acceptance/tests/data.rs`
is that round trip, minus the wrangler leg.
