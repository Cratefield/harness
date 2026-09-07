# Portability — the phase-3 move off Cloudflare

Status: **designed, not built.** Everything in this document is the
plan recorded in [ARCHITECTURE.md](ARCHITECTURE.md) section 10 and
[ADR 0008](adr/0008-native-runtime-is-multi-tenant-database-per-tenant.md),
specified in issues #18–#21 (native runtime, Postgres adapter, parity
suite, data move) and #23–#44 (multi-tenant specifics). None of the
phase-3 crates exist yet. When they land, this document becomes the
venture runbook; until then it is the contract the current code must not
break.

## Why the move is supposed to be cheap

Three decisions made on day one exist so that this page stays short:

1. **Modules only see ports** (ADR
   [0002](adr/0002-ports-and-adapters.md)). A module has never touched a
   Cloudflare binding, so there is nothing to un-teach it. Swapping the
   runtime swaps the adapters behind the same traits.
2. **Compile-time composition** (ADR
   [0003](adr/0003-compile-time-composition.md)). A venture backend is
   one `Cargo.toml` + one `src/harness.rs`; changing the `.runtime(..)`
   line and the adapter dependencies is the whole edit.
3. **Portable SQL** (ADR
   [0004](adr/0004-sea-query-and-portable-sql-migrations.md)).
   Migrations are written in the subset both SQLite and Postgres accept;
   queries are sea-query trees that render per dialect. `fz doctor`
   already lints the subset today.

What exists today toward this: the `cratefield-adapter-sqlite` `Database`
(native rusqlite), sea-query's dual-builder rendering behind
`Statement::render`, the portable-SQL lint, and the conformance suite
that applies every module's migrations to a fresh SQLite database twice.
What does not exist yet: `cratefield-adapter-postgres` (sqlx),
`cratefield-runtime-native` (axum on tokio), `fz data export` /
`fz data import`, a Redis `RateLimiter`, and the control database.

## The move, in order

Architecture section 10, expanded. Per venture:

1. **Stand up Postgres** for the venture and run the same module
   migrations — the postgres set. Modules that needed dialect-specific
   SQL ship `migrations/postgres/NNNN_<name>.sql` overrides; everything
   else reuses the sqlite-authored file content through the Postgres
   migrator in `cratefield-adapter-postgres`. Migration history is
   per-tenant (see below).

2. **Copy the data**: `fz data export` reads the venture's D1 and
   `fz data import` writes the Postgres database. ULID ids and ISO-8601
   timestamps are engine-neutral by design, so rows move verbatim.

3. **Switch the runtime** in `src/harness.rs` — the one-line diff the
   architecture promises:

   ```rust
   // before
   .runtime(Cloudflare::new().db("DB").mailer(Resend::from_env()).captcha(Turnstile::from_env()))
   // after
   .runtime(Native::new().db(Postgres::from_env()).rate_limiter(Redis::from_env()))
   ```

   `Resend` and `Turnstile` stay: they are adapters over the
   runtime-neutral `HttpClient` port, so the mailer and captcha move
   with you unchanged. Build a native binary; ship the Dockerfile from
   the venture template.

4. **Point `api.<domain>` at the new host.** DNS is the cutover. The
   Worker and the D1 database still exist and still answer, so a bad
   cutover is a DNS revert, not a restore.

No module code changes. That claim is what the parity suite protects:
from phase 3 on, `cratefield-testing` runs every module's tests against
SQLite **and** Postgres in CI, so "works on D1" and "works on Postgres"
cannot drift apart between releases.

## The native runtime is multi-tenant — one database per tenant

ADR 0008, because it changes what a venture's ops team inherits on the
self-hosted path:

- **One database per tenant.** Never one schema per tenant, never shared
  tables. Migration history, the tenant's secrets and its audit log live
  inside the tenant's own database, so a venture can be backed up,
  restored, moved or dropped as one unit. Isolation is the database
  boundary — no `search_path` switching, no row-level security. Factory
  Zero's own venture is an ordinary tenant.
- **A separate control database.** A small, low-traffic database that no
  venture role has credentials for holds the tenant registry and the
  global secrets store. Its connection string is the one value that
  comes from the environment; every tenant's connection string is a
  global secret resolved from it.
- **Two-tier secrets.** Global secrets (tenant connection strings,
  platform keys) live in the control database; tenant secrets
  (`HARNESS_SECRET`, `RESEND_API_KEY`, …) live in that tenant's
  database. Each store has its own data key wrapped by a KMS master key.
  Modules can only ever obtain a tenant store; the global store is
  unreachable from module code, enforced by both the API and by
  credentials.

The Cloudflare path is unchanged by all of this: one Worker, one D1, one
venture, as ADR 0003 says. If a native-runtime host grows past the
tenant count where one pool per tenant stops being fine (issue #32), the
answer is one process per tenant — the Worker shape — so the two paths
converge instead of forking.

## What a venture should do today to keep the move free

Nothing extra — the guardrails are already the rules:

- keep module queries on sea-query and migrations in the portable subset
  (`fz doctor` fails anything else);
- keep ventures on published, pinned `cratefield-*` versions so the
  phase-3 crates arrive as ordinary dependency bumps;
- treat `HARNESS_API` / core major bumps as the compatibility contract
  (see [COMPATIBILITY.md](COMPATIBILITY.md)) — a module that compiles
  against the contract today must compile against the native runtime
  when it ships.
