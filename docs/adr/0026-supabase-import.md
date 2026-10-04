# ADR 0026: Importing a Supabase project: `fz import supabase` and a dashboard button

Status: proposed, 2026-10-03. Issue #657. Builds on ADR 0008 (the native
runtime is one database per tenant) and on the guarantees `fz data`
already gives an export and an import (`docs/DATA-MOVE.md`). Depends on
#650 (bcrypt verify-and-upgrade and kept external ids) for the auth
phase, and links #653 (external subject-data providers) so module-privacy
can see imported user-linked tables. Supersedes nothing.

## Context

Ventures built on Supabase want to move onto the harness, and moving one
is currently a bespoke project. EarthOS is doing it by hand right now:
roughly 100 tables, PostGIS, 390 row-level-security policies and Supabase
Auth. Its epic is World-360/EarthOS.world#174. What one venture learns in
that exercise — which Supabase objects have a harness answer and which do
not, how to move the data without losing the guarantees an import already
has, how to keep a cutover reversible — is the same for the next one, so
the reusable part belongs here rather than in a venture.

Four things the harness does, and Supabase's model does not, are what
make this a decision rather than a script.

- **The harness rejects RLS and search_path switching** (ADR 0008). One
  database per tenant, isolation is the database boundary, and there is
  no `search_path` switching and no row-level security — the same line
  `docs/PORTABILITY.md` and `docs/TENANT-ROUTING.md` restate. A Supabase
  project's 390 policies have no harness equivalent; access has to be
  re-expressed in module and route code.
- **Passwords are argon2id, not bcrypt.** auth-core hashes with argon2id
  (`crates/auth-core/src/secrets.rs`); Supabase stores bcrypt. A moved
  user's hash cannot be carried across unchanged.
- **There is no feature-flag system.** A cutover is the switch
  `docs/DATA-MOVE.md` already describes — the runtime and database
  binding, and DNS — not a flag that can be ramped.
- **The `fz` CLI never prompts.** Workflow commands refuse rather than
  block (`crates/cli/src/workflow.rs`), and the workspace has no TUI.

And one more, about the clients: Supabase clients talk to PostgREST, and
the harness does not emulate PostgREST. `supabase-js` on the client
cannot be kept by any server-side move.

## Decision

**1. One phase engine, two front ends.** A new native-only library crate
— `cratefield-import-supabase`, which does not exist yet — owns the
phases. `fz import supabase` and the dashboard's "Migrate from Supabase"
button both drive it, and both produce the same plan and the same report.
One engine means the button cannot drift from the command. The target is
Postgres (`crates/adapter-postgres`) only: a venture on D1 moves to
Postgres first (`docs/DATA-MOVE.md`), because PostGIS and the rest of the
Supabase extension set have no D1 form.

**2. Inputs and secret handling.** Three inputs: the Supabase project
ref, a database URL for a read-only role, and the service-role key, plus
an optional Management API access token. The token is needed only to list
Edge Functions; without it the report says "not inspected" rather than
"none". The CLI reads the three from environment bindings, or from hidden
input in guided mode. The dashboard writes them through the secrets
screen as tenant-tier secrets bound to the run
(`crates/control-plane-dashboard/src/secrets_screen.rs`,
`docs/SECRETS-DESIGN.md`).

A run spans the dry run through cutover, or until it is abandoned. The
dashboard takes the inputs once and keeps them sealed as tenant-tier
secrets for the life of the run, deleting them at cutover or abandonment
— or at decommission, if the user opts in to keeping them so verify can
be re-run during the rollback window. The CLI never stores them at all:
they live only in process memory, read from the user's own environment on
each invocation, so a dry run and a later `--apply` read them again from
that environment. `fz` writes them nowhere.

They are held as `SecretBytes`, never written to the run ledger, the plan
or the report, and never logged. The database URL appears only as its
host and database name, with credentials stripped: `scrub_text` already
strips URL credentials (`crates/core/src/logging.rs`), and the importer
must never put a value in a field whose name escapes the redaction list.
The report never contains a password hash or an email: a per-user problem
is referenced by the Supabase user id alone, so the report can be shared.

**3. Phases — each resumable and idempotent.** The phases are: inspect →
plan/report → auth users → schema → data → storage → verify → cut over →
rollback window → decommission checklist. A run ledger records each step
with a content hash. Re-running skips a step whose recorded hash still
matches and resumes at the first incomplete step.

- **inspect** reads the catalogue only. The source session is put in
  read-only mode (its default_transaction_read_only setting is on) and
  every data read happens inside one REPEATABLE READ READ ONLY
  transaction with an exported snapshot, so every table is read from the
  same point in time. Inspect also checks that the target Postgres has
  every extension the source uses, and fails the plan if one is missing.
- **plan/report** writes the plan file and the report. The plan carries a
  hash of the inspection. Applying needs an approved plan whose hash
  still matches a fresh inspection; on drift the user must re-plan.
- **auth users.** Supabase auth.users rows become harness users through
  #650's import path, which owns external-id and metadata storage; this
  importer adds no auth tables. It moves the email, the verified flag
  (from the email-confirmed timestamp), the bcrypt hash and created_at.
  User metadata and app metadata travel as opaque JSON, never interpreted
  (so no Supabase column such as raw_user_meta_data is read by name). The
  Supabase user id is kept as the external id. A user without a password
  gets no credential and can sign in by magic link or OIDC.
  auth.identities rows map to auth-oidc identities where that provider is
  configured; otherwise they are reported. Sessions and refresh tokens
  are not imported: everyone signs in again (passwords still work), and
  Supabase-issued JWTs stop working at cutover. Phone auth, MFA factors
  and SAML/SSO are reported.
- **schema.** The Supabase `public` schema becomes a Postgres schema
  named `app` in the venture's database, never `public`, so names cannot
  collide with module tables (a Supabase public users table beside
  auth-core's `users`). Other user schemas keep their names, and the plan
  fails, asking for a mapping, if one collides with a reserved name.
  Supabase-managed schemas (auth, storage, realtime, extensions, graphql,
  vault, cron, net, pgsodium, supabase_functions …) are never copied as
  schemas; auth and storage have their own phases. Code reaches imported
  tables with schema-qualified names, so ADR 0008's no-search_path-
  switching rule holds. `app` is owned by the venture, not by any module:
  `harness_migrations` does not track it
  (`crates/adapter-postgres/src/migrate.rs`) and `fz migrations` leaves it
  alone. Foreign keys are created NOT VALID during load and validated in
  verify. A foreign key that points into auth.* is dropped and reported;
  its values are kept and checked in verify.

  Functions, triggers and views are part of this phase: they are copied
  verbatim when they do not reference auth.* or storage.*. Verbatim means
  the body is not rewritten. The importer pins each function's own
  search_path to `app` plus the extensions schema — a per-function
  attribute, not session switching. A body that names `public.`
  explicitly is reported, not rewritten.
- **data** is streamed with COPY, not through the DATA-MOVE JSONL file.
  It keeps DATA-MOVE's guarantees — a checksum per table, one transaction
  per table, and a refusal to write a non-empty target table unless the
  ledger says it is resuming that table — and adds what a direct
  database-to-database move needs and DATA-MOVE's file cannot give:
  primary-key range chunks for a very large table, each chunk recorded,
  so the unit of resumability is the chunk; resume driven by the run
  ledger rather than by `--append`; and a checksum computed over a
  canonical text rendering ordered by primary key, so source and target
  compare equal in verify. A table without a primary key is checksummed
  over its sorted rows and reported.
- **storage.** Object bodies are not in the database, so objects are read
  through the Storage API with a GET/list call and the service-role key.
  They are copied to R2 through its S3-compatible API, not through the
  Blob port, under the same `<bucket>/<object name>` key. Verify compares
  counts plus size and checksum. The report names each bucket's public
  flag and its storage policies. An object over the Blob port's 10 MiB
  cap is reported: it is copied and remains readable, but module code
  cannot write or replace it through the Blob port, whose cap is checked
  on put (`crates/core/src/ports/blob.rs`,
  `crates/runtime-cloudflare/src/ports/blob.rs`).
- **verify** compares the target against the frozen source — row counts
  and per-table checksums, sequence values, the auth user count and
  credential presence, and storage counts and checksums — and acts on the
  target: VALIDATE CONSTRAINT for every foreign key, and setval to at
  least the source's last_value. It also checks that every value in a
  dropped auth-reference column resolves to an imported user. It runs
  against the frozen source before cutover.
- **cut over.** No flag system exists, so cutover is the switch DATA-MOVE
  already describes, made on the venture's environment: the runtime and
  database binding, plus DNS and the base URL. Before it the user freezes
  writes on Supabase (maintenance mode). The importer then re-copies
  every table whose checksum changed since the data phase, re-runs verify,
  and only then records the cutover. It refuses while verify fails or
  while any reported item lacks a disposition (Decision 5). The importer
  never rewrites the venture's client code.
- **rollback window.** Default 14 days, configurable. The Supabase
  project is left untouched — the source is only ever read — so the
  frozen source is the rollback snapshot. The harness side gets a backup
  at cutover (the dashboard's backups screen). Rolling back means
  switching back, plus a generated report of the writes made on the
  harness since cutover: tables, row-count deltas, and users whose
  password or credentials changed, since those cannot go back to bcrypt.
  The user reconciles them. Automatic reverse sync is not in v1.
- **decommission checklist.** Generated, never executed by the importer.
  Revoke the read-only role. Rotate the service-role key. Delete any kept
  secrets. Take a final Supabase backup for retention. Remove supabase-js
  from the clients. Clean up DNS. Pause or delete the Supabase project.

**4. Dry run by default; the source is only read.** `fz import supabase`
with no flags runs inspect + plan and writes the report. Nothing touches
the target until an approved plan is applied (`--apply --plan <file>`),
and the dashboard's equivalent is an "Approve plan" step. The source is
only read: a read-only database role, GET-only Storage calls, and nothing
created on the source — no publications, no roles.

**5. What is automatic and what is reported.** Automatic:

- tables, columns, constraints, indexes, sequences, enums and extensions
  (PostGIS, citext, uuid-ossp, pgcrypto …) into `app`;
- functions, triggers and views verbatim, where they do not reference
  auth.* or storage.*;
- auth users;
- OAuth identities, where an auth-oidc provider is configured
  (`crates/auth-oidc/`);
- storage buckets and objects into R2, under the same keys.

Reported, never guessed:

- RLS policies — each listed with its table, command, roles and
  USING/WITH CHECK expression, plus a suggested code-level check and a
  generated failing test stub per policy;
- auth.uid() and auth.jwt() usage, per object;
- SECURITY DEFINER functions;
- GRANTs to anon, authenticated and service_role;
- Edge Functions;
- Realtime publications and channels; pg_cron jobs; webhooks and pg_net;
- Supabase-only extensions (pg_graphql, pg_net, pgsodium, vault …),
  skipped;
- foreign keys into auth.*;
- tables holding user-linked data that module-privacy cannot see until
  declared — module-privacy only sees data declared through
  `Module::personal_data` (`crates/module-privacy/`), so #653's external
  providers have to land before those tables are covered;
- PostgREST and supabase-js usage, which the database cannot show, so it
  goes on the checklist.

Test stubs are written into the run directory, never into the venture's
source tree. Each stub fails (todo-style) and names the policy and its
expression. Every reported item needs a disposition before cutover:
"covered", with a reference to the code or test that covers it, or
"waived" with a reason — recorded in the final report. An RLS policy
cannot be waived in bulk: each policy is its own line, needing its own
reference or its own reason. The point: once RLS is gone, the only thing
protecting the imported data is that nothing exposes the tables directly
(the harness has no PostgREST), and the dispositions are the record that
code now does the guarding.

**6. UX.** The CLI stays non-interactive by default, consistent with the
never-prompts rule. `fz import supabase --guided` is a TUI over the same
engine that produces the same plan file; the library choice is left to
the implementing issue, as a new dependency. The dashboard button is a
POST route that starts a run, which the control plane's step-wise job
pattern advances — like provisioning's `provision_progress`
(`crates/control-plane-dashboard/`, `docs/DASHBOARD.md`). A progress view
shows per-phase and per-table progress. The final report is JSON (the
source of truth) and Markdown rendered from it; both can be downloaded
from the dashboard and are written to the run directory by the CLI.

## Alternatives considered

- **pg_dump and pg_restore of the whole database.** It pulls the Supabase
  internal schemas, roles and RLS, needs a matching pg_dump binary
  (absent in the control plane), and gives no reviewable per-object plan
  or per-table verification. A user may still keep a pg_dump as their own
  extra snapshot.
- **Logical replication or CDC for a zero-downtime cutover.** It needs a
  publication and replication privileges on the source, which breaks
  "source only read". Deferred to after v1.
- **Translating RLS policies into code automatically.** That is guessing.
  Rejected.
- **Keeping Supabase Auth through JWT federation.** That is two auth
  systems. Rejected.
- **Importing into `public` beside the module tables.** Name collisions
  with module tables, and ownership gets blurred. Rejected.
- **Emulating PostgREST so supabase-js keeps working.** Out of scope.
- **Reusing the `fz data` JSONL file as-is.** An intermediate file of
  roughly 100 tables with geometry, built for the D1 shapes. We reuse its
  guarantees, not its file.

## Consequences

- Supabase ventures land on the Postgres runtime only.
- ADR 0008 still holds, with one extra schema per imported venture that
  harness migrations do not manage.
- Until every RLS disposition is covered, the imported data's safety rests
  on the harness exposing no direct table access.
- The CLI gains its first interactive mode, behind a flag.
- Two new dependencies come with the engine crate: a TUI library and an
  S3/Storage HTTP client.
- Users re-authenticate at cutover.
- Rollback has a known gap: harness-side writes need manual
  reconciliation.
- #650 must land first for the auth phase.

## Implementing issues

#657's plan ids map s2 = #658, s3 = #660, s4 = #659 and s5 = #661. The
scopes, in order:

1. #658 (s2) — the engine crate, the run ledger, inspect + plan/report
   (dry run) and non-interactive `fz import supabase`, including every
   "reported" item and the test stubs. This alone is useful to EarthOS.
2. #660 (s3) — schema + data + verify into `app`.
3. #659 (s4) — auth users and identities (after #650).
4. #661 (s5) — storage → R2, cutover, the rollback window, the
   decommission checklist, `--guided` TUI, the dashboard button and the
   progress view.

## References

- Issue #657 (this ADR); #650 (auth import), #653 (external subject-data
  providers); World-360/EarthOS.world#174 (the by-hand migration this
  generalises).
- ADR 0008 (native runtime is multi-tenant, database-per-tenant);
  `docs/DATA-MOVE.md`, `docs/PORTABILITY.md`, `docs/TENANT-ROUTING.md`,
  `docs/SECRETS-DESIGN.md`, `docs/DASHBOARD.md`.
- `crates/cli/src/data.rs`, `crates/cli/src/lib.rs`,
  `crates/cli/src/workflow.rs`, `crates/cli-acceptance/tests/data.rs`;
  `crates/adapter-postgres/src/migrate.rs`; `crates/core/src/logging.rs`;
  `crates/secrets/`; `crates/auth-core/src/secrets.rs`,
  `crates/auth-core/migrations/sqlite/0001_init.sql`; `crates/auth-oidc/`,
  `crates/auth-magic-link/`; `crates/core/src/ports/blob.rs`,
  `crates/runtime-cloudflare/src/ports/blob.rs`;
  `crates/module-privacy/`; `crates/control-plane-dashboard/`.
