<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/banners/cratefield-import-supabase.png" alt="cratefield-import-supabase — What a Supabase move takes." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-import-supabase"><img src="https://img.shields.io/crates/v/cratefield-import-supabase.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-import-supabase on crates.io"></a>
  <a href="https://docs.rs/cratefield-import-supabase"><img src="https://img.shields.io/docsrs/cratefield-import-supabase?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-import-supabase documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-import-supabase

The engine of the Supabase importer ([ADR 0026](https://github.com/Cratefield/harness/blob/main/docs/adr/0026-supabase-import.md)),
step one (issue #658): **inspect** a Supabase project read-only and produce
the migration report — every schema object, RLS policy, auth provider,
storage bucket, Edge Function and Realtime publication, each classified as
automatic, needs work or a blocker, with the data size and a rough transfer
time. `fz import supabase inspect` is its command-line front end; the
dashboard's "Migrate from Supabase" button will drive the same engine.

Native only: it reads Postgres through sqlx, and fails to compile on wasm
with a message saying so.

## Usage

```rust,no_run
use cratefield_import_supabase::{InspectOptions, Secret, inspect};

# async fn demo() -> Result<(), cratefield_import_supabase::InspectError> {
let url = Secret::new(std::env::var("SUPABASE_DB_URL").unwrap_or_default());
let report = inspect(&InspectOptions::new("abcdefghijklmnopqrst", url)).await?;
std::fs::write("report.json", report.to_json()).ok();
println!("{}", report.to_markdown());
# Ok(())
# }
```

`InspectOptions` also takes a `ManagementApi` (Edge Functions and the auth
configuration, over the `HttpClient` port) and an optional `Classifier`
(for RLS policies no rule places) with its threshold.

## Auth users (issue #659)

`read_users` and `record_mapping` are step two: moving the people. Inside
the same read-only snapshot `inspect` takes, `read_users` reads
`auth.users` and `auth.identities` and plans each account for the harness
admin import (`POST /v1/auth-core/admin/users/import`) — its address,
whether the source confirmed it, its bcrypt hash verbatim (upgraded to
argon2id on the first sign-in), and the OIDC links the harness can hold.
A phone-only or anonymous account is skipped, an OAuth provider the
harness has no slug for is reported unmapped, and each user's metadata
goes to the `import_supabase_users` mapping table `record_mapping` writes
in the target database, which the data step rewrites references through.
A role that cannot bypass row-level security on `auth.users` or
`auth.identities` is refused before a row is read, rather than silently
reading nothing.

## Guarantees

- **Read-only, checked.** One connection, its session default read-only,
  every read in one `REPEATABLE READ READ ONLY` transaction that is rolled
  back; before the rollback, Postgres must not have assigned a transaction
  id, or the inspection fails. The report records this evidence, and
  whether the role used could have written.
- **No secret in the output.** The database URL and the token are held
  cleared-on-drop and print as `[redacted]`; errors strip them; the report
  names the database by host, port and database only; SQL fragments pass
  through the harness's scrubber; only the auth configuration's
  `…_enabled` booleans are read. No password hash, email or row is read
  into the report.
- **RLS is advice, not translation.** Each policy gets a pattern (rules
  first, then optionally the classifier, above a threshold), a suggested
  check, a failing test stub and `disposition: undecided`.
- **A stable JSON.** `report_version` 2, sorted lists, no timestamp —
  documented in [`docs/import/supabase-report.md`](https://github.com/Cratefield/harness/blob/main/docs/import/supabase-report.md).

## Tests

`tests/inspect.rs` loads `tests/fixtures/supabase-project.sql` — a
Supabase-shaped project on plain Postgres 16 — into a throwaway database
on `FZ_TEST_POSTGRES_URL` (CI's service container) and snapshots the
report. The tests skip, saying why, when the variable is unset.
