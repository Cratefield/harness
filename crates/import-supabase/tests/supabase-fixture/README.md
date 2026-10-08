# EarthOS-shaped Supabase fixture

A live `supabase start` stack loaded with the **shape** of a real EarthOS Supabase
project — not its data. CI applies it, then runs `fz import supabase inspect --json`
twice: as the read-only role `docs/import/supabase.md` tells a user to create
(`pg_read_all_data` + `BYPASSRLS`) and as `postgres`, and asserts the two reports are
identical apart from `read_only` and `warnings`. That is
`.github/workflows/supabase-import-e2e.yml` (issue #733), driven by
`the_earthos_shaped_fixture_is_visible_to_the_documented_role` in
`crates/import-supabase/tests/inspect.rs`.

## Apply

```sh
supabase start
psql "postgresql://postgres:postgres@127.0.0.1:54322/postgres" -v ON_ERROR_STOP=1 -f schema.sql
SUPABASE_URL=http://127.0.0.1:54321 \
  DB_URL="postgresql://postgres:postgres@127.0.0.1:54322/postgres" \
  SERVICE_ROLE_KEY=... ./seed.sh
```

`schema.sql` runs FIRST, as `postgres`, on the `supabase db` port 54322 against
db `postgres`; it is idempotent (`drop ... if exists` first). `seed.sh` runs after
it as the same role. Neither is a migration — re-running over existing seed rows
is unsupported.

## Files

- `schema.sql` — ~310 lines of idempotent DDL: PostGIS wherever the stack keeps
  it (see below), two enums,
  the `public.users` shadow table (ids ARE `auth.users.id`, no FK back), the
  organization/member/project tenant shape, indexes, functions, the
  `touch_projects` trigger, six RLS policies (`projects_owner`,
  `projects_owner_via_parent`, `projects_tenant_via_parent`,
  `projects_public_read`, `projects_internal_deny_all`,
  `organizations_members_self`), RLS-on-no-policy `audit_events`, a
  `storage.objects` owner policy, the realtime publication, the pg_cron job, the
  grants. There is deliberately no read-only role here: the role
  `docs/import/supabase.md` tells a user to create is created by the job from
  that document verbatim, so a second hand-rolled one could only drift from it.
- `seed.sh` — Bash, `set -euo pipefail`. Five auth users via the GoTrue admin API,
  one per auth shape (confirmed with a password, unconfirmed, passwordless,
  phone-only, one with a google identity), mirrored into `public.users` by the
  `auth.users` trigger; organizations / members / projects / places /
  `projects_internal` / `audit_events`; one public and one private storage
  bucket, the private one with a `file_size_limit` and an `allowed_mime_types`
  list, each with an object; the five user ids written one per line to
  `$EARTHOS_USER_IDS_FILE` (default `/tmp/earthos-user-ids`). Nothing reads that
  file yet — the later phases of this job (#659 auth import, #660 data load,
  #661 storage copy) join the rows they create against the ids in it.

## Where PostGIS lives

Both files work whether PostGIS is installed in the `extensions` schema (what a
stock `supabase start` pre-installs, and which is *not* on the default
`search_path` of `"$user", public`) or in `public` (what a plain Postgres gets,
and what issue #733 says EarthOS's own layout is). They do it the same way: make
sure the extension exists, look up the schema it actually landed in through
`pg_extension.extnamespace`, and put that schema on the session search_path
before the first unqualified `geography` / `geometry` / `ST_MakePoint` use.
`schema.sql` section 2 and `seed.sh`'s row-insert block each open with that
lookup.

Note that `create extension if not exists postgis schema public` does **not**
pin PostGIS to `public`: where the extension is already installed — which is the
case on the stack this fixture targets — `if not exists` makes the whole
statement, `SCHEMA` clause included, a no-op, and the first unqualified type use
then fails with `type "geography" does not exist`.

## Needs the stack vs plain Postgres

`schema.sql` needs a stock stack: the RLS policies and `public.current_tenant_id()`
call `auth.uid()`, so the `auth` schema must exist. Four sections are guarded by
`do $$ … exception … end $$;` blocks and are no-ops when their object is absent —
the `handle_new_user` trigger on `auth.users` (§8), adding `public.projects` to the
`supabase_realtime` publication (§10), the pg_cron `earthos-heartbeat` job (§11),
and the `storage.objects` owner policy (§12, which `postgres` may not have the
right to create).

`seed.sh` needs GoTrue and Storage at `$SUPABASE_URL`, plus the `auth`, `storage`
and `public` schemas and a `psql` for its row inserts. It never prints
`$SERVICE_ROLE_KEY`, has no `set -x`, and parses every API response
instead of echoing it; the workflow registers the key with `::add-mask::` before
calling it. The google identity is the one row it writes as SQL — no admin
endpoint mints one — as `supabase_admin`, falling back to the plain connection.
`pg_cron` keeps its own policies on `cron.job` (SELECT only, for `postgres`) —
deliberate: the fixture exposes a policy on a managed schema too.