-- EarthOS-shaped Supabase fixture: SHAPE, not data.
--
-- Apply to a live `supabase start` stack FIRST (before seed.sh), as the
-- `postgres` superuser on the `supabase db` port 54322. DB_URL is the stack's
-- own connection string: `supabase status -o env` prints it as DB_URL, or
-- `eval "$(supabase status -o env)"` puts it in the environment.
--
--   psql "$DB_URL" -v ON_ERROR_STOP=1 -f schema.sql
--
-- Idempotent: every object is dropped before it is created, so a re-run
-- after a failed CI job starts from the same place. Re-running on top of a
-- stack that already has seed rows is NOT supported -- seed.sh runs after.
--
-- Everything is in `public` unless the section header says otherwise -- with
-- one exception: the PostGIS types in section 5 land in whichever schema
-- PostGIS is installed in, `extensions` on a stock Supabase stack and `public`
-- on a plain Postgres (see section 2). This
-- targets a stock `supabase start` (PG 17, PostGIS, GoTrue, storage, cron,
-- realtime). The RLS policies and public.current_tenant_id() call auth.uid(),
-- so the auth schema must exist. The three guarded sections (§8 trigger,
-- §10 publication, §11 pg_cron) tolerate their object being absent.

-- 1. Drop what a previous run left behind ----------------------------------
-- Policies and triggers go with their tables via cascade; the ones hung off
-- `auth.users` are dropped in their own guarded section below.
drop table if exists public.audit_events cascade;
drop table if exists public.projects_internal cascade;
drop table if exists public.projects cascade;
drop table if exists public.places cascade;
drop table if exists public.organizations_members cascade;
drop table if exists public.organizations cascade;
drop table if exists public.users cascade;
-- cascade: the auth.users trigger (section 8) depends on handle_new_user and
-- lives on a table this file does not own, so it is dropped with its function.
drop function if exists public.handle_new_user() cascade;
drop function if exists public.touch_updated_at() cascade;
drop function if exists public.current_tenant_id() cascade;
drop type if exists public.member_role;
drop type if exists public.project_status;

-- 2. Extensions -------------------------------------------------------------
-- Where PostGIS lives differs by deployment, and the fixture has to work in
-- both:
--   * a stock `supabase start` pre-installs postgis in the `extensions`
--     schema, which is NOT on the default search_path ("$user", public);
--   * a plain Postgres -- and EarthOS's own layout, per issue #733 -- has it
--     in `public`.
-- So the extension is made to exist, the schema it actually landed in is
-- looked up, and that schema is put on the session search_path. Everything
-- below then names `geography`/`geometry` and the PostGIS functions
-- unqualified and resolves in either layout.
--
-- `create extension if not exists postgis schema public` is NOT how this is
-- done on purpose: where the extension already exists -- which is the case on
-- the very stack this fixture targets -- `if not exists` makes the whole
-- statement, SCHEMA clause included, a no-op. It reads as a pin and pins
-- nothing, and the first unqualified use below dies with
-- `type "geography" does not exist` under the workflow's ON_ERROR_STOP.
create extension if not exists postgis;

do $postgis$
declare
    ext_schema text;
begin
    select n.nspname into ext_schema
    from pg_extension e
    join pg_namespace n on n.oid = e.extnamespace
    where e.extname = 'postgis';

    if ext_schema is null then
        raise exception
            'the postgis extension is installed in no schema; section 5 cannot declare its geography and geometry columns';
    end if;

    -- pg_catalog is implicit and stays implicit; `public` stays on the path so
    -- the rest of this file keeps resolving anything it did not qualify.
    perform set_config('search_path', format('%I, public', ext_schema), false);
end;
$postgis$;

-- 3. Enums -----------------------------------------------------------------
create type public.project_status as enum ('draft', 'active', 'paused', 'archived');
create type public.member_role as enum ('viewer', 'editor', 'admin');

-- 4. Shadow users ----------------------------------------------------------
-- public.users.id IS auth.users.id. There is deliberately NO foreign key to
-- auth.users: GoTrue creates the auth row first and the AFTER INSERT trigger
-- below fills this one, so the FK would be circular. seed.sh creates the
-- users through the GoTrue admin API and lets that trigger do the filling —
-- which is the point: a row inserted here by hand would be a shadow the
-- importer never sees a real project create.
create table public.users (
    id uuid primary key,
    email text,
    display_name text,
    avatar_url text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

-- 5. Tenant / parent shape -------------------------------------------------
create table public.organizations (
    id uuid primary key default gen_random_uuid(),
    name text not null,
    owner_id uuid not null references public.users (id) on delete restrict,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table public.organizations_members (
    organization_id uuid not null references public.organizations (id) on delete cascade,
    user_id uuid not null references public.users (id) on delete cascade,
    role text not null default 'member',
    created_at timestamptz not null default now(),
    primary key (organization_id, user_id)
);

create table public.projects (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations (id) on delete cascade,
    name text not null,
    description text,
    status public.project_status not null default 'draft',
    visibility text not null default 'private',
    published_at timestamptz,
    location geography(Point, 4326),
    boundary geometry(Polygon, 4326),
    created_by uuid references public.users (id) on delete set null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table public.places (
    id uuid primary key default gen_random_uuid(),
    name text not null,
    location geography(Point, 4326) not null,
    area geometry(Polygon, 4326),
    created_at timestamptz not null default now()
);

-- Deny-all target: RLS on, one policy that refuses everything.
create table public.projects_internal (
    id uuid primary key default gen_random_uuid(),
    project_id uuid not null references public.projects (id) on delete cascade,
    reviewer_role public.member_role not null default 'viewer',
    note text,
    created_at timestamptz not null default now()
);

-- RLS on with no policy at all: the locked table shape.
create table public.audit_events (
    id bigint generated always as identity primary key,
    organization_id uuid references public.organizations (id) on delete cascade,
    actor_id uuid references public.users (id) on delete set null,
    action text not null,
    payload jsonb not null default '{}'::jsonb,
    at timestamptz not null default now()
);

-- 6. Indexes on the FK columns, plus spatial indexes -----------------------
create index organizations_owner_id_idx on public.organizations (owner_id);
create index organizations_members_user_id_idx on public.organizations_members (user_id);
create index projects_organization_id_idx on public.projects (organization_id);
create index projects_created_by_idx on public.projects (created_by);
create index projects_internal_project_id_idx on public.projects_internal (project_id);
create index audit_events_organization_id_idx on public.audit_events (organization_id);
create index audit_events_actor_id_idx on public.audit_events (actor_id);
create index projects_location_gix on public.projects using gist (location);
create index projects_boundary_gix on public.projects using gist (boundary);
create index places_location_gix on public.places using gist (location);
create index places_area_gix on public.places using gist (area);

-- 7. Functions -------------------------------------------------------------
-- SECURITY DEFINER with an empty search_path: every reference is qualified,
-- because nothing resolves implicitly.
create or replace function public.current_tenant_id() returns uuid
    language sql stable security definer set search_path = '' as $$
    select om.organization_id
    from public.organizations_members om
    where om.user_id = auth.uid()
    order by om.organization_id
    limit 1
$$;

create or replace function public.touch_updated_at() returns trigger
    language plpgsql set search_path = '' as $$
begin
    new.updated_at := now();
    return new;
end;
$$;

-- The classic Supabase sign-up hook: mirrors auth.users into public.users.
create or replace function public.handle_new_user() returns trigger
    language plpgsql security definer set search_path = '' as $$
begin
    insert into public.users (id, email, display_name)
    values (
        new.id,
        new.email,
        coalesce(new.raw_user_meta_data ->> 'name', new.email)
    )
    on conflict (id) do nothing;
    return new;
end;
$$;

-- 8. Triggers --------------------------------------------------------------
create trigger touch_projects
    before insert or update on public.projects
    for each row execute function public.touch_updated_at();

-- Needs the stack: auth.users only exists on Supabase. The DO block swallows
-- the undefined_table error so the file also applies to a plain Postgres.
do $fixture$
begin
    execute 'drop trigger if exists on_auth_user_created on auth.users';
    execute 'create trigger on_auth_user_created after insert on auth.users'
        || ' for each row execute function public.handle_new_user()';
exception
    when undefined_table or undefined_object or undefined_function
         or invalid_schema_name or insufficient_privilege then null;
end;
$fixture$;

-- 9. Row level security ---------------------------------------------------
alter table public.users enable row level security;
alter table public.organizations enable row level security;
alter table public.organizations_members enable row level security;
alter table public.projects enable row level security;
alter table public.places enable row level security;
alter table public.projects_internal enable row level security;
alter table public.audit_events enable row level security;  -- no policies below

-- owner
create policy "projects_owner"
    on public.projects for select
    using (organization_id in (
        select o.id from public.organizations o where o.owner_id = auth.uid()
    ));

-- owner-via-parent. The parent row's owner_id can only be reached through a
-- subquery: a USING expression may not name another table's bare column.
create policy "projects_owner_via_parent"
    on public.projects for all
    using (exists (
        select 1 from public.organizations o
        where o.id = public.projects.organization_id
          and o.owner_id = auth.uid()
    ));

-- tenant-via-parent, through the membership table
create policy "projects_tenant_via_parent"
    on public.projects for select
    using (organization_id in (
        select om.organization_id from public.organizations_members om
        where om.user_id = auth.uid()
    ));

-- filtered public read
create policy "projects_public_read"
    on public.projects for select
    using (visibility = 'public' and published_at is not null);

-- deny-all
create policy "projects_internal_deny_all"
    on public.projects_internal for select
    using (false);

create policy "organizations_members_self"
    on public.organizations_members for select
    using (user_id = auth.uid());

-- 10. Realtime ---------------------------------------------------------------
-- supabase_realtime is a publication on a stock `supabase start` and does not
-- exist on a plain Postgres; undefined_object is caught so this is a no-op.
-- The membership is checked because `add table` raises duplicate_object on the
-- second run, and the header promises a re-run after a failed CI job works.
do $fixture$
begin
    if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
       and not exists (
           select 1 from pg_publication_tables
           where pubname = 'supabase_realtime'
             and schemaname = 'public'
             and tablename = 'projects'
       )
    then
        alter publication supabase_realtime add table public.projects;
    end if;
exception
    when undefined_object or insufficient_privilege then null;
end;
$fixture$;

-- 11. pg_cron ---------------------------------------------------------------
-- pg_cron ships its own policies on cron.job, granting SELECT only to the
-- postgres role. That is deliberate: the fixture must expose a policy on a
-- managed schema, which is a different disposition from an app policy.
-- Guarded because the `cron` schema is absent off-stack, and because
-- cron.schedule() needs privileges the CI role may not hold.
do $fixture$
begin
    perform cron.schedule('earthos-heartbeat', '*/5 * * * *', 'select 1');
exception
    when undefined_table or undefined_object or undefined_function
         or invalid_schema_name or insufficient_privilege then null;
end;
$fixture$;

-- 12. The fixture's storage policy -----------------------------------------
-- A policy on `storage.objects` the way a project writes one: the subject
-- reads its own objects and nobody else's. The inspector attaches it to the
-- bucket it names, so without it the storage-policy path is untested on the
-- real stack. Guarded because `storage` is Supabase's schema -- postgres
-- does not own `storage.objects` and so may not be able to add a policy to
-- it -- and because `owner_id` replaced `owner` part-way through storage's
-- history, so an older stack has neither the column to name nor the right to
-- create the policy. A skip is a skip; it is not a failure of the fixture.
-- Dropped first because this is the one object section 1 cannot reach: it
-- hangs off a table the fixture does not own, so a re-run would otherwise die
-- on `policy ... already exists`. Both statements share the block's
-- subtransaction, so a create that is refused takes the drop with it.
do $fixture$
begin
    execute 'drop policy if exists earthos_objects_owner_read on storage.objects';
    execute 'create policy earthos_objects_owner_read on storage.objects for select using '
        || '(owner_id = (select auth.uid())::text)';
exception
    when undefined_table or undefined_object or undefined_function or undefined_column
         or invalid_schema_name or insufficient_privilege then null;
end;
$fixture$;

-- 13. Grants ----------------------------------------------------------------
-- Supabase's default: every public table to every API role. Guarded because
-- the roles are cluster-wide on Supabase and absent on a plain Postgres.
--
-- There is deliberately no fixture-owned read-only role here. The role
-- docs/import/supabase.md tells a user to create is created by the job, from
-- that document verbatim, so the two cannot drift: a second, hand-rolled role
-- in this file would only ever be dead weight, and would give a reader a
-- second answer to "which role does inspect run as".
do $fixture$
declare
    role_name text;
    schema_name text;
begin
    -- Supabase's own default privileges: every public and storage table to
    -- every API role. `auth` is deliberately not in this list -- Supabase
    -- grants nothing there beyond the triggers the platform owns.
    foreach role_name in array array['anon', 'authenticated', 'service_role'] loop
        continue when not exists (select 1 from pg_roles where rolname = role_name);
        foreach schema_name in array array['public', 'storage'] loop
            continue when not exists (select 1 from pg_namespace where nspname = schema_name);
            execute format('grant usage on schema %I to %I', schema_name, role_name);
            execute format('grant all on all tables in schema %I to %I', schema_name, role_name);
        end loop;
    end loop;
end;
$fixture$;