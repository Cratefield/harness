-- A representative Supabase project, small enough to read (issue #658).
--
-- Plain Postgres 16 — the CI service container — cannot run Supabase's own
-- images, so this reproduces the shape inspect reads: Supabase's `auth`
-- and `storage` schemas (the columns inspect touches, with Supabase's
-- names and types), its API roles and default grants, its `auth.uid()` /
-- `auth.jwt()` / `auth.role()` functions, the `supabase_realtime`
-- publication, and a `public` schema like a real app's: RLS policies of
-- every common shape, an enum, triggers, views, functions and sequences.
--
-- Two blockers are planted on purpose: the `dblink` extension (no harness
-- equivalent) and a foreign key from a public table into `storage.objects`.
--
-- Every email below is fake and must never appear in a report.

-- Supabase's API roles are cluster-wide; tests share one server, so
-- creating them tolerates a concurrent creator.
DO $$ BEGIN CREATE ROLE anon NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE authenticated NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE service_role NOLOGIN BYPASSRLS; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;

CREATE SCHEMA extensions;
CREATE SCHEMA auth;
CREATE SCHEMA storage;
CREATE SCHEMA realtime;

CREATE EXTENSION pgcrypto WITH SCHEMA extensions;
CREATE EXTENSION "uuid-ossp" WITH SCHEMA extensions;
CREATE EXTENSION citext WITH SCHEMA extensions;
CREATE EXTENSION dblink WITH SCHEMA extensions;

-- auth ----------------------------------------------------------------------

CREATE TABLE auth.users (
    instance_id uuid,
    id uuid PRIMARY KEY,
    aud varchar(255),
    role varchar(255),
    email varchar(255),
    encrypted_password varchar(255),
    email_confirmed_at timestamptz,
    phone text,
    raw_app_meta_data jsonb,
    raw_user_meta_data jsonb,
    is_anonymous boolean NOT NULL DEFAULT false,
    created_at timestamptz,
    updated_at timestamptz
);

CREATE TABLE auth.identities (
    provider_id text NOT NULL,
    user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    identity_data jsonb NOT NULL,
    provider text NOT NULL,
    created_at timestamptz,
    id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    UNIQUE (provider_id, provider)
);

CREATE TABLE auth.mfa_factors (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    factor_type text NOT NULL,
    status text NOT NULL
);

CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$
    SELECT coalesce(
        nullif(current_setting('request.jwt.claim.sub', true), ''),
        (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
    )::uuid
$$;
CREATE FUNCTION auth.role() RETURNS text LANGUAGE sql STABLE AS $$
    SELECT nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role'
$$;
CREATE FUNCTION auth.jwt() RETURNS jsonb LANGUAGE sql STABLE AS $$
    SELECT coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb
$$;

INSERT INTO auth.users (id, aud, role, email, encrypted_password, email_confirmed_at, raw_user_meta_data, created_at) VALUES
    ('00000000-0000-4000-8000-000000000001', 'authenticated', 'authenticated', 'ada@example.test',
     '$2a$10$abcdefghijklmnopqrstuuOJ4f0Zf1rSYx2Zl8pQ1fSl8sQf2aZ1u', '2026-01-02 03:04:05+00', '{"name": "Ada"}', '2026-01-01 00:00:00+00'),
    ('00000000-0000-4000-8000-000000000002', 'authenticated', 'authenticated', 'grace@example.test',
     NULL, '2026-02-01 00:00:00+00', '{}', '2026-02-01 00:00:00+00'),
    ('00000000-0000-4000-8000-000000000003', 'authenticated', 'authenticated', 'linus@example.test',
     NULL, NULL, '{}', '2026-03-01 00:00:00+00');

INSERT INTO auth.identities (provider_id, user_id, identity_data, provider, created_at) VALUES
    ('00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000001',
     '{"sub": "00000000-0000-4000-8000-000000000001", "email": "ada@example.test"}', 'email', '2026-01-01 00:00:00+00'),
    ('1094857261', '00000000-0000-4000-8000-000000000002',
     '{"sub": "1094857261", "email": "grace@example.test"}', 'google', '2026-02-01 00:00:00+00'),
    ('5521', '00000000-0000-4000-8000-000000000003',
     '{"sub": "5521", "email": "linus@example.test"}', 'github', '2026-03-01 00:00:00+00');

INSERT INTO auth.mfa_factors VALUES
    ('00000000-0000-4000-8000-0000000000f1', '00000000-0000-4000-8000-000000000001', 'totp', 'verified');

-- storage -------------------------------------------------------------------

CREATE TABLE storage.buckets (
    id text PRIMARY KEY,
    name text NOT NULL,
    owner uuid,
    public boolean DEFAULT false,
    file_size_limit bigint,
    allowed_mime_types text[],
    created_at timestamptz DEFAULT now()
);

CREATE TABLE storage.objects (
    id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    bucket_id text REFERENCES storage.buckets (id),
    name text,
    owner uuid,
    metadata jsonb,
    created_at timestamptz DEFAULT now()
);
ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Avatar images are publicly accessible" ON storage.objects
    FOR SELECT USING (bucket_id = 'avatars');
CREATE POLICY "Users upload their own avatar" ON storage.objects
    FOR INSERT TO authenticated
    WITH CHECK (bucket_id = 'avatars' AND (SELECT auth.uid()) = owner);

INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types) VALUES
    ('avatars', 'avatars', true, 1048576, ARRAY['image/png', 'image/jpeg']),
    ('documents', 'documents', false, NULL, NULL);

INSERT INTO storage.objects (id, bucket_id, name, owner, metadata) VALUES
    ('00000000-0000-4000-8000-0000000000a1', 'avatars', 'ada.png', '00000000-0000-4000-8000-000000000001',
     '{"size": 20480, "mimetype": "image/png"}'),
    ('00000000-0000-4000-8000-0000000000a2', 'avatars', 'grace.jpg', '00000000-0000-4000-8000-000000000002',
     '{"size": 31744, "mimetype": "image/jpeg"}'),
    ('00000000-0000-4000-8000-0000000000d1', 'documents', 'team-1/handbook.pdf', '00000000-0000-4000-8000-000000000001',
     '{"size": 12582912, "mimetype": "application/pdf"}');

-- public --------------------------------------------------------------------

CREATE TYPE public.project_status AS ENUM ('draft', 'active', 'archived');

CREATE TABLE public.profiles (
    id uuid PRIMARY KEY REFERENCES auth.users (id) ON DELETE CASCADE,
    username extensions.citext UNIQUE,
    avatar_url text,
    updated_at timestamptz,
    CONSTRAINT username_length CHECK (char_length(username::text) >= 3)
);

CREATE TABLE public.teams (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name text NOT NULL
);

CREATE TABLE public.team_members (
    team_id bigint NOT NULL REFERENCES public.teams (id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    role text NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'member')),
    PRIMARY KEY (team_id, user_id)
);

CREATE TABLE public.projects (
    id bigserial PRIMARY KEY,
    team_id bigint NOT NULL REFERENCES public.teams (id),
    name text NOT NULL,
    status public.project_status NOT NULL DEFAULT 'draft',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX projects_team_id_idx ON public.projects (team_id);

-- Blocker: a foreign key into storage.objects, which becomes R2 keys.
CREATE TABLE public.attachments (
    id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    project_id bigint NOT NULL REFERENCES public.projects (id) ON DELETE CASCADE,
    object_id uuid NOT NULL REFERENCES storage.objects (id)
);

-- No primary key.
CREATE TABLE public.audit_log (
    at timestamptz NOT NULL DEFAULT now(),
    message text NOT NULL
);

CREATE SEQUENCE public.invoice_number_seq START 1000;

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.team_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.attachments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Public profiles are viewable by everyone." ON public.profiles
    FOR SELECT USING (true);
CREATE POLICY "Users can insert their own profile." ON public.profiles
    FOR INSERT WITH CHECK ((SELECT auth.uid()) = id);
CREATE POLICY "Users can update own profile." ON public.profiles
    FOR UPDATE USING (auth.uid() = id);
CREATE POLICY "Service role manages teams" ON public.teams
    TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "Signed-in users can list teams" ON public.teams
    FOR SELECT TO authenticated USING (true);
CREATE POLICY "Members see their memberships" ON public.team_members
    FOR SELECT USING (user_id = auth.uid());
CREATE POLICY "Team members can view projects" ON public.projects
    FOR SELECT TO authenticated
    USING (EXISTS (SELECT 1 FROM public.team_members m WHERE m.team_id = projects.team_id AND m.user_id = auth.uid()));
CREATE POLICY "Admins can delete projects" ON public.projects
    FOR DELETE USING ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');
CREATE POLICY "Archived projects stay visible for a grace period" ON public.projects
    FOR SELECT USING (status <> 'archived' OR created_at > now() - interval '30 days');
CREATE POLICY "Anyone can file an attachment" ON public.attachments
    FOR INSERT TO anon WITH CHECK (true);

-- The classic Supabase sign-up hook: a SECURITY DEFINER function on
-- auth.users that creates the profile.
CREATE FUNCTION public.handle_new_user() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
    INSERT INTO public.profiles (id, username)
    VALUES (new.id, new.raw_user_meta_data ->> 'user_name');
    RETURN new;
END;
$$;
CREATE TRIGGER on_auth_user_created AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

CREATE FUNCTION public.set_updated_at() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    new.updated_at := now();
    RETURN new;
END;
$$;
CREATE TRIGGER profiles_set_updated_at BEFORE UPDATE ON public.profiles
    FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE FUNCTION public.project_count(team bigint) RETURNS integer LANGUAGE sql STABLE AS $$
    SELECT count(*)::integer FROM public.projects WHERE team_id = team
$$;

CREATE VIEW public.active_projects AS
    SELECT id, team_id, name FROM public.projects WHERE status = 'active';
CREATE VIEW public.my_projects AS
    SELECT p.* FROM public.projects p
    WHERE p.team_id IN (SELECT team_id FROM public.team_members WHERE user_id = auth.uid());

-- Supabase's default grants: every public table to every API role.
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL TABLES IN SCHEMA public TO anon, authenticated, service_role;

CREATE PUBLICATION supabase_realtime FOR TABLE public.projects;

INSERT INTO public.profiles (id, username) VALUES
    ('00000000-0000-4000-8000-000000000001', 'ada'),
    ('00000000-0000-4000-8000-000000000002', 'grace');
INSERT INTO public.teams (name) VALUES ('Analytical Engines'), ('Compilers');
INSERT INTO public.team_members (team_id, user_id, role) VALUES
    (1, '00000000-0000-4000-8000-000000000001', 'owner'),
    (2, '00000000-0000-4000-8000-000000000002', 'owner'),
    (2, '00000000-0000-4000-8000-000000000003', 'member');
INSERT INTO public.projects (team_id, name, status) VALUES
    (1, 'Difference engine', 'archived'),
    (1, 'Note G', 'active'),
    (2, 'A-0', 'active'),
    (2, 'COBOL', 'draft');
INSERT INTO public.attachments (project_id, object_id) VALUES
    (1, '00000000-0000-4000-8000-0000000000d1');
INSERT INTO public.audit_log (message) VALUES ('created'), ('updated');

-- Planner estimates, as a live project's autovacuum would have left them.
ANALYZE;
