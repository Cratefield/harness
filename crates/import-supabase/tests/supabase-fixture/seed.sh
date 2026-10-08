#!/usr/bin/env bash
#
# Seed the EarthOS-shaped fixture on a live `supabase start` stack, after
# schema.sql has been applied (issue #733). Run as the `postgres` role on
# the `supabase db` port 54322.
#
# Reads three values from the environment, none of which is ever printed:
#
#   SUPABASE_URL        the stack's API URL, e.g. http://127.0.0.1:54321
#   SERVICE_ROLE_KEY    the stack's service-role JWT (GoTrue admin)
#   DB_URL              the stack's `supabase db` connection string
#
# Writes the created auth.users ids to $EARTHOS_USER_IDS_FILE, one per
# line (default /tmp/earthos-user-ids), so a caller can join the rows it
# wrote without parsing this script's output. Nothing in this job reads it
# yet: the later phases of the e2e job (#659 auth import, #660 data load,
# #661 storage copy) join the rows they create against the ids in it.
#
# Secrets: the keys stay in the environment and in curl's `Authorization`
# header. There is no `set -x` here, nothing echoes them, and the API's
# responses are parsed rather than printed — GoTrue returns the user it
# created, and a body in a CI log is a body in a CI log. The workflow
# registers the key with `::add-mask::` before calling this, so even a
# failing curl cannot leak one. They are the local stack's development-only
# keys, but a key in a log is a key.
#
# Why the GoTrue admin API and not SQL: the seed must create people the way
# a project creates them. GoTrue writes auth.users and auth.identities with
# its own columns, hashes the password and fires the AFTER INSERT trigger,
# which is what fills public.users (schema.sql section 8). Inserting
# auth.users directly skips all of that and would leave the fixture
# asserting a sign-up path nobody uses. The one exception is the google
# identity below, which no admin endpoint can create; that is called out
# where it happens.

set -euo pipefail

: "${SUPABASE_URL:?SUPABASE_URL is not set}"
: "${SERVICE_ROLE_KEY:?SERVICE_ROLE_KEY is not set}"
: "${DB_URL:?DB_URL is not set}"

gotrue="${SUPABASE_URL}/auth/v1"
storage="${SUPABASE_URL}/storage/v1"
ids_file="${EARTHOS_USER_IDS_FILE:-/tmp/earthos-user-ids}"

# `auth` and `storage` are owned by supabase_auth_admin /
# supabase_storage_admin; `postgres` reads them but cannot write to them, so
# the one row that has no admin endpoint is written as supabase_admin. Falls
# back to DB_URL when that role cannot connect, which is the plain-Postgres
# case where there is no auth schema to write to anyway.
admin_db_url() {
  local candidate
  candidate="$(printf '%s' "$DB_URL" | sed -e 's#^\([^:]*\)://[^@]*@#\1://supabase_admin:postgres@#')"
  if [ "$candidate" = "$DB_URL" ]; then
    printf '%s' "$DB_URL"
    return
  fi
  if psql "$candidate" --quiet --no-psqlrc --set ON_ERROR_STOP=1 \
    --command 'select 1' >/dev/null 2>&1; then
    printf '%s' "$candidate"
  else
    printf '%s' "$DB_URL"
  fi
}

# One user through the admin API, with the auth shape in the JSON body.
# Prints nothing but the new id; the label is the one thing printed if the
# body has no id, because "which user" is safe and the body is not.
create_user() {
  local label="$1" body="$2" response
  response="$(curl --silent --show-error --fail-with-body \
    --request POST "${gotrue}/admin/users" \
    --header "apikey: ${SERVICE_ROLE_KEY}" \
    --header "Authorization: Bearer ${SERVICE_ROLE_KEY}" \
    --header "Content-Type: application/json" \
    --data "$body")"
  printf '%s' "$response" | USER_LABEL="$label" python3 -c \
    'import json, os, sys
user = json.load(sys.stdin)
if "id" not in user:
    sys.exit("the GoTrue admin API created no %s user" % os.environ["USER_LABEL"])
print(user["id"])'
}

# One bucket through the Storage API, the way a project makes one. Public
# buckets need no key at all; the private one carries the size limit and the
# mime allowlist the inspector reads, and is the shape that has to be copied
# into R2 in the storage phase (#661).
create_bucket() {
  curl --silent --show-error --fail-with-body --output /dev/null \
    --request POST "${storage}/bucket" \
    --header "apikey: ${SERVICE_ROLE_KEY}" \
    --header "Authorization: Bearer ${SERVICE_ROLE_KEY}" \
    --header "Content-Type: application/json" \
    --data "$2"
}

# One object through the Storage API, so the object rows carry the metadata
# the per-bucket counts read (`metadata->>'size'`). `x-upsert` makes a re-run
# replace rather than fail.
upload_object() {
  curl --silent --show-error --fail-with-body --output /dev/null \
    --request POST "${storage}/object/$1/$2" \
    --header "apikey: ${SERVICE_ROLE_KEY}" \
    --header "Authorization: Bearer ${SERVICE_ROLE_KEY}" \
    --header "Content-Type: text/plain" \
    --header "x-upsert: true" \
    --data-binary "$3"
}

# The five people, one per auth shape the inspector counts separately:
# confirmed with a password, unconfirmed, passwordless (an SSO/phone-only
# project has those, and `users_without_password` is otherwise a zero that
# proves nothing), phone-only, and one with a google identity.
owner_id="$(create_user owner \
  '{"email":"earthos-owner@example.test","password":"earthos-owner-password","email_confirm":true}')"
editor_id="$(create_user editor \
  '{"email":"earthos-editor@example.test","password":"earthos-editor-password","email_confirm":false}')"
member_id="$(create_user member \
  '{"email":"earthos-member@example.test","email_confirm":true}')"
reader_id="$(create_user reader \
  '{"phone":"+15550000001","phone_confirm":true}')"
visitor_id="$(create_user visitor \
  '{"email":"earthos-visitor@example.test","password":"earthos-visitor-password","email_confirm":true}')"

printf '%s\n%s\n%s\n%s\n%s\n' \
  "$owner_id" "$editor_id" "$member_id" "$reader_id" "$visitor_id" >"$ids_file"

# The buckets: one public (a public URL is the whole read path for it) and
# one private and constrained, so `file_size_limit` and
# `allowed_mime_types` are real values in the report rather than nulls.
create_bucket earthos-media \
  '{"id":"earthos-media","name":"earthos-media","public":true}'
create_bucket earthos-avatars \
  '{"id":"earthos-avatars","name":"earthos-avatars","public":false,"file_size_limit":5242880,"allowed_mime_types":["image/png","image/jpeg"]}'

# A row in each, so the per-bucket object count and byte total have
# something to read rather than being zeros that prove nothing. Both bodies
# are tiny, so the over-the-blob-cap count stays zero — uploading 10 MB
# through the API to make one number non-zero is not worth the CI minutes,
# and the cap is the plain-Postgres fixture's business.
upload_object earthos-media map.svg 'the public map'
upload_object earthos-avatars owner.png 'the owner avatar'

# The google identity. GoTrue mints an identity from the provider's callback,
# and the admin API has no way to fake one, so this is the single row written
# as SQL. The USER it names was still created through the admin API above, so
# public.users exists for it through the same sign-up trigger as everyone
# else; `ON CONFLICT DO NOTHING` keeps a re-run from raising on the
# (provider_id, provider) unique index.
psql "$(admin_db_url)" --quiet --set ON_ERROR_STOP=1 --set visitor_id="$visitor_id" <<'SQL'
INSERT INTO auth.identities (provider_id, user_id, identity_data, provider)
VALUES ('earthos-visitor-google', :'visitor_id',
        '{"sub":"earthos-visitor-google","email_verified":true}'::jsonb, 'google')
ON CONFLICT (provider_id, provider) DO NOTHING;
SQL

# The rows the tenant shape needs to mean something: an organization, five
# memberships with each of the five roles, two projects (one private, one
# published, so the filtered public read has a row it admits), places with
# geometry, the deny-all table, and the audit log.
#
# Written through psql as `postgres`, because the tables' own RLS would
# otherwise refuse the insert — which is the point of the fixture, and not
# something a seed should have to work around by disabling.
psql "$DB_URL" --quiet --set ON_ERROR_STOP=1 \
  --set owner_id="$owner_id" --set editor_id="$editor_id" \
  --set member_id="$member_id" --set reader_id="$reader_id" \
  --set visitor_id="$visitor_id" <<'SQL'
-- Put the schema PostGIS is installed in on this session's search_path, for
-- the same reason schema.sql section 2 does: a stock `supabase start` keeps
-- postgis in `extensions`, which is not on the default search_path, so the
-- unqualified ST_MakePoint/ST_SetSRID calls and the ::geography cast below
-- would not resolve. The columns themselves were declared in that schema
-- already, so the search_path only has to make the names findable.
DO $$
DECLARE
    ext_schema text;
BEGIN
    SELECT n.nspname INTO ext_schema
    FROM pg_extension e
    JOIN pg_namespace n ON n.oid = e.extnamespace
    WHERE e.extname = 'postgis';

    IF ext_schema IS NULL THEN
        RAISE EXCEPTION 'the postgis extension is installed in no schema; the geography rows below cannot be written';
    END IF;

    PERFORM set_config('search_path', format('%I, public', ext_schema), false);
END;
$$;

INSERT INTO public.organizations (id, name, owner_id)
VALUES ('aaaaaaaa-0000-4000-8000-000000000001', 'EarthOS', :'owner_id')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.organizations_members (organization_id, user_id, role) VALUES
  ('aaaaaaaa-0000-4000-8000-000000000001', :'owner_id',  'admin'),
  ('aaaaaaaa-0000-4000-8000-000000000001', :'editor_id', 'editor'),
  ('aaaaaaaa-0000-4000-8000-000000000001', :'member_id', 'member'),
  ('aaaaaaaa-0000-4000-8000-000000000001', :'reader_id', 'viewer'),
  ('aaaaaaaa-0000-4000-8000-000000000001', :'visitor_id', 'guest')
ON CONFLICT DO NOTHING;

INSERT INTO public.projects (id, organization_id, name, description, status, visibility,
                             published_at, created_by, location) VALUES
  ('bbbbbbbb-0000-4000-8000-000000000001', 'aaaaaaaa-0000-4000-8000-000000000001',
   'Seed project', 'the private one', 'active', 'private', NULL, :'owner_id',
   ST_SetSRID(ST_MakePoint(-0.1276, 51.5072), 4326)::geography),
  ('bbbbbbbb-0000-4000-8000-000000000002', 'aaaaaaaa-0000-4000-8000-000000000001',
   'Published project', 'the public one', 'active', 'public', now(), :'owner_id',
   ST_SetSRID(ST_MakePoint(2.3522, 48.8566), 4326)::geography)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.places (id, name, location, area) VALUES
  ('cccccccc-0000-4000-8000-000000000001', 'London',
   ST_SetSRID(ST_MakePoint(-0.1276, 51.5072), 4326)::geography,
   ST_GeomFromText('POLYGON((-1 51, 0 51, 0 52, -1 52, -1 51))', 4326)),
  ('cccccccc-0000-4000-8000-000000000002', 'Paris',
   ST_SetSRID(ST_MakePoint(2.3522, 48.8566), 4326)::geography,
   ST_GeomFromText('POLYGON((2 48, 3 48, 3 49, 2 49, 2 48))', 4326))
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.projects_internal (id, project_id, reviewer_role, note) VALUES
  ('dddddddd-0000-4000-8000-000000000001', 'bbbbbbbb-0000-4000-8000-000000000001',
   'admin', 'never readable through the API')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.audit_events (organization_id, actor_id, action, payload) VALUES
  ('aaaaaaaa-0000-4000-8000-000000000001', :'owner_id', 'project.seeded',
   '{"seeded":true}'::jsonb),
  ('aaaaaaaa-0000-4000-8000-000000000001', :'editor_id', 'project.published',
   '{"seeded":true}'::jsonb);
SQL

# The ids, and nothing else: the caller joins rows with them, and an id is
# not a secret the way a key is.
printf 'earthos fixture: seeded 5 auth users, 2 buckets, ids in %s\n' "$ids_file"