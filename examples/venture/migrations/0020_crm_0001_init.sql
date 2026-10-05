-- The CRM's four tables (issue #572), in the portable SQL subset (ADR
-- 0004): one file serves SQLite, D1 and Postgres, and there is no
-- `migrations/postgres` override because nothing here needs one.
--
-- `email_normalized` and `domain` are the natural keys the store upserts
-- on, and both are UNIQUE-but-nullable: a contact with no address and an
-- organisation with no domain are rows the venture may legitimately hold,
-- and both engines allow many NULLs in a UNIQUE column.
--
-- `generation` starts at 1 and is bumped by every write, so an update can
-- carry the generation it read and refuse to overwrite a row somebody
-- else has moved on.

CREATE TABLE IF NOT EXISTS crm_organisations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    domain TEXT UNIQUE,
    website TEXT,
    email TEXT,
    phone TEXT,
    address TEXT,
    data TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    generation INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS crm_contacts (
    id TEXT PRIMARY KEY,
    email TEXT,
    email_normalized TEXT UNIQUE,
    name TEXT,
    phone TEXT,
    locale TEXT,
    organisation_id TEXT REFERENCES crm_organisations(id) ON DELETE SET NULL,
    source TEXT,
    data TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    generation INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS crm_tags (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    color TEXT
);

-- A tagging is polymorphic: `subject_id` names a row of whichever table
-- `subject_type` says. That is why there is no foreign key to
-- `crm_contacts` — and why the erasure declaration reaches these rows
-- through `subject_via` instead of a plain column match.
CREATE TABLE IF NOT EXISTS crm_taggings (
    tag_id TEXT NOT NULL REFERENCES crm_tags(id) ON DELETE CASCADE,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('contact', 'organisation', 'item')),
    subject_id TEXT NOT NULL,
    PRIMARY KEY (tag_id, subject_type, subject_id)
);
