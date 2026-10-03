-- auth issue #650 part B: the user import. An imported person is an
-- identities row with the new provider "import", whose provider_subject is
-- "<external_provider>:<external_id>"; the provider CHECK has to admit it.
-- SQLite cannot ALTER a CHECK constraint, so identities is rebuilt with
-- the widened list and its rows copied across, inside one migration — the
-- same rebuild 0003 used for single_use_tokens. The table's FK, its
-- UNIQUE (provider, provider_subject) and its index are all preserved.
-- Harness portable SQL subset (harness issue #8): plain DDL, no dialect
-- functions.

CREATE TABLE IF NOT EXISTS identities_rebuild (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    provider TEXT NOT NULL CHECK (provider IN ('google','apple','meta','password','magic_link','passkey','import')),
    provider_subject TEXT NOT NULL,                -- sub / Graph id / normalized email / <external_provider>:<external_id>
    email TEXT,
    email_verified INTEGER NOT NULL DEFAULT 0,
    name_at_link TEXT,
    created_at TEXT NOT NULL,
    last_login_at TEXT,
    UNIQUE (provider, provider_subject)
);

INSERT INTO identities_rebuild (id, user_id, provider, provider_subject, email, email_verified, name_at_link, created_at, last_login_at)
    SELECT id, user_id, provider, provider_subject, email, email_verified, name_at_link, created_at, last_login_at
    FROM identities;

DROP TABLE identities;
ALTER TABLE identities_rebuild RENAME TO identities;

CREATE INDEX IF NOT EXISTS idx_identities_user_id ON identities (user_id);
