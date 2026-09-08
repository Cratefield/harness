-- fz-module-linkedin, issue #6. Portable SQL subset (harness ADR 0004):
-- ULID text ids, ISO-8601 fixed-width TEXT timestamps so lexicographic order
-- is chronological order, no dialect functions.

-- The connected LinkedIn member. One per deployment: `singleton` is always 1
-- and unique, so a second connect without an explicit disconnect is a
-- constraint error rather than a silently forked identity. Pages, posts and
-- assets still carry account_id, so lifting the constraint later is an index
-- migration and not a table rewrite.
CREATE TABLE IF NOT EXISTS linkedin_accounts (
    id TEXT PRIMARY KEY,
    singleton INTEGER NOT NULL DEFAULT 1,
    person_urn TEXT,
    access_token TEXT NOT NULL,
    access_expires_at TEXT NOT NULL,
    refresh_token TEXT,
    refresh_expires_at TEXT,
    scopes TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    expiring_notified_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(singleton)
);

-- Every organization the account administers, company pages and showcase
-- pages alike: since January 2024 a showcase is an organization with
-- primaryOrganizationType BRAND, so they share one table and differ by `kind`.
CREATE TABLE IF NOT EXISTS linkedin_pages (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    urn TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    vanity_name TEXT,
    kind TEXT NOT NULL,
    parent_org_id TEXT,
    role TEXT NOT NULL,
    can_post_organic INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL,
    logo_urn TEXT,
    synced_at TEXT NOT NULL,
    UNIQUE(account_id, org_id)
);

-- Uploaded media. Not unique on (org_id, sha256): a PROCESSING_FAILED asset
-- must not permanently block re-uploading the same bytes, so dedupe is a
-- filtered lookup rather than a constraint.
CREATE TABLE IF NOT EXISTS linkedin_assets (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    image_urn TEXT NOT NULL,
    status TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    byte_len INTEGER NOT NULL,
    alt_text TEXT,
    checked_at TEXT,
    created_at TEXT NOT NULL
);

-- Our record of a post. `publishing_since` is the lease that keeps two cron
-- passes from creating the same post twice; `not_before` is the retry clock,
-- since the Clock port cannot sleep.
CREATE TABLE IF NOT EXISTS linkedin_posts (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    commentary TEXT NOT NULL,
    visibility TEXT NOT NULL,
    asset_id TEXT,
    article_source TEXT,
    article_title TEXT,
    article_description TEXT,
    state TEXT NOT NULL,
    post_urn TEXT,
    scheduled_at TEXT,
    not_before TEXT,
    publishing_since TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    error_code TEXT,
    error_detail TEXT,
    edited_at TEXT,
    previous_commentary TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    published_at TEXT,
    deleted_at TEXT,
    UNIQUE(org_id, idempotency_key)
);

-- One row per outstanding connect attempt. The row carries its own expiry
-- because Signer::verify reads the wall clock directly and cannot be driven
-- by a test clock; spending a state is a conditional DELETE whose affected
-- row count is the single-use proof.
CREATE TABLE IF NOT EXISTS linkedin_oauth_states (
    id TEXT PRIMARY KEY,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Requests spent per UTC day against LinkedIn's Development Tier cap. In the
-- database rather than in memory: a Worker isolate is not the unit the cap
-- applies to.
CREATE TABLE IF NOT EXISTS linkedin_request_budget (
    day TEXT PRIMARY KEY,
    spent INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS linkedin_posts_due ON linkedin_posts (state, not_before);
CREATE INDEX IF NOT EXISTS linkedin_assets_lookup ON linkedin_assets (org_id, sha256, status);
CREATE INDEX IF NOT EXISTS linkedin_pages_account ON linkedin_pages (account_id, state);
