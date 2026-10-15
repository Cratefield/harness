-- Service accounts and their API keys (issue #878). Portable SQL (ADR 0004):
-- TEXT columns, RFC 3339 timestamps, so the Postgres runner applies this same
-- file.
--
-- A service account is a non-human principal an organization owns. It never
-- signs in; its only credential is a key below. `disabled_at` set means every
-- key it holds is refused.
CREATE TABLE IF NOT EXISTS org_service_accounts (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    owner_sub TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    disabled_at TEXT
);
CREATE INDEX IF NOT EXISTS org_service_accounts_org_idx
    ON org_service_accounts (org_id, owner_sub);

-- One row per key. The key itself never reaches this table: `secret_hash` is
-- the SHA-256 of the whole `{brand}_{id}_{secret}` string, compared in
-- constant time, and `prefix` (`{brand}_{id}`) is the public handle a
-- settings page lists and revokes by. `scopes` is a space-separated subset in
-- the venture's vocabulary; the empty string means no subset.
CREATE TABLE IF NOT EXISTS org_service_account_keys (
    prefix TEXT PRIMARY KEY,
    secret_hash TEXT NOT NULL,
    account_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    scopes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT,
    last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS org_service_account_keys_account_idx
    ON org_service_account_keys (org_id, account_id);
