-- auth issue #627: per-organization enterprise SSO connections, OIDC
-- first. Postgres form: the two CHECK-list changes are applied in place
-- rather than by rebuilding the table (harness issue #18, ADR 0004: a
-- dialect override holds only where the SQL truly differs). The table is
-- the sqlite one; the sealed secret is TEXT in both dialects, so this
-- file keeps the same _sealed column name and AAD.
--
-- Harness portable SQL subset (harness issue #8): plain DDL, no dialect
-- functions.

CREATE TABLE IF NOT EXISTS sso_connections (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(id),
    org_ref TEXT NOT NULL,                          -- the venture's own name for the organization
    issuer TEXT NOT NULL,                           -- the IdP's issuer; the ID token's iss must equal it
    oidc_client_id TEXT NOT NULL,
    oidc_client_secret_sealed TEXT NOT NULL,        -- XChaCha20-Poly1305; never the plaintext
    domains TEXT NOT NULL,                          -- JSON array of lowercase domains
    status TEXT NOT NULL CHECK (status IN ('active','disabled')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sso_connections_client_id ON sso_connections (client_id);

ALTER TABLE identities DROP CONSTRAINT identities_provider_check;
ALTER TABLE identities ADD CONSTRAINT identities_provider_check CHECK (provider IN ('google','apple','meta','password','magic_link','passkey','import','sso'));

ALTER TABLE sessions ADD COLUMN sso_connection TEXT;
