-- Venture linking with Factory Zero: see the sqlite form for the rationale.
-- Postgres alters the named CHECK in place rather than rebuilding the table.

ALTER TABLE identities DROP CONSTRAINT identities_provider_check;
ALTER TABLE identities ADD CONSTRAINT identities_provider_check CHECK (provider IN ('google','apple','meta','password','magic_link','passkey','import','sso','factory-zero'));

CREATE TABLE IF NOT EXISTS user_client_grants (
    user_id TEXT NOT NULL REFERENCES users(id),
    client_id TEXT NOT NULL REFERENCES clients(id),
    granted_at TEXT NOT NULL,
    revoked_at TEXT,
    PRIMARY KEY (user_id, client_id)
);
