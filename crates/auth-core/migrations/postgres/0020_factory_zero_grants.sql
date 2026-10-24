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

-- 3. single_use_tokens admits 'link_intent' (see the sqlite form). Rebuilt
--    as 0009 did it, so the kind CHECK is the full list.
CREATE TABLE IF NOT EXISTS single_use_tokens_rebuild (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('magic_link','webauthn_challenge','authorization_code','refresh_token','email_verification','password_reset','email_change','link_intent')),
    token_hash BYTEA NOT NULL UNIQUE,
    user_id TEXT,
    client_id TEXT,
    payload TEXT,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);

INSERT INTO single_use_tokens_rebuild (id, kind, token_hash, user_id, client_id, payload, expires_at, consumed_at)
    SELECT id, kind, token_hash, user_id, client_id, payload, expires_at, consumed_at
    FROM single_use_tokens;

DROP TABLE single_use_tokens;
ALTER TABLE single_use_tokens_rebuild RENAME TO single_use_tokens;

CREATE INDEX IF NOT EXISTS idx_single_use_tokens_expires_at ON single_use_tokens (expires_at);
