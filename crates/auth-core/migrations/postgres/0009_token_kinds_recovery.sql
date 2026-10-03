-- auth issues #19/#20 (recovery), Postgres form: single_use_tokens
-- grows the email_verification and password_reset kinds. The
-- rebuild-the-table-and-copy pattern matches the sqlite migration step
-- for step, so both dialects end on the same shape; Postgres differs
-- only in the byte column type: BYTEA, not BLOB (harness issue #18, ADR
-- 0004). Harness portable SQL subset (harness issue #8): plain DDL, no
-- dialect functions.

CREATE TABLE IF NOT EXISTS single_use_tokens_rebuild (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('magic_link','webauthn_challenge','authorization_code','refresh_token','email_verification','password_reset')),
    token_hash BYTEA NOT NULL UNIQUE,                -- sha256 of the presented value; the value itself is never stored
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
