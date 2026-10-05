-- auth issue #648: changing the address an account is reached at. One
-- more single-use token kind — email_change — the link a person opens to
-- confirm the new address before the account moves to it. It is a row of
-- this table like a magic link or a reset link.
--
-- The address being moved to rides in payload, not a column of its own:
-- the column already exists, already holds exactly this kind of
-- per-token state (an authorization code's redirect_uri and PKCE
-- challenge, a refresh token's successor), and is already declared
-- redacted in personal_data, so the pending address is left out of
-- somebody's export the same way the rest of this table's state is.
-- A pending address is a row that is spent, retired or expired within
-- an hour; a column that outlives every read of it would not be.
--
-- SQLite cannot ALTER a CHECK constraint, so the table is rebuilt with
-- the extended kind list and the rows copied across, inside one
-- migration — the same step-for-step shape as 0003 and 0009. Harness
-- portable SQL subset (harness issue #8): plain DDL, no dialect
-- functions.

CREATE TABLE IF NOT EXISTS single_use_tokens_rebuild (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('magic_link','webauthn_challenge','authorization_code','refresh_token','email_verification','password_reset','email_change')),
    token_hash BLOB NOT NULL UNIQUE,                 -- sha256 of the presented value; the value itself is never stored
    user_id TEXT,
    client_id TEXT,
    payload TEXT,                                     -- per-kind state; for email_change, the address being moved to
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);

INSERT INTO single_use_tokens_rebuild (id, kind, token_hash, user_id, client_id, payload, expires_at, consumed_at)
    SELECT id, kind, token_hash, user_id, client_id, payload, expires_at, consumed_at
    FROM single_use_tokens;

DROP TABLE single_use_tokens;
ALTER TABLE single_use_tokens_rebuild RENAME TO single_use_tokens;

CREATE INDEX IF NOT EXISTS idx_single_use_tokens_expires_at ON single_use_tokens (expires_at);