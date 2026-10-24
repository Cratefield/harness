-- Venture linking with Factory Zero (chi-infra/factory0 docs/venture-linking.md).
--
-- Two changes ride along:
--
-- 1. identities admits 'factory-zero': a person who signs in to a venture
--    through Factory Zero is an identity row (provider 'factory-zero',
--    subject = their Factory Zero sub). The linking rules (issue #22)
--    decide which account that row belongs to; nothing here loosens them.
--    SQLite cannot ALTER a CHECK, so identities is rebuilt exactly as 0010
--    did it.
--
-- 2. user_client_grants records that a person has authorized a client (for
--    example a venture) on THIS deployment. A row is written when an
--    authorization code is issued to that client for that person, and the
--    account page lists the active ones. revoked_at is set by an explicit
--    revoke from the person; the next sign-in to that client clears it again,
--    because that sign-in is a fresh authorization.
--
-- Portable SQL subset (harness issue #8) for the table; the rebuild uses only
-- plain DDL.

CREATE TABLE IF NOT EXISTS identities_rebuild (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    provider TEXT NOT NULL CHECK (provider IN ('google','apple','meta','password','magic_link','passkey','import','sso','factory-zero')),
    provider_subject TEXT NOT NULL,
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

CREATE TABLE IF NOT EXISTS user_client_grants (
    user_id TEXT NOT NULL REFERENCES users(id),
    client_id TEXT NOT NULL REFERENCES clients(id),
    granted_at TEXT NOT NULL,
    revoked_at TEXT,
    PRIMARY KEY (user_id, client_id)
);

-- 3. single_use_tokens admits 'link_intent': the short-lived, single-use
--    record of "this person asked to link Factory Zero, and must sign in to
--    the venture first" (see crates/auth-oidc, the start route). Rebuilt
--    the same way 0009 did it, because SQLite cannot ALTER a CHECK.
CREATE TABLE IF NOT EXISTS single_use_tokens_rebuild (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('magic_link','webauthn_challenge','authorization_code','refresh_token','email_verification','password_reset','email_change','link_intent')),
    token_hash BLOB NOT NULL UNIQUE,
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
