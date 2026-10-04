-- auth issue #627: per-organization enterprise SSO connections, OIDC
-- first. One row per (venture client, organization): the issuer to send a
-- person to, the client credentials to present there, the email domains
-- that route a sign-in to it, and whether it is switched on.
--
-- The client secret is stored sealed, never in the clear: the column name
-- ends _sealed and the AAD binds it to this row and column
-- (auth-core/sso_connections/<id>/oidc_client_secret_sealed). The key
-- lives in AUTH_CORE_SSO_TOKEN_KEY, which is not in this database.
--
-- domains is a JSON array of normalized lowercase domain names. It is a
-- column rather than a child table because the whole set is read and
-- written together on every admin change and no query filters on one
-- domain in SQL; the rule that a domain belongs to at most one active
-- connection of a client is enforced where the writes happen.
--
-- Two changes ride along, because a CHECK list cannot be altered in
-- SQLite: identities is rebuilt with sso added to its provider list
-- (an SSO identity's subject is <connection id>:<provider sub>), and
-- sessions gains sso_connection, the connection a session was signed
-- in through, which becomes the access token's sso_connection claim
-- only while that connection belongs to the token's own client.
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

CREATE TABLE IF NOT EXISTS identities_rebuild (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    provider TEXT NOT NULL CHECK (provider IN ('google','apple','meta','password','magic_link','passkey','import','sso')),
    provider_subject TEXT NOT NULL,                -- sub / Graph id / normalized email / <external_provider>:<external_id> / <sso connection id>:<sub>
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

ALTER TABLE sessions ADD COLUMN sso_connection TEXT;
