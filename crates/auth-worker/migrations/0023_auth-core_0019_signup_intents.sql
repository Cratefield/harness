-- Issue: one entry flow with sign-up intents. An application may register the
-- roles-of-interest a new account picks while it is created (signup_intents,
-- a JSON array of intent definitions, NULL when the client has none). The
-- choice a person made is stored per (account, client) and echoed in the ID
-- token and at the userinfo endpoint as an intents claim.
--
-- An intent is a preference the person states, never a grant: roles stays
-- operator-granted through users.role (issue #912), and nothing here writes it.
--
-- Portable DDL, so the Postgres set reuses this file (ADR 0004).
ALTER TABLE clients ADD COLUMN signup_intents TEXT;

CREATE TABLE user_client_intents (
    user_id TEXT NOT NULL REFERENCES users(id),
    client_id TEXT NOT NULL REFERENCES clients(id),
    -- JSON array of intent keys, each one present in the client's list
    intents TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, client_id)
);
