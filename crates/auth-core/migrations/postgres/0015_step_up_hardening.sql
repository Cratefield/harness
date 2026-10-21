-- Issue #912, third review: the Postgres form of the step-up hardening
-- migration. It differs from the sqlite file in one way: a millisecond
-- timestamp since the epoch does not fit Postgres's 32-bit INTEGER, so the two
-- `created_ms` columns are BIGINT. SQLite's INTEGER is 64-bit already, so the
-- sqlite file stays as it is (ADR 0004).
--
-- The table is rebuilt under a new name and renamed over the original, the
-- pattern the other rebuilds use, so the unique constraint's generated name
-- cannot collide with the one the original table still holds.

ALTER TABLE users ADD COLUMN security_changed_at TEXT;

ALTER TABLE sessions ADD COLUMN acr TEXT;
ALTER TABLE sessions ADD COLUMN created_ms BIGINT;

DROP INDEX step_up_transactions_by_user;

CREATE TABLE step_up_transactions_rebuild (
    id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users(id),
    client_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    browser_hash TEXT,
    created_at TEXT NOT NULL,
    created_ms BIGINT NOT NULL DEFAULT 0,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);

INSERT INTO step_up_transactions_rebuild (id, user_id, client_id, token_hash, created_at, expires_at, consumed_at)
    SELECT id, user_id, client_id, token_hash, created_at, expires_at, consumed_at
    FROM step_up_transactions;

DROP TABLE step_up_transactions;

ALTER TABLE step_up_transactions_rebuild RENAME TO step_up_transactions;

CREATE INDEX step_up_transactions_by_user ON step_up_transactions (user_id);
