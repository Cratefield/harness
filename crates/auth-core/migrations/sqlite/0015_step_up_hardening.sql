-- Issue #912, second review: hardening of step-up and of the account
-- changes that step-up guards. Additive columns, plus one table rebuilt to
-- let a transaction belong to no account yet. Portable DDL, so the Postgres
-- set reuses this file (ADR 0004).
--
-- 1. users.security_changed_at: the last time a passkey was added or removed,
--    or the address changed. Within 24 hours, that account's passkey and
--    email ceremonies no longer satisfy a step-up, so a session that
--    enrolled a credential cannot use it to pass one.
ALTER TABLE users ADD COLUMN security_changed_at TEXT;

-- 2. sessions.acr: the authentication context a session earned by spending a
--    step-up transaction. NULL for an ordinary login.
-- 3. sessions.created_ms: when the session was created, to the millisecond,
--    so a ceremony that completes in the same second as its demand is still
--    told apart from the demand.
ALTER TABLE sessions ADD COLUMN acr TEXT;
ALTER TABLE sessions ADD COLUMN created_ms INTEGER;

-- 4. step_up_transactions: user_id becomes nullable, because a demand made
--    before anyone is signed in belongs to no account until the ceremony
--    that answers it. browser_hash binds such a demand to the browser that
--    asked (the hash of a cookie value). created_ms carries the demand's
--    time to the millisecond. Existing rows, none of which can be unbound,
--    take created_ms 0 and expire on their own.
DROP INDEX step_up_transactions_by_user;
ALTER TABLE step_up_transactions RENAME TO step_up_transactions_old;

CREATE TABLE step_up_transactions (
    id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users(id),
    client_id TEXT NOT NULL,
    -- hex SHA-256 of the transaction value carried through the login
    token_hash TEXT NOT NULL UNIQUE,
    -- hex SHA-256 of the browser cookie that asked, for an unbound demand
    browser_hash TEXT,
    created_at TEXT NOT NULL,
    created_ms INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);

INSERT INTO step_up_transactions (id, user_id, client_id, token_hash, created_at, expires_at, consumed_at)
    SELECT id, user_id, client_id, token_hash, created_at, expires_at, consumed_at
    FROM step_up_transactions_old;

DROP TABLE step_up_transactions_old;

CREATE INDEX step_up_transactions_by_user ON step_up_transactions (user_id);
