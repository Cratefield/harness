-- Issue #912, review follow-up: step-up as a server-side transaction.
--
-- A prompt=login or max_age=0 demand used to be a per-account timestamp,
-- which any later session could satisfy. It is now a transaction: one row
-- per demand, bound to the account and the client, single-use, and
-- expiring. A session satisfies it only when it was created by a ceremony
-- after the transaction began. The forward migration drops the per-account
-- column 0013 added, and adds the table that replaces it.
--
-- Portable DDL, so the Postgres set reuses this file (ADR 0004). The token
-- hash is hex text rather than BLOB for that reason.
ALTER TABLE users DROP COLUMN reauth_requested_at;

CREATE TABLE step_up_transactions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    client_id TEXT NOT NULL,
    -- hex SHA-256 of the transaction value carried through the login
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);

CREATE INDEX step_up_transactions_by_user ON step_up_transactions (user_id);

-- The record of a role change, the way user_admin_audit records a
-- disable or enable. A sibling table because that one's action CHECK
-- names only the switch.
CREATE TABLE user_role_audit (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    role TEXT NOT NULL CHECK (role IN ('owner','admin','member')),
    at TEXT NOT NULL
);

CREATE INDEX user_role_audit_by_user ON user_role_audit (user_id);
