-- Issue #854: the audit trail of the account on/off switch. One row per
-- admin call, written in the same batch as the users.status flip, so the
-- flag can never move without its record — the append-only pattern the
-- allowlist audit in control-plane-access uses.
--
-- A repeat call is recorded like the first: the row says what the operator
-- asked for and when, and asking twice is still an action worth a row.
-- Portable DDL, so the Postgres set reuses this file (ADR 0004).

CREATE TABLE user_admin_audit (
    id      TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    -- 'user.disable' | 'user.enable'
    action  TEXT NOT NULL CHECK (action IN ('user.disable','user.enable')),
    at      TEXT NOT NULL       -- RFC 3339
);

CREATE INDEX user_admin_audit_by_user ON user_admin_audit (user_id);
