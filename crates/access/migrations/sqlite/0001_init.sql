-- The whitelist: who may sign in. Cratefield is invite-only in v1, so a
-- login identity that is not matched here is refused, never provisioned.
-- An entry is either an exact `email` or a `domain` (`@example.com`), so an
-- operator can admit one person or a whole verified Google domain.
CREATE TABLE allowlist (
    value    TEXT PRIMARY KEY,          -- lowercased email, or "@domain"
    kind     TEXT NOT NULL,             -- 'email' | 'domain'
    note     TEXT NOT NULL DEFAULT '',  -- why they were invited, free text
    added_by TEXT NOT NULL,             -- operator identity
    added_at TEXT NOT NULL              -- RFC 3339
);

-- Every add and remove is an operator action and is kept, so the answer to
-- "who let this address in, and when" is always on record. Append-only:
-- a revoke deletes the allowlist row but leaves its own audit trail.
CREATE TABLE allowlist_audit (
    id     TEXT PRIMARY KEY,
    action TEXT NOT NULL,   -- 'allow' | 'revoke'
    value  TEXT NOT NULL,
    kind   TEXT NOT NULL,
    actor  TEXT NOT NULL,   -- operator identity
    at     TEXT NOT NULL    -- RFC 3339
);

CREATE INDEX allowlist_audit_by_value ON allowlist_audit (value);
