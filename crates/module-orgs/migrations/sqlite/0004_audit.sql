-- The audit log (issue #878). Portable SQL (ADR 0004). Append-only by API:
-- the module has no statement that updates or deletes a row here.
--
-- `credential` is a key or token *prefix*, or 'session' — never a secret.
-- `id` is time-ordered (a ULID), so `ORDER BY id` is the order things
-- happened in and the pagination cursor.
CREATE TABLE IF NOT EXISTS org_audit (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    on_behalf_of TEXT,
    credential TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    resource TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS org_audit_org_idx ON org_audit (org_id, id);
