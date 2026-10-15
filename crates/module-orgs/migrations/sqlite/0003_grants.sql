-- Access grants (issue #878). Portable SQL (ADR 0004).
--
-- One row says that `principal` holds `permission` on the selector
-- (`kind`, `space`, `path`) — or, with `effect = 'deny'`, that it must not
-- touch it. `path` is `/`-joined whole segments, '' for the whole space.
-- `principal` is opaque: a member, a service account, a role group, as the
-- venture names them. The unique key keeps one row per principal, selector
-- and effect, so re-granting updates the permission rather than stacking rows.
CREATE TABLE IF NOT EXISTS org_grants (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    principal TEXT NOT NULL,
    kind TEXT NOT NULL,
    space TEXT NOT NULL,
    path TEXT NOT NULL DEFAULT '',
    permission TEXT NOT NULL,
    effect TEXT NOT NULL,
    expires_at TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (org_id, principal, kind, space, path, effect)
);
-- "What may this principal reach" runs on every request that asks.
CREATE INDEX IF NOT EXISTS org_grants_principal_idx ON org_grants (org_id, principal);
-- "Who can see this space" runs on every share panel.
CREATE INDEX IF NOT EXISTS org_grants_space_idx ON org_grants (org_id, space);
