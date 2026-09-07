-- Accounts and ventures (issue #4). The control plane's own schema,
-- applied through the harness's migrations like any venture's.
--
-- An `account` is one invited customer; a `venture` is one backend they
-- provision. The chosen module set is recorded on the venture because the
-- deployed artifact is a function of it (harness ADR 0009), and the
-- status is a typed lifecycle, never free text.
--
-- Interim: until one-database-per-tenant lands (harness #32), the control
-- plane's own database holds every account, and isolation is by query
-- (every read is scoped to an account id). The repository enforces it and
-- a test proves one account cannot read another's ventures.
CREATE TABLE IF NOT EXISTS account (
    id         TEXT PRIMARY KEY,     -- ULID
    identity   TEXT NOT NULL UNIQUE, -- the Google-verified email
    name       TEXT NOT NULL,
    status     TEXT NOT NULL,        -- active | suspended
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS venture (
    id          TEXT PRIMARY KEY,    -- ULID
    account_id  TEXT NOT NULL REFERENCES account (id),
    slug        TEXT NOT NULL,
    subdomain   TEXT NOT NULL UNIQUE,
    module_set  TEXT NOT NULL,       -- the resolved slugs, sorted, '+'-joined
    status      TEXT NOT NULL,       -- draft | provisioning | live | degraded | archived
    tenant_id   TEXT NOT NULL,       -- the tenant whose db + secrets it owns
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS venture_by_account ON venture (account_id);
