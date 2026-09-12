-- Environments (control-plane #31). A venture's environments: each one
-- has its own database, its own secret store and its own module set, so
-- a schema change can be rehearsed somewhere that is not production.
--
-- Production is deliberately NOT a row here. Production is the venture
-- as it already exists -- its tenant, its module set, its subdomain --
-- and a mirrored "production" row would be a second copy of three
-- columns that every existing write path (the module-set editor, the
-- provisioning engine's status moves) would have to keep in sync. One
-- missed path and the record lies. The repository derives production
-- from the venture instead, and this table holds only the environments
-- a venture did not have before: staging, and whatever else is named
-- alongside it.
--
-- Interim, same as `venture`: isolation is by query through the
-- repository, every read scoped through the venture's account.
CREATE TABLE IF NOT EXISTS environment (
    id          TEXT PRIMARY KEY,     -- ULID
    venture_id  TEXT NOT NULL REFERENCES venture (id),
    name        TEXT NOT NULL,        -- "staging", ...; "production" is reserved for the venture itself
    tenant_id   TEXT NOT NULL,        -- the tenant whose db + secrets this environment owns
    module_set  TEXT NOT NULL,        -- the resolved slugs, sorted, '+'-joined
    subdomain   TEXT NOT NULL UNIQUE, -- where this environment would answer, beside the venture's own
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    UNIQUE (venture_id, name)
);

CREATE INDEX IF NOT EXISTS environment_by_venture ON environment (venture_id);
