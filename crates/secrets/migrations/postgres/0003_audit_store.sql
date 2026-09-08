-- Store attribution on the audit chain (issue #142); see the sqlite set
-- for the whole story. Postgres differs in nothing here: the column,
-- the empty default for pre-migration rows, and the index are the same
-- portable statements (ADR 0004).
ALTER TABLE harness_secret_audit ADD COLUMN IF NOT EXISTS store TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS harness_secret_audit_store_seq
    ON harness_secret_audit (store, seq);
