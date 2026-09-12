-- Store attribution on the secrets and key tables (the row-level twin
-- of the audit chain's #142); see the sqlite set for the whole story.
-- Postgres differs only in BYTEA for BLOB and in spelling `IF NOT
-- EXISTS` on the ADD COLUMN the same way (ADR 0004's portable subset).
CREATE TABLE harness_secrets_attributed (
    name       TEXT NOT NULL,
    version    INTEGER NOT NULL,
    key_id     TEXT NOT NULL REFERENCES harness_secret_keys (key_id),
    nonce      BYTEA NOT NULL,
    ciphertext BYTEA NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    deleted_at TEXT,
    store      TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (store, name, version)
);

INSERT INTO harness_secrets_attributed
    (name, version, key_id, nonce, ciphertext, created_at, created_by, deleted_at, store)
    SELECT name, version, key_id, nonce, ciphertext, created_at, created_by, deleted_at, ''
    FROM harness_secrets;

DROP TABLE harness_secrets;

ALTER TABLE harness_secrets_attributed RENAME TO harness_secrets;

ALTER TABLE harness_secret_keys ADD COLUMN IF NOT EXISTS store TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS harness_secrets_store_name
    ON harness_secrets (store, name);

CREATE INDEX IF NOT EXISTS harness_secret_keys_store_state
    ON harness_secret_keys (store, state);
