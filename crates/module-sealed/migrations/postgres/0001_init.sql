-- The sealed store's three tables (issue #757); see the sqlite set for
-- what they are. Postgres differs from the sqlite set in two ways: BYTEA,
-- not BLOB, which Postgres does not have, and append-only enforced by a
-- plpgsql trigger function rather than RAISE(ABORT).

CREATE TABLE IF NOT EXISTS sealed_blobs (
    subject                TEXT NOT NULL,
    blob_id                TEXT NOT NULL,
    version                INTEGER NOT NULL,
    purpose                TEXT NOT NULL,
    alg                    TEXT NOT NULL,
    wraps                  TEXT NOT NULL,
    created_by_credential  TEXT NOT NULL,
    ciphertext_len         INTEGER NOT NULL,
    -- The outer-wrapped body when it fits inline; NULL when it went to the
    -- blob store under `object_key`.
    outer_ct               BYTEA,
    object_key             TEXT,
    -- The server-side validator behind `ETag`/`If-Match`; see the
    -- sqlite set.
    revision               INTEGER NOT NULL,
    created_at             TEXT NOT NULL,
    updated_at             TEXT NOT NULL,
    PRIMARY KEY (subject, blob_id)
);

CREATE TABLE IF NOT EXISTS sealed_deks (
    subject       TEXT NOT NULL,
    blob_id       TEXT NOT NULL,
    kms_provider  TEXT NOT NULL,
    kms_key_ref   TEXT NOT NULL,
    wrapped_dek   BYTEA NOT NULL,
    revision      INTEGER NOT NULL,
    PRIMARY KEY (subject, blob_id)
);

CREATE TABLE IF NOT EXISTS sealed_audit (
    seq        INTEGER PRIMARY KEY,
    ts         TEXT NOT NULL,
    subject    TEXT NOT NULL,
    action     TEXT NOT NULL,
    blob_id    TEXT NOT NULL,
    version    INTEGER NOT NULL,
    prev_hash  BYTEA NOT NULL,
    hash       BYTEA NOT NULL
);

CREATE OR REPLACE FUNCTION sealed_audit_append_only()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'sealed_audit is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS sealed_audit_no_change ON sealed_audit;
CREATE TRIGGER sealed_audit_no_change
BEFORE UPDATE OR DELETE ON sealed_audit
FOR EACH ROW EXECUTE FUNCTION sealed_audit_append_only();
