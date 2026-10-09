-- The sealed store's three tables (issue #757), in the portable SQL subset
-- (ADR 0004). The `migrations/postgres` set differs only in the word for a
-- binary column and in how append-only is enforced: a plpgsql trigger
-- function rather than RAISE(ABORT).
--
-- The layout is the crypto-shredding contract. The client's ciphertext
-- exists in exactly one place (`sealed_blobs.outer_ct`, or the blob-store
-- object `object_key` names); the only key that opens it lives in
-- `sealed_deks`. Deleting the DEK row first is the shred: every remaining
-- copy of the body, in whatever store, is inert bytes from then on.

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
    outer_ct               BLOB,
    object_key             TEXT,
    -- The server-side validator behind `ETag`/`If-Match`: replaced with a
    -- fresh value by every mutation, and what every guarded mutation's WHERE
    -- clause must match. `version` cannot serve — it is the client's, and
    -- its payload's AAD binds it.
    revision               INTEGER NOT NULL,
    created_at             TEXT NOT NULL,
    updated_at             TEXT NOT NULL,
    PRIMARY KEY (subject, blob_id)
);

-- The wrapped data-encryption key, in a table of its own so erasure can
-- remove the key and the data with two statements and the shred is visible
-- as an absent row. `wrapped_dek` is opaque to this module: only the KMS
-- port can open it. `revision` moves in lockstep with `sealed_blobs`' so a
-- rotation can guard both rows with the one `If-Match` the caller holds.
CREATE TABLE IF NOT EXISTS sealed_deks (
    subject       TEXT NOT NULL,
    blob_id       TEXT NOT NULL,
    kms_provider  TEXT NOT NULL,
    kms_key_ref   TEXT NOT NULL,
    wrapped_dek   BLOB NOT NULL,
    revision      INTEGER NOT NULL,
    PRIMARY KEY (subject, blob_id)
);

-- The access chain (issue #757): one append-only row per create, read,
-- wrap edit, rotation and erasure. Every row's hash covers the previous
-- row's hash, so altering or removing any row breaks every link after it.
CREATE TABLE IF NOT EXISTS sealed_audit (
    seq        INTEGER PRIMARY KEY,
    ts         TEXT NOT NULL,
    subject    TEXT NOT NULL,
    action     TEXT NOT NULL,
    blob_id    TEXT NOT NULL,
    version    INTEGER NOT NULL,
    prev_hash  BLOB NOT NULL,
    hash       BLOB NOT NULL
);

-- Append-only, enforced by the database rather than by convention — the
-- same triggers the secrets store's audit chain carries. A `CREATE
-- TRIGGER` is portable enough for the subset both engines here accept.
CREATE TRIGGER IF NOT EXISTS sealed_audit_no_update
BEFORE UPDATE ON sealed_audit
BEGIN
    SELECT RAISE(ABORT, 'sealed_audit is append-only');
END;

CREATE TRIGGER IF NOT EXISTS sealed_audit_no_delete
BEFORE DELETE ON sealed_audit
BEGIN
    SELECT RAISE(ABORT, 'sealed_audit is append-only');
END;
