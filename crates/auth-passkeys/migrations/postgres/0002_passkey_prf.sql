-- The PRF extension (issue #756). This is the SQLite migration
-- `sqlite/0002_passkey_prf.sql` with one word changed: BYTEA, not BLOB,
-- which Postgres does not have. Nothing else differs, so the two dialects
-- carry the same columns in the same order under the same constraints.
--
-- `credential_id` is the authenticator's opaque id, exactly as
-- `credentials.passkey_credential_id` holds it — BYTEA there too, in
-- `postgres/0001_init.sql`. The row is created lazily the first time a salt
-- is needed, so a credential registered before this table existed gets one on
-- its next login. `supported` is sticky: one ceremony that evaluated the
-- extension proves the passkey can, and a later one reporting otherwise never
-- downgrades it. The salt comes from the same CSPRNG as the challenges and is
-- not a secret — the browser receives it, and the authenticator hashes its own
-- secret with it. An extension *output* has no column and is never stored; rows
-- go away with their credential (see `prf::forget` in src/prf.rs).
CREATE TABLE IF NOT EXISTS auth_passkeys_prf (
    credential_id BYTEA PRIMARY KEY,
    salt BYTEA NOT NULL,
    prf TEXT NOT NULL CHECK (prf IN ('supported', 'unsupported', 'unknown')),
    updated_at TEXT NOT NULL
);