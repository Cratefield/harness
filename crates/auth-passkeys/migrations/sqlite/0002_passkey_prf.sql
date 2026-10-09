-- The PRF extension (issue #756): one row per passkey, holding the random
-- salt `login/options` hands out (`prf.eval.first` or, keyed by credential
-- id, `prf.evalByCredential`) and what the ceremonies so far showed about
-- whether the authenticator can answer the extension at all.
--
-- `credential_id` is the authenticator's opaque id, exactly as
-- `credentials.passkey_credential_id` holds it. The row is created lazily
-- the first time a salt is needed, so a credential registered before this
-- table existed gets one on its next login. `supported` is sticky: one
-- ceremony that evaluated the extension proves the passkey can, and a
-- later one reporting otherwise never downgrades it. The salt comes from
-- the same CSPRNG as the challenges and is not a secret — the browser
-- receives it, and the authenticator hashes its own secret with it. An
-- extension *output* has no column and is never stored; rows go away with
-- their credential (see `prf::forget` in src/prf.rs).
CREATE TABLE IF NOT EXISTS auth_passkeys_prf (
    credential_id BLOB PRIMARY KEY,
    salt BLOB NOT NULL,
    prf TEXT NOT NULL CHECK (prf IN ('supported', 'unsupported', 'unknown')),
    updated_at TEXT NOT NULL
);
