-- Issue #914: passkey-first sign-up without an email address. Three tables,
-- all portable DDL, so the Postgres set reuses this file (ADR 0004).
--
-- recovery_codes: one-time codes an account can sign back in with when it has
-- no other way in. Only an Argon2id hash of each code is stored, never the
-- code. A code is spent once (used_at); regenerating deletes the set.
CREATE TABLE recovery_codes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    -- Argon2id PHC string of the code
    code_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    used_at TEXT
);

CREATE INDEX recovery_codes_by_user ON recovery_codes (user_id);

-- security_notices: what happened to the account's sign-in, for the signed-in
-- person to read in the app. Written beside every passkey or address change
-- and every recovery, so an account with no address still hears of them.
CREATE TABLE security_notices (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    -- a short machine kind, e.g. passkey_added, recovery_used
    kind TEXT NOT NULL,
    -- the sentence shown to the person
    detail TEXT NOT NULL,
    created_at TEXT NOT NULL,
    read_at TEXT
);

CREATE INDEX security_notices_by_user ON security_notices (user_id);

-- terms_acceptances: the terms and privacy versions an account accepted at
-- sign-up, with when. The versions are the deployment's, as shown.
CREATE TABLE terms_acceptances (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    terms_version TEXT NOT NULL,
    privacy_version TEXT NOT NULL,
    accepted_at TEXT NOT NULL
);

CREATE INDEX terms_acceptances_by_user ON terms_acceptances (user_id);
