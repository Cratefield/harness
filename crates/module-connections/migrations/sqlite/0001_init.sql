-- One row per third-party connection (issue #624): who connected which
-- provider, and the two sealed tokens that keep it alive. Both tokens are
-- stored only in the sealed form `XChaChaSealer` writes and are bound to the
-- row and column they belong to, so a blob copied into another row or column
-- fails to open. `status` is one of `active`, `needs_reconnect`, `revoked`:
-- a refresh token the provider rejects moves a row to `needs_reconnect` (a
-- human must authorize again), a user-initiated `revoke` moves it to
-- `revoked` and clears both token columns. Every timestamp is an RFC 3339
-- UTC string with whole seconds, so the comparisons the refresh pass makes
-- are the ones the columns can carry.
CREATE TABLE IF NOT EXISTS connection (
    id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    provider TEXT NOT NULL,
    external_account_id TEXT,
    display_name TEXT,
    scopes TEXT NOT NULL,
    status TEXT NOT NULL,
    access_token_sealed TEXT,
    refresh_token_sealed TEXT,
    access_expires_at TEXT,
    refresh_expires_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
-- A person's connections are listed by subject, so that is the index the
-- list and the privacy erasure scan.
CREATE INDEX IF NOT EXISTS connection_subject_idx ON connection (subject);
-- The refresh pass scans the active rows due to expire, so the index it
-- reads is (status, access_expires_at): status narrows to the live rows and
-- the second column orders the rest by when they lapse.
CREATE INDEX IF NOT EXISTS connection_refresh_idx ON connection (status, access_expires_at);

-- One row per connect attempt still in flight. The `state` reaches this
-- table only as its SHA-256 hash, so a database dump, a backup or a query
-- log holds nothing that can be replayed as one. `return_to` is the URL the
-- browser is sent back to after the callback; its origin is checked against
-- the venture's allowed origins before the row is written and again before
-- the redirect. `verifier_sealed` is the PKCE verifier, sealed with the
-- state row's id in its AAD so it cannot be lifted into another attempt.
-- `spent_at` records the guarded single-use consume; `expires_at` is the
-- ten-minute deadline the scheduled purge removes rows past.
CREATE TABLE IF NOT EXISTS connection_state (
    state_hash TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    provider TEXT NOT NULL,
    return_to TEXT NOT NULL,
    verifier_sealed TEXT,
    expires_at TEXT NOT NULL,
    spent_at TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS connection_state_expires_idx ON connection_state (expires_at);
