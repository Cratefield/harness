-- One row per device authorization request (RFC 8628, issue #587). The
-- table stores both codes as SHA-256 hashes and nothing else: a
-- `device_code` is a bearer credential the polling client presents, and a
-- `user_code` is the short string a person reads off a screen, so a
-- database dump, a backup or a log line must not be replayable as either.
-- Both columns are therefore `*_hash`, and no clear-text column exists.
--
-- `status` is one of `pending`, `approved`, `denied`, `consumed`. The
-- guarded conditional UPDATE that moves it is the single-use check: exactly
-- one caller per transition sees a row count of one. `last_polled_at` and
-- `interval_secs` implement RFC 8628 §3.5's polling interval, held per row
-- so a `slow_down` widens the wait by five seconds without a second table.
-- `expires_at` is the moment the pair stops being usable; the scheduled
-- purge deletes rows past it. Every timestamp is an RFC 3339 UTC string
-- with whole seconds, so the comparisons the handlers make are the ones
-- the columns can carry.
CREATE TABLE IF NOT EXISTS device_auth_codes (
    device_code_hash TEXT PRIMARY KEY,
    user_code_hash TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    name TEXT,
    status TEXT NOT NULL,
    approver_subject TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_polled_at TEXT,
    interval_secs INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS device_auth_codes_expires_idx ON device_auth_codes (expires_at);
CREATE INDEX IF NOT EXISTS device_auth_codes_status_idx ON device_auth_codes (status);
