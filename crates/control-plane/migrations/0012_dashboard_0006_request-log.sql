-- The control plane's own request log: one row per request this
-- dashboard's router served, so the Logs screen has something truthful to
-- show. The columns are deliberately the minimum an operator needs to
-- answer "what happened" — when, method, path, status, duration, and the
-- account the session belonged to when there was one. No query string, no
-- body, no header is recorded: a path is a path, and everything else is
-- where personal data and credentials live. The SQL is the portable
-- subset both engines accept, so the one file serves the SQLite and the
-- Postgres migration sets (ADR 0004).
CREATE TABLE request_log (
    -- ULID. Its first 48 bits are the millisecond, so it sorts by time
    -- across milliseconds; inside one, the remaining 80 bits are random
    -- and two rows sort arbitrarily. Reads order by `at` first and use
    -- the id only to break a tie, which is as much order as a
    -- millisecond-resolution clock can honestly give.
    id          TEXT PRIMARY KEY,
    at          TEXT NOT NULL,               -- RFC 3339, when the request arrived
    method      TEXT NOT NULL,
    path        TEXT NOT NULL,               -- the path only; the query string never reaches here
    status      INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    account_id  TEXT NOT NULL DEFAULT ''     -- the session's account, '' when nobody was signed in
);

-- Retention scans `at` on every recorded write; the prefix filter scans
-- `path`. Both stay cheap and indexed rather than turning the screen into
-- a table scan.
CREATE INDEX request_log_at ON request_log (at);
CREATE INDEX request_log_path ON request_log (path);
