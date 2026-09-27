-- cratefield-module-webhooks, issue #536.
--
-- Portable subset (ADR 0004): TEXT ids (ULIDs), ISO-8601 TEXT timestamps,
-- INTEGER counters, no dialect functions. SQLite has no ENUM, so a closed
-- set is TEXT plus a CHECK constraint, which both SQLite/D1 and Postgres
-- accept.

-- One delivery target per subject. `secret` is credential material: it is
-- returned exactly once, at creation, and never listed.
CREATE TABLE IF NOT EXISTS webhooks_endpoints (
    id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    -- Comma-separated event types, or `*` for everything.
    event_types TEXT NOT NULL DEFAULT '*',
    created_at TEXT NOT NULL
);

-- Fan-out reads every endpoint of one subject, once per event.
CREATE INDEX IF NOT EXISTS webhooks_endpoints_by_subject
    ON webhooks_endpoints (subject);

-- The core `Outbox` table (#128), verbatim from `Outbox::create_table_sql`
-- — the unit test in `store.rs` fails if the two ever drift. One row per
-- (event, endpoint), so each endpoint retries independently.
CREATE TABLE IF NOT EXISTS webhooks_outbox (
    id TEXT PRIMARY KEY,
    topic TEXT NOT NULL,
    payload TEXT NOT NULL,
    subject TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    locked_until TEXT,
    created_at TEXT NOT NULL
);

-- The claim reads due rows in attempt order.
CREATE INDEX IF NOT EXISTS webhooks_outbox_by_due
    ON webhooks_outbox (next_attempt_at);

-- One row per attempt actually made, for the delivery log. `status_code`
-- is NULL when the transport failed before an answer (a timeout, a
-- refused destination), and `error` carries why.
CREATE TABLE IF NOT EXISTS webhooks_deliveries (
    id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    status_code INTEGER,
    error TEXT,
    at TEXT NOT NULL
);

-- The log is read per subject, newest first.
CREATE INDEX IF NOT EXISTS webhooks_deliveries_by_subject
    ON webhooks_deliveries (subject, at);

-- The terminal state core's `Outbox` does not have (ADR 0016). A row moves
-- here from `webhooks_outbox` in one batch and stays visible to
-- `fz data export`, which sees exactly what `Module::tables()` declares.
CREATE TABLE IF NOT EXISTS webhooks_dead_letters (
    id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    -- The caller's event payload, kept so `replay` can re-enqueue it
    -- without the original publisher being alive to republish.
    data TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    reason TEXT NOT NULL CHECK (
        reason IN ('attempts_exhausted', 'rejected', 'malformed')
    ),
    last_error TEXT NOT NULL,
    status_code INTEGER,
    created_at TEXT NOT NULL,
    failed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS webhooks_dead_letters_by_subject
    ON webhooks_dead_letters (subject);
