-- cratefield-module-notifications, issue #182.
--
-- Portable subset (ADR 0004): TEXT ids, ISO-8601 TEXT timestamps, integer
-- booleans, no dialect functions. SQLite has no ENUM, so a closed set is
-- TEXT plus a CHECK constraint, which is the same shape in the portable
-- stream and in Postgres.

CREATE TABLE IF NOT EXISTS notifications_subscriptions (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    transport TEXT NOT NULL CHECK (transport IN ('apns', 'fcm', 'webpush')),
    -- The serialised `Recipient`. Credential material (ADR 0015): it goes
    -- where secrets go and never into a log, an event payload or a
    -- response body.
    recipient_json TEXT NOT NULL,
    -- SHA-256 of the canonical recipient, hex. Re-registering the same
    -- device is an upsert on it, and a device that moves account re-homes
    -- onto the new one instead of accumulating a second row.
    recipient_hash TEXT NOT NULL,
    app_id TEXT,
    app_version TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    UNIQUE (transport, recipient_hash)
);

-- Fan-out reads every live subscription for one account, once per
-- notification.
CREATE INDEX IF NOT EXISTS notifications_subscriptions_by_account
    ON notifications_subscriptions (account_id);

-- All three channel switches are created here, in the first migration,
-- although the in-app inbox (#187) and email (#189) children are what give
-- the last two meaning: three sibling issues editing one table in the same
-- migration stream would collide. This child reads only `push`.
--
-- A row exists only for a category an account has an opinion about.
-- Absent means "the category's declared default", so a venture changing a
-- default moves exactly the accounts that never chose.
CREATE TABLE IF NOT EXISTS notifications_preferences (
    account_id TEXT NOT NULL,
    category TEXT NOT NULL,
    push INTEGER NOT NULL,
    in_app INTEGER NOT NULL,
    email INTEGER NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (account_id, category)
);

-- The core `Outbox` table (#128), verbatim from `Outbox::create_table_sql`
-- — `tests/schema.rs` fails if the two ever drift.
CREATE TABLE IF NOT EXISTS notifications_outbox (
    id TEXT PRIMARY KEY,
    topic TEXT NOT NULL,
    payload TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    locked_until TEXT,
    created_at TEXT NOT NULL
);

-- The terminal state core's `Outbox` does not have (ADR 0016). A row moves
-- here from `notifications_outbox` in one batch: a send that will never
-- succeed leaves the work queue and stays visible to `fz data export`,
-- which sees exactly what `Module::tables()` declares.
CREATE TABLE IF NOT EXISTS notifications_dead_letters (
    id TEXT PRIMARY KEY,
    topic TEXT NOT NULL,
    payload TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    reason TEXT NOT NULL CHECK (
        reason IN (
            'rejected',
            'not_configured',
            'attempts_exhausted',
            'malformed'
        )
    ),
    last_error TEXT NOT NULL,
    created_at TEXT NOT NULL,
    failed_at TEXT NOT NULL
);
