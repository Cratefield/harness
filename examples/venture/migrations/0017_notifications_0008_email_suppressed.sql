-- Issue #232: a notification the per-category cooldown suppressed has to
-- leave a trace, so the scheduled drain can coalesce the burst into one
-- summary mail once the window has rolled. One row per suppressed
-- notification; the rows for a burst are deleted when its summary is sent,
-- which is what makes a second tick a no-op.
CREATE TABLE IF NOT EXISTS notifications_email_suppressed (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    category TEXT NOT NULL,
    notification_id TEXT NOT NULL UNIQUE,
    suppressed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS notifications_email_suppressed_window
    ON notifications_email_suppressed (account_id, category, suppressed_at);
