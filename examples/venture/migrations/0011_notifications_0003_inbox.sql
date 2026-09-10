-- The in-app inbox (issue #187): the channel that works without any
-- permission, and the only one the account can scroll back through.
--
-- A row is written on every `notify` for a category that declares
-- `in_app`, including when the account has no device and when its *push*
-- preference is off: those switch off push, not the record. The
-- `in_app` preference column already exists (0001), because #182 created
-- all three channel switches together so this child adds no second
-- migration stream to `notifications_preferences`.

CREATE TABLE IF NOT EXISTS notifications_inbox (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    -- The fan-out id shared with the push rows, so a client that already
    -- rendered the in-app item can dedupe the push that follows it.
    notification_id TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    url TEXT,
    icon TEXT,
    -- The notification's `data` object, as written to the push payload.
    data_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    -- NULL until the account reads it, and until it archives it. Both are
    -- timestamps rather than flags so retention can act on either.
    read_at TEXT,
    archived_at TEXT
);

-- The list read: one account's inbox, newest first.
--
-- On `(created_at, id)` and not on `id` alone. `id` comes from the `IdGen`
-- port, whose `UlidIdGen` reads the real clock and randomises the tail, so
-- two ids minted in the same millisecond have no defined order and neither
-- is tied to `created_at`, which comes from the `Clock` port. `created_at`
-- is the time the API reports, so it orders the list; `id` only breaks
-- ties, which is what makes the order total and the cursor exact.
CREATE INDEX IF NOT EXISTS notifications_inbox_by_account
    ON notifications_inbox (account_id, created_at DESC, id DESC);

-- The unread count, and the `unread=true` filter beside it.
CREATE INDEX IF NOT EXISTS notifications_inbox_unread
    ON notifications_inbox (account_id, read_at);
