-- Email as a notification channel (issue #189).
--
-- `notify()` runs inside another module's batch or off a bus event, where
-- there is no request and so no verified claims. The address therefore
-- cannot come from a token at send time: it is written here on an
-- authenticated route, where claims are available, and the drain reads
-- only this table. An account with no row simply gets no email, and an
-- unverified address is never mailed.

CREATE TABLE IF NOT EXISTS notifications_email_targets (
    account_id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    -- NULL until the address is proven. The drain refuses to send to an
    -- unverified address: an unverified one is somebody else's mailbox
    -- until proven otherwise, and mailing it is the mistake that gets a
    -- sending domain blocked.
    verified_at TEXT,
    -- Set by a one-click unsubscribe for `all`, and by a bounce once the
    -- provider webhook exists. Distinct from a per-category preference:
    -- this is the whole channel off for this address.
    unsubscribed_at TEXT,
    unsubscribed_reason TEXT,
    updated_at TEXT NOT NULL
);

-- The per-account per-category send window the cooldown counts over.
-- One row per mail actually sent, pruned by the same retention tick as
-- the inbox.
CREATE TABLE IF NOT EXISTS notifications_email_sends (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    category TEXT NOT NULL,
    sent_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS notifications_email_sends_window
    ON notifications_email_sends (account_id, category, sent_at);
