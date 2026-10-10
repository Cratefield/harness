-- The Telegram module's four tables (issue #764).

-- The dedup ledger over `Inbox::create_table_sql` (core): one row per
-- delivered update id, so Telegram's at-least-once redelivery is a no-op.
CREATE TABLE IF NOT EXISTS telegram_inbox (
    event_key TEXT PRIMARY KEY,
    seen_at TEXT NOT NULL
);

-- One-time link codes, stored only as the SHA-256 hash: the code itself
-- rides a Telegram deep link and never lands in the database.
CREATE TABLE IF NOT EXISTS telegram_link_codes (
    code_hash TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);

-- Who has linked their Telegram account. One row per subject; the
-- Telegram user id is unique across subjects, so one Telegram user can
-- stand behind at most one account.
CREATE TABLE IF NOT EXISTS telegram_links (
    subject TEXT PRIMARY KEY,
    telegram_user_id INTEGER NOT NULL UNIQUE,
    chat_id INTEGER NOT NULL,
    linked_at TEXT NOT NULL
);

-- One consent request: what the venture asked, whether it moves value,
-- and where the decision stands. A Telegram tap alone never moves a row
-- past `awaiting_passkey` — only the web app's passkey-confirmed
-- `/confirm` route does.
CREATE TABLE IF NOT EXISTS telegram_actions (
    action_id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    action TEXT NOT NULL,
    value_moving INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','approved','denied','awaiting_passkey')),
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    decided_at TEXT
);
