-- Per-recipient language (issue #190).
--
-- Its own migration because 0001 to 0005 are applied, and an applied
-- migration is never edited.
--
-- The language a notification is written in cannot be chosen when it is
-- queued: one account can have an English browser and a Bahasa phone, and
-- the caller knows about neither. It is resolved at delivery, per
-- recipient, from these two columns and the venture's default.

-- The device's own setting, as the client sent it or as `Accept-Language`
-- said at registration. NULL means "this device never said", which is not
-- the same as "this device wants the default": the account's answer is
-- consulted next, and only then the venture's.
--
-- Only a parsed, canonicalised BCP 47 tag is ever written here. The value
-- arrives from a request body or a header, so it is parsed at the route
-- and a tag that does not parse is dropped rather than stored — which is
-- what keeps this column short, and keeps arbitrary header text out of
-- every log, export and rendered page downstream.
ALTER TABLE notifications_subscriptions ADD COLUMN locale TEXT;

-- The account's own answer: one inbox, one mailbox, one language for
-- both.
--
-- A table of its own rather than a row in `notifications_preferences`,
-- which the issue proposed before that table existed. Preferences are
-- keyed `(account_id, category)` with three NOT NULL channel switches,
-- so an account-level row would have to invent a category name and
-- three booleans that mean nothing. A locale is not a preference about
-- a category.
CREATE TABLE IF NOT EXISTS notifications_locales (
    account_id TEXT PRIMARY KEY,
    locale TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- What an inbox row was rendered in, so a client can set `lang` and `dir`
-- on the item and a reader of Arabic is not shown right-to-left text laid
-- out left to right. NULL for every row written before this migration,
-- and for a venture that renders its own strings.
ALTER TABLE notifications_inbox ADD COLUMN locale TEXT;

-- The message the row was rendered from, kept beside the rendered text so
-- a client that wants to re-render in another language can. The module
-- never re-renders a stored row itself: changing an account's locale does
-- not rewrite its history, which is stated plainly in docs/NOTIFICATIONS.md
-- rather than hidden.
ALTER TABLE notifications_inbox ADD COLUMN loc_key TEXT;
ALTER TABLE notifications_inbox ADD COLUMN loc_args_json TEXT;
