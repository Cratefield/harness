-- The #182 review: bound and record cross-account device take-overs, and
-- give `Outbox::claim_due` an index to read.
--
-- `0001_init.sql` shipped in #222 and is applied, so these arrive as their
-- own migration rather than as edits to it: an edited migration never
-- reaches a venture that already ran the original, and the harness locks
-- each collected file by content (`locked-migration-edited`).

-- When this row last changed account, and NULL for the ordinary case of a
-- device that has only ever had one. A device token is not an
-- authenticator, so taking a device over needs no proof beyond holding the
-- token: this column is what bounds how many take-overs one account gets
-- in an hour, and it is the record ops reads when someone reports a phone
-- that went quiet.
ALTER TABLE notifications_subscriptions ADD COLUMN rehomed_at TEXT;

-- `Outbox::claim_due` filters and orders on `next_attempt_at`, and it runs
-- on every request that sends a notification and on every scheduled tick.
-- It is the hottest read the module has; without this it is the only one
-- that scans the whole table.
CREATE INDEX IF NOT EXISTS notifications_outbox_due
    ON notifications_outbox (next_attempt_at);
