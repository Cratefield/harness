-- Two things the review of #182 found, after 0001 had already shipped.
--
-- `rehomed_at`: when this row last changed account, NULL for the ordinary
-- case of a device that has only ever had one. A device token is not an
-- authenticator — taking a device over needs no proof beyond holding the
-- token — so this column is what bounds how many take-overs one account
-- gets in an hour, and it is the record ops reads when someone reports a
-- phone that went quiet.
ALTER TABLE notifications_subscriptions ADD COLUMN rehomed_at TEXT;

-- `claim_due` is the hottest read in the module: every notifying request
-- drains, and so does every cron tick. Without this it filters and sorts
-- on `next_attempt_at` across every queued, leased and retry-scheduled
-- row. 0001 indexed a far colder read and missed this one.
CREATE INDEX IF NOT EXISTS notifications_outbox_due
    ON notifications_outbox (next_attempt_at);
