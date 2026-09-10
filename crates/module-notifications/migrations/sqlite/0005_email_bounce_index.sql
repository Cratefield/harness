-- Bounce suppression reads the target table by address (issue #233).
--
-- Every other access to `notifications_email_targets` is by
-- `account_id`, which is the primary key. The provider webhook is the
-- exception: Resend reports a bounce against the address it tried, and
-- knows nothing about accounts. Without this index that lookup is a scan
-- of every address the venture holds, on a table that grows with the
-- account list.
--
-- Deliberately not UNIQUE: two accounts sharing a mailbox is ordinary —
-- a couple, a shared team address — and both of them must be suppressed
-- when it bounces.
--
-- Its own migration because 0004 is applied, and an applied migration is
-- never edited.
CREATE INDEX IF NOT EXISTS notifications_email_targets_address
    ON notifications_email_targets (email);
