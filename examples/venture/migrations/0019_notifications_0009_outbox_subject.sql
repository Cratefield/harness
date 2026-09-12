-- The subject a queued notification is for (issue #266).
--
-- Its own migration because 0001 to 0008 are applied, and an applied
-- migration is never edited.
--
-- The value is already in the row, and unreachable there: `payload` is the
-- serialised job and both job shapes carry an `account_id`, but export and
-- erasure key on a *column* (`... WHERE subject = ?`), and reading it out of
-- JSON would be dialect-specific SQL the portable subset forbids (ADR 0004).
-- Until now the outbox could only be published as `unreachable` — a queued
-- copy of a person's message sat outside the erasure catalogue.
--
-- Nullable and not backfilled. A row written before this migration keeps
-- NULL, drains exactly as before, and is returned for nobody's subject:
-- guessing an account for it out of the payload would put the privacy
-- module in the business of parsing every module's JSON.
ALTER TABLE notifications_outbox ADD COLUMN subject TEXT;

-- Erasure counts the rows, deletes them, then counts again to prove it, so
-- the column it matches on gets the index the due-time column already has.
CREATE INDEX IF NOT EXISTS notifications_outbox_by_subject
    ON notifications_outbox (subject);
