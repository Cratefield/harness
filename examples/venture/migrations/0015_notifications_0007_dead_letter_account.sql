-- The account a dead letter was for (issue #244).
--
-- Its own migration because 0001 to 0006 are applied, and an applied
-- migration is never edited.
--
-- The value is already in the row, and unreachable there: `payload` is the
-- serialised job and both job shapes carry an `account_id`, but export and
-- erasure key on a *column* (`... WHERE account_id = ?`), and reading it out
-- of JSON would be dialect-specific SQL the portable subset forbids
-- (ADR 0004). So a notification that gave up sat outside the erasure
-- catalogue while the same message, still in `notifications_inbox`, was
-- inside it. A dead letter holds the title and body written to one person;
-- it goes when they ask.
--
-- Nullable and not backfilled. A row written before this migration keeps
-- NULL, and so does one whose payload never parsed as a job (the `malformed`
-- reason) — that row names nobody, and guessing an account for it would be
-- worse than admitting none.
ALTER TABLE notifications_dead_letters ADD COLUMN account_id TEXT;

-- Erasure counts the rows, deletes them, then counts again to prove it, so
-- the column it matches on gets the index every other account-keyed table
-- here already has.
CREATE INDEX IF NOT EXISTS notifications_dead_letters_by_account
    ON notifications_dead_letters (account_id);
