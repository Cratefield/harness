-- Issue #137: revocable per-subscription unsubscribe tokens. A signed
-- unsubscribe link stays live only while its signing key is in the
-- bounded ring (ADR 0014), so retiring a compromised key must not strand
-- subscribers. The opaque token below is minted with each confirmation
-- mail and lives in the row: revoking it is a row update, never a global
-- key decision. NULL means "never mailed since #137": the row answers
-- only its legacy signed link until the next mail rotates one in.
ALTER TABLE subscribers ADD COLUMN unsubscribe_token TEXT;

-- The unsubscribe endpoint resolves this column directly. Unique keeps
-- guesses structurally impossible; SQLite and Postgres both allow
-- multiple NULLs in a unique index.
CREATE UNIQUE INDEX IF NOT EXISTS subscribers_unsubscribe_token ON subscribers (unsubscribe_token);
