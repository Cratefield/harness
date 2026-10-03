-- auth issue #650 part B: the user import. An imported person is an
-- identities row with the new provider "import", whose provider_subject is
-- "<external_provider>:<external_id>"; the provider CHECK has to admit it.
-- Postgres can alter a named CHECK constraint in place, so the table is
-- not rebuilt: the column's own check — which Postgres names
-- identities_provider_check from its table and column — is dropped and
-- re-added with the widened list (harness issue #18, ADR 0004: a dialect
-- override holds only where the SQL truly differs).

ALTER TABLE identities DROP CONSTRAINT identities_provider_check;
ALTER TABLE identities ADD CONSTRAINT identities_provider_check CHECK (provider IN ('google','apple','meta','password','magic_link','passkey','import'));
