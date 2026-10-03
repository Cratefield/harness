-- The Backups screen's records (issue #29): every backup attempt, and
-- every restore rehearsal.
--
-- A FAILED attempt is a row too. A backup history that only records
-- successes is how people find out at restore time: the failure you
-- could have acted on was quietly not written down. The screen renders
-- both verdicts from this table and nothing else.
--
-- backup_attempt holds no credential and no data from any venture's
-- database: what was backed up (a scope key, 'control-plane' today),
-- who or what asked (an operator identity, or a job name once
-- scheduling exists), where it went (a destination string -- 'operator
-- download' for the export this screen serves, an object URL once an
-- R2 adapter exists), the size and sha256 of what was produced, and
-- whether it succeeded.
--
-- restore_rehearsal is the proof the pipeline was ever exercised: which
-- attempt was rehearsed against, by whom, when, and what they saw. An
-- empty table is the honest 'never rehearsed' the screen shows rather
-- than confidence nobody earned.
--
-- As with hostname above: no cross-module REFERENCES, isolation by
-- query.
CREATE TABLE IF NOT EXISTS backup_attempt (
    id           TEXT PRIMARY KEY,     -- ULID
    account_id   TEXT NOT NULL,        -- the account of the operator who acted
    scope        TEXT NOT NULL,        -- what was backed up: 'control-plane' today
    requested_by TEXT NOT NULL,        -- the operator identity, or the job that asked
    destination  TEXT NOT NULL DEFAULT '', -- where it went; '' when it went nowhere
    size_bytes   INTEGER,              -- NULL when nothing was produced
    sha256       TEXT NOT NULL DEFAULT '',
    succeeded    INTEGER NOT NULL,     -- 0 | 1
    error        TEXT NOT NULL DEFAULT '',
    started_at   TEXT NOT NULL,        -- RFC 3339
    finished_at  TEXT NOT NULL         -- RFC 3339
);

CREATE INDEX IF NOT EXISTS backup_attempt_by_account ON backup_attempt (account_id);

CREATE TABLE IF NOT EXISTS restore_rehearsal (
    id           TEXT PRIMARY KEY,     -- ULID
    account_id   TEXT NOT NULL,        -- the account of the operator who rehearsed
    attempt_id   TEXT NOT NULL,        -- the backup_attempt it was rehearsed against
    rehearsed_by TEXT NOT NULL,        -- the operator identity
    outcome      TEXT NOT NULL,        -- what the operator saw, in their words
    rehearsed_at TEXT NOT NULL         -- RFC 3339
);

CREATE INDEX IF NOT EXISTS rehearsal_by_account ON restore_rehearsal (account_id);
