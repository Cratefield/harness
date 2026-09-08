-- The provisioning progress of one venture: the last step that completed, and
-- the error if the run stopped. Keyed by venture so a resume knows exactly
-- where to pick up, and so a failure is recoverable (its step and message are
-- on record). Holds no secret: the platform credential and the venture's own
-- secrets live in the secrets store, never here.
CREATE TABLE provision_progress (
    venture_id TEXT PRIMARY KEY,
    last_step  TEXT NOT NULL DEFAULT '',  -- the last completed step, '' = none yet
    error      TEXT NOT NULL DEFAULT '',  -- the failing step's message, '' = none
    updated_at TEXT NOT NULL
);
