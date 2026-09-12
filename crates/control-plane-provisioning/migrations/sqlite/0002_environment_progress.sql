-- Provisioning progress for environments (control-plane #31).
--
-- The same shape as `provision_progress`, its own table: an
-- environment's run is not the venture's run. Recording a staging
-- environment's progress under the venture's ledger would make a
-- stopped staging run read as the venture itself failing to provision,
-- and reusing `provision_progress` with an environment id in its
-- `venture_id` column would put a lie in the column's name — the kind
-- of convenient fiction this control plane refuses to record.
CREATE TABLE IF NOT EXISTS environment_progress (
    environment_id TEXT PRIMARY KEY,
    last_step      TEXT NOT NULL,  -- the last step that completed; '' when the first step failed
    error          TEXT NOT NULL,  -- the recorded failure of a stopped run; '' while running clean
    updated_at     TEXT NOT NULL
);
