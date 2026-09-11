CREATE TABLE IF NOT EXISTS sidecar_notes (
    id TEXT PRIMARY KEY,
    text TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sidecar_notes_created_at
    ON sidecar_notes (created_at);
