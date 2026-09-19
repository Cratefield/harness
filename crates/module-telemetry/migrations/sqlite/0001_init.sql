-- Aggregate usage telemetry (issue #413). Two tables, both aggregate: a
-- batch never becomes a row per event, it accumulates into one bucket per
-- dimension tuple, so a client that runs a command ten thousand times
-- leaves one row behind per day, not ten thousand rows. `bucket_key` is
-- that dimension tuple joined with `|`, day first: two writes on
-- different days are different buckets, and a bucket is where an
-- install's counts accumulate for one day. The join is unambiguous
-- without claiming the venture-declared event name cannot carry a `|` —
-- it could, before validate_config refuses it: the six components before
-- the name and the three after it are closed values (the ISO day, the
-- 32-hex install id, enum wire names, the version triple) that cannot,
-- so the tuple splits uniquely from both ends regardless.
CREATE TABLE IF NOT EXISTS telemetry_events (
    bucket_key TEXT PRIMARY KEY,
    day TEXT NOT NULL,
    install_id TEXT NOT NULL,
    client_kind TEXT NOT NULL,
    client_version TEXT NOT NULL,
    platform TEXT NOT NULL,
    arch TEXT NOT NULL,
    event TEXT NOT NULL,
    outcome TEXT NOT NULL,
    error_kind TEXT NOT NULL,
    duration_bucket TEXT NOT NULL,
    events INTEGER NOT NULL DEFAULT 0,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS telemetry_events_day_idx ON telemetry_events (day);
CREATE INDEX IF NOT EXISTS telemetry_events_install_idx ON telemetry_events (install_id);

-- The payload's `modules` list, flattened: which of the venture's declared
-- modules a reporting client composes, one row per install and day. The
-- primary key makes a module reported twice in one day one row, which is
-- what the ingest's ON CONFLICT DO NOTHING relies on.
CREATE TABLE IF NOT EXISTS telemetry_modules (
    install_id TEXT NOT NULL,
    day TEXT NOT NULL,
    module TEXT NOT NULL,
    PRIMARY KEY (install_id, day, module)
);
