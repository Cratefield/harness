-- The dedup ledger over `Inbox::create_table_sql` (core): one row per
-- delivered event id, so a redelivery is a no-op. A ledger, not a record —
-- the event payloads live only on the bus.
CREATE TABLE IF NOT EXISTS owlpost_inbox (
    event_key TEXT PRIMARY KEY,
    seen_at TEXT NOT NULL
);
