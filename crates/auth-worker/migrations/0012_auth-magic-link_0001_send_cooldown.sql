-- The durable one-send-per-window ledger for sign-in links (issue #133's
-- shape). The rate limiter is a distributed counter whose transport can
-- fail open; this row is what the database enforces.
--
-- `subject` is the normalised address, on its own and not joined to
-- anything else, so a subject access request can reach it with the
-- address alone — see `personal_data()` in src/lib.rs.
CREATE TABLE IF NOT EXISTS auth_magic_link_send_cooldown (
    subject TEXT PRIMARY KEY,
    last_sent_at TEXT NOT NULL
);
