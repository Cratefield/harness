-- The passkey offer's "Not now" ledger (see src/offer.rs). This is the SQLite
-- migration `sqlite/0003_offer_dismissals.sql` with nothing changed: both
-- dialects carry the same columns under the same constraints, and TEXT is the
-- same type in both.
--
-- Keyed by the account, not held in a cookie, so the snooze follows the
-- person across browsers. `dismissed_at` is an RFC 3339 instant. A later
-- "Not now" replaces the row. The row names an account, so it is erased
-- with the account (see `personal_data()` in src/lib.rs).
CREATE TABLE IF NOT EXISTS auth_passkeys_offer_dismissals (
    user_id TEXT PRIMARY KEY,
    dismissed_at TEXT NOT NULL
);
