-- The passkey offer's "Not now" ledger (see src/offer.rs): one row per
-- account that declined the offer to add a passkey at sign-in, and when.
--
-- Keyed by the account, not held in a cookie, so the snooze follows the
-- person across browsers. `dismissed_at` is an RFC 3339 instant. A later
-- "Not now" replaces the row. The row names an account, so it is erased
-- with the account (see `personal_data()` in src/lib.rs).
CREATE TABLE IF NOT EXISTS auth_passkeys_offer_dismissals (
    user_id TEXT PRIMARY KEY,
    dismissed_at TEXT NOT NULL
);
