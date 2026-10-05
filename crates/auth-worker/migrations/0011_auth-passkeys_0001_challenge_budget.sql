-- The durable challenge budget behind `login/options` (see `budget` in
-- src/budget.rs and `limit_challenges` in src/request.rs). The rate limiter
-- is an optional port, so a composition without one used to leave the
-- endpoint an unlimited enumeration oracle and write amplifier; this row is
-- what the database enforces instead, on the same terms the send-cooldown
-- ledger is for sign-in links.
--
-- `subject` is a composite key: `ip:<client address>` for the request
-- itself and `email:<normalized address>` when the browser named an
-- account. The composite form is why this table is declared Unreachable in
-- `personal_data()` — the same shape the waitlist cooldown has — and the
-- rows are short-lived: the scheduled handler deletes anything whose window
-- closed more than a day ago.
CREATE TABLE IF NOT EXISTS auth_passkeys_challenge_budget (
    subject TEXT PRIMARY KEY,
    window_started_at TEXT NOT NULL,
    issued INTEGER NOT NULL
);
