-- Issue #912: step-up re-authentication, roles and the per-client roles
-- claim. Three additive columns, all portable DDL, so the Postgres set
-- reuses this file unchanged (ADR 0004).
--
-- 1. users.role: the account's role in this instance, one of owner, admin
--    or member. Every existing account is a member; ownership is granted
--    through the admin API (POST /admin/users/{sub}/role), never by a
--    client, and is emitted as the roles claim only for clients that
--    asked for it (clients.roles_claim).
-- 2. users.reauth_requested_at: when a request last demanded a fresh
--    authentication ceremony for this account (prompt=login, or max_age=0).
--    A ceremony that completes after it satisfies the demand. NULL when
--    nothing is pending.
-- 3. clients.roles_claim: whether this client's tokens carry roles.
--    Off by default, so an existing client's tokens do not change shape.
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'member'
    CHECK (role IN ('owner','admin','member'));
ALTER TABLE users ADD COLUMN reauth_requested_at TEXT;
ALTER TABLE clients ADD COLUMN roles_claim INTEGER NOT NULL DEFAULT 0
    CHECK (roles_claim IN (0,1));
