-- Organizations, their memberships and their invitations (issue #652). Three
-- tables, all keyed by plain TEXT ids the module mints (a ULID), so the set
-- is portable (ADR 0004): the Postgres runner applies this same file when the
-- portable-SQL lint passes. Every timestamp is an RFC 3339 UTC string with
-- whole seconds, so the comparisons the invitation path makes are the ones
-- the columns can carry.

-- One row per organization. `created_by` names the account that created it;
-- the org outlives that account, so it is declared `retain` rather than
-- erased (see `Module::personal_data`).
CREATE TABLE IF NOT EXISTS orgs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- One row per membership. `role` is one of the roles the venture configured;
-- `owner` is always among them and is the role the creator gets. `invited_by`
-- names whoever added them, when they did not create the org themselves.
-- The primary key makes a person's membership in one org unique, which is
-- what lets "add a member" be a guarded insert rather than a read-then-write.
CREATE TABLE IF NOT EXISTS org_members (
    org_id TEXT NOT NULL,
    user_sub TEXT NOT NULL,
    role TEXT NOT NULL,
    invited_by TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (org_id, user_sub)
);
-- "Which orgs do I belong to" is the read that runs on every request of an
-- app that scopes on membership, so `user_sub` is the index it scans.
CREATE INDEX IF NOT EXISTS org_members_user_idx ON org_members (user_sub);

-- One row per invitation. The raw token and the invitee's address never
-- reach this table: `token_hash` is the SHA-256 of the token the mail
-- carried, and `email_hash` the SHA-256 of the normalized address, so a dump
-- or a query log holds nothing that can be replayed or read back. The token
-- is single-use and lapses at `expires_at`: the one accept that finds
-- `accepted_at` still NULL stamps it, together with `spend_id` — the accept
-- call's own id — and the membership that accept adds is conditional on that
-- same `spend_id` in the same transaction, so no second accept can add
-- anybody and no spend can be spent twice.
CREATE TABLE IF NOT EXISTS org_invitations (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    email_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    invited_by TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    accepted_at TEXT,
    spend_id TEXT,
    created_at TEXT NOT NULL
);
-- The scheduled purge removes lapsed invitations, so it scans by expiry.
CREATE INDEX IF NOT EXISTS org_invitations_expires_idx ON org_invitations (expires_at);
