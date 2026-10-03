-- One custom hostname, claimed by one venture (the Domains screen,
-- issue #30).
--
-- A venture is reachable at its subdomain today; this table is how a
-- customer puts their own hostname in front of it through Cloudflare for
-- SaaS. The state column is a typed lifecycle (added -> awaiting DNS ->
-- verifying -> certificate issuing -> live, with failed recoverable only
-- by starting the flow again), never free text: the same rule the
-- venture table follows on its status.
--
-- The hostname is stored in its ASCII (punycode) form -- the form DNS
-- speaks -- normalised on the way in, and UNIQUE across the whole table
-- because two ventures cannot serve one name. A claim held by another
-- venture is refused by the screen with a reason, and by the database
-- under it.
--
-- account_id and venture_id carry no REFERENCES clause on purpose: the
-- account and venture tables belong to the console module, and this
-- crate's own connection table set the precedent that a cross-module
-- foreign key couples two modules' migration orders for one diagram
-- edge. Isolation stays by query (harness #32): every read below is
-- scoped to the account that owns the claiming venture.
CREATE TABLE IF NOT EXISTS hostname (
    id               TEXT PRIMARY KEY,     -- ULID
    account_id       TEXT NOT NULL,        -- the claiming venture's account
    venture_id       TEXT NOT NULL,        -- the venture that claims it
    hostname         TEXT NOT NULL UNIQUE, -- punycode/ASCII form
    state            TEXT NOT NULL,        -- added | awaiting-dns | verifying | certificate-issuing | live | failed
    last_error       TEXT NOT NULL DEFAULT '',
    added_at         TEXT NOT NULL,        -- RFC 3339
    state_changed_at TEXT NOT NULL,        -- RFC 3339, when the current state was entered
    updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS hostname_by_venture ON hostname (venture_id);
CREATE INDEX IF NOT EXISTS hostname_by_account ON hostname (account_id);
