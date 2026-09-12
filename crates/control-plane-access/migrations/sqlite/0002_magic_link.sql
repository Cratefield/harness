-- Pending magic-link sign-ins (Cratefield issue #3). One row per mailed
-- link, keyed by the SHA-256 of the 32 random bytes in the URL: the token
-- itself is never stored, and a row cannot be turned back into a way in
-- without it.
--
-- The email column is a person's address and the row lives exactly as
-- long as the link it belongs to could work: following the link deletes
-- the row (the delete's row count is what makes it single-use under
-- concurrency), and every new request sweeps rows whose TTL has passed.
-- The address is deleted with the row, never overwritten, and never
-- copied anywhere else by this flow.
CREATE TABLE magic_link (
    token_hash TEXT PRIMARY KEY,   -- sha256 hex of the mailed token
    email      TEXT NOT NULL,      -- the allowlisted address it was mailed to
    expires_at BIGINT NOT NULL,    -- unix seconds
    created_at TEXT NOT NULL       -- RFC 3339
);
