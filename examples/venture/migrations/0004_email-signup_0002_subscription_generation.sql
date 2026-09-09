-- Issue #127: confirmation tokens bind to (id, generation). The
-- generation bumps when a row re-enters pending from another state
-- (resubscription after unsubscribe), so tokens from an earlier
-- subscription lifecycle can never confirm the new one. Existing rows
-- are generation 1, which is what a pre-#127 bare-id token parses as.
ALTER TABLE subscribers ADD COLUMN generation INTEGER NOT NULL DEFAULT 1;
