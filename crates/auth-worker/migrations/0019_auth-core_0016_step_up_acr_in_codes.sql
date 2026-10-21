-- Issue #912, third review: the authentication context a step-up earns
-- belongs to the authorization code that spent the transaction, not to the
-- session. A session outlives that one request: a refresh days later, or
-- another client's request on the same session, must never carry the
-- context. 0015 added sessions.acr; this drops it again, forward only.
ALTER TABLE sessions DROP COLUMN acr;
