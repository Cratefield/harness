-- Issue #649: the locale an account is written to in. Nullable because a
-- person who has never chosen one must not be forced into one, and because
-- a magic link resolves a locale per request from the request itself
-- without ever writing a column. When it is set it is a tag the deployment
-- lists in AUTH_LOCALES: registration stores one only when it is supported.
ALTER TABLE users ADD COLUMN locale TEXT;
