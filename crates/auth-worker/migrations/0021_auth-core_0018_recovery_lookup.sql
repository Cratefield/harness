-- Issue #914, security review: recovery codes are <lookup>-<secret>. The
-- lookup is public and finds one row; the secret is what is hashed. Hashing
-- with Argon2 cost a verify per candidate row and a timing difference between
-- unknown and known accounts; a 80-bit random secret needs no slow hash, so the
-- stored form is SHA-256 of the secret (hex). 0017 was never applied, so the
-- rows it could have held are removed here; regenerate after upgrading.
DELETE FROM recovery_codes;
ALTER TABLE recovery_codes ADD COLUMN lookup_id TEXT;
CREATE UNIQUE INDEX recovery_codes_by_lookup ON recovery_codes (lookup_id);
