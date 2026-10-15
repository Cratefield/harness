-- Postgres widens `revision` to BIGINT here; SQLite's INTEGER is already
-- 64-bit, so this dialect has nothing to change. It exists so both sets
-- carry the same ids.

SELECT 1;
