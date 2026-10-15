-- `revision` is a random 63-bit validator (`fresh_revision`), which a
-- Postgres INTEGER (32-bit) cannot hold: every guarded write failed with
-- "integer out of range". Widen both columns to BIGINT.

ALTER TABLE sealed_blobs ALTER COLUMN revision TYPE BIGINT;
ALTER TABLE sealed_deks ALTER COLUMN revision TYPE BIGINT;
