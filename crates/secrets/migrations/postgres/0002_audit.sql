-- The secret-access audit chain (issue #41); see the sqlite set for what
-- it is. Postgres differs only in how append-only is enforced: a
-- plpgsql trigger function rather than RAISE(ABORT).
CREATE TABLE IF NOT EXISTS harness_secret_audit (
    seq        BIGINT PRIMARY KEY,
    ts         TEXT NOT NULL,
    actor      TEXT NOT NULL,
    name       TEXT NOT NULL,
    version    INTEGER,
    action     TEXT NOT NULL,
    allowed    INTEGER NOT NULL,
    request_id TEXT,
    prev_hash  BYTEA NOT NULL,
    hash       BYTEA NOT NULL
);

CREATE OR REPLACE FUNCTION harness_secret_audit_append_only()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'harness_secret_audit is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS harness_secret_audit_no_change ON harness_secret_audit;
CREATE TRIGGER harness_secret_audit_no_change
BEFORE UPDATE OR DELETE ON harness_secret_audit
FOR EACH ROW EXECUTE FUNCTION harness_secret_audit_append_only();
