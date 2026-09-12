-- The rotation policy for one secret store (scheduled rotation): how
-- old the data key may get before the schedule rotates it, and how old
-- a secret value may get before the page marks it overdue for a person
-- to replace.
--
-- Owned by the dashboard module, not by `cratefield-secrets`: that
-- crate is a library with no `scheduled` hook and no business deciding
-- deployment cadence — this module owns the composition, the KMS and
-- the schedule, so it owns the policy the schedule reads.
--
-- One row per store, keyed by the store id exactly as the secrets
-- tables key it (`StoreId::as_str()`). A store with no row uses the
-- deployment default from config; a policy is per store and not per
-- secret, because a threshold a schedule cannot act on is a report, and
-- one number per store is already enough rope for a page that must not
-- pretend to rotate credentials.
--
-- `updated_by`/`updated_at` are the audit record for a policy change:
-- the secrets store's own hash chain records accesses to secret
-- material through the store's API, and this row is not secret
-- material — its "who decided this" travels with it.
CREATE TABLE IF NOT EXISTS secret_rotation_policy (
    store                TEXT PRIMARY KEY,
    key_max_age_days     INTEGER NOT NULL,  -- data key rotated at/after this age
    secret_max_age_days  INTEGER NOT NULL,  -- a live value this old reads OVERDUE
    updated_by           TEXT NOT NULL,     -- the operator who last changed it
    updated_at           TEXT NOT NULL      -- RFC 3339, from the clock port
);
