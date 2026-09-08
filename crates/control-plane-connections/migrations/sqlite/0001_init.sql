-- What a venture has connected, and whether the connection is good. This
-- table holds only *metadata*: the connection kind, its state, a reason when
-- it is invalid, and a non-secret hint (a public OAuth client id, never a
-- key). The secret material itself lives in the tenant secrets store
-- (factory0-secrets): encrypted, AAD-bound, audited, rotatable. Nothing here
-- is a credential, so a leak of this table leaks no secret.
CREATE TABLE connection (
    tenant_id  TEXT NOT NULL,           -- the venture's tenant (isolation key)
    kind       TEXT NOT NULL,           -- the connection kind key
    state      TEXT NOT NULL,           -- 'connected' | 'invalid' | 'not-connected'
    reason     TEXT NOT NULL DEFAULT '',-- why it is invalid, for the operator
    hint       TEXT NOT NULL DEFAULT '',-- non-secret label (public client id)
    updated_at TEXT NOT NULL,           -- RFC 3339
    PRIMARY KEY (tenant_id, kind)
);
