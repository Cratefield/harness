//! Venture connections (issue #6): the credentials a customer supplies for
//! their own venture, kept in the tenant secrets layer.
//!
//! With **hosted Cloudflare** (the ADR) the customer connects no Cloudflare
//! account — the platform deploys into its own. So a customer's connections
//! are their venture's **Google OAuth client** (for their end users' login,
//! distinct from the control plane's own Google login) and any **third-party
//! key** a chosen module needs (a Resend key, a Stripe key), each surfaced
//! only when a module that needs it is in the set.
//!
//! **Where the secret lives, and where it does not.** Secret material — an
//! OAuth client secret, an API key — goes into that venture's tenant store in
//! [`cratefield_secrets`]: encrypted, AAD-bound to the store, audited on every
//! access, and rotated on every re-connect. This crate's own `connection`
//! table holds only metadata: the connection kind, its
//! [`ConnectionState`], a reason when it is invalid, and a **non-secret**
//! hint (a public OAuth client id, never a key). A leak of this table leaks
//! no credential, and the types make it hard to put one there.
//!
//! Reads of a stored secret ([`Connections::google_client_secret`],
//! [`Connections::module_key`]) return a [`SecretBytes`], which zeroizes on
//! drop and does not print its contents — the provisioning engine (#7) reads
//! them to configure a venture, and nothing renders them.
//!
//! **Who may reach a credential: [`VentureScope`] (issue #142).** The unit
//! of authorization is the *venture*, never a caller's memory of a tenant
//! id. Every credential method takes a [`VentureScope`], and the only way
//! to build one is [`Connections::grant`], which resolves the venture
//! against the control plane's `venture` table and **refuses a venture
//! that is not there** — recording the refusal on the durable audit chain
//! *before* any secret store is touched. A granted scope then carries its
//! venture into every access as the audit actor (`venture:<id>`), so "who
//! read this credential" is never a free-text field the caller chose. Even
//! a store collision fails closed: a scope reaches only the tenant store
//! it was granted for — store attribution scopes every row-level query,
//! and the store seals its ciphertexts with that tenant in the AAD
//! (issue #142) — so another venture's bytes are not even a candidate,
//! and a row that crossed anyway would fail as `NotAuthentic`: a
//! recorded, denied access.
//!
//! The audit sink is owned by [`Connections::new`], which wires the
//! durable per-store chain router ([`cratefield_secrets::chain_sink`])
//! over the shared control database: credential accesses are verifiable
//! by default with [`cratefield_secrets::verify`], not verifiable only if
//! a caller remembered to ask.

#![forbid(unsafe_code)]

pub mod guide;
pub mod stripe;

use std::sync::Arc;

use cratefield_catalog::ModuleSet;
use cratefield_core::{Database, DbError, Statement};
use cratefield_secrets::{
    Access, Actor, Audit, AuditEvent, ChainAudit, SecretBytes, Secrets, SecretsError, StoreId,
    chain_sink,
};
use sea_query::Value as SeaValue;
use serde::{Deserialize, Serialize};

/// The schema migration for the connection-metadata table. The secret store's
/// own migrations ([`cratefield_secrets::migrations`]) are applied separately.
pub const MIGRATION: cratefield_core::SqlMigration = cratefield_core::SqlMigration::new(
    "0001",
    "init",
    include_str!("../migrations/sqlite/0001_init.sql"),
);

/// The secret name a venture's Google OAuth **client secret** is stored under.
/// The client *id* is public and is not a secret; it is kept as the hint.
const GOOGLE_SECRET_NAME: &str = "venture-google-client-secret";

/// The suffix Google marks a well-formed OAuth client id with. Used only to
/// reject an obviously-wrong pair at connect time; it is not authentication.
const GOOGLE_CLIENT_ID_SUFFIX: &str = ".apps.googleusercontent.com";

// ---------------------------------------------------------------------------
// Connection kinds and state
// ---------------------------------------------------------------------------

/// One thing a venture connects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionKind {
    /// The venture's own Google OAuth client, for its end users' login.
    VentureGoogleOauth,
    /// A third-party key a selected module needs, named by module slug and
    /// service (`resend`, `stripe`, ...).
    ModuleKey { module: String, service: String },
}

impl ConnectionKind {
    /// The stable key that identifies this connection in the `connection`
    /// table and the wizard.
    #[must_use]
    pub fn key(&self) -> String {
        match self {
            ConnectionKind::VentureGoogleOauth => "venture-google-oauth".to_owned(),
            ConnectionKind::ModuleKey { module, service } => {
                format!("module:{module}:{service}")
            }
        }
    }

    /// The secret store name the credential is kept under.
    #[must_use]
    fn secret_name(&self) -> String {
        match self {
            ConnectionKind::VentureGoogleOauth => GOOGLE_SECRET_NAME.to_owned(),
            ConnectionKind::ModuleKey { module, service } => {
                format!("module:{module}:{service}")
            }
        }
    }

    /// Parses a [`key`](ConnectionKind::key) back into a kind.
    #[must_use]
    pub fn parse(key: &str) -> Option<Self> {
        if key == "venture-google-oauth" {
            return Some(ConnectionKind::VentureGoogleOauth);
        }
        let rest = key.strip_prefix("module:")?;
        let (module, service) = rest.split_once(':')?;
        (!module.is_empty() && !service.is_empty()).then(|| ConnectionKind::ModuleKey {
            module: module.to_owned(),
            service: service.to_owned(),
        })
    }
}

/// Whether a connection is usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectionState {
    /// Nothing connected yet.
    NotConnected,
    /// A credential is stored and passed its connect-time check.
    Connected,
    /// A credential was supplied but rejected; see the reason.
    Invalid,
}

impl ConnectionState {
    fn as_str(self) -> &'static str {
        match self {
            ConnectionState::NotConnected => "not-connected",
            ConnectionState::Connected => "connected",
            ConnectionState::Invalid => "invalid",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        match s {
            "not-connected" => Some(ConnectionState::NotConnected),
            "connected" => Some(ConnectionState::Connected),
            "invalid" => Some(ConnectionState::Invalid),
            _ => None,
        }
    }
}

/// A connection's metadata, as the wizard and dashboard read it. Carries no
/// secret material — `hint` is a public label only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub kind: ConnectionKind,
    pub state: ConnectionState,
    /// Why the connection is invalid; empty otherwise.
    pub reason: String,
    /// A non-secret label: a public OAuth client id, or empty for a key.
    pub hint: String,
    pub updated_at: String,
}

impl Connection {
    /// Whether this connection is good to use.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.state == ConnectionState::Connected
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failures from the connections layer. A *rejected credential* is not one of
/// these — that is an [`Connection`] in state [`ConnectionState::Invalid`]
/// with a reason. These are infrastructure faults.
#[derive(Debug)]
pub enum ConnError {
    Secrets(SecretsError),
    Db(DbError),
    /// A stored row was malformed (an unknown state or kind).
    Malformed(String),
    /// A [`Connections::grant`] named a venture the control plane does not
    /// have, so no scope can exist for it. The denial is on the audit
    /// chain before this error is returned (issue #142).
    UnknownVenture(String),
}

impl std::fmt::Display for ConnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnError::Secrets(err) => write!(f, "secrets: {err}"),
            ConnError::Db(err) => write!(f, "database: {err}"),
            ConnError::Malformed(what) => write!(f, "malformed: {what}"),
            ConnError::UnknownVenture(id) => write!(f, "unknown venture `{id}`"),
        }
    }
}

impl std::error::Error for ConnError {}

impl From<SecretsError> for ConnError {
    fn from(err: SecretsError) -> Self {
        ConnError::Secrets(err)
    }
}
impl From<DbError> for ConnError {
    fn from(err: DbError) -> Self {
        ConnError::Db(err)
    }
}

// ---------------------------------------------------------------------------
// The connections service
// ---------------------------------------------------------------------------

/// Proof that a venture was resolved to its tenant by
/// [`Connections::grant`] — the only way one exists (issue #142).
///
/// The fields are private and there is no constructor, `From`, or
/// deserialization: a caller cannot name a tenant store it was not
/// granted, so every credential method below receives a checked
/// authorization rather than a string it would have to trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VentureScope {
    venture: String,
    tenant: String,
}

impl VentureScope {
    /// The venture this scope was granted for.
    #[must_use]
    pub fn venture(&self) -> &str {
        &self.venture
    }
    /// The tenant store that venture's credentials live in.
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
    /// The actor every credential access under this scope is attributed
    /// to: the venture itself, never a caller-chosen string.
    fn actor(&self) -> Actor {
        Actor::new(format!("venture:{}", self.venture))
            .expect("a venture-prefixed actor is never empty")
    }
}

/// Connects a venture's credentials and tracks their state. Secret material
/// goes to the tenant secret store; this type's own table holds only
/// metadata, scoped by tenant id (isolation by query, harness #32, as with
/// accounts). Every credential method takes a [`VentureScope`] (issue
/// #142), and every store access lands on the durable audit chain wired by
/// [`Connections::new`].
pub struct Connections {
    secrets: Secrets,
    db: Arc<dyn Database>,
}

impl Connections {
    /// A service over the shared control database. The audit sink is
    /// owned here: the durable per-store chain router replaces whatever
    /// sink the passed [`Secrets`] was built with, because an access of
    /// a live credential that survives only as a log line is the gap
    /// issue #142 closes — every access must land on a chain
    /// [`cratefield_secrets::verify`] can check.
    #[must_use]
    pub fn new(secrets: Secrets, db: Arc<dyn Database>) -> Self {
        Self {
            secrets: secrets.with_audit(chain_sink(Arc::clone(&db))),
            db,
        }
    }

    /// Resolves a venture id into the [`VentureScope`] every credential
    /// method demands.
    ///
    /// The venture must exist in the control plane's `venture` table (the
    /// accounts module's, read here directly so this crate does not gain
    /// a dependency on it), and the tenant it maps to becomes the only
    /// store the returned scope can reach. An unknown venture is a
    /// **recorded refusal**: a denied `Get` is appended to the durable
    /// chain of the store the attempt tried to name *before* the error is
    /// returned, so probing for valid venture ids leaves evidence, and no
    /// secret store is opened on the refusal path. An empty id is refused
    /// outright — it names no store a refusal could be recorded against.
    ///
    /// `actor` is who asked for the grant (a console operator) and rides
    /// on the refusal event; afterwards, credential accesses are
    /// attributed to the venture itself.
    ///
    /// # Errors
    ///
    /// [`ConnError::UnknownVenture`] when no such venture exists;
    /// [`ConnError::Secrets`] or [`ConnError::Db`] on infrastructure
    /// failure.
    pub async fn grant(&self, venture_id: &str, actor: &Actor) -> Result<VentureScope, ConnError> {
        if venture_id.trim().is_empty() {
            return Err(ConnError::UnknownVenture(String::new()));
        }
        let rows = self
            .db
            .query(&Statement::with_values(
                "SELECT tenant_id FROM venture WHERE id = ?",
                vec![text(venture_id)],
            ))
            .await?;
        if let Some(tenant) = rows.first().and_then(|row| row.get::<String>("tenant_id")) {
            return Ok(VentureScope {
                venture: venture_id.to_owned(),
                tenant,
            });
        }
        let store = StoreId::Tenant(venture_id.to_owned());
        let denied = AuditEvent {
            store: &store,
            access: Access::Get,
            actor,
            name: None,
            version: None,
            allowed: false,
            request_id: None,
        };
        ChainAudit::new(store.clone(), Arc::clone(&self.db))
            .record(&denied)
            .await?;
        Err(ConnError::UnknownVenture(venture_id.to_owned()))
    }

    /// Connects a venture's Google OAuth client. The client **id** is public
    /// and kept as the hint; the client **secret** is stored in the tenant
    /// secret store (which rotates on re-connect and audits the write).
    ///
    /// An obviously-wrong pair — an id that is not a Google client id, or an
    /// empty secret — is not stored; it is recorded as
    /// [`ConnectionState::Invalid`] with a reason and returned as such, so the
    /// caller shows the reason rather than believing it connected. Live
    /// verification against Google is a later seam (the wizard, #8).
    ///
    /// # Errors
    ///
    /// [`ConnError::Secrets`] or [`ConnError::Db`] on infrastructure failure.
    pub async fn connect_google(
        &self,
        scope: &VentureScope,
        client_id: &str,
        client_secret: &str,
        now: &str,
    ) -> Result<Connection, ConnError> {
        let kind = ConnectionKind::VentureGoogleOauth;
        let client_id = client_id.trim();
        // The same check `guidance` shows beside the field, so a value the
        // wizard accepted is never refused here (issue #6).
        if let Some(reason) = kind.guidance("").expects.refuse(client_id) {
            return self
                .record_invalid(scope, &kind, &reason, client_id, now)
                .await;
        }
        if client_secret.trim().is_empty() {
            return self
                .record_invalid(scope, &kind, "the client secret is empty", client_id, now)
                .await;
        }
        self.store_secret(scope, &kind, client_secret).await?;
        self.record_connected(scope, &kind, client_id, now).await
    }

    /// Connects a module's third-party key. Stored the same way; the key is
    /// never kept as a hint. An empty key is recorded invalid.
    ///
    /// # Errors
    ///
    /// [`ConnError::Secrets`] or [`ConnError::Db`].
    pub async fn connect_module_key(
        &self,
        scope: &VentureScope,
        module: &str,
        service: &str,
        key: &str,
        now: &str,
    ) -> Result<Connection, ConnError> {
        let kind = ConnectionKind::ModuleKey {
            module: module.to_owned(),
            service: service.to_owned(),
        };
        if key.trim().is_empty() {
            return self
                .record_invalid(scope, &kind, "the key is empty", "", now)
                .await;
        }
        self.store_secret(scope, &kind, key).await?;
        // No hint: a key is secret, so nothing about it is shown.
        self.record_connected(scope, &kind, "", now).await
    }

    /// Removes a connection: deletes the stored secret (audited by the secrets
    /// layer) and marks the connection not-connected.
    ///
    /// # Errors
    ///
    /// [`ConnError::Secrets`] or [`ConnError::Db`].
    pub async fn disconnect(
        &self,
        scope: &VentureScope,
        kind: &ConnectionKind,
        now: &str,
    ) -> Result<Connection, ConnError> {
        self.store(scope)
            .delete(&kind.secret_name(), &scope.actor())
            .await?;
        self.upsert(
            scope.tenant(),
            kind,
            ConnectionState::NotConnected,
            "",
            "",
            now,
        )
        .await
    }

    /// The state of one connection, or `None` if the venture has never
    /// touched it.
    ///
    /// # Errors
    ///
    /// [`ConnError::Db`].
    pub async fn state_of(
        &self,
        scope: &VentureScope,
        kind: &ConnectionKind,
    ) -> Result<Option<Connection>, ConnError> {
        let rows = self
            .db
            .query(&Statement::with_values(
                "SELECT kind, state, reason, hint, updated_at FROM connection \
                 WHERE tenant_id = ? AND kind = ?",
                vec![text(scope.tenant()), text(&kind.key())],
            ))
            .await?;
        rows.first().map(connection_from_row).transpose()
    }

    /// Every connection a venture has, for the dashboard. Scoped to the tenant.
    ///
    /// # Errors
    ///
    /// [`ConnError::Db`].
    pub async fn all(&self, scope: &VentureScope) -> Result<Vec<Connection>, ConnError> {
        let rows = self
            .db
            .query(&Statement::with_values(
                "SELECT kind, state, reason, hint, updated_at FROM connection \
                 WHERE tenant_id = ? ORDER BY kind ASC",
                vec![text(scope.tenant())],
            ))
            .await?;
        rows.rows.iter().map(connection_from_row).collect()
    }

    /// Reads the venture's Google client secret for provisioning. Audited by
    /// the secrets layer. Returns [`SecretBytes`], which does not print.
    ///
    /// # Errors
    ///
    /// [`ConnError::Secrets`].
    pub async fn google_client_secret(
        &self,
        scope: &VentureScope,
    ) -> Result<Option<SecretBytes>, ConnError> {
        Ok(self
            .store(scope)
            .get(GOOGLE_SECRET_NAME, &scope.actor())
            .await?)
    }

    /// Reads a module's stored key for provisioning. Audited by the secrets
    /// layer.
    ///
    /// # Errors
    ///
    /// [`ConnError::Secrets`].
    pub async fn module_key(
        &self,
        scope: &VentureScope,
        module: &str,
        service: &str,
    ) -> Result<Option<SecretBytes>, ConnError> {
        let name = ConnectionKind::ModuleKey {
            module: module.to_owned(),
            service: service.to_owned(),
        }
        .secret_name();
        Ok(self.store(scope).get(&name, &scope.actor()).await?)
    }

    // -- internals ------------------------------------------------------

    fn store(&self, scope: &VentureScope) -> cratefield_secrets::SecretStore {
        self.secrets.tenant(scope.tenant(), self.db.clone())
    }

    async fn store_secret(
        &self,
        scope: &VentureScope,
        kind: &ConnectionKind,
        value: &str,
    ) -> Result<(), ConnError> {
        self.store(scope)
            .put(
                &kind.secret_name(),
                &SecretBytes::new(value.as_bytes().to_vec()),
                &scope.actor(),
            )
            .await?;
        Ok(())
    }

    async fn record_connected(
        &self,
        scope: &VentureScope,
        kind: &ConnectionKind,
        hint: &str,
        now: &str,
    ) -> Result<Connection, ConnError> {
        self.upsert(
            scope.tenant(),
            kind,
            ConnectionState::Connected,
            "",
            hint,
            now,
        )
        .await
    }

    async fn record_invalid(
        &self,
        scope: &VentureScope,
        kind: &ConnectionKind,
        reason: &str,
        hint: &str,
        now: &str,
    ) -> Result<Connection, ConnError> {
        self.upsert(
            scope.tenant(),
            kind,
            ConnectionState::Invalid,
            reason,
            hint,
            now,
        )
        .await
    }

    async fn upsert(
        &self,
        tenant: &str,
        kind: &ConnectionKind,
        state: ConnectionState,
        reason: &str,
        hint: &str,
        now: &str,
    ) -> Result<Connection, ConnError> {
        self.db
            .execute(&Statement::with_values(
                "INSERT INTO connection (tenant_id, kind, state, reason, hint, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?) \
                 ON CONFLICT(tenant_id, kind) DO UPDATE SET \
                 state = excluded.state, reason = excluded.reason, \
                 hint = excluded.hint, updated_at = excluded.updated_at",
                vec![
                    text(tenant),
                    text(&kind.key()),
                    text(state.as_str()),
                    text(reason),
                    text(hint),
                    text(now),
                ],
            ))
            .await?;
        Ok(Connection {
            kind: kind.clone(),
            state,
            reason: reason.to_owned(),
            hint: hint.to_owned(),
            updated_at: now.to_owned(),
        })
    }
}

// ---------------------------------------------------------------------------
// Which modules need which keys
// ---------------------------------------------------------------------------

/// A third-party key a module needs to work. Declared by the catalog, not
/// guessed: a module gets an entry here only when it genuinely requires a
/// customer-supplied key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyNeed {
    /// The module slug that needs the key.
    pub module: String,
    /// The service the key is for (`resend`, `stripe`, ...).
    pub service: String,
    /// A human label for the wizard ("Resend API key").
    pub label: String,
}

impl KeyNeed {
    /// The connection kind this need corresponds to.
    #[must_use]
    pub fn kind(&self) -> ConnectionKind {
        ConnectionKind::ModuleKey {
            module: self.module.clone(),
            service: self.service.clone(),
        }
    }
}

/// The declared module-key needs. The wizard asks it which keys to surface
/// for a chosen module set.
#[derive(Debug, Clone, Default)]
pub struct KeyRegistry {
    needs: Vec<KeyNeed>,
}

impl KeyRegistry {
    #[must_use]
    pub fn new(needs: Vec<KeyNeed>) -> Self {
        Self { needs }
    }

    /// The curated registry for the shipped catalog. **Empty for now, and
    /// honestly so:** in hosted mode the platform provides mail, and none of
    /// the curated modules (email-signup, waitlist, cms) requires a
    /// customer-supplied third-party key. A module gains an entry here when it
    /// actually needs one.
    #[must_use]
    pub fn curated() -> Self {
        Self::default()
    }

    /// The keys to surface for a chosen module set: a need is surfaced only
    /// when its module is in the set.
    #[must_use]
    pub fn needs_for(&self, set: &ModuleSet) -> Vec<&KeyNeed> {
        self.needs
            .iter()
            .filter(|need| set.contains(&need.module))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn connection_from_row(row: &cratefield_core::Row) -> Result<Connection, ConnError> {
    let kind_key = field(row, "kind")?;
    Ok(Connection {
        kind: ConnectionKind::parse(&kind_key)
            .ok_or_else(|| ConnError::Malformed(format!("connection kind `{kind_key}`")))?,
        state: ConnectionState::parse(&field(row, "state")?)
            .ok_or_else(|| ConnError::Malformed("connection state".to_owned()))?,
        reason: field(row, "reason")?,
        hint: field(row, "hint")?,
        updated_at: field(row, "updated_at")?,
    })
}

fn field(row: &cratefield_core::Row, name: &str) -> Result<String, ConnError> {
    row.get(name)
        .ok_or_else(|| ConnError::Malformed(format!("row has no `{name}`")))
}

fn text(value: &str) -> SeaValue {
    SeaValue::String(Some(Box::new(value.to_owned())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_kms::{Dek, Kms, LocalFileKms};
    use cratefield_secrets::migrations as secret_migrations;

    const GOOD_ID: &str = "1234567890-abc.apps.googleusercontent.com";

    fn kms() -> Arc<dyn Kms> {
        let kek = Dek::generate().expect("rng");
        Arc::new(LocalFileKms::from_key(kek, "test-kek", "test").expect("not production"))
    }

    /// A connections service on a fresh in-memory db carrying both the secret
    /// store's schema and this crate's connection table.
    fn connections() -> (Connections, Arc<dyn Database>) {
        let db = SqliteDatabase::in_memory().expect("db");
        db.apply_migrations("secrets", secret_migrations().sqlite)
            .expect("secrets schema");
        db.apply_migrations("connections", &[MIGRATION])
            .expect("connections schema");
        let db: Arc<dyn Database> = Arc::new(db);
        (Connections::new(Secrets::new(kms()), Arc::clone(&db)), db)
    }

    fn actor() -> Actor {
        Actor::new("operator").expect("named")
    }

    use cratefield_adapter_sqlite::SqliteDatabase;
    use cratefield_secrets::verify;

    fn bytes(value: Vec<u8>) -> SeaValue {
        SeaValue::Bytes(Some(Box::new(value)))
    }

    /// The accounts module's `venture` table in the minimum shape
    /// `grant` reads. Seeded here rather than depended on: connections
    /// must not gain a compile-time tie to that crate to enforce the
    /// venture boundary (issue #142).
    async fn ensure_venture_table(db: &Arc<dyn Database>) {
        db.execute(&Statement::new(
            "CREATE TABLE IF NOT EXISTS venture (id TEXT PRIMARY KEY, account_id TEXT NOT \
             NULL, tenant_id TEXT NOT NULL)",
        ))
        .await
        .expect("venture table");
    }

    async fn grant_scope(
        conns: &Connections,
        db: &Arc<dyn Database>,
        venture: &str,
        tenant: &str,
    ) -> VentureScope {
        ensure_venture_table(db).await;
        db.execute(&Statement::with_values(
            "INSERT INTO venture (id, account_id, tenant_id) VALUES (?, ?, ?)",
            vec![text(venture), text("acc_test"), text(tenant)],
        ))
        .await
        .expect("seed venture");
        conns.grant(venture, &actor()).await.expect("grant")
    }

    /// One store's audit rows: `(action, actor, allowed)`, in chain order.
    async fn audit_rows(db: &Arc<dyn Database>, store: &str) -> Vec<(String, String, i64)> {
        db.query(&Statement::with_values(
            "SELECT action, actor, allowed FROM harness_secret_audit WHERE store = ? \
             ORDER BY seq ASC",
            vec![text(store)],
        ))
        .await
        .expect("audit rows")
        .rows
        .iter()
        .map(|row| {
            (
                row.get("action").unwrap_or_default(),
                row.get("actor").unwrap_or_default(),
                row.get::<i64>("allowed").unwrap_or_default(),
            )
        })
        .collect()
    }

    // -- kind round-trips ----------------------------------------------

    #[test]
    fn a_kind_key_round_trips() {
        assert_eq!(
            ConnectionKind::parse("venture-google-oauth"),
            Some(ConnectionKind::VentureGoogleOauth)
        );
        let mk = ConnectionKind::ModuleKey {
            module: "email-signup".into(),
            service: "resend".into(),
        };
        assert_eq!(ConnectionKind::parse(&mk.key()), Some(mk));
        assert_eq!(ConnectionKind::parse("module:onlyone"), None);
    }

    // -- google connect -------------------------------------------------

    #[pollster::test]
    async fn a_good_google_pair_connects_and_stores_the_secret() {
        let (conns, db) = connections();
        let scope = grant_scope(&conns, &db, "ven_a", "ten_a").await;
        let c = conns
            .connect_google(&scope, GOOD_ID, "super-secret-value", "t0")
            .await
            .expect("infra ok");
        assert_eq!(c.state, ConnectionState::Connected);
        assert_eq!(c.hint, GOOD_ID, "the public client id is the hint");
        // The secret is retrievable for provisioning.
        let got = conns
            .google_client_secret(&scope)
            .await
            .expect("read")
            .expect("present");
        assert_eq!(got.expose(), b"super-secret-value");
    }

    #[pollster::test]
    async fn a_bad_client_id_is_refused_with_a_reason_and_not_stored() {
        let (conns, db) = connections();
        let scope = grant_scope(&conns, &db, "ven_a", "ten_a").await;
        let c = conns
            .connect_google(&scope, "not-a-google-id", "whatever", "t0")
            .await
            .expect("a decision, not an error");
        assert_eq!(c.state, ConnectionState::Invalid);
        assert!(
            c.reason.contains("Google OAuth client id"),
            "reason: {}",
            c.reason
        );
        // Nothing was stored.
        assert!(
            conns
                .google_client_secret(&scope)
                .await
                .expect("read")
                .is_none(),
            "an invalid pair leaves no secret behind"
        );
    }

    #[pollster::test]
    async fn an_empty_google_secret_is_refused() {
        let (conns, db) = connections();
        let scope = grant_scope(&conns, &db, "ven_a", "ten_a").await;
        let c = conns
            .connect_google(&scope, GOOD_ID, "   ", "t0")
            .await
            .unwrap();
        assert_eq!(c.state, ConnectionState::Invalid);
        assert!(c.reason.contains("empty"));
    }

    #[pollster::test]
    async fn reconnecting_rotates_the_stored_secret() {
        let (conns, db) = connections();
        let scope = grant_scope(&conns, &db, "ven_a", "ten_a").await;
        conns
            .connect_google(&scope, GOOD_ID, "first-secret", "t0")
            .await
            .unwrap();
        conns
            .connect_google(&scope, GOOD_ID, "second-secret", "t1")
            .await
            .unwrap();
        let got = conns.google_client_secret(&scope).await.unwrap().unwrap();
        assert_eq!(got.expose(), b"second-secret", "the rotation won");
    }

    // -- module keys ----------------------------------------------------

    #[pollster::test]
    async fn a_module_key_connects_without_leaking_a_hint() {
        let (conns, db) = connections();
        let scope = grant_scope(&conns, &db, "ven_a", "ten_a").await;
        let c = conns
            .connect_module_key(&scope, "email-signup", "resend", "re_live_abc123", "t0")
            .await
            .unwrap();
        assert_eq!(c.state, ConnectionState::Connected);
        assert_eq!(c.hint, "", "a key is secret; no hint");
        let got = conns
            .module_key(&scope, "email-signup", "resend")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.expose(), b"re_live_abc123");
    }

    // -- state, disconnect, isolation ----------------------------------

    #[pollster::test]
    async fn disconnect_removes_the_secret_and_marks_not_connected() {
        let (conns, db) = connections();
        let scope = grant_scope(&conns, &db, "ven_a", "ten_a").await;
        conns
            .connect_google(&scope, GOOD_ID, "secret", "t0")
            .await
            .unwrap();
        let c = conns
            .disconnect(&scope, &ConnectionKind::VentureGoogleOauth, "t1")
            .await
            .unwrap();
        assert_eq!(c.state, ConnectionState::NotConnected);
        assert!(
            conns.google_client_secret(&scope).await.unwrap().is_none(),
            "the secret is gone"
        );
    }

    #[pollster::test]
    async fn disconnecting_something_never_connected_is_a_harmless_no_op() {
        let (conns, db) = connections();
        let scope = grant_scope(&conns, &db, "ven_a", "ten_a").await;
        let c = conns
            .disconnect(&scope, &ConnectionKind::VentureGoogleOauth, "t0")
            .await
            .expect("no error");
        assert_eq!(c.state, ConnectionState::NotConnected);
    }

    #[pollster::test]
    async fn one_venture_does_not_see_anothers_connections() {
        let (conns, db) = connections();
        let sa = grant_scope(&conns, &db, "ven_a", "ten_a").await;
        let sb = grant_scope(&conns, &db, "ven_b", "ten_b").await;
        conns
            .connect_google(&sa, GOOD_ID, "a-secret", "t0")
            .await
            .unwrap();
        assert_eq!(conns.all(&sa).await.unwrap().len(), 1);
        assert!(
            conns.all(&sb).await.unwrap().is_empty(),
            "tenant b sees nothing of tenant a"
        );
        assert!(
            conns
                .state_of(&sb, &ConnectionKind::VentureGoogleOauth)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The connection table must never hold secret material — only metadata.
    #[pollster::test]
    async fn no_secret_reaches_the_connection_table_or_a_rendered_connection() {
        let (conns, db) = connections();
        let scope = grant_scope(&conns, &db, "ven_a", "ten_a").await;
        let secret = "TOP-SECRET-DO-NOT-LEAK";
        let c = conns
            .connect_google(&scope, GOOD_ID, secret, "t0")
            .await
            .unwrap();
        // Not in the returned, renderable Connection.
        assert!(!format!("{c:?}").contains(secret));
        // Not anywhere in the connection metadata table.
        let rows = db
            .query(&Statement::new(
                "SELECT tenant_id, kind, state, reason, hint, updated_at FROM connection",
            ))
            .await
            .unwrap();
        for row in &rows.rows {
            for name in ["tenant_id", "kind", "state", "reason", "hint", "updated_at"] {
                let cell: String = row.get(name).unwrap_or_default();
                assert!(
                    !cell.contains(secret),
                    "secret leaked into connection.{name}"
                );
            }
        }
    }

    // -- issue #142: venture scopes and the durable chain --------------

    #[pollster::test]
    async fn an_unknown_venture_grant_is_denied_on_the_chain_before_any_store() {
        let (conns, db) = connections();
        ensure_venture_table(&db).await;
        let err = conns
            .grant("ghost", &actor())
            .await
            .expect_err("no such venture exists");
        assert!(
            matches!(&err, ConnError::UnknownVenture(id) if id == "ghost"),
            "{err}"
        );
        // The attempt is evidence: a denied Get on the chain of the very
        // store it tried to name, attributed to who asked.
        assert_eq!(
            audit_rows(&db, "ghost").await,
            vec![("get".to_owned(), "operator".to_owned(), 0)],
            "the refusal is the store's first chain row"
        );
        verify(&StoreId::Tenant("ghost".to_owned()), &*db)
            .await
            .expect("a refusal is still a chain");
        // And the secret store itself was never opened: a denial that
        // planted or read a secret row would be a store touch.
        assert!(
            db.query(&Statement::new("SELECT name FROM harness_secrets"))
                .await
                .expect("query")
                .is_empty(),
            "a refusal must not touch a secret store"
        );
    }

    #[pollster::test]
    async fn a_scope_cannot_read_another_ventures_credential_even_in_one_database() {
        let (conns, db) = connections();
        let sa = grant_scope(&conns, &db, "ven_a", "ten_a").await;
        let sb = grant_scope(&conns, &db, "ven_b", "ten_b").await;
        conns
            .connect_google(&sa, GOOD_ID, "a-secret-for-ten-a-only", "t0")
            .await
            .unwrap();
        // The bytes sit in the shared physical database; venture B's
        // scope still cannot read them. Store attribution scopes the
        // read to ten_b's rows, of which this name is not one — so B's
        // answer is *nothing*, not a refusal to decrypt ten_a's bytes
        // (which is what this returned before attribution, when every
        // query was store-blind and only the AAD caught the crossing).
        assert!(
            conns.google_client_secret(&sb).await.unwrap().is_none(),
            "venture a's row must not even be a candidate for venture b"
        );
        // The access is still audited and attributed to the venture
        // that made it, on its own chain.
        let rows = audit_rows(&db, "ten_b").await;
        assert!(
            rows.contains(&("get".to_owned(), "venture:ven_b".to_owned(), 1)),
            "{rows:?}"
        );
        verify(&StoreId::Tenant("ten_b".to_owned()), &*db)
            .await
            .expect("venture b's chain verifies");
    }

    #[pollster::test]
    async fn credential_accesses_form_a_verifiable_chain_attributed_to_the_venture() {
        let (conns, db) = connections();
        let scope = grant_scope(&conns, &db, "ven_a", "ten_a").await;
        conns
            .connect_google(&scope, GOOD_ID, "secret-value", "t0")
            .await
            .unwrap();
        conns
            .google_client_secret(&scope)
            .await
            .unwrap()
            .expect("present");
        conns
            .disconnect(&scope, &ConnectionKind::VentureGoogleOauth, "t1")
            .await
            .unwrap();
        assert_eq!(
            audit_rows(&db, "ten_a").await,
            vec![
                ("put".to_owned(), "venture:ven_a".to_owned(), 1),
                ("get".to_owned(), "venture:ven_a".to_owned(), 1),
                ("delete".to_owned(), "venture:ven_a".to_owned(), 1),
            ],
            "one row per call, every row attributed to the venture — not a caller-chosen name"
        );
        verify(&StoreId::Tenant("ten_a".to_owned()), &*db)
            .await
            .expect("the credential chain verifies end to end");
    }

    #[pollster::test]
    async fn a_hand_crafted_plaintext_row_is_refused_as_not_authentic() {
        let (conns, db) = connections();
        let scope = grant_scope(&conns, &db, "ven_a", "ten_a").await;
        conns
            .connect_google(&scope, GOOD_ID, "real-secret", "t0")
            .await
            .unwrap();
        let key_id = db
            .query(&Statement::with_values(
                "SELECT key_id FROM harness_secrets WHERE name = ? AND version = 1",
                vec![text(GOOGLE_SECRET_NAME)],
            ))
            .await
            .expect("query")
            .first()
            .and_then(|row| row.get::<String>("key_id"))
            .expect("the real row's key");
        // Plant a row shaped like the store's own but carrying raw bytes
        // where the sealed envelope should be: writing to the table is
        // not reading the credential (issue #142). Stamped with the
        // tenant's own store, because whoever can write this row can
        // write that column too — store attribution scopes honest
        // queries, and the AAD is what refuses a dishonest row.
        db.execute(&Statement::with_values(
            "INSERT INTO harness_secrets (name, version, key_id, nonce, ciphertext, \
             created_at, created_by, store) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                text(GOOGLE_SECRET_NAME),
                SeaValue::BigInt(Some(999)),
                text(&key_id),
                bytes(vec![0; 24]),
                bytes(b"hunter2-plaintext-credential".to_vec()),
                text("t9"),
                text("hand-crafted"),
                text("ten_a"),
            ],
        ))
        .await
        .expect("plant row");
        let err = conns
            .google_client_secret(&scope)
            .await
            .expect_err("a planted row must not serve as a credential");
        assert!(
            matches!(
                &err,
                ConnError::Secrets(SecretsError::NotAuthentic { store, .. }) if store == "ten_a"
            ),
            "{err}"
        );
    }

    #[pollster::test]
    async fn stored_credential_bytes_never_look_like_the_credential() {
        let (conns, db) = connections();
        let scope = grant_scope(&conns, &db, "ven_a", "ten_a").await;
        let sentinel = b"SENTINEL-CREDENTIAL-MATERIAL";
        conns
            .connect_google(&scope, GOOD_ID, "SENTINEL-CREDENTIAL-MATERIAL", "t0")
            .await
            .unwrap();
        let rows = db
            .query(&Statement::with_values(
                "SELECT nonce, ciphertext FROM harness_secrets WHERE name = ?",
                vec![text(GOOGLE_SECRET_NAME)],
            ))
            .await
            .expect("query");
        assert_eq!(rows.len(), 1, "the connect stored exactly one row");
        for row in &rows.rows {
            for column in ["nonce", "ciphertext"] {
                let stored: Vec<u8> = row.get(column).unwrap_or_default();
                assert!(
                    !stored.windows(sentinel.len()).any(|w| w == &sentinel[..]),
                    "{column} holds the credential in the clear"
                );
            }
        }
    }

    // -- module-key surfacing ------------------------------------------

    #[test]
    fn a_key_is_surfaced_only_when_its_module_is_selected() {
        use cratefield_catalog::{Catalog, CatalogModule, ModuleRelease, ReleaseReview, Tier};
        fn pin() -> Vec<ModuleRelease> {
            vec![ModuleRelease {
                version: "1.0.0".into(),
                digest: format!("sha256:{}", "a".repeat(64)),
                review: ReleaseReview::Approved {
                    reviewer: "test".into(),
                    reviewed_at: "2026-01-01T00:00:00Z".into(),
                },
            }]
        }
        let registry = KeyRegistry::new(vec![KeyNeed {
            module: "newsletter".into(),
            service: "resend".into(),
            label: "Resend API key".into(),
        }]);
        // A catalog with the module, and one without it in the set.
        let catalog = Catalog {
            modules: vec![
                CatalogModule {
                    slug: "newsletter".into(),
                    name: "Newsletter".into(),
                    summary: String::new(),
                    tier: Tier::Optional,
                    depends_on: vec![],
                    releases: pin(),
                    // A fixture about resolution; the wizard's copy is
                    // not what it is testing.
                    detail: cratefield_catalog::ModuleDetail::default(),
                },
                CatalogModule {
                    slug: "waitlist".into(),
                    name: "Waitlist".into(),
                    summary: String::new(),
                    tier: Tier::Optional,
                    depends_on: vec![],
                    releases: pin(),
                    // A fixture about resolution; the wizard's copy is
                    // not what it is testing.
                    detail: cratefield_catalog::ModuleDetail::default(),
                },
            ],
        };
        let with_it = catalog.resolve(&["newsletter"]).unwrap();
        let without = catalog.resolve(&["waitlist"]).unwrap();
        assert_eq!(
            registry.needs_for(&with_it).len(),
            1,
            "surfaced when selected"
        );
        assert!(registry.needs_for(&without).is_empty(), "hidden when not");
        // The curated registry is honestly empty.
        assert!(KeyRegistry::curated().needs_for(&with_it).is_empty());
    }
}
