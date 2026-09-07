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
//! [`factory0_secrets`]: encrypted, AAD-bound to the store, audited on every
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

#![forbid(unsafe_code)]

use std::sync::Arc;

use cratefield_catalog::ModuleSet;
use factory0_core::{Database, DbError, Statement};
use factory0_secrets::{Actor, SecretBytes, Secrets, SecretsError};
use sea_query::Value as SeaValue;
use serde::{Deserialize, Serialize};

/// The schema migration for the connection-metadata table. The secret store's
/// own migrations ([`factory0_secrets::migrations`]) are applied separately.
pub const MIGRATION: factory0_core::SqlMigration = factory0_core::SqlMigration {
    id: "0001",
    name: "init",
    sql: include_str!("../migrations/sqlite/0001_init.sql"),
};

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
}

impl std::fmt::Display for ConnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnError::Secrets(err) => write!(f, "secrets: {err}"),
            ConnError::Db(err) => write!(f, "database: {err}"),
            ConnError::Malformed(what) => write!(f, "malformed: {what}"),
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

/// Connects a venture's credentials and tracks their state. Secret material
/// goes to the tenant secret store; this type's own table holds only
/// metadata, scoped by tenant id (isolation by query, harness #32, as with
/// accounts).
pub struct Connections {
    secrets: Secrets,
    db: Arc<dyn Database>,
}

impl Connections {
    #[must_use]
    pub fn new(secrets: Secrets, db: Arc<dyn Database>) -> Self {
        Self { secrets, db }
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
        tenant: &str,
        client_id: &str,
        client_secret: &str,
        actor: &Actor,
        now: &str,
    ) -> Result<Connection, ConnError> {
        let kind = ConnectionKind::VentureGoogleOauth;
        let client_id = client_id.trim();
        if !client_id.ends_with(GOOGLE_CLIENT_ID_SUFFIX) {
            return self
                .record_invalid(
                    tenant,
                    &kind,
                    "the client id is not a Google OAuth client id (expected one ending in \
                     .apps.googleusercontent.com)",
                    client_id,
                    now,
                )
                .await;
        }
        if client_secret.trim().is_empty() {
            return self
                .record_invalid(tenant, &kind, "the client secret is empty", client_id, now)
                .await;
        }
        self.store_secret(tenant, &kind, client_secret, actor)
            .await?;
        self.record_connected(tenant, &kind, client_id, now).await
    }

    /// Connects a module's third-party key. Stored the same way; the key is
    /// never kept as a hint. An empty key is recorded invalid.
    ///
    /// # Errors
    ///
    /// [`ConnError::Secrets`] or [`ConnError::Db`].
    pub async fn connect_module_key(
        &self,
        tenant: &str,
        module: &str,
        service: &str,
        key: &str,
        actor: &Actor,
        now: &str,
    ) -> Result<Connection, ConnError> {
        let kind = ConnectionKind::ModuleKey {
            module: module.to_owned(),
            service: service.to_owned(),
        };
        if key.trim().is_empty() {
            return self
                .record_invalid(tenant, &kind, "the key is empty", "", now)
                .await;
        }
        self.store_secret(tenant, &kind, key, actor).await?;
        // No hint: a key is secret, so nothing about it is shown.
        self.record_connected(tenant, &kind, "", now).await
    }

    /// Removes a connection: deletes the stored secret (audited by the secrets
    /// layer) and marks the connection not-connected.
    ///
    /// # Errors
    ///
    /// [`ConnError::Secrets`] or [`ConnError::Db`].
    pub async fn disconnect(
        &self,
        tenant: &str,
        kind: &ConnectionKind,
        actor: &Actor,
        now: &str,
    ) -> Result<Connection, ConnError> {
        self.store(tenant)
            .delete(&kind.secret_name(), actor)
            .await?;
        self.upsert(tenant, kind, ConnectionState::NotConnected, "", "", now)
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
        tenant: &str,
        kind: &ConnectionKind,
    ) -> Result<Option<Connection>, ConnError> {
        let rows = self
            .db
            .query(&Statement::with_values(
                "SELECT kind, state, reason, hint, updated_at FROM connection \
                 WHERE tenant_id = ? AND kind = ?",
                vec![text(tenant), text(&kind.key())],
            ))
            .await?;
        rows.first().map(connection_from_row).transpose()
    }

    /// Every connection a venture has, for the dashboard. Scoped to the tenant.
    ///
    /// # Errors
    ///
    /// [`ConnError::Db`].
    pub async fn all(&self, tenant: &str) -> Result<Vec<Connection>, ConnError> {
        let rows = self
            .db
            .query(&Statement::with_values(
                "SELECT kind, state, reason, hint, updated_at FROM connection \
                 WHERE tenant_id = ? ORDER BY kind ASC",
                vec![text(tenant)],
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
        tenant: &str,
        actor: &Actor,
    ) -> Result<Option<SecretBytes>, ConnError> {
        Ok(self.store(tenant).get(GOOGLE_SECRET_NAME, actor).await?)
    }

    /// Reads a module's stored key for provisioning. Audited by the secrets
    /// layer.
    ///
    /// # Errors
    ///
    /// [`ConnError::Secrets`].
    pub async fn module_key(
        &self,
        tenant: &str,
        module: &str,
        service: &str,
        actor: &Actor,
    ) -> Result<Option<SecretBytes>, ConnError> {
        let name = ConnectionKind::ModuleKey {
            module: module.to_owned(),
            service: service.to_owned(),
        }
        .secret_name();
        Ok(self.store(tenant).get(&name, actor).await?)
    }

    // -- internals ------------------------------------------------------

    fn store(&self, tenant: &str) -> factory0_secrets::SecretStore {
        self.secrets.tenant(tenant, self.db.clone())
    }

    async fn store_secret(
        &self,
        tenant: &str,
        kind: &ConnectionKind,
        value: &str,
        actor: &Actor,
    ) -> Result<(), ConnError> {
        self.store(tenant)
            .put(
                &kind.secret_name(),
                &SecretBytes::new(value.as_bytes().to_vec()),
                actor,
            )
            .await?;
        Ok(())
    }

    async fn record_connected(
        &self,
        tenant: &str,
        kind: &ConnectionKind,
        hint: &str,
        now: &str,
    ) -> Result<Connection, ConnError> {
        self.upsert(tenant, kind, ConnectionState::Connected, "", hint, now)
            .await
    }

    async fn record_invalid(
        &self,
        tenant: &str,
        kind: &ConnectionKind,
        reason: &str,
        hint: &str,
        now: &str,
    ) -> Result<Connection, ConnError> {
        self.upsert(tenant, kind, ConnectionState::Invalid, reason, hint, now)
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

fn connection_from_row(row: &factory0_core::Row) -> Result<Connection, ConnError> {
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

fn field(row: &factory0_core::Row, name: &str) -> Result<String, ConnError> {
    row.get(name)
        .ok_or_else(|| ConnError::Malformed(format!("row has no `{name}`")))
}

fn text(value: &str) -> SeaValue {
    SeaValue::String(Some(Box::new(value.to_owned())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory0_kms::{Dek, Kms, LocalFileKms};
    use factory0_secrets::migrations as secret_migrations;

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

    use factory0_adapter_sqlite::SqliteDatabase;

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
        let (conns, _db) = connections();
        let c = conns
            .connect_google("ten_a", GOOD_ID, "super-secret-value", &actor(), "t0")
            .await
            .expect("infra ok");
        assert_eq!(c.state, ConnectionState::Connected);
        assert_eq!(c.hint, GOOD_ID, "the public client id is the hint");
        // The secret is retrievable for provisioning.
        let got = conns
            .google_client_secret("ten_a", &actor())
            .await
            .expect("read")
            .expect("present");
        assert_eq!(got.expose(), b"super-secret-value");
    }

    #[pollster::test]
    async fn a_bad_client_id_is_refused_with_a_reason_and_not_stored() {
        let (conns, _db) = connections();
        let c = conns
            .connect_google("ten_a", "not-a-google-id", "whatever", &actor(), "t0")
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
                .google_client_secret("ten_a", &actor())
                .await
                .expect("read")
                .is_none(),
            "an invalid pair leaves no secret behind"
        );
    }

    #[pollster::test]
    async fn an_empty_google_secret_is_refused() {
        let (conns, _db) = connections();
        let c = conns
            .connect_google("ten_a", GOOD_ID, "   ", &actor(), "t0")
            .await
            .unwrap();
        assert_eq!(c.state, ConnectionState::Invalid);
        assert!(c.reason.contains("empty"));
    }

    #[pollster::test]
    async fn reconnecting_rotates_the_stored_secret() {
        let (conns, _db) = connections();
        conns
            .connect_google("ten_a", GOOD_ID, "first-secret", &actor(), "t0")
            .await
            .unwrap();
        conns
            .connect_google("ten_a", GOOD_ID, "second-secret", &actor(), "t1")
            .await
            .unwrap();
        let got = conns
            .google_client_secret("ten_a", &actor())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.expose(), b"second-secret", "the rotation won");
    }

    // -- module keys ----------------------------------------------------

    #[pollster::test]
    async fn a_module_key_connects_without_leaking_a_hint() {
        let (conns, _db) = connections();
        let c = conns
            .connect_module_key(
                "ten_a",
                "email-signup",
                "resend",
                "re_live_abc123",
                &actor(),
                "t0",
            )
            .await
            .unwrap();
        assert_eq!(c.state, ConnectionState::Connected);
        assert_eq!(c.hint, "", "a key is secret; no hint");
        let got = conns
            .module_key("ten_a", "email-signup", "resend", &actor())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.expose(), b"re_live_abc123");
    }

    // -- state, disconnect, isolation ----------------------------------

    #[pollster::test]
    async fn disconnect_removes_the_secret_and_marks_not_connected() {
        let (conns, _db) = connections();
        conns
            .connect_google("ten_a", GOOD_ID, "secret", &actor(), "t0")
            .await
            .unwrap();
        let c = conns
            .disconnect("ten_a", &ConnectionKind::VentureGoogleOauth, &actor(), "t1")
            .await
            .unwrap();
        assert_eq!(c.state, ConnectionState::NotConnected);
        assert!(
            conns
                .google_client_secret("ten_a", &actor())
                .await
                .unwrap()
                .is_none(),
            "the secret is gone"
        );
    }

    #[pollster::test]
    async fn disconnecting_something_never_connected_is_a_harmless_no_op() {
        let (conns, _db) = connections();
        let c = conns
            .disconnect("ten_a", &ConnectionKind::VentureGoogleOauth, &actor(), "t0")
            .await
            .expect("no error");
        assert_eq!(c.state, ConnectionState::NotConnected);
    }

    #[pollster::test]
    async fn one_venture_does_not_see_anothers_connections() {
        let (conns, _db) = connections();
        conns
            .connect_google("ten_a", GOOD_ID, "a-secret", &actor(), "t0")
            .await
            .unwrap();
        assert_eq!(conns.all("ten_a").await.unwrap().len(), 1);
        assert!(
            conns.all("ten_b").await.unwrap().is_empty(),
            "tenant b sees nothing of tenant a"
        );
        assert!(
            conns
                .state_of("ten_b", &ConnectionKind::VentureGoogleOauth)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The connection table must never hold secret material — only metadata.
    #[pollster::test]
    async fn no_secret_reaches_the_connection_table_or_a_rendered_connection() {
        let (conns, db) = connections();
        let secret = "TOP-SECRET-DO-NOT-LEAK";
        let c = conns
            .connect_google("ten_a", GOOD_ID, secret, &actor(), "t0")
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

    // -- module-key surfacing ------------------------------------------

    #[test]
    fn a_key_is_surfaced_only_when_its_module_is_selected() {
        use cratefield_catalog::{Catalog, CatalogModule, Tier};
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
                },
                CatalogModule {
                    slug: "waitlist".into(),
                    name: "Waitlist".into(),
                    summary: String::new(),
                    tier: Tier::Optional,
                    depends_on: vec![],
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
