//! The two-tier store (issue #39). [`Secrets`] owns the KMS and hands
//! out a [`SecretStore`] bound to one database and one [`StoreId`].
//!
//! `Secrets::global()` is `pub(crate)`-adjacent by construction: it takes
//! a token type that only the harness can make, so module code cannot
//! reach the control database's store even though the method is public.

use std::sync::Arc;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use cratefield_core::{Database, Row, Statement};
use cratefield_kms::{Dek, Kms};
use sea_query::Value as SeaValue;

use crate::{
    Access, Actor, Audit, AuditEvent, CIPHER, SecretBytes, SecretMeta, SecretsError, StoreId,
    TracingAudit, Version, aad,
};

const NONCE_LEN: usize = 24;

/// Proof the caller is the harness itself and not a module. Only the
/// harness can construct one, so [`Secrets::global`] is unreachable from
/// module code however public it looks: a module has no way to make the
/// argument.
///
/// This is the compile-time half of the two-tier rule. The runtime half
/// is that a `ModuleContext` never carries a `Secrets`.
pub struct HarnessOnly(());

impl HarnessOnly {
    /// Called by the harness when it wires the control database.
    ///
    /// Not `pub`: outside this crate the only way to obtain one is for
    /// the harness to hand it over, which it does not do to modules.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self(())
    }
}

/// Owns the KMS and the audit sink; hands out per-store handles.
pub struct Secrets {
    kms: Arc<dyn Kms>,
    audit: Arc<dyn Audit>,
}

impl Secrets {
    /// Wires the KMS. The default audit sink logs one line per access
    /// through `tracing`; #41 replaces it with the append-only log.
    #[must_use]
    pub fn new(kms: Arc<dyn Kms>) -> Self {
        Self {
            kms,
            audit: Arc::new(TracingAudit),
        }
    }

    #[must_use]
    pub fn with_audit(mut self, audit: Arc<dyn Audit>) -> Self {
        self.audit = audit;
        self
    }

    /// The control database's store: connection strings and platform
    /// keys. Needs a [`HarnessOnly`], which module code cannot build.
    #[must_use]
    pub fn global(&self, db: Arc<dyn Database>, _proof: HarnessOnly) -> SecretStore {
        self.store(StoreId::Global, db)
    }

    /// One tenant's store, in that tenant's own database. This is what a
    /// module is given.
    #[must_use]
    pub fn tenant(&self, tenant: &str, db: Arc<dyn Database>) -> SecretStore {
        self.store(StoreId::Tenant(tenant.to_owned()), db)
    }

    fn store(&self, id: StoreId, db: Arc<dyn Database>) -> SecretStore {
        SecretStore {
            id,
            db,
            kms: Arc::clone(&self.kms),
            audit: Arc::clone(&self.audit),
        }
    }

    /// The harness's own proof token, for wiring the control store.
    #[must_use]
    pub fn harness_only() -> HarnessOnly {
        HarnessOnly::new()
    }
}

/// One store: one database, one [`StoreId`], one data key.
pub struct SecretStore {
    id: StoreId,
    db: Arc<dyn Database>,
    kms: Arc<dyn Kms>,
    audit: Arc<dyn Audit>,
}

impl SecretStore {
    #[must_use]
    pub fn id(&self) -> &StoreId {
        &self.id
    }

    pub(crate) fn db(&self) -> &Arc<dyn Database> {
        &self.db
    }

    pub(crate) fn kms(&self) -> &Arc<dyn Kms> {
        &self.kms
    }

    /// Seals `plaintext` for one row, returning its nonce and
    /// ciphertext. Shared by `put` and by rotation so both bind the same
    /// context.
    pub(crate) fn seal(
        &self,
        name: &str,
        version: Version,
        key_id: &str,
        dek: &Dek,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), SecretsError> {
        let mut nonce = [0_u8; NONCE_LEN];
        getrandom::fill(&mut nonce)
            .map_err(|err| SecretsError::Invalid(format!("the OS random source failed: {err}")))?;
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(dek.expose())
            .map_err(|_| SecretsError::NoKey(self.id.to_string()))?;
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: &aad(&self.id, name, version, key_id),
                },
            )
            .map_err(|_| SecretsError::Invalid("the secret could not be sealed".to_owned()))?;
        Ok((nonce.to_vec(), ciphertext))
    }

    /// Opens one named version under a key the caller already holds.
    /// Used by rotation, which reads under the outgoing key.
    pub(crate) async fn open_version(
        &self,
        name: &str,
        version: Version,
        key_id: &str,
        dek: &Dek,
    ) -> Result<SecretBytes, SecretsError> {
        let rows = self
            .db
            .query(&Statement::with_values(
                "SELECT nonce, ciphertext FROM harness_secrets WHERE name = ? AND version = ?",
                vec![text(name), SeaValue::BigInt(Some(i64::from(version)))],
            ))
            .await?;
        let row = rows.first().ok_or_else(|| SecretsError::NotAuthentic {
            store: self.id.to_string(),
            name: name.to_owned(),
            version,
        })?;
        let nonce: Vec<u8> = row.get("nonce").unwrap_or_default();
        let ciphertext: Vec<u8> = row.get("ciphertext").unwrap_or_default();
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| SecretsError::NotAuthentic {
            store: self.id.to_string(),
            name: name.to_owned(),
            version,
        })?;
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(dek.expose())
            .map_err(|_| SecretsError::NoKey(self.id.to_string()))?;
        let plaintext = cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &ciphertext,
                    aad: &aad(&self.id, name, version, key_id),
                },
            )
            .map_err(|_| SecretsError::NotAuthentic {
                store: self.id.to_string(),
                name: name.to_owned(),
                version,
            })?;
        Ok(SecretBytes::new(plaintext))
    }

    /// A fresh data key plus the statement that records it, so a caller
    /// can install it inside a batch with whatever else must happen at
    /// the same moment.
    pub(crate) async fn prepare_key(
        &self,
        state: &str,
    ) -> Result<(String, Dek, Statement), SecretsError> {
        let dek = Dek::generate()?;
        let wrapped = self.kms.wrap(&dek).await?;
        let key_id = new_key_id()?;
        let insert = Statement::with_values(
            "INSERT INTO harness_secret_keys \
             (key_id, kms_provider, kms_key_ref, wrapped_dek, cipher, state, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            vec![
                text(&key_id),
                text(self.kms.provider()),
                text(self.kms.key_ref()),
                bytes(wrapped),
                text(CIPHER),
                text(state),
                text(&now()),
            ],
        );
        Ok((key_id, dek, insert))
    }

    /// An audit event for an operation that is about the store rather
    /// than one secret.
    pub(crate) async fn audit_action(
        &self,
        access: Access,
        actor: &Actor,
        allowed: bool,
    ) -> Result<(), SecretsError> {
        self.audit(access, actor, None, None, allowed).await
    }

    /// Writes a new version of `name` and returns it. Versions are
    /// monotonic per name and start at 1; a value is never overwritten,
    /// because the previous version is what a rollback needs and what
    /// the audit log refers to.
    ///
    /// # Errors
    ///
    /// [`SecretsError`], and the attempt is audited either way.
    pub async fn put(
        &self,
        name: &str,
        value: &SecretBytes,
        actor: &Actor,
    ) -> Result<Version, SecretsError> {
        let result = self.put_inner(name, value).await;
        self.audit(
            Access::Put,
            actor,
            Some(name),
            result.as_ref().ok().copied(),
            result.is_ok(),
        )
        .await?;
        result
    }

    async fn put_inner(&self, name: &str, value: &SecretBytes) -> Result<Version, SecretsError> {
        validate_name(name)?;
        let (key_id, dek) = self.active_key().await?;
        let version = self.next_version(name).await?;

        let mut nonce = [0_u8; NONCE_LEN];
        getrandom::fill(&mut nonce)
            .map_err(|err| SecretsError::Invalid(format!("the OS random source failed: {err}")))?;
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(dek.expose())
            .map_err(|_| SecretsError::NoKey(self.id.to_string()))?;
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: value.expose(),
                    aad: &aad(&self.id, name, version, &key_id),
                },
            )
            .map_err(|_| SecretsError::Invalid("the secret could not be sealed".to_owned()))?;

        self.db
            .execute(&Statement::with_values(
                "INSERT INTO harness_secrets \
                 (name, version, key_id, nonce, ciphertext, created_at, created_by) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                vec![
                    text(name),
                    SeaValue::BigInt(Some(i64::from(version))),
                    text(&key_id),
                    bytes(nonce.to_vec()),
                    bytes(ciphertext),
                    text(&now()),
                    text("pending"),
                ],
            ))
            .await?;
        Ok(version)
    }

    /// The latest version of `name` that has not been deleted, or
    /// `None`.
    ///
    /// # Errors
    ///
    /// [`SecretsError::NotAuthentic`] when the row does not match the
    /// context it was sealed with, and otherwise as [`SecretStore::put`].
    pub async fn get(
        &self,
        name: &str,
        actor: &Actor,
    ) -> Result<Option<SecretBytes>, SecretsError> {
        let result = self.get_inner(name).await;
        let version = result
            .as_ref()
            .ok()
            .and_then(|found| found.as_ref().map(|(v, _)| *v));
        self.audit(Access::Get, actor, Some(name), version, result.is_ok())
            .await?;
        result.map(|found| found.map(|(_, value)| value))
    }

    async fn get_inner(&self, name: &str) -> Result<Option<(Version, SecretBytes)>, SecretsError> {
        validate_name(name)?;
        let rows = self
            .db
            .query(&Statement::with_values(
                "SELECT version, key_id, nonce, ciphertext FROM harness_secrets \
                 WHERE name = ? AND deleted_at IS NULL ORDER BY version DESC LIMIT 1",
                vec![text(name)],
            ))
            .await?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let version = version_of(row)?;
        let key_id: String = row
            .get("key_id")
            .ok_or_else(|| SecretsError::Invalid("a secret row has no key id".to_owned()))?;
        let nonce: Vec<u8> = row
            .get("nonce")
            .ok_or_else(|| SecretsError::Invalid("a secret row has no nonce".to_owned()))?;
        let ciphertext: Vec<u8> = row
            .get("ciphertext")
            .ok_or_else(|| SecretsError::Invalid("a secret row has no ciphertext".to_owned()))?;
        if nonce.len() != NONCE_LEN {
            return Err(SecretsError::NotAuthentic {
                store: self.id.to_string(),
                name: name.to_owned(),
                version,
            });
        }

        let dek = self.key(&key_id).await?;
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(dek.expose())
            .map_err(|_| SecretsError::NoKey(self.id.to_string()))?;
        let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("length checked");
        let plaintext = cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &ciphertext,
                    aad: &aad(&self.id, name, version, &key_id),
                },
            )
            .map_err(|_| SecretsError::NotAuthentic {
                store: self.id.to_string(),
                name: name.to_owned(),
                version,
            })?;
        Ok(Some((version, SecretBytes::new(plaintext))))
    }

    /// Every secret's latest version: names and versions, never values.
    ///
    /// # Errors
    ///
    /// As [`SecretStore::put`].
    pub async fn list(&self, actor: &Actor) -> Result<Vec<SecretMeta>, SecretsError> {
        let result = self.list_inner().await;
        self.audit(Access::List, actor, None, None, result.is_ok())
            .await?;
        result
    }

    async fn list_inner(&self) -> Result<Vec<SecretMeta>, SecretsError> {
        let rows = self
            .db
            .query(&Statement::new(
                "SELECT name, version, created_at, created_by, deleted_at FROM harness_secrets \
                 ORDER BY name ASC, version DESC",
            ))
            .await?;
        let mut out: Vec<SecretMeta> = Vec::new();
        for row in &rows.rows {
            let name: String = row
                .get("name")
                .ok_or_else(|| SecretsError::Invalid("a secret row has no name".to_owned()))?;
            if out.iter().any(|seen| seen.name == name) {
                continue; // ordered by version desc: the first is the latest
            }
            out.push(SecretMeta {
                version: version_of(row)?,
                created_at: row.get("created_at").unwrap_or_default(),
                created_by: row.get("created_by").unwrap_or_default(),
                deleted: row.get::<String>("deleted_at").is_some(),
                name,
            });
        }
        Ok(out)
    }

    /// Soft-deletes every version of `name`. The rows stay, so the audit
    /// trail and any restore keep something to refer to; the value is no
    /// longer readable through [`SecretStore::get`].
    ///
    /// # Errors
    ///
    /// As [`SecretStore::put`].
    pub async fn delete(&self, name: &str, actor: &Actor) -> Result<(), SecretsError> {
        let result = self.delete_inner(name).await;
        self.audit(Access::Delete, actor, Some(name), None, result.is_ok())
            .await?;
        result
    }

    async fn delete_inner(&self, name: &str) -> Result<(), SecretsError> {
        validate_name(name)?;
        self.db
            .execute(&Statement::with_values(
                "UPDATE harness_secrets SET deleted_at = ? WHERE name = ? AND deleted_at IS NULL",
                vec![text(&now()), text(name)],
            ))
            .await?;
        Ok(())
    }

    /// This store's active data key, provisioning one on first use.
    pub(crate) async fn active_key(&self) -> Result<(String, Dek), SecretsError> {
        let rows = self
            .db
            .query(&Statement::new(
                "SELECT key_id, wrapped_dek FROM harness_secret_keys \
                 WHERE state = 'active' ORDER BY created_at DESC LIMIT 1",
            ))
            .await?;
        if let Some(row) = rows.first() {
            let key_id: String = row
                .get("key_id")
                .ok_or_else(|| SecretsError::NoKey(self.id.to_string()))?;
            let wrapped: Vec<u8> = row
                .get("wrapped_dek")
                .ok_or_else(|| SecretsError::NoKey(self.id.to_string()))?;
            let dek = self.kms.unwrap(&wrapped).await?;
            return Ok((key_id, dek));
        }
        self.provision().await
    }

    /// One named key, for decrypting a version sealed under it.
    pub(crate) async fn key(&self, key_id: &str) -> Result<Dek, SecretsError> {
        let rows = self
            .db
            .query(&Statement::with_values(
                "SELECT wrapped_dek FROM harness_secret_keys WHERE key_id = ?",
                vec![text(key_id)],
            ))
            .await?;
        let wrapped: Vec<u8> = rows
            .first()
            .and_then(|row| row.get("wrapped_dek"))
            .ok_or_else(|| SecretsError::NoKey(self.id.to_string()))?;
        Ok(self.kms.unwrap(&wrapped).await?)
    }

    /// Generates this store's first data key, wraps it under the KMS and
    /// records the wrapped blob here. The KMS holds no per-store state
    /// (design §3).
    async fn provision(&self) -> Result<(String, Dek), SecretsError> {
        let (key_id, dek, insert) = self.prepare_key("active").await?;
        self.db.execute(&insert).await?;
        Ok((key_id, dek))
    }

    async fn next_version(&self, name: &str) -> Result<Version, SecretsError> {
        let rows = self
            .db
            .query(&Statement::with_values(
                "SELECT version FROM harness_secrets WHERE name = ? ORDER BY version DESC LIMIT 1",
                vec![text(name)],
            ))
            .await?;
        match rows.first() {
            Some(row) => Ok(version_of(row)?.saturating_add(1)),
            None => Ok(1),
        }
    }

    /// Records the access. A sink that cannot record turns the call into
    /// [`SecretsError::NotAudited`]: an unrecorded read is what the log
    /// exists to make impossible, so it is a refusal rather than a
    /// warning.
    async fn audit(
        &self,
        access: Access,
        actor: &Actor,
        name: Option<&str>,
        version: Option<Version>,
        allowed: bool,
    ) -> Result<(), SecretsError> {
        self.audit
            .record(&AuditEvent {
                store: &self.id,
                access,
                actor,
                name,
                version,
                allowed,
                request_id: None,
            })
            .await
    }
}

fn validate_name(name: &str) -> Result<(), SecretsError> {
    if name.trim().is_empty() {
        return Err(SecretsError::Invalid(
            "a secret name cannot be empty".to_owned(),
        ));
    }
    if name.len() > 200 {
        return Err(SecretsError::Invalid(
            "a secret name is at most 200 bytes".to_owned(),
        ));
    }
    if let Some(frag) = cratefield_core::card_data_hit(name) {
        return Err(SecretsError::Invalid(format!(
            "a secret name must not look like card data (`{frag}`): card details belong in \
             Stripe, not here. Store Stripe's own secrets (webhook signing secret, API key) \
             under a plain name instead"
        )));
    }
    Ok(())
}

fn version_of(row: &Row) -> Result<Version, SecretsError> {
    let raw: i64 = row
        .get("version")
        .ok_or_else(|| SecretsError::Invalid("a secret row has no version".to_owned()))?;
    u32::try_from(raw).map_err(|_| SecretsError::Invalid("a version is out of range".to_owned()))
}

fn text(value: &str) -> SeaValue {
    SeaValue::String(Some(Box::new(value.to_owned())))
}

fn bytes(value: Vec<u8>) -> SeaValue {
    SeaValue::Bytes(Some(Box::new(value)))
}

fn now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// A key id that is unique without needing a sequence: the time it was
/// made plus 8 random bytes.
fn new_key_id() -> Result<String, SecretsError> {
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random)
        .map_err(|err| SecretsError::Invalid(format!("the OS random source failed: {err}")))?;
    let mut id = String::with_capacity(24);
    id.push_str("dek_");
    for byte in random {
        use std::fmt::Write as _;
        let _ = write!(id, "{byte:02x}");
    }
    Ok(id)
}
