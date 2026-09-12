//! Key rotation (issue #42): the data key, and the wrapping under the
//! master key.
//!
//! Keys that never rotate are an audit finding; rotation that has never
//! been rehearsed is an outage. Both operations therefore take a `plan`
//! flag that answers "what would this do" without doing it, and both are
//! written so that **reads keep working throughout** — a secret row names
//! the key that sealed it, so the old key stays readable until nothing
//! references it.
//!
//! What each one is for:
//!
//! - [`rotate_dek`] replaces the data key. Every live secret is
//!   re-encrypted, so the old key protects nothing afterwards. This is
//!   the yearly rotation and the one to run after an incident.
//! - [`rewrap`] leaves the data keys alone and re-wraps them under the
//!   master key's current material. Nothing is re-encrypted, because
//!   nothing needs to be: the secrets are sealed under the DEKs, not
//!   under the KEK.

use cratefield_core::Statement;
use sea_query::Value as SeaValue;

use crate::{Access, Actor, SecretStore, SecretsError};

/// What a rotation did, or would do with `plan`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationReport {
    /// The key that was active before.
    pub from_key: Option<String>,
    /// The key that is active after. `None` in a plan.
    pub to_key: Option<String>,
    /// Secret versions re-encrypted, or that would be.
    pub reencrypted: usize,
    /// Whether the old key was retired: true only when nothing
    /// references it any more.
    pub retired_old: bool,
    /// `true` when nothing was changed.
    pub planned: bool,
}

/// What a re-wrap did, or would do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewrapReport {
    /// Data keys re-wrapped, or that would be.
    pub keys: usize,
    /// The master key reference they now point at.
    pub key_ref: String,
    pub planned: bool,
}

impl SecretStore {
    /// Rotates this store's data key: a new key becomes active, every
    /// live secret version is re-encrypted under it, and the old key is
    /// retired once nothing references it.
    ///
    /// Reads keep working throughout, because each secret row names the
    /// key that sealed it and the old key row stays until the end. A
    /// rotation interrupted half way leaves a store whose secrets are
    /// split across two keys, which is a valid state: running it again
    /// finishes the job.
    ///
    /// # Errors
    ///
    /// [`SecretsError`]. The attempt is audited either way.
    pub async fn rotate_dek(
        &self,
        actor: &Actor,
        plan: bool,
    ) -> Result<RotationReport, SecretsError> {
        let result = self.rotate_dek_inner(plan).await;
        self.audit_action(Access::RotateDek, actor, result.is_ok())
            .await?;
        result
    }

    async fn rotate_dek_inner(&self, plan: bool) -> Result<RotationReport, SecretsError> {
        let (old_key_id, old_dek) = self.active_key().await?;
        let live = self.live_versions().await?;

        if plan {
            return Ok(RotationReport {
                from_key: Some(old_key_id),
                to_key: None,
                reencrypted: live.len(),
                retired_old: false,
                planned: true,
            });
        }

        // Retire the old key and install the new one together, so there
        // is never a moment with two active keys (which key would a
        // concurrent `put` pick?) or none (a concurrent `put` would
        // provision a third).
        let (new_key_id, new_dek, insert) = self.prepare_key("active").await?;
        self.db()
            .batch_atomic(&[
                Statement::with_values(
                    "UPDATE harness_secret_keys SET state = 'retiring' WHERE key_id = ?",
                    vec![text(&old_key_id)],
                ),
                insert,
            ])
            .await?;

        // Re-encrypt one version at a time. Each row is independently
        // valid before and after, so a read in between sees either the
        // old key or the new one, and both are present.
        let mut reencrypted = 0;
        for (name, version) in &live {
            let plaintext = self
                .open_version(name, *version, &old_key_id, &old_dek)
                .await?;
            let (nonce, ciphertext) =
                self.seal(name, *version, &new_key_id, &new_dek, plaintext.expose())?;
            self.db()
                .execute(&Statement::with_values(
                    "UPDATE harness_secrets SET key_id = ?, nonce = ?, ciphertext = ? \
                     WHERE name = ? AND version = ?",
                    vec![
                        text(&new_key_id),
                        blob(nonce),
                        blob(ciphertext),
                        text(name),
                        SeaValue::BigInt(Some(i64::from(*version))),
                    ],
                ))
                .await?;
            reencrypted += 1;
        }

        // Retire the old key only when nothing points at it. A
        // soft-deleted secret still references its key, so a store with
        // deleted rows keeps the old key `retiring` — deliberately: its
        // ciphertexts are still there, and a key nothing can read is not
        // the same as a key nobody needs.
        let remaining = self.versions_under(&old_key_id).await?;
        let retired_old = remaining == 0;
        if retired_old {
            self.db()
                .execute(&Statement::with_values(
                    "UPDATE harness_secret_keys SET state = 'retired' WHERE key_id = ?",
                    vec![text(&old_key_id)],
                ))
                .await?;
        }

        Ok(RotationReport {
            from_key: Some(old_key_id),
            to_key: Some(new_key_id),
            reencrypted,
            retired_old,
            planned: false,
        })
    }

    /// Re-wraps every data key under the master key's current material,
    /// without touching a single secret. After a KMS rotates its key
    /// material in place, old wrapped keys still unwrap; this makes sure
    /// none of them depends on the old material any more.
    ///
    /// # Errors
    ///
    /// [`SecretsError`]. The attempt is audited either way.
    pub async fn rewrap(&self, actor: &Actor, plan: bool) -> Result<RewrapReport, SecretsError> {
        let result = self.rewrap_inner(plan).await;
        self.audit_action(Access::Rewrap, actor, result.is_ok())
            .await?;
        result
    }

    async fn rewrap_inner(&self, plan: bool) -> Result<RewrapReport, SecretsError> {
        let rows = self
            .db()
            .query(&Statement::with_values(
                format!(
                    "SELECT key_id FROM harness_secret_keys \
                     WHERE state <> 'retired' AND {} ORDER BY key_id",
                    crate::scoped_store()
                ),
                vec![text(self.id().as_str())],
            ))
            .await?;
        let key_ids: Vec<String> = rows
            .rows
            .iter()
            .filter_map(|row| row.get::<String>("key_id"))
            .collect();

        if plan {
            return Ok(RewrapReport {
                keys: key_ids.len(),
                key_ref: self.kms().key_ref().to_owned(),
                planned: true,
            });
        }

        for key_id in &key_ids {
            // Unwrap under whatever wrapped it, wrap again under the
            // current master key. The data key itself does not change,
            // so nothing sealed under it has to be touched.
            let dek = self.key(key_id).await?;
            let wrapped = self.kms().wrap(&dek).await?;
            self.db()
                .execute(&Statement::with_values(
                    "UPDATE harness_secret_keys SET wrapped_dek = ?, kms_provider = ?, \
                     kms_key_ref = ? WHERE key_id = ?",
                    vec![
                        blob(wrapped),
                        text(self.kms().provider()),
                        text(self.kms().key_ref()),
                        text(key_id),
                    ],
                ))
                .await?;
        }

        Ok(RewrapReport {
            keys: key_ids.len(),
            key_ref: self.kms().key_ref().to_owned(),
            planned: false,
        })
    }

    /// Every live secret version, oldest name first. Soft-deleted
    /// versions are left alone: they are not readable, so re-encrypting
    /// them would only move unreadable bytes around.
    async fn live_versions(&self) -> Result<Vec<(String, u32)>, SecretsError> {
        let rows = self
            .db()
            .query(&Statement::with_values(
                format!(
                    "SELECT name, version FROM harness_secrets \
                     WHERE deleted_at IS NULL AND {} ORDER BY name ASC, version ASC",
                    crate::scoped_store()
                ),
                vec![text(self.id().as_str())],
            ))
            .await?;
        let mut out = Vec::with_capacity(rows.rows.len());
        for row in &rows.rows {
            let name: String = row
                .get("name")
                .ok_or_else(|| SecretsError::Invalid("a secret row has no name".to_owned()))?;
            let version: i64 = row
                .get("version")
                .ok_or_else(|| SecretsError::Invalid("a secret row has no version".to_owned()))?;
            let version = u32::try_from(version)
                .map_err(|_| SecretsError::Invalid("a version is out of range".to_owned()))?;
            out.push((name, version));
        }
        Ok(out)
    }

    async fn versions_under(&self, key_id: &str) -> Result<i64, SecretsError> {
        let rows = self
            .db()
            .query(&Statement::with_values(
                format!(
                    "SELECT COUNT(*) AS n FROM harness_secrets WHERE key_id = ? AND {}",
                    crate::scoped_store()
                ),
                vec![text(key_id), text(self.id().as_str())],
            ))
            .await?;
        Ok(rows
            .first()
            .and_then(|row| row.get::<i64>("n"))
            .unwrap_or(0))
    }
}

fn text(value: &str) -> SeaValue {
    SeaValue::String(Some(Box::new(value.to_owned())))
}

fn blob(value: Vec<u8>) -> SeaValue {
    SeaValue::Bytes(Some(Box::new(value)))
}
