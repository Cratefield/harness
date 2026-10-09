//! The grant store port: every grant lives here with its on-chain id,
//! its status and its usage ledger.

use time::OffsetDateTime;

use crate::grant::{GrantRecord, Usage};

/// Why a store call failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// Two writers raced on the same grant record and produced
    /// contradictory state — for example attaching a different on-chain
    /// binding to an already-granted record.
    #[error("conflicting concurrent write to the grant record")]
    Conflict,
    /// The store under the port failed.
    #[error("the grant store failed: {0}")]
    Backing(&'static str),
}

/// The grant store port. `record_usage`/`usage_since` are the usage
/// ledger the caps are read from: append-only transfers with the instant
/// they happened, folded on read.
#[async_trait::async_trait]
pub trait GrantStore: Send + Sync {
    /// Saves the record, keyed by its spec's id (upsert).
    ///
    /// # Errors
    /// [`StoreError`] when the backing store fails or the write races.
    async fn save(&self, record: GrantRecord) -> Result<(), StoreError>;

    /// Loads the record for `id`.
    ///
    /// # Errors
    /// [`StoreError`] when the backing store fails.
    async fn get(&self, id: &str) -> Result<Option<GrantRecord>, StoreError>;

    /// Loads every record for `owner`, newest first.
    ///
    /// # Errors
    /// [`StoreError`] when the backing store fails.
    async fn list(&self, owner: &str) -> Result<Vec<GrantRecord>, StoreError>;

    /// Appends one action's usage to the ledger at `at`.
    ///
    /// # Errors
    /// [`StoreError`] when the backing store fails.
    async fn record_usage(
        &self,
        id: &str,
        usage: &crate::grant::Usage,
        at: OffsetDateTime,
    ) -> Result<(), StoreError>;

    /// Folds the ledger entries recorded at or after `since` into one
    /// [`Usage`].
    ///
    /// # Errors
    /// [`StoreError`] when the backing store fails.
    async fn usage_since(&self, id: &str, since: OffsetDateTime) -> Result<Usage, StoreError>;
}
