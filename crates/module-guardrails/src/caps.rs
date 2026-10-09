//! Spend caps and their two ports: valuation (`Prices`) and memory
//! (`SpendLedger`).
//!
//! All caps are micro-USD, per token, because raw token amounts do not
//! compare. A token with no configured cap has a cap of zero — default deny
//! reaches the caps too. What is capped is the simulation's outflow for the
//! acting address, not what the caller claimed.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::{Duration, OffsetDateTime};

use crate::action::{Chain, TokenKey};

/// The spend windows, per subject. Every map is micro-USD keyed by token;
/// a missing entry is a cap of zero. `period` is the rolling window the
/// `per_period` map is measured over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caps {
    /// The most one action may move, per token.
    pub per_action: BTreeMap<TokenKey, u128>,
    /// The most one UTC day may move, per token, the day starting at the
    /// decision instant's UTC midnight.
    pub per_day: BTreeMap<TokenKey, u128>,
    /// How long the rolling window is. Must be positive and within range of
    /// a timestamp: anything else disables the window, and the engine
    /// refuses the subject instead of trusting it.
    pub period: Duration,
    /// The most the rolling window may move, per token.
    pub per_period: BTreeMap<TokenKey, u128>,
    /// The largest slippage a swap may carry, in basis points
    /// (`(quoted - min) / quoted`). A swap with no bound configured is
    /// refused.
    pub max_slippage_bps: u64,
}

impl Caps {
    /// The same micro-USD limit on every window, for one token: the policy
    /// for a subject that works in one or two assets and does not need a
    /// table each. Other tokens keep their default cap of zero.
    #[must_use]
    pub fn uniform(
        token: &TokenKey,
        per_action: u128,
        per_day: u128,
        per_period: u128,
        period: Duration,
        max_slippage_bps: u64,
    ) -> Self {
        let one = |v: u128| BTreeMap::from([(token.clone(), v)]);
        Self {
            per_action: one(per_action),
            per_day: one(per_day),
            period,
            per_period: one(per_period),
            max_slippage_bps,
        }
    }
}

/// One recorded outflow: what token, how much in micro-USD.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendEntry {
    /// The token that moved.
    pub key: TokenKey,
    /// The micro-USD value of what moved.
    pub micro_usd: u128,
}

/// Why valuation failed.
#[derive(Debug, Clone, thiserror::Error)]
#[error("prices: {0}")]
pub struct PricesError(pub String);

/// The valuation port: raw amount to micro-USD.
///
/// An oracle-backed adapter prices by (chain, token) with the token's
/// decimals; this crate ships a fixed-table fake. A missing quote is not an
/// error — it is `Ok(None)` — because "no price" is a normal oracle state,
/// and the engine's answer to it is a deny, not a panic.
#[async_trait]
pub trait Prices: Send + Sync {
    /// The micro-USD value of `raw_amount` smallest units of `token` on
    /// `chain`, or `None` when the oracle has no quote.
    ///
    /// # Errors
    ///
    /// When the oracle itself fails (unreachable, malformed). Distinct from
    /// "no quote": an oracle failure denies too, but logs differently.
    async fn micro_usd(
        &self,
        chain: &Chain,
        token: &str,
        raw_amount: u128,
    ) -> Result<Option<u128>, PricesError>;
}

/// Why the ledger could not answer or record.
#[derive(Debug, Clone, thiserror::Error)]
#[error("spend ledger: {0}")]
pub struct LedgerError(pub String);

/// The memory port: what a subject has already spent in a window, and the
/// write side that accumulates it.
///
/// **The caller must serialize per subject**: `spent` + `record` is a
/// check-then-act pair, and only the harness's one-actor-per-subject
/// contract makes it sound. See the crate README's Limits.
#[async_trait]
pub trait SpendLedger: Send + Sync {
    /// The micro-USD `subject` has recorded against `token` at or after
    /// `since`.
    ///
    /// # Errors
    ///
    /// When the ledger cannot be read; the engine denies on any error.
    async fn spent(
        &self,
        subject: &str,
        token: &TokenKey,
        since: OffsetDateTime,
    ) -> Result<u128, LedgerError>;

    /// Records outflows at `at`. Called only on an allow.
    ///
    /// # Errors
    ///
    /// When the record cannot be persisted; the engine denies on any error.
    async fn record(
        &self,
        subject: &str,
        entries: &[SpendEntry],
        at: OffsetDateTime,
    ) -> Result<(), LedgerError>;
}
