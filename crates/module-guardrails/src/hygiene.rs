//! Allowance hygiene: the approvals a wallet already carries, checked
//! against the same policy that gates new actions.
//!
//! Old approvals are the quiet way past every gate in this crate: an
//! `approve(spender, u256::max)` from three months ago needs no new
//! signature. The scan reads a wallet's open allowances and reports the
//! ones it would not issue today — unlimited ones, and ones to spenders the
//! policy does not name — each with a revoke remedy: an `approve(spender,
//! 0)` transaction, which is a revoke and not a grant, so the simulation
//! gate does not refuse it for naming a non-allowlisted spender. When the
//! subject's policy sets `auto_revoke`, the remedy is sent through
//! [`Guardrails::check`](crate::Guardrails::check) and only reported as done
//! if the engine allowed it, so a revoke is itself simulated, capped and
//! audited.
//!
//! The scan is EVM-only: `AllowanceSource` is an EVM-shaped port, and a
//! Solana wallet's token delegations are revoked with the Token program's
//! `Revoke` instruction, which has no calldata twin here.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::action::{Action, Chain, U256, u256_from_u128};
use crate::deny::SEL_APPROVE;

/// One open allowance on a wallet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allowance {
    /// The approved token, lowercase hex.
    pub token: String,
    /// The spender holding the allowance.
    pub spender: String,
    /// The approved amount.
    pub amount: U256,
}

/// Why a finding is a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum HygieneReason {
    /// The amount crosses the unlimited line.
    Unlimited,
    /// The spender is not on the effective spender allowlist.
    SpenderNotAllowlisted,
}

/// What to do about a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Remedy {
    /// The revoke transaction, for the caller to sign and send.
    Suggest(Action),
    /// The revoke transaction, already allowed by the engine and sent
    /// through the `WalletSigner` the host wired.
    Revoked(Action),
    /// No revoke can be built: the allowance's spender is not a usable
    /// `0x`-hex address, so nothing automatic is safe to send. Fix the
    /// spender spelling at the source.
    Unremediable,
}

/// One finding: the allowance, why it is a finding, and the remedy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HygieneFinding {
    /// The allowance that would not be issued today.
    pub allowance: Allowance,
    /// Why.
    pub reason: HygieneReason,
    /// The `approve(spender, 0)` revoke, where one can be built.
    pub remedy: Remedy,
}

/// Why the allowance source could not answer.
#[derive(Debug, Clone, thiserror::Error)]
#[error("allowances: {0}")]
pub struct AllowanceError(pub String);

/// The port that reads a wallet's open allowances. An adapter wraps the
/// provider's `allowance(token, owner, spender)` calls over the token list
/// it watches.
#[async_trait]
pub trait AllowanceSource: Send + Sync {
    /// Every open allowance of `owner` on `chain`.
    ///
    /// # Errors
    ///
    /// When the on-chain reads fail; the scan reports nothing rather than
    /// guessing, and logs.
    async fn open_allowances(
        &self,
        chain: &Chain,
        owner: &str,
    ) -> Result<Vec<Allowance>, AllowanceError>;
}

/// The `approve(spender, 0)` calldata for a revoke, or `None` when `spender`
/// is not exactly `0x` plus 40 hex digits — a revoke naming the zero
/// address would revoke nothing and report success.
#[must_use]
pub fn revoke_calldata(spender: &str) -> Option<Vec<u8>> {
    let hexed = spender.strip_prefix("0x")?;
    if hexed.len() != 40 || !hexed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut data = SEL_APPROVE.to_be_bytes().to_vec();
    let mut word = [0_u8; 32];
    hex::decode_to_slice(hexed, &mut word[12..]).ok()?;
    data.extend_from_slice(&word);
    data.extend_from_slice(&u256_from_u128(0));
    Some(data)
}

/// The revoke action for one allowance on an EVM chain, or `None` when the
/// allowance's spender cannot name a revoke target (see
/// [`revoke_calldata`]).
#[must_use]
pub fn revoke_action(chain_id: u64, allowance: &Allowance) -> Option<Action> {
    Some(Action::EvmTx {
        chain_id,
        to: Some(allowance.token.clone()),
        value: u256_from_u128(0),
        data: revoke_calldata(&allowance.spender)?,
        authorizations: Vec::new(),
    })
}
