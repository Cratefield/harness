//! The `Simulator` port: what a request would actually do, before it is
//! allowed to do it.
//!
//! Simulation is not optional. A policy that reasons only over the request
//! sees the transaction a caller wrote; a policy that reasons over a
//! simulation sees what the chain would do — the approvals a flash-loan
//! callback would take, the delegatecalls a proxy would make, the balances
//! that would actually move. An adapter wraps `eth_simulateV1` (state-overridden
//! to the acting address, with the trace enabled) for EVM chains and
//! `simulateTransaction` for Solana; this crate ships the port and the
//! engine, no RPC client.

use async_trait::async_trait;
use serde::Serialize;

use crate::action::{Request, U256};

/// The kind of a call frame in the simulation trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CallKind {
    /// A plain call.
    Call,
    /// A delegatecall: runs foreign code as the caller. Only ever safe into
    /// an allowlisted contract.
    DelegateCall,
    /// A read-only call.
    StaticCall,
    /// Contract creation.
    Create,
}

/// One balance change the simulation observed: `delta` in the token's
/// smallest unit, negative for a debit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BalanceChange {
    /// Whose balance moved.
    pub owner: String,
    /// Which token, or `native`.
    pub token: String,
    /// The signed delta.
    pub delta: i128,
}

/// One approval the simulation observed being taken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApprovalChange {
    /// The token, lowercase hex or `native`.
    pub token: String,
    /// The approving owner.
    pub owner: String,
    /// The spender that received the allowance.
    pub spender: String,
    /// The allowance amount.
    pub amount: U256,
}

impl ApprovalChange {
    /// Whether the amount crosses the unlimited line (2^128).
    #[must_use]
    pub fn is_unlimited(&self) -> bool {
        crate::action::u256_is_unlimited(&self.amount)
    }
}

/// One frame of the simulation's call trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CallFrame {
    /// How the frame was entered.
    pub kind: CallKind,
    /// The target, lowercase hex.
    pub to: String,
}

/// What the simulation observed. `success == false` is a revert: denied, not
/// an error — a revert is an answer about the request, an unavailable
/// simulator is a control-plane fault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SimulationReport {
    /// Whether the execution succeeded.
    pub success: bool,
    /// Every balance change observed.
    pub balance_changes: Vec<BalanceChange>,
    /// Every approval observed.
    pub approvals: Vec<ApprovalChange>,
    /// The call trace.
    pub calls: Vec<CallFrame>,
}

impl SimulationReport {
    /// A clean report: success, nothing observed.
    #[must_use]
    pub fn clean() -> Self {
        Self {
            success: true,
            balance_changes: Vec::new(),
            approvals: Vec::new(),
            calls: Vec::new(),
        }
    }

    /// A revert.
    #[must_use]
    pub fn reverted() -> Self {
        Self {
            success: false,
            ..Self::clean()
        }
    }
}

/// Why the simulation could not be produced. A reverted execution is *not*
/// an error — it is [`SimulationReport::reverted`].
#[derive(Debug, Clone, thiserror::Error)]
pub enum SimError {
    /// The endpoint could not be reached or refused the call.
    #[error("simulator unavailable: {0}")]
    Unavailable(String),
    /// The endpoint's reply did not decode into a report.
    #[error("simulator reply malformed: {0}")]
    Malformed(String),
}

/// The port the engine requires an implementation of. Adapters wrap the
/// provider's simulation endpoints; the fakes in this crate script the
/// reports tests need.
#[async_trait]
pub trait Simulator: Send + Sync {
    /// Simulates the request against current state.
    ///
    /// # Errors
    ///
    /// When the simulation cannot be produced at all (unreachable endpoint,
    /// undecodable reply). The engine denies on any error: fail closed.
    async fn simulate(&self, request: &Request) -> Result<SimulationReport, SimError>;
}
