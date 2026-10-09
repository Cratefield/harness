//! The Solana side: Swig roles and sessions (program-scoped actions,
//! SOL/token limits, session expiry, revoke by removing the role) and
//! Squads v4 spending limits for treasury-style transfers.

use crate::grant::{GrantSpec, OnChainBinding};
use crate::types::{OwnerSignature, Pubkey};

/// A transaction signature, base58, as the RPC assigned it.
pub type Signature = String;

/// Why a Swig call failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SwigError {
    /// The spec was refused before anything went on chain.
    #[error("the grant spec was refused: {0}")]
    SpecInvalid(#[from] crate::grant::SpecError),
    /// The signature did not match the credential the spec names.
    #[error("the owner signature does not match the grant's credential")]
    SignatureMismatch,
    /// The spec's scope is not a Swig grant, so this port has nothing to
    /// create.
    #[error("the grant scope is not a Swig grant")]
    ScopeMismatch,
    /// The role does not exist, so it cannot be revoked.
    #[error("no such Swig role: {0}")]
    UnknownRole(String),
    /// The RPC refused or could not be reached.
    #[error("the Solana RPC call failed: {0}")]
    Rpc(String),
}

/// Why a Squads call failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SquadsError {
    /// The spec was refused before anything went on chain.
    #[error("the grant spec was refused: {0}")]
    SpecInvalid(#[from] crate::grant::SpecError),
    /// The signature did not match the credential the spec names.
    #[error("the owner signature does not match the grant's credential")]
    SignatureMismatch,
    /// The spec's scope is not a Squads grant, so this port has nothing
    /// to create.
    #[error("the grant scope is not a Squads grant")]
    ScopeMismatch,
    /// The spending limit does not exist, so it cannot be revoked.
    #[error("no such spending limit: {0}")]
    UnknownLimit(String),
    /// The RPC refused or could not be reached.
    #[error("the Solana RPC call failed: {0}")]
    Rpc(String),
}

/// The Swig port: one role per grant on a Swig wallet, held by a session
/// authority that expires on chain after the spec's TTL. The role carries
/// the program scopes and the SOL/token limits (recurring, and per
/// destination where the spec sets one). Revocation is role removal —
/// owner-signed, like the grant.
#[async_trait::async_trait]
pub trait SwigSessions: Send + Sync {
    /// Creates the role and session authority for `spec`.
    ///
    /// # Errors
    /// [`SwigError::SpecInvalid`] for a spec the crate refuses,
    /// [`SwigError::SignatureMismatch`] when the signature does not match
    /// the credential, [`SwigError::Rpc`] when the transaction fails.
    async fn create_role(
        &self,
        spec: &GrantSpec,
        owner_signature: &OwnerSignature,
    ) -> Result<OnChainBinding, SwigError>;

    /// Removes the role the binding names — the owner-signed on-chain
    /// revoke. The session authority stops working at once.
    ///
    /// # Errors
    /// [`SwigError::UnknownRole`] when the role is already gone,
    /// [`SwigError::Rpc`] when the transaction fails.
    async fn revoke_role(
        &self,
        binding: &OnChainBinding,
        owner_signature: &OwnerSignature,
    ) -> Result<Signature, SwigError>;
}

/// The Squads v4 port: spending limits on a treasury vault, so automation
/// can move treasury funds only within the limit the owner signed.
#[async_trait::async_trait]
pub trait SquadsLimits: Send + Sync {
    /// Creates the spending limits for `spec` on the vault.
    ///
    /// # Errors
    /// [`SquadsError::SpecInvalid`] for a spec the crate refuses,
    /// [`SquadsError::SignatureMismatch`] when the signature does not
    /// match the credential, [`SquadsError::Rpc`] when the transaction
    /// fails.
    async fn create_spending_limit(
        &self,
        spec: &GrantSpec,
        owner_signature: &OwnerSignature,
    ) -> Result<OnChainBinding, SquadsError>;

    /// Deactivates the spending limit the binding names — the
    /// owner-signed revoke, confirmed by the multisig's own threshold.
    ///
    /// # Errors
    /// [`SquadsError::UnknownLimit`] when the limit is already gone,
    /// [`SquadsError::Rpc`] when the transaction fails.
    async fn revoke_spending_limit(
        &self,
        binding: &OnChainBinding,
        owner_signature: &OwnerSignature,
    ) -> Result<Signature, SquadsError>;
}

/// The system program's pubkey, the safest concrete program id an
/// adapter can name in a native-transfer limit.
///
/// # Panics
/// Never at a working checkout: the key is the system program's fixed,
/// well-known one, and its parse is total.
#[must_use]
pub fn system_program() -> Pubkey {
    // The system program's key is 32 zero bytes — in base58, a run of 32
    // `1`s — built here rather than pasted as a long literal.
    let key = "1".repeat(32);
    Pubkey::parse(&key).expect("the system program key")
}
