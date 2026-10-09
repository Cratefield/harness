//! `cratefield-signer` — the key-reference signing port for wallet
//! automation (issue #761).
//!
//! A venture asks to sign an EVM transaction, an ERC-4337
//! `UserOperation`, EIP-712 data or a Solana message **by key
//! reference**. It never handles raw keys: keys are minted here and
//! referenced everywhere else, and no API in this crate — port,
//! reference implementations, or fakes — exports private key material.
//! That guarantee is the trait's shape ([`KeySigner`] has no method
//! that can answer the question) as much as any implementation's
//! discipline.
//!
//! Every signature is audit-chained: subject, key reference, payload
//! hash, decoded intent, policy decision, outcome. Every sign call
//! passes through the guardrails module before the provider is called,
//! and [`GuardedSigner`] is the composition that makes skipping it
//! impossible. Audit failure fails closed, as does a guardrail that
//! cannot evaluate: an unrecorded or undecided signature is one that
//! never happened.
//!
//! The default composition is [`SecretsSigner`] — a secp256k1 or
//! ed25519 key held in the Secrets port, unsealed only inside `sign` —
//! wrapped in a [`GuardedSigner`]. It mints **session keys only**,
//! never owner keys: there is no import API, and a key's whole life is
//! under a secret a venture can delete.
//!
//! ```
//! use cratefield_signer::{
//!     EvmTransaction, FakeSigner, GuardedSigner, MemorySignAudit, Payload, Scheme,
//!     SignerError, StaticGuardrails, Subject,
//! };
//!
//! # fn main() -> Result<(), SignerError> {
//! let guardrails = StaticGuardrails::new().allow_evm(
//!     1,
//!     "0x000000000000000000000000000000000000aaaa",
//!     [0xa9, 0x05, 0x9c, 0xbb], // ERC-20 transfer
//! )?;
//! let signer = GuardedSigner::new(FakeSigner::new(), guardrails, MemorySignAudit::new());
//! let subject = Subject::new("acme", None)?;
//! let key = pollster::block_on(async {
//!     signer.create_key(&subject, Scheme::Secp256k1, "session-1").await
//! })?;
//!
//! let tx = EvmTransaction {
//!     chain_id: 1,
//!     nonce: 0,
//!     max_priority_fee_per_gas: 1_000_000_000,
//!     max_fee_per_gas: 2_000_000_000,
//!     gas_limit: 21_000,
//!     to: Some("0x000000000000000000000000000000000000aaaa".into()),
//!     value: 1_000_000_000_000_000_000,
//!     data: vec![0xa9, 0x05, 0x9c, 0xbb], // the allowed selector
//! };
//! let signature = pollster::block_on(async {
//!     signer
//!         .sign(&subject, key.key_ref(), &Payload::EvmTransaction(tx))
//!         .await
//! })?;
//! assert!(matches!(signature, cratefield_signer::Signature::Secp256k1 { .. }));
//! # Ok(())
//! # }
//! ```
//!
//! ## Reading order
//!
//! - [`payload`]: what can be signed, how each signing hash is
//!   computed, and the [`Intent`] the guardrails see.
//! - [`port`]: the [`KeySigner`] trait and its error vocabulary.
//! - [`guardrails`]: the [`Guardrails`] seam and the
//!   [`StaticGuardrails`] reference allowlist.
//! - [`audit`]: the [`SignAudit`] seam and the hash-chained
//!   [`MemorySignAudit`].
//! - [`guarded`]: [`GuardedSigner`], the order enforcement lives in.
//! - [`secrets_signer`]: the Secrets-port provider.
//! - [`fakes`] and [`conformance`]: the deterministic fake and the
//!   suite every provider runs.

#![forbid(unsafe_code)]

pub mod audit;
pub mod conformance;
mod crypto;
pub mod fakes;
pub mod guarded;
pub mod guardrails;
pub mod keys;
pub mod payload;
pub mod port;
mod rlp;
pub mod secrets_signer;

pub use audit::{
    AuditAnchor, MemorySignAudit, PolicyDecisionRecord, SignAudit, SignAuditRecord, SignOutcome,
};
pub use conformance::{guardrails_conformance, key_signer_conformance, sign_audit_conformance};
pub use fakes::{FakeGuardrails, FakeSigner, RefusingAudit};
pub use guarded::GuardedSigner;
pub use guardrails::{Guardrails, PolicyDecision, SignContext, StaticGuardrails};
pub use keys::{KeyInfo, KeyRef, KeyRole, Scheme, Signature, Subject};
pub use payload::{
    Chain, Eip712, EvmTransaction, Intent, Payload, SELECTOR_EXECUTE, SolanaMessage, UserOperation,
};
pub use port::{KeySigner, SignerError};
pub use secrets_signer::SecretsSigner;
