//! `cratefield-adapter-turnkey` — the Turnkey provider for the
//! [`KeySigner`](cratefield_signer::KeySigner) port (issue #761).
//!
//! Every end user gets a Turnkey **sub-organization**: their passkey is
//! the root user, a wallet is minted inside it, and our backend is only
//! a **delegated access** user — a second root user whose API key (the
//! P-256 pair this crate stamps with, held in the Secrets port) is
//! scoped by `EFFECT_ALLOW` policies to exactly what the venture
//! allows, then dropped from the root quorum so it can never widen its
//! own permissions. [`set_kill_switch`](TurnkeySigner::set_kill_switch)
//! freezes the backend's signing with one `EFFECT_DENY` policy;
//! [`clear_kill_switch`](TurnkeySigner::clear_kill_switch) lifts it.
//!
//! Signing goes **by key reference** through the port: EVM transactions
//! as `ACTIVITY_TYPE_SIGN_TRANSACTION_V2` (the one activity Turnkey's
//! policy engine parses, so `eth.tx.to`, `eth.tx.chain_id`,
//! `eth.tx.value` and `eth.tx.data[0..10]` conditions bind), digests —
//! `userOpHash`, EIP-712, Solana messages — as
//! `ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2`. No export activity is ever
//! wrapped.
//!
//! ```
//! use cratefield_adapter_turnkey::{AllowRule, key_ref};
//! use cratefield_signer::Scheme;
//!
//! # fn main() -> Result<(), cratefield_signer::SignerError> {
//! // The allow rules a sub-organization's backend is scoped to, and the
//! // reference naming one of its keys — both built without any I/O.
//! let rule = AllowRule::evm(
//!     1,
//!     "0x000000000000000000000000000000000000aaaa",
//!     Some("0xa9059cbb"), // ERC-20 transfer
//!     Some(1_000_000_000_000_000_000),
//! )?;
//! assert_eq!(
//!     rule.condition(),
//!     "eth.tx.to == '0x000000000000000000000000000000000000aaaa' \
//!      && eth.tx.chain_id == 1 \
//!      && eth.tx.data[0..10] == '0xa9059cbb' \
//!      && eth.tx.value <= 1000000000000000000"
//! );
//! let reference = key_ref(
//!     "acme",
//!     "11111111-2222-3333-4444-555555555555",
//!     Scheme::Secp256k1,
//!     "0x000000000000000000000000000000000000aaaa",
//! )?;
//! assert!(reference.as_str().starts_with("turnkey/acme/"));
//! # Ok(())
//! # }
//! ```
//!
//! ## Reading order
//!
//! - [`api`]: [`TurnkeySigner`] — construction, the setup flow, kill
//!   switches, and the typed activity calls underneath the port.
//! - [`policy`]: the pure builders — allow rules, the delegated-access
//!   consensus, and the validators that keep the policy language
//!   injection-proof.
//! - [`stamp`]: the `X-Stamp`, signed inside the call that unseals the
//!   API key.
//! - [`evm`]: the EIP-1559 wire forms — the unsigned transaction
//!   `sign_transaction` asks for, and the signed one back.
//! - [`signer`]: the [`KeySigner`](cratefield_signer::KeySigner)
//!   implementation and the key-reference format, with every answer
//!   verified against the reference's identity before it is returned.
//!
//! ## Why the port's conformance suite does not run here
//!
//! [`cratefield_signer::key_signer_conformance`] starts at
//! `create_key`, and this provider's keys are born with their owner's
//! passkey at sub-organization creation — the port's signature cannot
//! carry an attestation. Its determinism check (RFC 6979 / ed25519,
//! "a provider that disagrees is doing something exotic") also excludes
//! a provider whose signatures are minted by distributed signing
//! infrastructure. The adapter's tests cover what transfers: signing
//! verified against the published identity, scheme mismatches, malformed
//! payloads, and the status-to-error mapping.

#![forbid(unsafe_code)]

pub mod api;
pub mod evm;
pub mod policy;
pub mod signer;
pub mod stamp;

pub use api::{PasskeyAttestation, SubOrgSetup, SubOrganization, TurnkeySigner};
pub use policy::{AllowRule, EvmAddress, ProgramKey, Selector, da_consensus};
pub use signer::key_ref;
