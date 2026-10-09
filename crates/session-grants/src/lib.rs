//! `cratefield-session-grants`: on-chain session grants — scoped, capped,
//! expiring, revocable automation keys (issue #762) for ERC-4337/ERC-7579
//! Kernel accounts, EIP-7702 EOAs, Swig roles and Squads v4 vaults.
//!
//! The owner signs a grant once; the server then acts only inside the
//! on-chain limits. The crate holds the ports (bundler+paymaster, Kernel
//! permissions, Swig sessions, Squads spending limits, grant store), the
//! domain model between them, the off-chain enforcer that gates every
//! server action, the summary the owner reads before signing, and —
//! behind the `testing` feature — a fake for every port plus the
//! conformance suites any real adapter runs against.
//!
//! The two-layer revocation is the design's spine: a deny or pause is an
//! off-chain store write that stops the server immediately, before the
//! owner has signed anything else; the on-chain revoke (`uninstallPlugin`,
//! Swig role removal, Squads limit deactivation) is owner-signed and
//! frees the chain state afterwards.
//!
//! One refusal is absolute: an EIP-7702 authorization for `chain_id = 0`
//! would be valid on every chain, so no grant accepts one — not the
//! constructor, not the wire format, not the spec validation.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod enforce;
mod evm;
#[cfg(feature = "testing")]
mod fakes;
mod grant;
mod solana;
mod store;
mod summary;
mod types;

#[cfg(feature = "testing")]
pub mod conformance;

// The ports.
pub use crate::evm::{
    Bundler, BundlerClient, BundlerError, ENTRY_POINT_V07, GasEstimate, JsonRpcError,
    JsonRpcTransport, KernelError, KernelPermissions, Sponsorship, UserOpHash, UserOpReceipt,
    UserOperation,
};
pub use crate::solana::{
    Signature, SquadsError, SquadsLimits, SwigError, SwigSessions, system_program,
};
pub use crate::store::{GrantStore, StoreError};

// The domain model.
pub use crate::enforce::{Decision, DenyReason, EnforceError, Enforcer, window_start};
pub use crate::grant::{
    ArgCondition, CallPolicy, Chain, Cluster, EvmGrant, GrantId, GrantRecord, GrantScope,
    GrantSpec, GrantStatus, IntendedAction, NativeLimit, OnChainBinding, OwnerId, ProgramScope,
    RateLimit, RecurringLimit, SpecError, SpendPeriod, SpendingLimit, SquadsGrant, SwigGrant,
    TokenLimit, Transfer, Usage, ValidityWindow,
};
pub use crate::summary::{GrantSummary, SummaryEntry, summarize};
pub use crate::types::{
    Address, AuthorizationError, Eip7702Authorization, LiteralError, OwnerCredential,
    OwnerSignature, Pubkey, Selector, SignedAuthorization,
};

// The test kit, on the `testing` feature only.
#[cfg(feature = "testing")]
pub use crate::fakes::{
    FakeBundler, FakeKernelPermissions, FakeRpc, FakeSquads, FakeSwig, FixedClock,
    MemoryGrantStore, MutableClock, WINDOW_START, destination, evm_account, evm_session_key,
    evm_spec, evm_target, passkey, passkey_signature, second_destination, squads_spec,
    swig_session_key, swig_spec, swig_wallet, token_program, transfer_selector, usdc_mint, window,
};
