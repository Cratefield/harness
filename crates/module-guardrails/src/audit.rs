//! The audit record: one entry per decision, allow or deny, on [`check`]
//! and on every sign, so an operator can answer "what did the guardrails do
//! and why" from the sink alone.
//!
//! Every entry carries a typed verdict. [`Severity`] exists so a sink can
//! alert without re-deriving importance: `Info` for an allow, `Warn` for an
//! ordinary policy refusal, `Critical` for a hard deny, a kill switch, a
//! simulation failure or any port error — the decisions that mean either an
//! attack attempt or a broken control plane.
//!
//! [`check`]: crate::Guardrails::check

use async_trait::async_trait;
use serde::Serialize;
use time::OffsetDateTime;

use crate::action::TokenKey;
use crate::kill::Scope;

/// How much a decision should interest an operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Severity {
    /// An allow: routine.
    Info,
    /// An ordinary refusal: allowlist, caps, slippage.
    Warn,
    /// A hard deny, a kill switch, a simulation failure or a port error.
    Critical,
}

/// Why the engine refused, typed so sinks can group and alert. `Display`
/// renders the compact text that goes in logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum DenyReason {
    /// The kill switch is engaged at this scope.
    KillSwitch(Scope),
    /// A statically-known dangerous shape; refused whatever the allowlist
    /// says.
    HardDeny(HardDeny),
    /// The chain, contract, selector, program, destination, spender or
    /// delegate is not on the effective allowlist.
    NotAllowlisted(NotAllowlisted),
    /// The simulator is unavailable or errored: fail closed.
    SimulationFailed,
    /// The simulation ran and reverted.
    SimulationReverted,
    /// A spend cap would be exceeded.
    CapExceeded(CapExceeded),
    /// The swap's slippage exceeds the subject's bound.
    SlippageExceeded,
    /// A swap-shaped action (the actor both pays and receives) arrived with
    /// no `SwapQuote` at all, so there is no bound to compare.
    SlippageUnbounded,
    /// The subject has no caps configured. Caps are required, not optional.
    NoCaps,
    /// The subject's caps are configured but unusable: a non-positive or
    /// out-of-range period would silently disable the rolling window.
    InvalidCaps,
    /// A USD cap applies and the price oracle returned no quote for the
    /// token.
    NoPrice(TokenKey),
    /// A port errored; the port is named, the detail is in the log.
    Port(&'static str),
}

impl DenyReason {
    /// Whether this reason is [`Severity::Critical`].
    #[must_use]
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            DenyReason::KillSwitch(_)
                | DenyReason::HardDeny(_)
                | DenyReason::SimulationFailed
                | DenyReason::SimulationReverted
                | DenyReason::Port(_)
        )
    }
}

impl std::fmt::Display for DenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DenyReason::KillSwitch(scope) => write!(f, "kill switch engaged at {}", scope.key()),
            DenyReason::HardDeny(h) => write!(f, "hard deny: {h}"),
            DenyReason::NotAllowlisted(n) => write!(f, "not allowlisted: {n}"),
            DenyReason::SimulationFailed => write!(f, "simulation failed"),
            DenyReason::SimulationReverted => write!(f, "simulation reverted"),
            DenyReason::CapExceeded(c) => write!(f, "cap exceeded: {c}"),
            DenyReason::SlippageExceeded => write!(f, "slippage exceeded"),
            DenyReason::SlippageUnbounded => write!(f, "swap with no slippage bound"),
            DenyReason::NoCaps => write!(f, "no caps configured"),
            DenyReason::InvalidCaps => write!(f, "caps period invalid"),
            DenyReason::NoPrice(token) => write!(f, "no price for {}", token.key()),
            DenyReason::Port(name) => write!(f, "port error: {name}"),
        }
    }
}

/// The statically-known dangerous shapes, refused before any allowlist is
/// consulted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum HardDeny {
    /// `setApprovalForAll`, which grants a spender everything.
    ApprovalForAll,
    /// An approval whose amount crosses the unlimited line (or, on Solana,
    /// `u64::MAX`).
    UnlimitedApproval,
    /// A permit whose spender is not on the spender allowlist.
    PermitUnknownSpender(String),
    /// A permit whose amount is unlimited, or is not statically boundable
    /// (Permit2's batch forms, where the amounts live in a dynamic array).
    PermitUnlimited,
    /// Solana owner reassignment: System `Assign` / `AssignWithSeed`, or
    /// SPL `SetAuthority`.
    OwnerReassignment,
    /// Solana `AdvanceNonceAccount`: durable-nonce use.
    NonceAdvance,
    /// An EIP-7702 authorization with `chain_id == 0`: replayable on every
    /// chain.
    Eip7702ZeroChain,
    /// A delegatecall, in the simulation trace, to a contract that is not
    /// allowlisted.
    DelegateCall(String),
}

impl std::fmt::Display for HardDeny {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HardDeny::ApprovalForAll => write!(f, "setApprovalForAll"),
            HardDeny::UnlimitedApproval => write!(f, "unlimited approval"),
            HardDeny::PermitUnknownSpender(s) => write!(f, "permit to unknown spender {s}"),
            HardDeny::PermitUnlimited => write!(f, "permit amount unlimited or unbounded"),
            HardDeny::OwnerReassignment => write!(f, "owner reassignment"),
            HardDeny::NonceAdvance => write!(f, "durable nonce advance"),
            HardDeny::Eip7702ZeroChain => write!(f, "EIP-7702 authorization for every chain"),
            HardDeny::DelegateCall(to) => write!(f, "delegatecall to {to}"),
        }
    }
}

/// Which allowlist an action fell outside.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum NotAllowlisted {
    /// The chain is not allowlisted.
    Chain,
    /// The contract is not known to the policy.
    Contract(String),
    /// The contract is known, but not for this selector. The string is the
    /// `0x`-prefixed selector, or the reason no selector could be read.
    Selector(String),
    /// The Solana program is not allowlisted.
    Program(String),
    /// A destination — transfer recipient, approve target, credit account —
    /// is not allowlisted.
    Destination(String),
    /// An approval spender is not allowlisted.
    Spender(String),
    /// An EIP-7702 delegate is not an allowlisted contract.
    Delegate(String),
}

impl std::fmt::Display for NotAllowlisted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotAllowlisted::Chain => write!(f, "chain"),
            NotAllowlisted::Contract(c) => write!(f, "contract {c}"),
            NotAllowlisted::Selector(s) => write!(f, "selector {s}"),
            NotAllowlisted::Program(p) => write!(f, "program {p}"),
            NotAllowlisted::Destination(d) => write!(f, "destination {d}"),
            NotAllowlisted::Spender(s) => write!(f, "spender {s}"),
            NotAllowlisted::Delegate(d) => write!(f, "delegate {d}"),
        }
    }
}

/// Which spend window a cap breach landed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CapExceeded {
    /// The single action's outflow.
    PerAction,
    /// The UTC-day total.
    PerDay,
    /// The rolling-period total.
    PerPeriod,
}

impl std::fmt::Display for CapExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CapExceeded::PerAction => write!(f, "per action"),
            CapExceeded::PerDay => write!(f, "per UTC day"),
            CapExceeded::PerPeriod => write!(f, "per rolling period"),
        }
    }
}

/// What was decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Verdict {
    /// Every gate passed; the caller may act.
    Allow,
    /// Refused, for every reason the engine could cheaply collect.
    Deny(Vec<DenyReason>),
}

/// One recorded decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditEntry {
    /// A fresh id, from the `IdGen` port.
    pub id: String,
    /// When the decision was made, from the core `Clock` port.
    pub at: OffsetDateTime,
    /// The venture the acting wallet belongs to.
    pub venture: String,
    /// The subject the policy was resolved for.
    pub subject: String,
    /// What was asked, as [`Request::summary`](crate::Request::summary).
    pub action: String,
    /// Which gate produced the entry: `check`, `sign` or `hygiene`.
    pub stage: &'static str,
    /// The decision.
    pub verdict: Verdict,
    /// How loudly to care.
    pub severity: Severity,
}

/// Why the audit sink could not record.
#[derive(Debug, Clone, thiserror::Error)]
#[error("audit sink: {0}")]
pub struct AuditError(pub String);

/// Where decisions are recorded. Wired with a database-backed sink in
/// production; every decision passes through it, and a sink error fails the
/// decision closed.
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Records one entry. An error is the decision's `Deny`, not a warning.
    ///
    /// # Errors
    ///
    /// When the sink cannot persist the entry; the caller refuses the
    /// action.
    async fn record(&self, entry: &AuditEntry) -> Result<(), AuditError>;
}
