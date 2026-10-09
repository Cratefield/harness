//! The policy engine every automated value-moving action must pass
//! (issue #763). Default deny everywhere; fail closed on any port error.
//! The README below is the crate documentation: the decision order, the
//! ports, and the limits of what a policy alone can enforce.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod action;
mod audit;
mod caps;
mod deny;
mod fakes;
mod hygiene;
mod kill;
mod policy;
mod simulate;

use async_trait::async_trait;
use time::OffsetDateTime;

use cratefield_core::{
    AnyError, BoxFuture, Clock, Config, ConfigError, IdGen, Migrations, Module, ModuleContext,
    Port, SystemClock, UlidIdGen,
};

pub use crate::action::{
    Action, Authorization7702, Chain, Request, SolanaInstruction, SwapQuote, TokenKey, U256,
    u256_from_u128, u256_is_unlimited, u256_to_u128,
};
pub use crate::audit::{
    AuditEntry, AuditError, AuditSink, CapExceeded, DenyReason, HardDeny, NotAllowlisted, Severity,
    Verdict,
};
pub use crate::caps::{Caps, LedgerError, Prices, PricesError, SpendEntry, SpendLedger};
pub use crate::deny::{
    SEL_APPROVE, SEL_INCREASE_ALLOWANCE, SEL_PERMIT_2612, SEL_PERMIT_DAI, SEL_PERMIT2_APPROVE,
    SEL_PERMIT2_BATCH, SEL_PERMIT2_SINGLE, SEL_SET_APPROVAL_FOR_ALL, SEL_TRANSFER,
    SEL_TRANSFER_FROM, SPL_TOKEN_2022_PROGRAM, SPL_TOKEN_PROGRAM, SYS_ADVANCE_NONCE, SYS_ASSIGN,
    SYS_ASSIGN_WITH_SEED, SYS_TRANSFER, SYSTEM_PROGRAM, TOK_APPROVE, TOK_APPROVE_CHECKED,
    TOK_REVOKE, TOK_SET_AUTHORITY, TOK_TRANSFER, TOK_TRANSFER_CHECKED, hard_denies,
    system_discriminant, tok_discriminant, word, word_addr,
};
pub use crate::fakes::{
    FailingAudit, FixedPrices, MemoryAllowances, MemoryAudit, MemoryKillSwitch, MemoryLedger,
    RecordedSpend, RecordingSigner, Script, ScriptedSimulator, SignScript,
};
pub use crate::hygiene::{
    Allowance, AllowanceError, AllowanceSource, HygieneFinding, HygieneReason, Remedy,
    revoke_action, revoke_calldata,
};
pub use crate::kill::{KillSwitch, KillSwitchError, Scope, turnkey_deny_policy};
pub use crate::policy::{Allowlist, Policy, SubjectPolicy, allowlist_denies, solana_destination};
pub use crate::simulate::{
    ApprovalChange, BalanceChange, CallFrame, CallKind, SimError, SimulationReport, Simulator,
};

/// Why the builder refused to build: a required port was not wired.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("guardrails: required port not wired: {0}")]
pub struct BuildError(&'static str);

/// Why the wallet signer refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("wallet signer: {0}")]
pub struct SignError(pub String);

/// The port that turns an approved request into a signed transaction or
/// signature — the thing a Turnkey-style provider adapter implements.
/// Reached only through [`GuardedSigner`], which re-checks the kill switch
/// first.
#[async_trait]
pub trait WalletSigner: Send + Sync {
    /// Signs the request.
    ///
    /// # Errors
    ///
    /// Whatever the provider reports; the caller audits it as a port error.
    async fn sign(&self, request: &Request) -> Result<Vec<u8>, SignError>;
}

/// A token that exists only because `Guardrails::check` returned `Ok`.
/// Opaque and deliberately not `Clone`: one approval is one audited
/// decision. Constructible by nobody outside this crate — the private
/// `Seal` field sees to that.
#[derive(Debug)]
pub struct Approval {
    request: Request,
    _seal: Seal,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Seal;

impl Approval {
    /// The approved request, for the signer to act on.
    #[must_use]
    pub fn request(&self) -> &Request {
        &self.request
    }
}

/// A refusal, with every reason the engine collected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied {
    /// Why, in the order the gates ran.
    pub reasons: Vec<DenyReason>,
}

impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "denied:")?;
        for reason in &self.reasons {
            write!(f, " {reason}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Denied {}

/// The engine. Built once per venture, from ports and a [`Policy`]; see
/// [`Guardrails::builder`].
pub struct Guardrails {
    policy: Policy,
    kill: std::sync::Arc<dyn KillSwitch>,
    sim: std::sync::Arc<dyn Simulator>,
    prices: std::sync::Arc<dyn Prices>,
    ledger: std::sync::Arc<dyn SpendLedger>,
    audit: std::sync::Arc<dyn AuditSink>,
    clock: std::sync::Arc<dyn Clock>,
    ids: std::sync::Arc<dyn IdGen>,
    allowances: Option<std::sync::Arc<dyn AllowanceSource>>,
}

impl Guardrails {
    /// Starts a builder. Every port is required except the allowance
    /// source, which only the hygiene scan needs; the clock and id
    /// generator default to core's [`SystemClock`] and [`UlidIdGen`].
    #[must_use]
    pub fn builder() -> GuardrailsBuilder {
        GuardrailsBuilder::default()
    }

    /// The policy in force.
    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Whether jobs may be scheduled for this venture and subject at all:
    /// the kill-switch check alone, for the actor that queues work. A port
    /// error answers `false` — fail closed.
    pub async fn job_allowed(&self, venture: &str, subject: &str) -> bool {
        self.kill_denies(venture, subject).await.is_empty()
    }

    /// Runs the full gauntlet and, on allow, hands back the one approval
    /// token [`GuardedSigner::sign`] accepts.
    ///
    /// # Errors
    ///
    /// [`Denied`] with every reason the engine could cheaply collect, when
    /// any gate refuses. An audit-sink error after the ledger recorded the
    /// spend leaves the spend recorded (over-counting is the conservative
    /// direction) and still denies.
    pub async fn check(&self, req: Request) -> Result<Approval, Denied> {
        let summary = req.summary();
        let now = self.clock.now();
        match self.evaluate(&req, now).await {
            Err(mut reasons) => {
                if self
                    .audit_decision(
                        "check",
                        &req.venture,
                        &req.subject,
                        &summary,
                        Verdict::Deny(reasons.clone()),
                    )
                    .await
                    .is_err()
                {
                    reasons.push(DenyReason::Port("audit"));
                }
                Err(Denied { reasons })
            }
            Ok(entries) => {
                // Gate 6: the ledger, only on the way to an allow.
                if !entries.is_empty()
                    && self
                        .ledger
                        .record(&req.subject, &entries, now)
                        .await
                        .is_err()
                {
                    let reasons = vec![DenyReason::Port("ledger")];
                    let _ = self
                        .audit_decision(
                            "check",
                            &req.venture,
                            &req.subject,
                            &summary,
                            Verdict::Deny(reasons.clone()),
                        )
                        .await;
                    return Err(Denied { reasons });
                }
                // Gate 7: the audit, last — its error is still a deny.
                if self
                    .audit_decision(
                        "check",
                        &req.venture,
                        &req.subject,
                        &summary,
                        Verdict::Allow,
                    )
                    .await
                    .is_err()
                {
                    return Err(Denied {
                        reasons: vec![DenyReason::Port("audit")],
                    });
                }
                Ok(Approval {
                    request: req,
                    _seal: Seal,
                })
            }
        }
    }

    /// Reads a wallet's open allowances and reports the ones today's policy
    /// would not issue, each with its `approve(spender, 0)` revoke. With
    /// `auto_revoke` on the subject's policy, the revoke is sent through
    /// [`Guardrails::check`] — simulated, capped and audited like any other
    /// action — and reported [`Remedy::Revoked`] only when allowed.
    ///
    /// EVM chains only; see [`crate::AllowanceSource`] for why.
    pub async fn scan_allowances(
        &self,
        venture: &str,
        subject: &str,
        chain: &Chain,
        owner: &str,
    ) -> Vec<HygieneFinding> {
        let Some(source) = &self.allowances else {
            return Vec::new();
        };
        let Chain::Evm { chain_id } = chain else {
            return Vec::new();
        };
        let Ok(open) = source.open_allowances(chain, owner).await else {
            tracing::warn!(venture, subject, owner, "guardrails: allowance scan failed");
            return Vec::new();
        };
        let mut findings = Vec::new();
        for allowance in open {
            let reason = if u256_is_unlimited(&allowance.amount) {
                HygieneReason::Unlimited
            } else if !self.policy.spender_allowed(subject, &allowance.spender) {
                HygieneReason::SpenderNotAllowlisted
            } else {
                continue;
            };
            let deny = match reason {
                HygieneReason::Unlimited => DenyReason::HardDeny(HardDeny::UnlimitedApproval),
                HygieneReason::SpenderNotAllowlisted => {
                    DenyReason::NotAllowlisted(NotAllowlisted::Spender(allowance.spender.clone()))
                }
            };
            let _ = self
                .audit_decision(
                    "hygiene",
                    venture,
                    subject,
                    &format!("allowance {} <- {}", allowance.token, allowance.spender),
                    Verdict::Deny(vec![deny]),
                )
                .await;
            let remedy = match revoke_action(*chain_id, &allowance) {
                // A spender no revoke can name: report it, but never claim
                // a revoke was sent.
                None => Remedy::Unremediable,
                Some(action) if self.policy.auto_revokes(subject) => {
                    let req = Request {
                        venture: venture.to_owned(),
                        subject: subject.to_owned(),
                        from: owner.to_owned(),
                        action: action.clone(),
                        swap: None,
                    };
                    match self.check(req).await {
                        Ok(_) => Remedy::Revoked(action),
                        Err(_) => Remedy::Suggest(action),
                    }
                }
                Some(action) => Remedy::Suggest(action),
            };
            findings.push(HygieneFinding {
                allowance,
                reason,
                remedy,
            });
        }
        findings
    }

    /// Every kill-switch scope that blocks this actor.
    async fn kill_denies(&self, venture: &str, subject: &str) -> Vec<DenyReason> {
        let mut out = Vec::new();
        for scope in Scope::for_actor(venture, subject) {
            match self.kill.engaged(&scope).await {
                Ok(true) => out.push(DenyReason::KillSwitch(scope)),
                Ok(false) => {}
                Err(_) => out.push(DenyReason::Port("kill switch")),
            }
        }
        out
    }

    /// Gates 1-5: everything up to and including the caps. `Ok` carries the
    /// priced spend entries the ledger must record on the way to an allow.
    async fn evaluate(
        &self,
        req: &Request,
        now: OffsetDateTime,
    ) -> Result<Vec<SpendEntry>, Vec<DenyReason>> {
        let mut reasons = self.kill_denies(&req.venture, &req.subject).await;
        if reasons.is_empty() {
            reasons = hard_denies(req, &self.policy);
        }
        if reasons.is_empty() {
            reasons = allowlist_denies(req, &self.policy);
        }
        if !reasons.is_empty() {
            return Err(reasons);
        }
        let report = match self.sim.simulate(req).await {
            Ok(report) if report.success => report,
            Ok(_) => return Err(vec![DenyReason::SimulationReverted]),
            Err(_) => return Err(vec![DenyReason::SimulationFailed]),
        };
        reasons = self.report_denies(req, &report);
        if reasons.is_empty() {
            return self.cap_denies(req, &report, now).await;
        }
        Err(reasons)
    }

    /// The simulation report's own denies: unlimited approvals, approvals
    /// to unknown spenders, credits to unknown destinations, delegatecalls
    /// into unknown contracts.
    fn report_denies(&self, req: &Request, report: &SimulationReport) -> Vec<DenyReason> {
        let subject = &req.subject;
        let evm = req.chain().is_evm();
        let mut out = Vec::new();
        for approval in &report.approvals {
            if approval.is_unlimited() {
                out.push(DenyReason::HardDeny(HardDeny::UnlimitedApproval));
            }
            // approve(spender, 0) revokes, it does not grant: the hygiene
            // scan's auto-revoke lands here, naming a spender the policy no
            // longer allows — which is rather the point.
            if approval.amount != [0_u8; 32]
                && !self.policy.spender_allowed(subject, &approval.spender)
            {
                out.push(DenyReason::NotAllowlisted(NotAllowlisted::Spender(
                    approval.spender.clone(),
                )));
            }
        }
        for change in &report.balance_changes {
            // A positive delta for anyone but the actor is the actor paying
            // them: the recipient is a destination.
            if change.delta > 0
                && change.owner != req.from
                && !self.policy.destination_allowed(subject, &change.owner, evm)
            {
                out.push(DenyReason::NotAllowlisted(NotAllowlisted::Destination(
                    change.owner.clone(),
                )));
            }
        }
        for call in &report.calls {
            if call.kind == CallKind::DelegateCall && !self.policy.contract_known(subject, &call.to)
            {
                out.push(DenyReason::HardDeny(HardDeny::DelegateCall(
                    call.to.clone(),
                )));
            }
        }
        out
    }

    /// The caps half of gate 5: the swap bound, then the three windows per
    /// outflowing token. `Ok` is the priced entries to record.
    async fn cap_denies(
        &self,
        req: &Request,
        report: &SimulationReport,
        now: OffsetDateTime,
    ) -> Result<Vec<SpendEntry>, Vec<DenyReason>> {
        let Some(caps) = self.policy.caps_for(&req.subject) else {
            return Err(vec![DenyReason::NoCaps]);
        };
        let mut out = Vec::new();
        // A swap-shaped report — the actor both pays and receives — must
        // carry an explicit bound, or there is nothing to compare: refuse
        // it rather than wave it through unpriced.
        let pays = report
            .balance_changes
            .iter()
            .any(|c| c.owner == req.from && c.delta < 0);
        let receives = report
            .balance_changes
            .iter()
            .any(|c| c.owner == req.from && c.delta > 0);
        match (&req.swap, pays && receives) {
            (Some(quote), _) => {
                let over_bps = if quote.quoted_out == 0 || quote.min_out > quote.quoted_out {
                    u128::MAX
                } else {
                    (quote.quoted_out - quote.min_out).saturating_mul(10_000) / quote.quoted_out
                };
                if over_bps > u128::from(caps.max_slippage_bps) {
                    out.push(DenyReason::SlippageExceeded);
                }
            }
            (None, true) => out.push(DenyReason::SlippageUnbounded),
            (None, false) => {}
        }
        let outflows = outflows_of(req, report);
        if outflows.is_empty() {
            return if out.is_empty() {
                Ok(Vec::new())
            } else {
                Err(out)
            };
        }
        // A non-positive or out-of-range period would silently disable the
        // rolling window; refuse the subject instead of trusting it.
        if caps.period <= time::Duration::ZERO {
            return Err(vec![DenyReason::InvalidCaps]);
        }
        let Some(period_start) = now.checked_sub(caps.period) else {
            return Err(vec![DenyReason::InvalidCaps]);
        };
        let day_start = now.replace_time(time::Time::MIDNIGHT);
        let mut entries = Vec::new();
        for (token, raw) in outflows {
            let usd = match self.prices.micro_usd(&token.chain, &token.token, raw).await {
                Ok(Some(usd)) => usd,
                Ok(None) => {
                    out.push(DenyReason::NoPrice(token.clone()));
                    continue;
                }
                Err(_) => {
                    out.push(DenyReason::Port("prices"));
                    continue;
                }
            };
            let limit = |m: &std::collections::BTreeMap<TokenKey, u128>| {
                m.get(&token).copied().unwrap_or(0)
            };
            if usd > limit(&caps.per_action) {
                out.push(DenyReason::CapExceeded(CapExceeded::PerAction));
            }
            match self.ledger.spent(&req.subject, &token, day_start).await {
                Ok(spent)
                    if spent
                        .checked_add(usd)
                        .is_none_or(|t| t > limit(&caps.per_day)) =>
                {
                    out.push(DenyReason::CapExceeded(CapExceeded::PerDay));
                }
                Ok(_) => {}
                Err(_) => out.push(DenyReason::Port("ledger")),
            }
            match self.ledger.spent(&req.subject, &token, period_start).await {
                Ok(spent)
                    if spent
                        .checked_add(usd)
                        .is_none_or(|t| t > limit(&caps.per_period)) =>
                {
                    out.push(DenyReason::CapExceeded(CapExceeded::PerPeriod));
                }
                Ok(_) => {}
                Err(_) => out.push(DenyReason::Port("ledger")),
            }
            entries.push(SpendEntry {
                key: token.clone(),
                micro_usd: usd,
            });
        }
        if out.is_empty() {
            Ok(entries)
        } else {
            Err(out)
        }
    }

    /// Records one decision. An error is the caller's deny, not a log line.
    async fn audit_decision(
        &self,
        stage: &'static str,
        venture: &str,
        subject: &str,
        action: &str,
        verdict: Verdict,
    ) -> Result<(), AuditError> {
        let severity = match &verdict {
            Verdict::Allow => Severity::Info,
            Verdict::Deny(reasons) if reasons.iter().any(DenyReason::is_critical) => {
                Severity::Critical
            }
            Verdict::Deny(_) => Severity::Warn,
        };
        let entry = AuditEntry {
            id: self.ids.ulid(),
            at: self.clock.now(),
            venture: venture.to_owned(),
            subject: subject.to_owned(),
            action: action.to_owned(),
            stage,
            verdict,
            severity,
        };
        let result = self.audit.record(&entry).await;
        match (&entry.severity, &result) {
            (Severity::Critical, _) => {
                tracing::error!(audit = %entry.id, venture = %entry.venture, subject = %entry.subject, stage, "guardrails {}: {}", stage, entry.action);
            }
            (Severity::Warn, _) => {
                tracing::warn!(audit = %entry.id, venture = %entry.venture, subject = %entry.subject, stage, "guardrails {}: {}", stage, entry.action);
            }
            (Severity::Info, Err(_)) => {
                tracing::error!(audit = %entry.id, stage, "guardrails: audit sink failed after an allow");
            }
            (Severity::Info, Ok(())) => {}
        }
        result
    }
}

/// The outflows a report would move: the actor's negative balance changes,
/// as (token, raw amount).
fn outflows_of(req: &Request, report: &SimulationReport) -> Vec<(TokenKey, u128)> {
    let chain = req.chain();
    report
        .balance_changes
        .iter()
        .filter(|c| c.owner == req.from && c.delta < 0)
        .map(|c| {
            (
                TokenKey {
                    chain: chain.clone(),
                    token: c.token.clone(),
                },
                c.delta.unsigned_abs(),
            )
        })
        .collect()
}

/// Builds a [`Guardrails`]. Every port is required except the allowance
/// source; the clock and id generator default to core's.
#[derive(Default)]
pub struct GuardrailsBuilder {
    policy: Option<Policy>,
    kill: Option<std::sync::Arc<dyn KillSwitch>>,
    simulator: Option<std::sync::Arc<dyn Simulator>>,
    prices: Option<std::sync::Arc<dyn Prices>>,
    ledger: Option<std::sync::Arc<dyn SpendLedger>>,
    audit: Option<std::sync::Arc<dyn AuditSink>>,
    allowances: Option<std::sync::Arc<dyn AllowanceSource>>,
    clock: Option<std::sync::Arc<dyn Clock>>,
    ids: Option<std::sync::Arc<dyn IdGen>>,
}

impl GuardrailsBuilder {
    /// Sets the policy.
    #[must_use]
    pub fn policy(mut self, policy: Policy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Wires the kill switch.
    #[must_use]
    pub fn kill_switch(mut self, kill: impl KillSwitch + 'static) -> Self {
        self.kill = Some(std::sync::Arc::new(kill));
        self
    }

    /// Wires the simulator.
    #[must_use]
    pub fn simulator(mut self, simulator: impl Simulator + 'static) -> Self {
        self.simulator = Some(std::sync::Arc::new(simulator));
        self
    }

    /// Wires the price oracle.
    #[must_use]
    pub fn prices(mut self, prices: impl Prices + 'static) -> Self {
        self.prices = Some(std::sync::Arc::new(prices));
        self
    }

    /// Wires the spend ledger.
    #[must_use]
    pub fn ledger(mut self, ledger: impl SpendLedger + 'static) -> Self {
        self.ledger = Some(std::sync::Arc::new(ledger));
        self
    }

    /// Wires the audit sink.
    #[must_use]
    pub fn audit(mut self, audit: impl AuditSink + 'static) -> Self {
        self.audit = Some(std::sync::Arc::new(audit));
        self
    }

    /// Wires the allowance source (optional; the hygiene scan only).
    #[must_use]
    pub fn allowances(mut self, allowances: impl AllowanceSource + 'static) -> Self {
        self.allowances = Some(std::sync::Arc::new(allowances));
        self
    }

    /// Overrides the clock (default [`SystemClock`]).
    #[must_use]
    pub fn clock(mut self, clock: impl Clock + 'static) -> Self {
        self.clock = Some(std::sync::Arc::new(clock));
        self
    }

    /// Overrides the id generator (default [`UlidIdGen`]).
    #[must_use]
    pub fn id_gen(mut self, ids: impl IdGen + 'static) -> Self {
        self.ids = Some(std::sync::Arc::new(ids));
        self
    }

    /// Builds.
    ///
    /// # Errors
    ///
    /// [`BuildError`] naming the first required port that was not wired.
    pub fn build(self) -> Result<Guardrails, BuildError> {
        Ok(Guardrails {
            policy: self.policy.ok_or(BuildError("policy"))?,
            kill: self.kill.ok_or(BuildError("kill switch"))?,
            sim: self.simulator.ok_or(BuildError("simulator"))?,
            prices: self.prices.ok_or(BuildError("prices"))?,
            ledger: self.ledger.ok_or(BuildError("ledger"))?,
            audit: self.audit.ok_or(BuildError("audit"))?,
            clock: self
                .clock
                .unwrap_or_else(|| std::sync::Arc::new(SystemClock)),
            ids: self.ids.unwrap_or_else(|| std::sync::Arc::new(UlidIdGen)),
            allowances: self.allowances,
        })
    }
}

/// The signer hosts hand to code that moves value. `sign` consumes the
/// approval `Guardrails::check` issued and re-checks all three kill-switch
/// scopes — so engaging the switch after a check blocks the in-flight job
/// at the moment of signing, and audits that decision too.
pub struct GuardedSigner {
    engine: std::sync::Arc<Guardrails>,
    inner: std::sync::Arc<dyn WalletSigner>,
}

impl GuardedSigner {
    /// Wraps `inner`, reached only through approvals from `engine`.
    #[must_use]
    pub fn new(
        engine: std::sync::Arc<Guardrails>,
        inner: std::sync::Arc<dyn WalletSigner>,
    ) -> Self {
        Self { engine, inner }
    }

    /// Signs the approved request, unless a kill switch has been engaged
    /// since it was issued.
    ///
    /// # Errors
    ///
    /// [`Denied`] when any scope is engaged, a port errors, or the signer
    /// itself fails — every one audited.
    pub async fn sign(&self, approval: Approval) -> Result<Vec<u8>, Denied> {
        let req = approval.request;
        let summary = req.summary();
        let reasons = self.engine.kill_denies(&req.venture, &req.subject).await;
        if !reasons.is_empty() {
            let mut reasons = reasons;
            if self
                .engine
                .audit_decision(
                    "sign",
                    &req.venture,
                    &req.subject,
                    &summary,
                    Verdict::Deny(reasons.clone()),
                )
                .await
                .is_err()
            {
                reasons.push(DenyReason::Port("audit"));
            }
            return Err(Denied { reasons });
        }
        if self
            .engine
            .audit_decision("sign", &req.venture, &req.subject, &summary, Verdict::Allow)
            .await
            .is_err()
        {
            return Err(Denied {
                reasons: vec![DenyReason::Port("audit")],
            });
        }
        if let Ok(signature) = self.inner.sign(&req).await {
            return Ok(signature);
        }
        let reasons = vec![DenyReason::Port("signer")];
        let _ = self
            .engine
            .audit_decision(
                "sign",
                &req.venture,
                &req.subject,
                &summary,
                Verdict::Deny(reasons.clone()),
            )
            .await;
        Err(Denied { reasons })
    }
}

/// One watched wallet for the module's scheduled hygiene scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchedWallet {
    /// The venture the wallet belongs to.
    pub venture: String,
    /// The subject whose policy governs it.
    pub subject: String,
    /// The chain to scan.
    pub chain: Chain,
    /// The wallet address.
    pub owner: String,
}

/// The engine as a harness [`Module`]: no tables, no routes to speak of,
/// and a `scheduled` hook that runs the hygiene scan over the watched
/// wallets.
#[derive(Clone)]
pub struct GuardrailsModule {
    engine: std::sync::Arc<Guardrails>,
    watched: std::sync::Arc<Vec<WatchedWallet>>,
}

impl GuardrailsModule {
    /// Mounts the engine; `watch` adds scanned wallets.
    #[must_use]
    pub fn new(engine: std::sync::Arc<Guardrails>) -> Self {
        Self {
            engine,
            watched: std::sync::Arc::new(Vec::new()),
        }
    }

    /// Adds a wallet to the scheduled hygiene scan.
    #[must_use]
    pub fn watch(&self, wallet: WatchedWallet) -> Self {
        let mut watched = (*self.watched).clone();
        watched.push(wallet);
        Self {
            engine: std::sync::Arc::clone(&self.engine),
            watched: std::sync::Arc::new(watched),
        }
    }

    /// The engine, for hosts that call `check` or `job_allowed` directly.
    #[must_use]
    pub fn engine(&self) -> std::sync::Arc<Guardrails> {
        std::sync::Arc::clone(&self.engine)
    }
}

impl Module for GuardrailsModule {
    fn name(&self) -> &'static str {
        "guardrails"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        // The engine carries its own ports, wired at build time.
        &[]
    }

    fn migrations(&self) -> Migrations {
        Migrations::EMPTY
    }

    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }

    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        axum::Router::new().route("/", axum::routing::get(|| async { "guardrails" }))
    }

    fn scheduled<'a>(
        &'a self,
        ctx: &'a ModuleContext,
        cron: &'a str,
    ) -> BoxFuture<'a, Result<(), AnyError>> {
        let _ = (ctx, cron);
        Box::pin(async move {
            for wallet in self.watched.iter() {
                for finding in self
                    .engine
                    .scan_allowances(
                        &wallet.venture,
                        &wallet.subject,
                        &wallet.chain,
                        &wallet.owner,
                    )
                    .await
                {
                    tracing::warn!(
                        venture = %wallet.venture,
                        subject = %wallet.subject,
                        owner = %wallet.owner,
                        "guardrails hygiene: {:?} on {} <- {}",
                        finding.reason,
                        finding.allowance.token,
                        finding.allowance.spender
                    );
                }
            }
            Ok(())
        })
    }
}
