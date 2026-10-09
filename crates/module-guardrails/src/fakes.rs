//! Fakes for every port in this crate, public so tests and other crates can
//! wire a full engine with no I/O. Each is a cheap cloneable handle over a
//! shared interior, in the style of `cratefield_testing`'s fakes.
//!
//! Interior mutability here records test observations; it is not request
//! state (ADR 0007) — the scoped `Mutex` allow follows the policy in the
//! workspace `clippy.toml`.

#![allow(clippy::disallowed_types)]
// Every accessor locks an unpoisoned fixture mutex; per-method `# Panics`
// sections would add noise without information.
#![allow(clippy::missing_panics_doc)]

use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

use crate::action::{Chain, Request, TokenKey};
use crate::audit::{AuditEntry, AuditError, AuditSink};
use crate::caps::{LedgerError, Prices, PricesError, SpendEntry, SpendLedger};
use crate::hygiene::{Allowance, AllowanceError, AllowanceSource};
use crate::kill::{KillSwitch, KillSwitchError, Scope};
use crate::simulate::{SimError, SimulationReport, Simulator};
use crate::{SignError, WalletSigner};

// ---------------------------------------------------------------------------
// MemoryKillSwitch

/// A kill switch in memory. Engagements are a set of scope keys.
#[derive(Clone, Default)]
pub struct MemoryKillSwitch {
    engaged: Arc<Mutex<BTreeMap<String, String>>>,
}

impl MemoryKillSwitch {
    /// An unengaged switch.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The reason each engaged scope was engaged with, keyed by scope key.
    #[must_use]
    pub fn engagements(&self) -> BTreeMap<String, String> {
        self.engaged.lock().expect("unpoisoned").clone()
    }
}

#[async_trait]
impl KillSwitch for MemoryKillSwitch {
    async fn engaged(&self, scope: &Scope) -> Result<bool, KillSwitchError> {
        Ok(self
            .engaged
            .lock()
            .expect("unpoisoned")
            .contains_key(&scope.key()))
    }

    async fn engage(&self, scope: Scope, reason: &str) -> Result<(), KillSwitchError> {
        self.engaged
            .lock()
            .expect("unpoisoned")
            .insert(scope.key(), reason.to_owned());
        Ok(())
    }

    async fn release(&self, scope: &Scope) -> Result<(), KillSwitchError> {
        self.engaged
            .lock()
            .expect("unpoisoned")
            .remove(&scope.key());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ScriptedSimulator

/// What a [`ScriptedSimulator`] answers with.
#[derive(Debug, Clone)]
pub enum Script {
    /// The configured report.
    Report(SimulationReport),
    /// The configured error.
    Fail(SimError),
}

/// A simulator that answers every call with the configured script and
/// records the requests it was asked about.
#[derive(Clone, Default)]
pub struct ScriptedSimulator {
    inner: Arc<Mutex<ScriptedSim>>,
}

#[derive(Default)]
struct ScriptedSim {
    script: Option<Script>,
    calls: Vec<Request>,
}

impl ScriptedSimulator {
    /// A simulator with no script: it errors like an unreachable endpoint
    /// until a script is set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Answers every simulation with `report`.
    #[must_use]
    pub fn respond(self, report: SimulationReport) -> Self {
        self.set(Script::Report(report));
        self
    }

    /// Fails every simulation with `error`.
    #[must_use]
    pub fn fail(self, error: SimError) -> Self {
        self.set(Script::Fail(error));
        self
    }

    /// Answers with a clean report: success, nothing observed.
    #[must_use]
    pub fn clean(self) -> Self {
        self.respond(SimulationReport::clean())
    }

    fn set(&self, script: Script) {
        self.inner.lock().expect("unpoisoned").script = Some(script);
    }

    /// The requests it has been asked about, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<Request> {
        self.inner.lock().expect("unpoisoned").calls.clone()
    }
}

#[async_trait]
impl Simulator for ScriptedSimulator {
    async fn simulate(&self, request: &Request) -> Result<SimulationReport, SimError> {
        let mut inner = self.inner.lock().expect("unpoisoned");
        inner.calls.push(request.clone());
        match &inner.script {
            Some(Script::Report(report)) => Ok(report.clone()),
            Some(Script::Fail(error)) => Err(error.clone()),
            None => Err(SimError::Unavailable("no script configured".to_owned())),
        }
    }
}

// ---------------------------------------------------------------------------
// FixedPrices

/// A price oracle with a fixed table: token key to micro-USD per smallest
/// unit. A token missing from the table has no quote.
#[derive(Clone, Default)]
pub struct FixedPrices {
    table: Arc<Mutex<BTreeMap<TokenKey, u128>>>,
}

impl FixedPrices {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Prices one token at `micros_per_unit` micro-USD per smallest unit.
    #[must_use]
    pub fn price(self, key: TokenKey, micros_per_unit: u128) -> Self {
        self.table
            .lock()
            .expect("unpoisoned")
            .insert(key, micros_per_unit);
        self
    }

    /// Prices the native coin of `chain`.
    #[must_use]
    pub fn native(self, chain: Chain, micros_per_unit: u128) -> Self {
        self.price(TokenKey::native(chain), micros_per_unit)
    }
}

#[async_trait]
impl Prices for FixedPrices {
    async fn micro_usd(
        &self,
        chain: &Chain,
        token: &str,
        raw_amount: u128,
    ) -> Result<Option<u128>, PricesError> {
        let key = TokenKey {
            chain: chain.clone(),
            token: token.to_owned(),
        };
        Ok(self
            .table
            .lock()
            .expect("unpoisoned")
            .get(&key)
            .map(|per| per.saturating_mul(raw_amount)))
    }
}

// ---------------------------------------------------------------------------
// MemoryLedger

/// A spend ledger in memory: an append-only list of entries.
#[derive(Clone, Default)]
pub struct MemoryLedger {
    entries: Arc<Mutex<Vec<RecordedSpend>>>,
}

/// One recorded entry, with its subject and instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedSpend {
    /// The subject that spent.
    pub subject: String,
    /// The token and amount.
    pub entry: SpendEntry,
    /// When it was recorded.
    pub at: OffsetDateTime,
}

impl MemoryLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every recorded entry, in order.
    #[must_use]
    pub fn recorded(&self) -> Vec<RecordedSpend> {
        self.entries.lock().expect("unpoisoned").clone()
    }
}

#[async_trait]
impl SpendLedger for MemoryLedger {
    async fn spent(
        &self,
        subject: &str,
        token: &TokenKey,
        since: OffsetDateTime,
    ) -> Result<u128, LedgerError> {
        let entries = self.entries.lock().expect("unpoisoned");
        Ok(entries
            .iter()
            .filter(|r| r.subject == subject && r.entry.key == *token && r.at >= since)
            .fold(0_u128, |acc, r| acc.saturating_add(r.entry.micro_usd)))
    }

    async fn record(
        &self,
        subject: &str,
        spend: &[SpendEntry],
        at: OffsetDateTime,
    ) -> Result<(), LedgerError> {
        let mut entries = self.entries.lock().expect("unpoisoned");
        for entry in spend {
            entries.push(RecordedSpend {
                subject: subject.to_owned(),
                entry: entry.clone(),
                at,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MemoryAudit

/// An audit sink in memory, inspectable by the test.
#[derive(Clone, Default)]
pub struct MemoryAudit {
    entries: Arc<Mutex<Vec<AuditEntry>>>,
}

impl MemoryAudit {
    /// An empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every recorded entry, in order.
    #[must_use]
    pub fn entries(&self) -> Vec<AuditEntry> {
        self.entries.lock().expect("unpoisoned").clone()
    }

    /// How many entries are recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().expect("unpoisoned").len()
    }

    /// Whether nothing has been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl AuditSink for MemoryAudit {
    async fn record(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        self.entries.lock().expect("unpoisoned").push(entry.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MemoryAllowances

/// An allowance source with a fixed list.
#[derive(Clone, Default)]
pub struct MemoryAllowances {
    allowances: Arc<Mutex<Vec<Allowance>>>,
}

impl MemoryAllowances {
    /// No open allowances.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Serves `allowances` for every (chain, owner).
    #[must_use]
    pub fn with(self, allowances: Vec<Allowance>) -> Self {
        *self.allowances.lock().expect("unpoisoned") = allowances;
        self
    }
}

#[async_trait]
impl AllowanceSource for MemoryAllowances {
    async fn open_allowances(
        &self,
        _chain: &Chain,
        _owner: &str,
    ) -> Result<Vec<Allowance>, AllowanceError> {
        Ok(self.allowances.lock().expect("unpoisoned").clone())
    }
}

// ---------------------------------------------------------------------------
// RecordingSigner

/// What a [`RecordingSigner`] does when asked to sign.
#[derive(Debug, Clone)]
pub enum SignScript {
    /// Returns the bytes.
    Sign(Vec<u8>),
    /// Returns the error, with this message.
    Fail(String),
}

/// A wallet signer that records every request it is asked to sign and
/// answers with the configured script.
#[derive(Clone, Default)]
pub struct RecordingSigner {
    inner: Arc<Mutex<RecordedSigning>>,
}

#[derive(Default)]
struct RecordedSigning {
    script: Option<SignScript>,
    signed: Vec<Request>,
}

impl RecordingSigner {
    /// Signs to `signature`.
    #[must_use]
    pub fn signing(self, signature: Vec<u8>) -> Self {
        self.set(SignScript::Sign(signature));
        self
    }

    /// Fails with `message`.
    #[must_use]
    pub fn failing(self, message: &str) -> Self {
        self.set(SignScript::Fail(message.to_owned()));
        self
    }

    fn set(&self, script: SignScript) {
        let mut inner = self.inner.lock().expect("unpoisoned");
        inner.script = Some(script);
    }

    /// Every request it has been asked to sign, in order.
    #[must_use]
    pub fn signed(&self) -> Vec<Request> {
        self.inner.lock().expect("unpoisoned").signed.clone()
    }
}

#[async_trait]
impl WalletSigner for RecordingSigner {
    async fn sign(&self, request: &Request) -> Result<Vec<u8>, SignError> {
        let mut inner = self.inner.lock().expect("unpoisoned");
        inner.signed.push(request.clone());
        match &inner.script {
            Some(SignScript::Sign(bytes)) => Ok(bytes.clone()),
            Some(SignScript::Fail(message)) => Err(SignError(message.clone())),
            None => Err(SignError("no script configured".to_owned())),
        }
    }
}

// ---------------------------------------------------------------------------
// FailingAudit

/// An audit sink that always errors, for the fail-closed test.
#[derive(Clone, Copy, Debug, Default)]
pub struct FailingAudit;

#[async_trait]
impl AuditSink for FailingAudit {
    async fn record(&self, _entry: &AuditEntry) -> Result<(), AuditError> {
        Err(AuditError("sink down".to_owned()))
    }
}
