//! The fakes for every port in the crate, for tests here and in adapters
//! that later implement the ports for real: an in-memory grant store, a
//! bundler and a JSON-RPC transport that record what was sent, a Kernel
//! permission registry, and Swig/Squads registries — plus the two clocks
//! the enforcement tests move by hand.
//!
//! This module is the crate's own test kit, gated behind the `testing`
//! feature so a default build carries none of it. Its state is guarded by
//! `std::sync::Mutex`: shared mutable state, but test-only and scoped, the
//! way `cratefield-testing`'s recording fakes are (ADR 0007; the scoped
//! allow follows the policy in `clippy.toml`). Every accessor locks an
//! unpoisoned fixture mutex; per-method `# Panics` sections would be the
//! same sentence on every one — a poisoned lock panics the test that
//! shares it.

#![allow(clippy::disallowed_types)]
#![allow(clippy::missing_panics_doc)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cratefield_core::Clock;
use time::OffsetDateTime;

use crate::evm::{
    Bundler, BundlerError, GasEstimate, JsonRpcError, JsonRpcTransport, KernelError,
    KernelPermissions, Sponsorship, UserOpHash, UserOpReceipt, UserOperation,
};
use crate::grant::{GrantId, GrantRecord, GrantScope, OnChainBinding, Usage};
use crate::solana::{Signature, SquadsError, SquadsLimits, SwigError, SwigSessions};
use crate::store::{GrantStore, StoreError};
use crate::types::{OwnerCredential, OwnerSignature};

// -------------------------------------------------------------------------
// Clocks

/// A clock stopped at one instant. For a check whose answer depends on
/// "now" and never moves.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

/// A clock a test moves by hand, so expiry and recurring windows are
/// exercised without sleeping. Every clone shares the one instant.
#[derive(Debug, Clone)]
pub struct MutableClock(Arc<Mutex<OffsetDateTime>>);

impl MutableClock {
    /// A clock stopped at `at`.
    #[must_use]
    pub fn new(at: OffsetDateTime) -> Self {
        Self(Arc::new(Mutex::new(at)))
    }

    /// Moves the clock forward by `secs` seconds.
    pub fn advance_seconds(&self, secs: i64) {
        *self.0.lock().expect("clock lock") += time::Duration::seconds(secs);
    }

    /// The clock's current instant.
    #[must_use]
    pub fn now(&self) -> OffsetDateTime {
        *self.0.lock().expect("clock lock")
    }
}

impl Clock for MutableClock {
    fn now(&self) -> OffsetDateTime {
        self.now()
    }
}

// -------------------------------------------------------------------------
// MemoryGrantStore

/// The in-memory [`GrantStore`]: the grant records keyed by id, each with
/// its usage ledger. Shared clones see one state.
#[derive(Debug, Clone, Default)]
pub struct MemoryGrantStore {
    inner: Arc<Mutex<HashMap<GrantId, Stored>>>,
}

#[derive(Debug, Default)]
struct Stored {
    record: Option<GrantRecord>,
    ledger: Vec<(OffsetDateTime, Usage)>,
}

impl MemoryGrantStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many grants are stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().expect("store lock").len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl GrantStore for MemoryGrantStore {
    async fn save(&self, record: GrantRecord) -> Result<(), StoreError> {
        let mut map = self.inner.lock().expect("store lock");
        let stored = map.entry(record.spec.id.clone()).or_default();
        // Never swap one grant's on-chain binding for another's.
        if let Some(existing) = &stored.record
            && existing.on_chain.is_some()
            && record.on_chain.is_some()
            && existing.on_chain != record.on_chain
        {
            return Err(StoreError::Conflict);
        }
        stored.record = Some(record);
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<GrantRecord>, StoreError> {
        Ok(self
            .inner
            .lock()
            .expect("store lock")
            .get(id)
            .and_then(|stored| stored.record.clone()))
    }

    async fn list(&self, owner: &str) -> Result<Vec<GrantRecord>, StoreError> {
        let mut records: Vec<GrantRecord> = self
            .inner
            .lock()
            .expect("store lock")
            .values()
            .filter_map(|stored| stored.record.clone())
            .filter(|record| record.spec.owner == owner)
            .collect();
        records.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then(a.spec.id.cmp(&b.spec.id))
        });
        Ok(records)
    }

    async fn record_usage(
        &self,
        id: &str,
        usage: &Usage,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let mut map = self.inner.lock().expect("store lock");
        let stored = map
            .get_mut(id)
            .ok_or(StoreError::Backing("no grant under that id"))?;
        stored.ledger.push((at, usage.clone()));
        Ok(())
    }

    async fn usage_since(&self, id: &str, since: OffsetDateTime) -> Result<Usage, StoreError> {
        let map = self.inner.lock().expect("store lock");
        let stored = map
            .get(id)
            .ok_or(StoreError::Backing("no grant under that id"))?;
        let mut usage = Usage::default();
        for (at, entry) in &stored.ledger {
            if *at >= since {
                usage.merge(entry);
            }
        }
        Ok(usage)
    }
}

// -------------------------------------------------------------------------
// FakeRpc

/// The [`JsonRpcTransport`] fake: captures every `(method, params)` pair
/// and answers from a per-method script, with defaults that look like the
/// Pimlico/ZeroDev endpoints. `BundlerClient` over this fake exercises
/// the adapter's method names and result mapping offline.
#[derive(Debug, Default)]
pub struct FakeRpc {
    captured: Mutex<Vec<(String, String)>>,
    script: Mutex<HashMap<String, serde_json::Value>>,
    sent: Mutex<Vec<String>>,
}

impl FakeRpc {
    /// An empty fake with the default answers.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Overrides the result of one method.
    pub fn answer(&self, method: &str, result: serde_json::Value) {
        self.script
            .lock()
            .expect("rpc script lock")
            .insert(method.to_owned(), result);
    }

    /// The captured calls as `(method, params-json)` pairs.
    #[must_use]
    pub fn captured(&self) -> Vec<(String, String)> {
        self.captured
            .lock()
            .expect("rpc capture lock")
            .iter()
            .map(|(method, params)| (method.clone(), params.clone()))
            .collect()
    }
}

#[async_trait]
impl JsonRpcTransport for FakeRpc {
    async fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, JsonRpcError> {
        self.captured
            .lock()
            .expect("rpc capture lock")
            .push((method.to_owned(), params.to_string()));
        if let Some(scripted) = self
            .script
            .lock()
            .expect("rpc script lock")
            .get(method)
            .cloned()
        {
            return Ok(scripted);
        }
        let default = match method {
            "eth_chainId" => serde_json::Value::String("0x2105".to_owned()),
            "eth_estimateUserOperationGas" => serde_json::json!({
                "verificationGasLimit": "150000",
                "callGasLimit": "60000",
                "preVerificationGas": "50000"
            }),
            "pm_sponsorUserOperation" => serde_json::json!({
                "paymasterAndData": format!("0x{}", "a".repeat(96)),
                "verificationGasLimit": "200000",
                "callGasLimit": "60000",
                "preVerificationGas": "50000"
            }),
            "eth_sendUserOperation" => {
                // Remember the hash this fake handed out, so a later
                // receipt for it resolves and any other hash is null —
                // the way a real endpoint treats an unmined op.
                let hash = "0xabc123".to_owned();
                self.sent.lock().expect("rpc sent lock").push(hash.clone());
                serde_json::Value::String(hash)
            }
            "eth_getUserOperationReceipt" => {
                let known = params
                    .get(0)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|hash| {
                        self.sent
                            .lock()
                            .expect("rpc sent lock")
                            .iter()
                            .any(|sent| sent == hash)
                    });
                if known {
                    serde_json::json!({
                        "userOpHash": "0xabc123",
                        "transactionHash": "0xdef456",
                        "success": true
                    })
                } else {
                    serde_json::Value::Null
                }
            }
            _ => serde_json::Value::Null,
        };
        Ok(default)
    }
}

// -------------------------------------------------------------------------
// FakeBundler

/// The [`Bundler`] fake: deterministic hashes and receipts, every sent
/// operation kept for assertions. No network, no chain state.
#[derive(Debug, Default)]
pub struct FakeBundler {
    chain_id: u64,
    state: Mutex<BundlerState>,
}

#[derive(Debug, Default)]
struct BundlerState {
    sent: Vec<(UserOpHash, UserOperation)>,
    receipts: HashMap<UserOpHash, UserOpReceipt>,
}

impl FakeBundler {
    /// A fake bundler on `chain_id`.
    #[must_use]
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            state: Mutex::new(BundlerState::default()),
        }
    }

    /// The operations that were sent, as `(hash, operation)` pairs.
    #[must_use]
    pub fn sent(&self) -> Vec<(UserOpHash, UserOperation)> {
        self.state.lock().expect("bundler lock").sent.clone()
    }
}

#[async_trait]
impl Bundler for FakeBundler {
    async fn chain_id(&self) -> Result<u64, BundlerError> {
        Ok(self.chain_id)
    }

    async fn estimate_gas(&self, _op: &UserOperation) -> Result<GasEstimate, BundlerError> {
        Ok(GasEstimate {
            verification_gas_limit: "150000".to_owned(),
            call_gas_limit: "60000".to_owned(),
            pre_verification_gas: "50000".to_owned(),
        })
    }

    async fn sponsor(&self, _op: &UserOperation) -> Result<Sponsorship, BundlerError> {
        Ok(Sponsorship {
            paymaster_and_data: format!("0x{}", "b".repeat(38)),
            verification_gas_limit: "200000".to_owned(),
            call_gas_limit: "60000".to_owned(),
            pre_verification_gas: "50000".to_owned(),
        })
    }

    async fn send(&self, op: &UserOperation) -> Result<UserOpHash, BundlerError> {
        let mut state = self.state.lock().expect("bundler lock");
        let at = state.sent.len() + 1;
        let hash = format!("0xop{at:032x}");
        state.receipts.insert(
            hash.clone(),
            UserOpReceipt {
                user_op_hash: hash.clone(),
                transaction_hash: format!("0xtx{at:032x}"),
                success: true,
            },
        );
        state.sent.push((hash.clone(), op.clone()));
        Ok(hash)
    }

    async fn receipt(&self, hash: &str) -> Result<Option<UserOpReceipt>, BundlerError> {
        Ok(self
            .state
            .lock()
            .expect("bundler lock")
            .receipts
            .get(hash)
            .cloned())
    }
}

// -------------------------------------------------------------------------
// Signature checks shared by the fakes

/// The one credential check every fake applies: the signature must be the
/// kind the spec's credential can produce, and — when the grant names an
/// EVM chain — an EIP-7702 authorization must name that same chain (never
/// 0: the type already refuses that at construction and on the wire).
pub(crate) fn check_signature(
    credential: &OwnerCredential,
    signature: &OwnerSignature,
    chain_id: Option<u64>,
) -> Result<(), Mismatch> {
    match (credential, signature) {
        (OwnerCredential::Passkey { .. }, OwnerSignature::PasskeyAssertion { .. }) => Ok(()),
        (OwnerCredential::Eip7702 { .. }, OwnerSignature::Authorization(signed)) => {
            match chain_id {
                Some(chain_id) if signed.delegation.chain_id() == chain_id => Ok(()),
                None => Ok(()),
                _ => Err(Mismatch),
            }
        }
        _ => Err(Mismatch),
    }
}

/// The signature did not match the credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Mismatch;

// -------------------------------------------------------------------------
// FakeKernelPermissions

/// The [`KernelPermissions`] fake: an in-memory registry of installed
/// permissions. The permission id and the serialized permission account
/// are deterministic per grant, so tests can assert on them.
#[derive(Debug, Default)]
pub struct FakeKernelPermissions {
    state: Mutex<KernelState>,
}

#[derive(Debug, Default)]
struct KernelState {
    installed: HashMap<GrantId, (String, String)>,
    uninstalled: Vec<String>,
}

impl FakeKernelPermissions {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The installed permissions as `(grant id, permission id, serialized)`
    /// triples.
    #[must_use]
    pub fn installed(&self) -> Vec<(GrantId, String, String)> {
        self.state
            .lock()
            .expect("kernel lock")
            .installed
            .iter()
            .map(|(id, (permission, serialized))| {
                (id.clone(), permission.clone(), serialized.clone())
            })
            .collect()
    }

    /// The permission ids that have been uninstalled.
    #[must_use]
    pub fn uninstalled(&self) -> Vec<String> {
        self.state.lock().expect("kernel lock").uninstalled.clone()
    }
}

#[async_trait]
impl KernelPermissions for FakeKernelPermissions {
    async fn grant(
        &self,
        spec: &crate::grant::GrantSpec,
        owner_signature: &OwnerSignature,
    ) -> Result<OnChainBinding, KernelError> {
        spec.validate()?;
        let GrantScope::EvmKernel(grant) = &spec.scope else {
            return Err(KernelError::ScopeMismatch);
        };
        check_signature(&spec.credential, owner_signature, Some(grant.chain_id))
            .map_err(|_| KernelError::SignatureMismatch)?;
        let mut state = self.state.lock().expect("kernel lock");
        let at = state.installed.len() + 1;
        let entry = state.installed.entry(spec.id.clone()).or_insert_with(|| {
            (
                // The permission id the validator derives from the
                // session key and the policy set.
                format!("0xperm{at:062x}"),
                // `serializePermissionAccount`: the serialized
                // permission context the server keeps.
                format!("0xserialized-permission-account-{at:062x}"),
            )
        });
        Ok(OnChainBinding::KernelPermission {
            permission_id: entry.0.clone(),
            serialized: entry.1.clone(),
        })
    }

    async fn revoke(
        &self,
        binding: &OnChainBinding,
        _owner_signature: &OwnerSignature,
    ) -> Result<UserOpHash, KernelError> {
        let OnChainBinding::KernelPermission { permission_id, .. } = binding else {
            return Err(KernelError::ScopeMismatch);
        };
        let mut state = self.state.lock().expect("kernel lock");
        if !state
            .installed
            .values()
            .any(|(permission, _)| permission == permission_id)
        {
            return Err(KernelError::UnknownPermission(permission_id.clone()));
        }
        state
            .installed
            .retain(|_, (permission, _)| permission != permission_id);
        state.uninstalled.push(permission_id.clone());
        // The `uninstallPlugin` operation, owner-signed, through the
        // bundler.
        Ok(format!("0xuninstall{permission_id}"))
    }
}

// -------------------------------------------------------------------------
// FakeSwig

/// The [`SwigSessions`] fake: roles with session expiry read off the
/// injected clock, removable by revoke.
#[derive(Default)]
pub struct FakeSwig {
    state: Mutex<SwigState>,
    clock: Mutex<Option<Arc<dyn Clock>>>,
}

impl std::fmt::Debug for FakeSwig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeSwig").finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
struct SwigState {
    roles: HashMap<u32, RoleRow>,
    next: u32,
}

#[derive(Debug, Clone)]
struct RoleRow {
    grant_id: String,
    session_key: crate::types::Pubkey,
    expires_at: OffsetDateTime,
}

impl FakeSwig {
    /// An empty registry. Roles created before `clock` is set expire off
    /// the Unix epoch; tests set the clock they move.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the clock the sessions expire against.
    pub fn with_clock(&self, clock: std::sync::Arc<dyn Clock>) {
        *self.clock.lock().expect("swig clock lock") = Some(clock);
    }

    /// The live roles as `(role id, grant id, session key, expires at)`.
    #[must_use]
    pub fn roles(&self) -> Vec<(u32, String, crate::types::Pubkey, OffsetDateTime)> {
        self.state
            .lock()
            .expect("swig lock")
            .roles
            .iter()
            .map(|(id, row)| {
                (
                    *id,
                    row.grant_id.clone(),
                    row.session_key.clone(),
                    row.expires_at,
                )
            })
            .collect()
    }
}

#[async_trait]
impl SwigSessions for FakeSwig {
    async fn create_role(
        &self,
        spec: &crate::grant::GrantSpec,
        owner_signature: &OwnerSignature,
    ) -> Result<OnChainBinding, SwigError> {
        spec.validate()?;
        let GrantScope::SolanaSwig(grant) = &spec.scope else {
            return Err(SwigError::ScopeMismatch);
        };
        check_signature(&spec.credential, owner_signature, None)
            .map_err(|_| SwigError::SignatureMismatch)?;
        let now = match self.clock.lock().expect("swig clock lock").as_ref() {
            Some(clock) => clock.now(),
            None => OffsetDateTime::UNIX_EPOCH,
        };
        let mut state = self.state.lock().expect("swig lock");
        state.next += 1;
        let role_id = state.next;
        state.roles.insert(
            role_id,
            RoleRow {
                grant_id: spec.id.clone(),
                session_key: grant.session_key.clone(),
                expires_at: now
                    + time::Duration::seconds(
                        i64::try_from(grant.session_ttl_secs).unwrap_or(i64::MAX),
                    ),
            },
        );
        Ok(OnChainBinding::SwigRole { role_id })
    }

    async fn revoke_role(
        &self,
        binding: &OnChainBinding,
        _owner_signature: &OwnerSignature,
    ) -> Result<Signature, SwigError> {
        let OnChainBinding::SwigRole { role_id } = binding else {
            return Err(SwigError::ScopeMismatch);
        };
        let mut state = self.state.lock().expect("swig lock");
        state
            .roles
            .remove(role_id)
            .ok_or_else(|| SwigError::UnknownRole(role_id.to_string()))?;
        Ok(format!("swig-revoke-role-{role_id}"))
    }
}

// -------------------------------------------------------------------------
// FakeSquads

/// The [`SquadsLimits`] fake: spending limits keyed by a deterministic
/// address, removable by revoke.
#[derive(Debug, Default)]
pub struct FakeSquads {
    state: Mutex<SquadsState>,
}

#[derive(Debug, Default)]
struct SquadsState {
    limits: HashMap<String, String>,
    next: usize,
}

impl FakeSquads {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The live spending limits as `(address, grant id)` pairs.
    #[must_use]
    pub fn limits(&self) -> Vec<(String, String)> {
        self.state
            .lock()
            .expect("squads lock")
            .limits
            .iter()
            .map(|(address, grant)| (address.clone(), grant.clone()))
            .collect()
    }
}

/// Builds a deterministic, valid-base58 address for the `n`-th fake
/// spending limit.
fn spending_limit_address(n: usize) -> String {
    let mut address = format!("SpendingLimit{n}");
    while address.len() < 44 {
        address.push('1');
    }
    address
}

#[async_trait]
impl SquadsLimits for FakeSquads {
    async fn create_spending_limit(
        &self,
        spec: &crate::grant::GrantSpec,
        owner_signature: &OwnerSignature,
    ) -> Result<OnChainBinding, SquadsError> {
        spec.validate()?;
        let GrantScope::SolanaSquads(_) = &spec.scope else {
            return Err(SquadsError::ScopeMismatch);
        };
        check_signature(&spec.credential, owner_signature, None)
            .map_err(|_| SquadsError::SignatureMismatch)?;
        let mut state = self.state.lock().expect("squads lock");
        state.next += 1;
        let address = spending_limit_address(state.next);
        state.limits.insert(address.clone(), spec.id.clone());
        Ok(OnChainBinding::SquadsLimit {
            spending_limit: crate::types::Pubkey::parse(&address)
                .expect("a generated base58 address"),
        })
    }

    async fn revoke_spending_limit(
        &self,
        binding: &OnChainBinding,
        _owner_signature: &OwnerSignature,
    ) -> Result<Signature, SquadsError> {
        let OnChainBinding::SquadsLimit { spending_limit } = binding else {
            return Err(SquadsError::ScopeMismatch);
        };
        let mut state = self.state.lock().expect("squads lock");
        state
            .limits
            .remove(spending_limit.as_str())
            .ok_or_else(|| SquadsError::UnknownLimit(spending_limit.to_string()))?;
        Ok(format!("squads-revoke-{}", spending_limit.as_str()))
    }
}

// -------------------------------------------------------------------------
// Spec and signature builders

/// `2026-01-01T00:00:00Z`: every builder's `valid_after`.
pub const WINDOW_START: OffsetDateTime =
    match time::Date::from_calendar_date(2026, time::Month::January, 1) {
        Ok(date) => date.midnight().assume_utc(),
        Err(_) => panic!("the fixed window start is a valid date"),
    };

const WINDOW_DAYS: i64 = 30;

/// The account every EVM builder names.
pub fn evm_account() -> crate::types::Address {
    crate::types::Address::parse("0x1111111111111111111111111111111111111111")
        .expect("a fixed literal")
}

/// The session key every EVM builder names.
pub fn evm_session_key() -> crate::types::Address {
    crate::types::Address::parse("0x2222222222222222222222222222222222222222")
        .expect("a fixed literal")
}

/// The contract every EVM builder allows.
pub fn evm_target() -> crate::types::Address {
    crate::types::Address::parse("0x3333333333333333333333333333333333333333")
        .expect("a fixed literal")
}

/// The USDC-style selector every EVM builder allows (`transfer`).
pub fn transfer_selector() -> crate::types::Selector {
    crate::types::Selector::parse("0xa9059cbb").expect("a fixed literal")
}

/// A made-up Solana key: 44 copies of `ch`. [`crate::types::Pubkey`]
/// accepts it (base58 alphabet, 32-44 characters), and no real account can
/// collide with it — a real key never repeats one character 44 times.
fn made_up_key(ch: char) -> crate::types::Pubkey {
    let key: String = std::iter::repeat_n(ch, 44).collect();
    crate::types::Pubkey::parse(&key).expect("a made-up key")
}

/// The Swig wallet every Swig builder names — a made-up key, not a real
/// account.
pub fn swig_wallet() -> crate::types::Pubkey {
    made_up_key('1')
}

/// The session authority every Swig builder names — a made-up key.
pub fn swig_session_key() -> crate::types::Pubkey {
    made_up_key('2')
}

/// The token program every Swig builder scopes to — a made-up key.
pub fn token_program() -> crate::types::Pubkey {
    made_up_key('3')
}

/// The destination every Swig and Squads builder names — a made-up key.
pub fn destination() -> crate::types::Pubkey {
    made_up_key('4')
}

/// The token mint every Squads builder names — a made-up key.
pub fn usdc_mint() -> crate::types::Pubkey {
    made_up_key('5')
}

/// A second destination, distinct from [`destination`], for the tests that
/// need a recipient the grant does not allow — a made-up key.
pub fn second_destination() -> crate::types::Pubkey {
    made_up_key('6')
}

/// The passkey credential the builders name.
#[must_use]
pub fn passkey() -> OwnerCredential {
    OwnerCredential::Passkey {
        credential_id: "cred-762".to_owned(),
    }
}

/// The WebAuthn assertion matching [`passkey`] — fixture-shaped, the
/// real thing is the authenticator's.
#[must_use]
pub fn passkey_signature() -> OwnerSignature {
    OwnerSignature::PasskeyAssertion {
        authenticator_data: "0xaabbccdd".to_owned(),
        client_data_json:
            r#"{"type":"webauthn.get","challenge":"Z3JhbnQtNzYy","origin":"https://example.com"}"#
                .to_owned(),
        signature: "0x3021aabb".to_owned(),
    }
}

/// A validity window starting at `at` and running [`WINDOW_DAYS`] days —
/// a fixed span, so a test can sit a [`MutableClock`] inside or past it.
#[must_use]
pub fn window(at: OffsetDateTime) -> crate::grant::ValidityWindow {
    crate::grant::ValidityWindow {
        valid_after: at,
        valid_until: at + time::Duration::days(WINDOW_DAYS),
    }
}

/// An EVM Kernel spec: one `transfer` call policy with a 0.1 ETH
/// per-call cap, a 1 ETH daily recurring value limit, a 10 calls per
/// hour rate limit, and a validity window starting at `at`.
#[must_use]
pub fn evm_spec(id: &str, at: OffsetDateTime) -> crate::grant::GrantSpec {
    crate::grant::GrantSpec {
        id: id.to_owned(),
        owner: "user-762".to_owned(),
        credential: passkey(),
        window: window(at),
        rate_limit: Some(crate::grant::RateLimit {
            max_calls: 10,
            period_secs: 3_600,
        }),
        scope: crate::grant::GrantScope::EvmKernel(crate::grant::EvmGrant {
            chain_id: 8453,
            account: evm_account(),
            session_key: evm_session_key(),
            calls: vec![crate::grant::CallPolicy {
                target: evm_target(),
                selector: transfer_selector(),
                args: Vec::new(),
                value_cap: Some(100_000_000_000_000_000),
            }],
            value_limit: Some(crate::grant::NativeLimit {
                recurring: crate::grant::RecurringLimit {
                    amount: 1_000_000_000_000_000_000,
                    period_secs: 86_400,
                },
                per_destination: None,
            }),
            token_limit: None,
        }),
    }
}

/// A Swig spec: the token program scoped, a 2 SOL hourly recurring limit
/// with a 0.5 SOL per-destination cap, a day-long session, and a window
/// starting at `at`.
#[must_use]
pub fn swig_spec(id: &str, at: OffsetDateTime) -> crate::grant::GrantSpec {
    crate::grant::GrantSpec {
        id: id.to_owned(),
        owner: "user-762".to_owned(),
        credential: passkey(),
        window: window(at),
        rate_limit: None,
        scope: crate::grant::GrantScope::SolanaSwig(crate::grant::SwigGrant {
            cluster: crate::grant::Cluster::Mainnet,
            swig: swig_wallet(),
            role_id: None,
            session_key: swig_session_key(),
            session_ttl_secs: 86_400,
            programs: vec![crate::grant::ProgramScope {
                program: token_program(),
            }],
            sol_limit: Some(crate::grant::NativeLimit {
                recurring: crate::grant::RecurringLimit {
                    amount: 2_000_000_000,
                    period_secs: 3_600,
                },
                per_destination: Some(crate::grant::RecurringLimit {
                    amount: 500_000_000,
                    period_secs: 3_600,
                }),
            }),
            token_limits: Vec::new(),
        }),
    }
}

/// A Squads spec: one weekly 5 USDC spending limit on vault 2 restricted
/// to [`destination`], and a window starting at `at`.
#[must_use]
pub fn squads_spec(id: &str, at: OffsetDateTime) -> crate::grant::GrantSpec {
    crate::grant::GrantSpec {
        id: id.to_owned(),
        owner: "user-762".to_owned(),
        credential: passkey(),
        window: window(at),
        rate_limit: None,
        scope: crate::grant::GrantScope::SolanaSquads(crate::grant::SquadsGrant {
            cluster: crate::grant::Cluster::Mainnet,
            multisig: swig_wallet(),
            vault_index: 2,
            limits: vec![crate::grant::SpendingLimit {
                mint: Some(usdc_mint()),
                amount: 5_000_000_000,
                period: crate::grant::SpendPeriod::Weekly,
                destinations: vec![destination()],
            }],
        }),
    }
}
