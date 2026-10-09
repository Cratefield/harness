//! The grant model: what the owner signs once, what the server may do
//! inside it, and the usage ledger the caps are read from.

use std::fmt;

use time::OffsetDateTime;

use crate::types::{Address, OwnerCredential, Pubkey, Selector};

/// Which chain family — and where on it — a grant lives.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Chain {
    /// An EVM chain. `chain_id` is never 0: [`GrantSpec::validate`]
    /// refuses a zero, the same rule [`crate::Eip7702Authorization`]
    /// enforces.
    Evm {
        /// The EVM chain id.
        chain_id: u64,
    },
    /// A Solana cluster.
    Solana {
        /// Which cluster.
        cluster: Cluster,
    },
}

/// The Solana cluster a grant is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Cluster {
    /// Solana mainnet-beta.
    Mainnet,
    /// Solana devnet.
    Devnet,
    /// Solana testnet.
    Testnet,
}

impl fmt::Display for Cluster {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Mainnet => "mainnet",
            Self::Devnet => "devnet",
            Self::Testnet => "testnet",
        })
    }
}

/// The window a grant is valid in, compared against the [`cratefield_core::Clock`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidityWindow {
    /// The first instant the server may act.
    pub valid_after: OffsetDateTime,
    /// The last instant the server may act. An expired grant is refused
    /// even while its on-chain permission still exists — the owner still
    /// has to revoke on chain to free the state.
    pub valid_until: OffsetDateTime,
}

impl ValidityWindow {
    /// Whether `at` falls inside the window (both ends inclusive).
    #[must_use]
    pub fn contains(&self, at: OffsetDateTime) -> bool {
        self.valid_after <= at && at <= self.valid_until
    }
}

/// How many actions the server may take per rolling period, on top of the
/// spend caps — the bound that survives a cap set in a worthless token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    /// The most actions in one period.
    pub max_calls: u32,
    /// The period's length, in seconds. Windows are fixed, anchored to
    /// the Unix epoch, so usage accounting never drifts.
    pub period_secs: u64,
}

/// An amount per fixed period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecurringLimit {
    /// The most that may move in one period.
    pub amount: u128,
    /// The period's length, in seconds, anchored to the Unix epoch.
    pub period_secs: u64,
}

/// A native-coin spend cap: a recurring total, and optionally a tighter
/// recurring cap per destination (Swig's per-destination session limit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeLimit {
    /// The recurring total across all destinations.
    pub recurring: RecurringLimit,
    /// A tighter recurring cap per single destination, when the grant
    /// wants one destination not to be able to drain the total.
    pub per_destination: Option<RecurringLimit>,
}

/// A token (ERC-20 on EVM, SPL on Solana) spend cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenLimit {
    /// The token contract (EVM) or mint (Solana).
    pub token: String,
    /// The recurring total across all destinations.
    pub recurring: RecurringLimit,
    /// An optional tighter recurring cap per single destination.
    pub per_destination: Option<RecurringLimit>,
}

/// One EVM call the grant allows: target and selector, the argument
/// conditions the arguments must satisfy, and a per-call native cap.
/// This mirrors one Kernel permission's call policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallPolicy {
    /// The contract that may be called.
    pub target: Address,
    /// The function that may be called on it.
    pub selector: Selector,
    /// Conditions on ABI-encoded argument words: argument `index` (0-based,
    /// after the selector) must equal `equals` (a `0x` word). Empty means
    /// every overload of that selector is allowed.
    pub args: Vec<ArgCondition>,
    /// The most native value one call may carry. `None` means the call
    /// carries no value.
    pub value_cap: Option<u128>,
}

/// One argument condition: the ABI-encoded word at `index` must equal
/// `equals` (for example a fixed recipient or spender).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgCondition {
    /// The 0-based argument index, after the selector.
    pub index: u8,
    /// The `0x`-hex 32-byte word the argument must equal.
    pub equals: String,
}

impl ArgCondition {
    /// Whether the encoded word at this condition's index matches.
    #[must_use]
    pub fn matches(&self, args: &[String]) -> bool {
        args.get(usize::from(self.index))
            .is_some_and(|word| word.eq_ignore_ascii_case(&self.equals))
    }
}

/// One Swig program scope: every instruction the session sends to this
/// program is allowed, subject to the SOL and token limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramScope {
    /// The program id the session may target.
    pub program: Pubkey,
}

/// One Squads v4 spending limit for a treasury vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendingLimit {
    /// The token mint; `None` is the native coin (SOL).
    pub mint: Option<Pubkey>,
    /// The most that may move per [`SpendingLimit::period`].
    pub amount: u128,
    /// How the amount refills.
    pub period: SpendPeriod,
    /// The recipients allowed. Empty means any recipient.
    pub destinations: Vec<Pubkey>,
}

/// How a Squads spending limit refills.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SpendPeriod {
    /// The limit is spent once and must be recreated.
    Once,
    /// The limit refills every UTC day.
    Daily,
    /// The limit refills every UTC week.
    Weekly,
    /// The limit refills every UTC month.
    Monthly,
}

impl SpendPeriod {
    /// The period's length in seconds, for usage accounting: fixed-window
    /// approximations of the calendar periods (a day is 86 400 s, a week
    /// 604 800, a month 30 days), anchored to the Unix epoch like every
    /// window in this crate.
    #[must_use]
    pub fn period_secs(self) -> u64 {
        match self {
            Self::Once => u64::MAX,
            Self::Daily => 86_400,
            Self::Weekly => 604_800,
            Self::Monthly => 2_592_000,
        }
    }
}

/// What the grant puts on chain, per protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GrantScope {
    /// An ERC-4337 Kernel smart account with the permission validator
    /// installed for a session key (ERC-7579 permissions).
    EvmKernel(EvmGrant),
    /// A Swig wallet role with a session authority.
    SolanaSwig(SwigGrant),
    /// A Squads v4 spending limit on a treasury vault.
    SolanaSquads(SquadsGrant),
}

impl GrantScope {
    /// The chain the scope lives on.
    #[must_use]
    pub fn chain(&self) -> Chain {
        match self {
            Self::EvmKernel(grant) => Chain::Evm {
                chain_id: grant.chain_id,
            },
            Self::SolanaSwig(grant) => Chain::Solana {
                cluster: grant.cluster,
            },
            Self::SolanaSquads(grant) => Chain::Solana {
                cluster: grant.cluster,
            },
        }
    }
}

/// The EVM side of a grant: the account, the session key, the call
/// policies and the spend caps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmGrant {
    /// The EVM chain id. Never 0 — see [`crate::Chain`].
    pub chain_id: u64,
    /// The smart account (Kernel) the permission is installed on.
    pub account: Address,
    /// The session key the permission validator accepts: the key the
    /// server acts with.
    pub session_key: Address,
    /// Every call policy the grant allows; a call matching none of them
    /// is refused before it reaches the account.
    pub calls: Vec<CallPolicy>,
    /// The native-coin (gas-value) spend cap, when calls may carry value.
    pub value_limit: Option<NativeLimit>,
    /// The ERC-20 spend cap, when calls may move tokens.
    pub token_limit: Option<TokenLimit>,
}

/// The Swig side of a grant: one role on a Swig wallet, held by a session
/// authority that expires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwigGrant {
    /// The cluster the Swig wallet lives on.
    pub cluster: Cluster,
    /// The Swig wallet the role is created on.
    pub swig: Pubkey,
    /// The role's id, assigned by the wallet when the role is created.
    /// `None` until the role exists on chain.
    pub role_id: Option<u32>,
    /// The session authority the server acts with.
    pub session_key: Pubkey,
    /// How long the session authority lives, in seconds, from creation.
    /// The on-chain session expiry is the hard bound; the spec's
    /// [`GrantSpec::window`] should not outlive it.
    pub session_ttl_secs: u64,
    /// The programs the session may target.
    pub programs: Vec<ProgramScope>,
    /// The SOL spend cap.
    pub sol_limit: Option<NativeLimit>,
    /// The SPL token spend caps.
    pub token_limits: Vec<TokenLimit>,
}

/// The Squads side of a grant: spending limits on one treasury vault, so
/// automation can move treasury funds only within them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SquadsGrant {
    /// The cluster the multisig lives on.
    pub cluster: Cluster,
    /// The Squads v4 multisig.
    pub multisig: Pubkey,
    /// The vault index the spending limits draw from.
    pub vault_index: u8,
    /// The spending limits granted.
    pub limits: Vec<SpendingLimit>,
}

/// The grant id: assigned by the server, stable across the store.
pub type GrantId = String;

/// The harness user the grant belongs to.
pub type OwnerId = String;

/// The grant the owner signs once: who owns it, how long it lives, how
/// fast it may act, and exactly what it may do on which chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantSpec {
    /// The grant's id.
    pub id: GrantId,
    /// The owner the grant is for.
    pub owner: OwnerId,
    /// The credential that signs the grant and its later revoke.
    pub credential: OwnerCredential,
    /// When the server may act.
    pub window: ValidityWindow,
    /// How often the server may act.
    pub rate_limit: Option<RateLimit>,
    /// What the grant puts on chain.
    pub scope: GrantScope,
}

/// Why a spec is not a grantable one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SpecError {
    /// The window's ends are the wrong way round, or `valid_until` is not
    /// after `valid_after`.
    #[error("the validity window must end strictly after it starts")]
    WindowBackwards,
    /// An EVM grant was asked for chain 0; every EVM grant names a real
    /// chain, the same rule the EIP-7702 authorization enforces.
    #[error("chain_id = 0 grants are refused: name the one chain the grant lives on")]
    ChainIdZero,
    /// The scope names nothing to do: no call policies, no programs, no
    /// spending limits. A grant that allows nothing is a mistake, not a
    /// safety feature.
    #[error("the grant scope is empty: name at least one call policy, program or spending limit")]
    EmptyScope,
    /// A Swig session was given a non-positive TTL, so its session
    /// authority could never expire on chain.
    #[error("the Swig session TTL must be at least one second")]
    SessionTtl,
}

impl GrantSpec {
    /// Checks the invariants the ports and the enforcer rely on.
    ///
    /// # Errors
    /// [`SpecError`] for a backwards window, a chain-0 EVM grant, an
    /// empty scope or a non-positive Swig session TTL.
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.window.valid_after >= self.window.valid_until {
            return Err(SpecError::WindowBackwards);
        }
        if let Chain::Evm { chain_id } = self.scope.chain()
            && chain_id == 0
        {
            return Err(SpecError::ChainIdZero);
        }
        let empty = match &self.scope {
            GrantScope::EvmKernel(grant) => grant.calls.is_empty(),
            GrantScope::SolanaSwig(grant) => {
                if grant.session_ttl_secs == 0 {
                    return Err(SpecError::SessionTtl);
                }
                grant.programs.is_empty()
                    && grant.sol_limit.is_none()
                    && grant.token_limits.is_empty()
            }
            GrantScope::SolanaSquads(grant) => grant.limits.is_empty(),
        };
        if empty {
            return Err(SpecError::EmptyScope);
        }
        Ok(())
    }
}

/// What the grant call put on chain, kept in the [`crate::GrantRecord`] so
/// the later revoke can name it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OnChainBinding {
    /// The ERC-7579 permission: its on-chain permission id, and the
    /// serialized permission account (`serializePermissionAccount`) the
    /// server replays on every later operation.
    KernelPermission {
        /// The permission id the validator derived.
        permission_id: String,
        /// The serialized permission account blob.
        serialized: String,
    },
    /// The Swig role, by its on-chain role id.
    SwigRole {
        /// The role id the wallet assigned.
        role_id: u32,
    },
    /// The Squads spending limit account.
    SquadsLimit {
        /// The spending limit's address.
        spending_limit: Pubkey,
    },
}

/// Where a grant is in its life. The off-chain statuses (`Denied`,
/// `Paused`) are the server's kill switches and take effect immediately;
/// `Revoked` is recorded only after the owner signed the on-chain revoke.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GrantStatus {
    /// Signed, on chain, inside its window: the server may act within the
    /// caps.
    Active,
    /// Denied off chain. Immediate and total: the server refuses before
    /// it even looks at the caps, and it does not matter whether the
    /// on-chain permission still exists.
    Denied,
    /// Paused off chain, with the intent to resume.
    Paused,
    /// The owner signed the on-chain revoke and it is confirmed; the
    /// permission no longer exists on chain either.
    Revoked,
}

/// One grant as the store holds it: the signed spec, where it stands, and
/// what it put on chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRecord {
    /// The signed spec.
    pub spec: GrantSpec,
    /// Where the grant stands.
    pub status: GrantStatus,
    /// What the grant call put on chain; `None` until the owner's
    /// signature was applied and the port confirmed the grant.
    pub on_chain: Option<OnChainBinding>,
    /// When the record was created.
    pub created_at: OffsetDateTime,
}

impl GrantRecord {
    /// A record that awaits its on-chain confirmation.
    #[must_use]
    pub fn pending(spec: GrantSpec, created_at: OffsetDateTime) -> Self {
        Self {
            spec,
            status: GrantStatus::Active,
            on_chain: None,
            created_at,
        }
    }

    /// Attaches what the grant call put on chain. Idempotent for the same
    /// binding; refuses to silently swap one binding for another.
    ///
    /// # Errors
    /// [`crate::StoreError::Conflict`] when a different binding is already
    /// attached.
    pub fn attach(&mut self, binding: OnChainBinding) -> Result<(), crate::StoreError> {
        match &self.on_chain {
            None => self.on_chain = Some(binding),
            Some(existing) if existing == &binding => {}
            Some(_) => return Err(crate::StoreError::Conflict),
        }
        Ok(())
    }

    /// Denies off chain: immediate, independent of the on-chain state.
    /// Refuses to un-revoke.
    pub fn deny(&mut self) {
        if self.status != GrantStatus::Revoked {
            self.status = GrantStatus::Denied;
        }
    }

    /// Pauses off chain, with the intent to resume. Refuses to un-revoke.
    pub fn pause(&mut self) {
        if self.status != GrantStatus::Revoked {
            self.status = GrantStatus::Paused;
        }
    }

    /// Resumes a paused grant.
    pub fn resume(&mut self) {
        if self.status == GrantStatus::Paused {
            self.status = GrantStatus::Active;
        }
    }

    /// Records that the owner-signed on-chain revoke confirmed.
    pub fn mark_revoked(&mut self) {
        self.status = GrantStatus::Revoked;
    }
}

/// One movement the server made: the destination, the token (if not the
/// native coin) and the amount. The usage ledger is a list of these, so
/// every cap — total, per-destination, per-token — is a fold over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    /// Where the value went, as the chain's literal.
    pub destination: String,
    /// The token, when the movement was not the native coin.
    pub token: Option<String>,
    /// How much moved.
    pub amount: u128,
}

/// What the server has spent under a grant, as recorded transfers plus
/// the action count.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Usage {
    /// How many actions were taken.
    pub calls: u64,
    /// The recorded movements.
    pub transfers: Vec<Transfer>,
}

impl Usage {
    /// The usage one action generates.
    #[must_use]
    pub fn of(action: &IntendedAction) -> Self {
        let transfers = match action {
            IntendedAction::EvmCall { value, token, .. } => {
                let mut transfers = Vec::new();
                if *value > 0 {
                    transfers.push(Transfer {
                        destination: String::new(),
                        token: None,
                        amount: *value,
                    });
                }
                if let Some((token, amount)) = token {
                    transfers.push(Transfer {
                        destination: String::new(),
                        token: Some(token.as_str().to_owned()),
                        amount: *amount,
                    });
                }
                transfers
            }
            IntendedAction::SolanaTransfer {
                lamports,
                destination,
                token,
                ..
            } => {
                let mut transfers = Vec::new();
                if *lamports > 0 {
                    transfers.push(Transfer {
                        destination: destination.as_str().to_owned(),
                        token: None,
                        amount: *lamports,
                    });
                }
                if let Some((mint, amount)) = token {
                    transfers.push(Transfer {
                        destination: destination.as_str().to_owned(),
                        token: Some(mint.as_str().to_owned()),
                        amount: *amount,
                    });
                }
                transfers
            }
        };
        Self {
            calls: 1,
            transfers,
        }
    }

    /// Folds `other` into this usage.
    pub fn merge(&mut self, other: &Self) {
        self.calls += other.calls;
        self.transfers.extend(other.transfers.iter().cloned());
    }

    /// The total native value moved.
    #[must_use]
    pub fn native_total(&self) -> u128 {
        self.transfers
            .iter()
            .filter(|t| t.token.is_none())
            .map(|t| t.amount)
            .sum()
    }

    /// The native value moved to one destination.
    #[must_use]
    pub fn native_to(&self, destination: &str) -> u128 {
        self.transfers
            .iter()
            .filter(|t| t.token.is_none() && t.destination == destination)
            .map(|t| t.amount)
            .sum()
    }

    /// The total value moved of one token.
    #[must_use]
    pub fn token_total(&self, token: &str) -> u128 {
        self.transfers
            .iter()
            .filter(|t| t.token.as_deref() == Some(token))
            .map(|t| t.amount)
            .sum()
    }

    /// The value moved of one token to one destination.
    #[must_use]
    pub fn token_to(&self, token: &str, destination: &str) -> u128 {
        self.transfers
            .iter()
            .filter(|t| t.token.as_deref() == Some(token) && t.destination == destination)
            .map(|t| t.amount)
            .sum()
    }
}

/// One action the server wants to take under a grant. The enforcer checks
/// this against the spec, the status, the window and the usage ledger
/// before any port call goes out.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IntendedAction {
    /// One EVM call through the account.
    EvmCall {
        /// The chain the call goes to.
        chain_id: u64,
        /// The contract to call.
        target: Address,
        /// The function to call.
        selector: Selector,
        /// The ABI-encoded argument words, after the selector.
        args: Vec<String>,
        /// The native value the call carries.
        value: u128,
        /// The ERC-20 movement inside the call: `(token, amount)`.
        token: Option<(Address, u128)>,
    },
    /// One Solana transfer out of the Swig wallet or the vault.
    SolanaTransfer {
        /// The cluster the transfer goes to.
        cluster: Cluster,
        /// The program the instruction targets.
        program: Pubkey,
        /// The native lamports the transfer carries.
        lamports: u128,
        /// The recipient.
        destination: Pubkey,
        /// The SPL movement inside the transfer: `(mint, amount)`.
        token: Option<(Pubkey, u128)>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AuthorizationError;

    fn window(at: OffsetDateTime) -> ValidityWindow {
        ValidityWindow {
            valid_after: at - time::Duration::hours(1),
            valid_until: at + time::Duration::hours(1),
        }
    }

    #[test]
    fn usage_folds_and_aggregates() {
        let mut usage = Usage::default();
        usage.merge(&Usage::of(&IntendedAction::SolanaTransfer {
            cluster: Cluster::Mainnet,
            program: Pubkey::parse("So11111111111111111111111111111111111111112")
                .expect("a program"),
            lamports: 1_000,
            destination: Pubkey::parse("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM")
                .expect("a destination"),
            token: None,
        }));
        usage.merge(&Usage::of(&IntendedAction::SolanaTransfer {
            cluster: Cluster::Mainnet,
            program: Pubkey::parse("So11111111111111111111111111111111111111112")
                .expect("a program"),
            lamports: 500,
            destination: Pubkey::parse("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM")
                .expect("a destination"),
            token: None,
        }));
        assert_eq!(usage.calls, 2);
        assert_eq!(usage.native_total(), 1_500);
        assert_eq!(
            usage.native_to("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"),
            1_500
        );
    }

    #[test]
    fn spec_validation_refuses_backwards_windows_and_zero_chains() {
        let at = OffsetDateTime::UNIX_EPOCH;
        let target =
            Address::parse("0x0000000000000000000000000000000000000001").expect("an address");
        let calls = vec![CallPolicy {
            target: target.clone(),
            selector: Selector::parse("0xa9059cbb").expect("a selector"),
            args: Vec::new(),
            value_cap: None,
        }];
        let mut spec = GrantSpec {
            id: "g".into(),
            owner: "o".into(),
            credential: OwnerCredential::Passkey {
                credential_id: "c".into(),
            },
            window: ValidityWindow {
                valid_after: at,
                valid_until: at,
            },
            rate_limit: None,
            scope: GrantScope::EvmKernel(EvmGrant {
                chain_id: 1,
                account: target.clone(),
                session_key: target.clone(),
                calls,
                value_limit: None,
                token_limit: None,
            }),
        };
        assert_eq!(
            spec.validate().expect_err("equal ends"),
            SpecError::WindowBackwards
        );

        if let GrantScope::EvmKernel(grant) = &mut spec.scope {
            grant.chain_id = 0;
        }
        spec.window = window(at);
        // The authorization constructor refuses 0; the spec does too.
        assert_eq!(
            spec.validate().expect_err("chain zero"),
            SpecError::ChainIdZero
        );
        assert_eq!(
            crate::types::Eip7702Authorization::new(0, target, 0).expect_err("chain zero"),
            AuthorizationError::ChainIdZero
        );
    }
}
