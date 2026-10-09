//! The request an automated value-moving action must describe, plus the
//! chain, address and amount vocabulary the rest of the crate speaks.
//!
//! Addresses: EVM addresses are lowercase `0x`-prefixed hex, and policy
//! comparisons on EVM are case-insensitive (a checksummed spelling is never
//! a different contract); Solana addresses are base58 strings compared
//! exactly. Amounts are big-endian [`U256`] words — the raw `uint256` of the
//! chain — with no bignum dependency.

use serde::{Deserialize, Serialize};

/// A 256-bit unsigned integer, big-endian: the shape of an EVM `uint256`
/// word.
pub type U256 = [u8; 32];

/// `v` as a big-endian [`U256`].
#[must_use]
pub fn u256_from_u128(v: u128) -> U256 {
    let mut out = [0_u8; 32];
    out[16..].copy_from_slice(&v.to_be_bytes());
    out
}

/// The low 128 bits of `v`, or `None` when the value needs more than 128
/// bits (and so cannot be a micro-USD figure or a counted token amount).
#[must_use]
pub fn u256_to_u128(v: &U256) -> Option<u128> {
    if v[..16].iter().any(|&b| b != 0) {
        return None;
    }
    let mut low = [0_u8; 16];
    low.copy_from_slice(&v[16..]);
    Some(u128::from_be_bytes(low))
}

/// Whether `v >= 2^128` — the crate's "unlimited" line.
///
/// `MAX_UINT256` and Permit2's `MAX_UINT160` are both far above 2^128, and so is
/// every "infinite" approval a dapp writes in practice; no legitimate
/// bounded amount comes near it. An amount of exactly 2^128 or more is
/// treated as unlimited and refused: the boundary is deliberately coarse,
/// because the values that cross it are sentinel values, not money.
#[must_use]
pub fn u256_is_unlimited(v: &U256) -> bool {
    v[..16].iter().any(|&b| b != 0)
}

/// Which chain an action runs on.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Chain {
    /// An EVM chain, by its EIP-155 id.
    Evm {
        /// The chain id the action is signed for.
        chain_id: u64,
    },
    /// A Solana cluster, by name.
    Solana {
        /// The cluster id, e.g. `mainnet-beta`.
        cluster: String,
    },
}

impl Chain {
    /// Stable string form used in ledger keys, audit entries and scope
    /// labels: `evm:1`, `solana:mainnet-beta`.
    #[must_use]
    pub fn key(&self) -> String {
        match self {
            Chain::Evm { chain_id } => format!("evm:{chain_id}"),
            Chain::Solana { cluster } => format!("solana:{cluster}"),
        }
    }

    /// `true` for the EVM arms.
    #[must_use]
    pub fn is_evm(&self) -> bool {
        matches!(self, Chain::Evm { .. })
    }
}

/// An EIP-7702 authorization carried by an EVM transaction: a delegation of
/// the signer's code to `address`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authorization7702 {
    /// The chain the delegation is valid on. `0` means "all chains" —
    /// replayable everywhere, and a hard deny.
    pub chain_id: u64,
    /// The delegate contract, lowercase `0x` hex.
    pub address: String,
}

/// The swap context of an action, when it is a swap: the quoted output and
/// the minimum the caller will accept. Slippage is
/// `(quoted_out - min_out) / quoted_out` in basis points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapQuote {
    /// What the route quoted, in the output token's smallest unit.
    pub quoted_out: u128,
    /// What the transaction may actually settle for.
    pub min_out: u128,
}

/// One Solana instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaInstruction {
    /// The program invoked, base58.
    pub program_id: String,
    /// The accounts passed, base58, in order.
    pub accounts: Vec<String>,
    /// The instruction data; the first byte(s) are the discriminant.
    pub data: Vec<u8>,
}

/// What the acting address wants to do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// A plain EVM transaction. Empty `data` is a native transfer of
    /// `value` to `to`; with `data` it is a contract call. `to` of `None`
    /// is contract creation, which no policy can meaningfully allowlist.
    EvmTx {
        /// The EIP-155 chain id.
        chain_id: u64,
        /// The call or transfer target, lowercase `0x` hex; `None` creates
        /// a contract.
        to: Option<String>,
        /// The native value attached.
        value: U256,
        /// The calldata, selector first.
        data: Vec<u8>,
        /// EIP-7702 delegations carried by the transaction.
        #[serde(default)]
        authorizations: Vec<Authorization7702>,
    },
    /// An EIP-712 signature request — the Permit / Permit2 family. Nothing
    /// is broadcast, which is exactly why it is checked here: a signature
    /// is an approval the chain will honour later, on the strength of this
    /// one act.
    EvmTypedData {
        /// The EIP-155 chain id the domain pins.
        chain_id: u64,
        /// The primary type, e.g. `Permit`, `PermitSingle`.
        primary_type: String,
        /// The `verifyingContract` of the domain, lowercase `0x` hex.
        verifying_contract: String,
        /// The spender the signature empowers, when the type carries one.
        spender: Option<String>,
        /// The amount the signature empowers, when the type carries one.
        /// `None` on a spending type means "not statically known".
        amount: Option<U256>,
    },
    /// A Solana transaction: instructions executed in order.
    SolanaTx {
        /// The cluster id, e.g. `mainnet-beta`.
        cluster: String,
        /// The instructions.
        instructions: Vec<SolanaInstruction>,
    },
}

/// A value-moving action an actor wants to take, as the engine sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// The venture the acting wallet belongs to.
    pub venture: String,
    /// The subject (actor identity) the policy is resolved for.
    pub subject: String,
    /// The acting address — the wallet that signs, and the owner whose
    /// balance changes count as outflows.
    pub from: String,
    /// The action itself.
    pub action: Action,
    /// The swap context, when the action is a swap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swap: Option<SwapQuote>,
}

impl Request {
    /// The chain the action runs on.
    #[must_use]
    pub fn chain(&self) -> Chain {
        match &self.action {
            Action::EvmTx { chain_id, .. } | Action::EvmTypedData { chain_id, .. } => Chain::Evm {
                chain_id: *chain_id,
            },
            Action::SolanaTx { cluster, .. } => Chain::Solana {
                cluster: cluster.clone(),
            },
        }
    }

    /// One line for audit entries and logs: kind plus the fields that
    /// identify the action. Never carries amounts.
    #[must_use]
    pub fn summary(&self) -> String {
        match &self.action {
            Action::EvmTx {
                chain_id,
                to,
                data,
                authorizations,
                ..
            } => {
                let sel = data.first_chunk::<4>().map_or_else(
                    || "native".to_owned(),
                    |s| format!("sel=0x{:08x}", u32::from_be_bytes(*s)),
                );
                let auth = if authorizations.is_empty() {
                    String::new()
                } else {
                    format!(" 7702x{}", authorizations.len())
                };
                format!(
                    "evm_tx chain={chain_id} to={} {sel}{auth}",
                    to.as_deref().unwrap_or("create")
                )
            }
            Action::EvmTypedData {
                chain_id,
                primary_type,
                verifying_contract,
                ..
            } => {
                format!(
                    "evm_typed_data chain={chain_id} type={primary_type} contract={verifying_contract}"
                )
            }
            Action::SolanaTx {
                cluster,
                instructions,
            } => {
                format!("solana_tx cluster={cluster} ix={}", instructions.len())
            }
        }
    }
}

/// What token a balance change or a cap is about: the chain plus the token's
/// address (EVM, lowercase hex) or mint (Solana, base58), or `"native"` for
/// the chain's own coin.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TokenKey {
    /// The chain the token lives on.
    pub chain: Chain,
    /// The token address or mint, or `native`.
    pub token: String,
}

impl TokenKey {
    /// The chain's native coin.
    #[must_use]
    pub fn native(chain: Chain) -> Self {
        Self {
            chain,
            token: "native".to_owned(),
        }
    }

    /// Stable string form, for logs and ledger keys.
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}:{}", self.chain.key(), self.token)
    }
}
