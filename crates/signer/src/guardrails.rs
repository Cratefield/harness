//! The guardrails seam: what every sign call passes through before the
//! provider is called (issue #761). The trait is the seam a real policy
//! engine plugs into; [`StaticGuardrails`] is the reference
//! implementation — an allowlist of EVM `(chain, to, selector)` rules
//! and Solana program ids, a per-transaction value cap, and a kill
//! switch that denies everything while it is tripped.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;

use crate::crypto;
use crate::keys::{KeyRef, Subject};
use crate::payload::{Chain, Intent};
use crate::port::SignerError;

/// What the guardrails see for one sign attempt: who, which key, the
/// digest a signature would commit to, and the decoded intent. No raw
/// calldata — a guardrail that reads hex is a guardrail nobody can
/// review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignContext {
    /// Who is asking.
    pub subject: Subject,
    /// Which key would sign.
    pub key_ref: KeyRef,
    /// The payload's signing digest, from
    /// [`Payload::payload_hash`](crate::payload::Payload::payload_hash).
    pub payload_hash: [u8; 32],
    /// The decoded intent.
    pub intent: Intent,
}

/// The guardrails' answer. `Deny` carries the reason, which is what the
/// audit record shows and what the caller sees as
/// [`SignerError::Denied`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Sign it.
    Allow,
    /// Refuse, with a reason a human can read.
    Deny {
        /// Why not.
        reason: String,
    },
}

impl PolicyDecision {
    /// Whether this is an allow.
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// The policy seam. Returns a [`SignerError`] — not just a deny — when
/// the policy itself cannot be evaluated; the caller fails closed on
/// that too.
#[async_trait]
pub trait Guardrails: Send + Sync {
    /// Decides one sign attempt.
    ///
    /// # Errors
    ///
    /// When the policy cannot be evaluated at all (its store is down,
    /// its config did not parse), so the caller must refuse rather than
    /// assume.
    async fn check(&self, context: &SignContext) -> Result<PolicyDecision, SignerError>;
}

/// One allowlist entry for EVM payloads. Every field that is `Some`
/// must match the intent for the rule to apply; `None` matches
/// anything.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EvmRule {
    chain_id: u64,
    to: Option<String>,
    selector: Option<[u8; 4]>,
    verifying_contract: Option<String>,
}

/// The reference [`Guardrails`]: an explicit allowlist plus a value cap
/// plus a kill switch. Anything not on the list is denied — the default
/// answer is no.
///
/// The kill switch is an `Arc<AtomicBool>`, so cloning the guardrails
/// shares one switch: trip it anywhere and every holder denies
/// everything until it is cleared.
///
/// ```
/// use cratefield_signer::StaticGuardrails;
///
/// let guardrails = StaticGuardrails::new()
///     .allow_evm(1, "0x000000000000000000000000000000000000aaaa", [0xa9, 0x05, 0x9c, 0xbb])
///     .expect("a valid address")
///     .allow_eip712(1, "0x0000000071727De22E5E9d8BAf0edAc6f37da032")
///     .expect("a valid address")
///     .allow_program("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
///     .expect("a valid program id")
///     .max_value(1_000_000_000_000_000_000);
/// assert!(!guardrails.tripped());
/// guardrails.trip();
/// assert!(guardrails.tripped());
/// ```
#[derive(Clone, Debug, Default)]
pub struct StaticGuardrails {
    kill_switch: Arc<AtomicBool>,
    max_value: Option<u128>,
    evm: Vec<EvmRule>,
    programs: BTreeSet<String>,
}

impl StaticGuardrails {
    /// Nothing allowed yet, switch not tripped.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allows EVM payloads on `chain_id` to `to` calling `selector`
    /// (the four bytes after the calldata's start, so `0xa9059cbb` for
    /// an ERC-20 `transfer`).
    ///
    /// # Errors
    ///
    /// [`SignerError::Invalid`] when `to` is not an address; the
    /// allowlist never contains an entry that cannot match.
    pub fn allow_evm(
        mut self,
        chain_id: u64,
        to: &str,
        selector: [u8; 4],
    ) -> Result<Self, SignerError> {
        let to = crypto::parse_address(to)?;
        self.evm.push(EvmRule {
            chain_id,
            to: Some(format!("0x{}", hex::encode(to))),
            selector: Some(selector),
            verifying_contract: None,
        });
        Ok(self)
    }

    /// Allows EVM payloads on `chain_id` calling `selector`, whatever
    /// the recipient — for an approved contract whose recipients are
    /// not knowable up front. The value cap still applies.
    #[must_use]
    pub fn allow_evm_any_recipient(mut self, chain_id: u64, selector: [u8; 4]) -> Self {
        self.evm.push(EvmRule {
            chain_id,
            to: None,
            selector: Some(selector),
            verifying_contract: None,
        });
        self
    }

    /// Allows EIP-712 payloads on `chain_id` whose domain names
    /// `verifying_contract` — the one field of an EIP-712 intent that
    /// says who is asking for the signature.
    ///
    /// # Errors
    ///
    /// [`SignerError::Invalid`] when `verifying_contract` is not an
    /// address.
    pub fn allow_eip712(
        mut self,
        chain_id: u64,
        verifying_contract: &str,
    ) -> Result<Self, SignerError> {
        let contract = crypto::parse_address(verifying_contract)?;
        self.evm.push(EvmRule {
            chain_id,
            to: None,
            selector: None,
            verifying_contract: Some(format!("0x{}", hex::encode(contract))),
        });
        Ok(self)
    }

    /// Allows Solana messages that invoke `program` (a base58 pubkey).
    /// Every program a message invokes must be allowed; an unresolvable
    /// lookup-table program never matches, so the message is denied.
    ///
    /// # Errors
    ///
    /// [`SignerError::Invalid`] when `program` is not a 32-byte base58
    /// pubkey.
    pub fn allow_program(mut self, program: &str) -> Result<Self, SignerError> {
        crypto::parse_base58_pubkey(program)?;
        self.programs.insert(program.to_owned());
        Ok(self)
    }

    /// Caps the value a single allowed payload may carry, in wei. A
    /// payload above the cap is denied; payloads with no value (EIP-712
    /// data) are not measured by it.
    #[must_use]
    pub fn max_value(mut self, max_wei: u128) -> Self {
        self.max_value = Some(max_wei);
        self
    }

    /// Trips the kill switch: every holder of these guardrails — and
    /// every clone of them — denies everything until it is cleared.
    pub fn trip(&self) {
        self.kill_switch.store(true, Ordering::SeqCst);
    }

    /// Clears the kill switch.
    pub fn clear(&self) {
        self.kill_switch.store(false, Ordering::SeqCst);
    }

    /// Whether the kill switch is tripped.
    #[must_use]
    pub fn tripped(&self) -> bool {
        self.kill_switch.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Guardrails for StaticGuardrails {
    async fn check(&self, context: &SignContext) -> Result<PolicyDecision, SignerError> {
        if self.tripped() {
            return Ok(PolicyDecision::Deny {
                reason: "the kill switch is tripped".to_owned(),
            });
        }
        match context.intent.chain {
            Chain::Evm { chain_id } => self.check_evm(chain_id, &context.intent),
            Chain::Solana => Ok(self.check_solana(&context.intent)),
        }
    }
}

impl StaticGuardrails {
    fn check_evm(&self, chain_id: u64, intent: &Intent) -> Result<PolicyDecision, SignerError> {
        // The cap first, on any rule: a payload above it is denied even
        // if some rule would match it.
        if let Some(value) = &intent.value {
            let value: u128 = value.parse().map_err(|_| {
                SignerError::Payload(format!(
                    "the intent's value `{value}` is not a wei amount this guardrail can compare"
                ))
            })?;
            if let Some(max) = self.max_value
                && value > max
            {
                return Ok(PolicyDecision::Deny {
                    reason: format!("the value {value} wei is above the cap of {max} wei"),
                });
            }
        }
        let selector = match &intent.selector {
            Some(selector) => {
                let bytes = selector
                    .strip_prefix("0x")
                    .and_then(|rest| hex::decode(rest).ok());
                match bytes {
                    Some(bytes) if bytes.len() == 4 => {
                        Some(<[u8; 4]>::try_from(bytes).expect("length checked above"))
                    }
                    _ => {
                        return Ok(PolicyDecision::Deny {
                            reason: format!("the selector `{selector}` is not four bytes"),
                        });
                    }
                }
            }
            None => None,
        };
        let matched = self.evm.iter().any(|rule| {
            rule.chain_id == chain_id
                && rule
                    .to
                    .as_ref()
                    .is_none_or(|to| Some(to) == intent.to.as_ref())
                && rule
                    .selector
                    .as_ref()
                    .is_none_or(|rule_selector| Some(rule_selector) == selector.as_ref())
                && rule
                    .verifying_contract
                    .as_ref()
                    .is_none_or(|contract| Some(contract) == intent.verifying_contract.as_ref())
        });
        if matched {
            return Ok(PolicyDecision::Allow);
        }
        Ok(PolicyDecision::Deny {
            reason: format!(
                "no allowlist entry covers {}{}{}",
                Chain::Evm { chain_id },
                intent
                    .to
                    .as_ref()
                    .map(|to| format!(" to {to}"))
                    .unwrap_or_default(),
                intent
                    .selector
                    .as_ref()
                    .map(|selector| format!(" calling {selector}"))
                    .unwrap_or_default(),
            ),
        })
    }

    fn check_solana(&self, intent: &Intent) -> PolicyDecision {
        if intent.programs.is_empty() {
            return PolicyDecision::Deny {
                reason: "the message resolves no program ids to allow".to_owned(),
            };
        }
        if let Some(unknown) = intent
            .programs
            .iter()
            .find(|program| !self.programs.contains(*program))
        {
            return PolicyDecision::Deny {
                reason: format!("the program `{unknown}` is not on the allowlist"),
            };
        }
        PolicyDecision::Allow
    }
}
