//! The allowlists: what a subject may touch at all. Default deny — an
//! allowlist that names nothing allows nothing.
//!
//! A policy has a **global** layer and a **per-subject** layer, each an
//! [`Allowlist`]; the effective allowlist for a subject is the union of the
//! two, so a venture can name its common contracts once and per-actor
//! extras on top. Caps are different: they live per subject only, and they
//! are required — a subject with no caps is a subject that moves nothing.
//!
//! EVM addresses may be inserted in any case (checksummed or not); the
//! builders normalise to lowercase, and comparisons on EVM are
//! case-insensitive. Solana addresses are matched exactly.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::action::{Action, Chain, Request};
use crate::audit::{DenyReason, NotAllowlisted};
use crate::caps::Caps;
use crate::deny::{
    SEL_TRANSFER, SEL_TRANSFER_FROM, SYS_TRANSFER, TOK_TRANSFER, TOK_TRANSFER_CHECKED,
    system_discriminant, tok_discriminant, word_addr,
};

/// One layer of the allowlist: the chains, contracts, programs, destinations
/// and spenders named at this layer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allowlist {
    /// Chains this layer may act on.
    pub chains: BTreeSet<Chain>,
    /// EVM contracts this layer may call, each with its explicit selector
    /// set. A selector outside the set is refused even though the contract
    /// is known.
    pub evm_contracts: BTreeMap<String, BTreeSet<u32>>,
    /// Solana programs this layer may invoke.
    pub solana_programs: BTreeSet<String>,
    /// Destination addresses this layer may move funds to.
    pub destinations: BTreeSet<String>,
    /// Spenders this layer may approve or permit.
    pub spenders: BTreeSet<String>,
}

impl Allowlist {
    /// Allows a chain.
    #[must_use]
    pub fn chain(mut self, chain: Chain) -> Self {
        self.chains.insert(chain);
        self
    }

    /// Allows a contract for the given selectors; the address is normalised
    /// to lowercase.
    #[must_use]
    pub fn contract(mut self, address: &str, selectors: &[u32]) -> Self {
        self.evm_contracts
            .entry(address.to_ascii_lowercase())
            .or_default()
            .extend(selectors.iter().copied());
        self
    }

    /// Allows a Solana program.
    #[must_use]
    pub fn program(mut self, program_id: &str) -> Self {
        self.solana_programs.insert(program_id.to_owned());
        self
    }

    /// Allows a destination address.
    #[must_use]
    pub fn destination(mut self, address: &str) -> Self {
        self.destinations.insert(address.to_owned());
        self
    }

    /// Allows a spender.
    #[must_use]
    pub fn spender(mut self, address: &str) -> Self {
        self.spenders.insert(address.to_owned());
        self
    }

    /// Whether `address` names a destination: exact match always, and
    /// case-insensitive on EVM, where a checksummed spelling is never a
    /// different address.
    #[must_use]
    pub fn names_destination(&self, address: &str, evm: bool) -> bool {
        self.destinations.contains(address)
            || (evm
                && self
                    .destinations
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(address)))
    }

    /// Whether `address` names a spender; EVM comparisons are
    /// case-insensitive.
    #[must_use]
    pub fn names_spender(&self, address: &str) -> bool {
        self.spenders.contains(address)
            || self
                .spenders
                .iter()
                .any(|a| a.eq_ignore_ascii_case(address))
    }
}

/// One subject's layer of the policy: an [`Allowlist`], the subject's caps,
/// and whether the hygiene scan may revoke automatically.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectPolicy {
    /// What this subject may touch, on top of the global layer.
    #[serde(flatten)]
    pub allowlist: Allowlist,
    /// The spend caps. `None` denies everything: caps are required.
    #[serde(default)]
    pub caps: Option<Caps>,
    /// Whether the hygiene scan may send its revoke transactions through
    /// `check` automatically.
    #[serde(default)]
    pub auto_revoke: bool,
}

impl SubjectPolicy {
    /// An empty policy: allows nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allows a chain.
    #[must_use]
    pub fn chain(mut self, chain: Chain) -> Self {
        self.allowlist = self.allowlist.chain(chain);
        self
    }

    /// Allows a contract for the given selectors.
    #[must_use]
    pub fn contract(mut self, address: &str, selectors: &[u32]) -> Self {
        self.allowlist = self.allowlist.contract(address, selectors);
        self
    }

    /// Allows a Solana program.
    #[must_use]
    pub fn program(mut self, program_id: &str) -> Self {
        self.allowlist = self.allowlist.program(program_id);
        self
    }

    /// Allows a destination address.
    #[must_use]
    pub fn destination(mut self, address: &str) -> Self {
        self.allowlist = self.allowlist.destination(address);
        self
    }

    /// Allows a spender.
    #[must_use]
    pub fn spender(mut self, address: &str) -> Self {
        self.allowlist = self.allowlist.spender(address);
        self
    }

    /// Sets the caps.
    #[must_use]
    pub fn caps(mut self, caps: Caps) -> Self {
        self.caps = Some(caps);
        self
    }

    /// Lets the hygiene scan revoke automatically.
    #[must_use]
    pub fn auto_revoke(mut self, yes: bool) -> Self {
        self.auto_revoke = yes;
        self
    }
}

/// The whole policy: a global layer plus one [`SubjectPolicy`] per subject.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// What any subject may touch.
    #[serde(flatten)]
    pub allowlist: Allowlist,
    /// The per-subject layers, keyed by subject id.
    pub subjects: BTreeMap<String, SubjectPolicy>,
}

impl Policy {
    /// An empty policy: allows nothing, denies everything.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a subject's layer.
    #[must_use]
    pub fn subject(mut self, id: &str, policy: SubjectPolicy) -> Self {
        self.subjects.insert(id.to_owned(), policy);
        self
    }

    /// Allows a chain globally.
    #[must_use]
    pub fn chain(mut self, chain: Chain) -> Self {
        self.allowlist = self.allowlist.chain(chain);
        self
    }

    /// Allows a contract globally for the given selectors.
    #[must_use]
    pub fn contract(mut self, address: &str, selectors: &[u32]) -> Self {
        self.allowlist = self.allowlist.contract(address, selectors);
        self
    }

    /// Allows a Solana program globally.
    #[must_use]
    pub fn program(mut self, program_id: &str) -> Self {
        self.allowlist = self.allowlist.program(program_id);
        self
    }

    /// Allows a destination globally.
    #[must_use]
    pub fn destination(mut self, address: &str) -> Self {
        self.allowlist = self.allowlist.destination(address);
        self
    }

    /// Allows a spender globally.
    #[must_use]
    pub fn spender(mut self, address: &str) -> Self {
        self.allowlist = self.allowlist.spender(address);
        self
    }

    fn subject_of(&self, subject: &str) -> Option<&SubjectPolicy> {
        self.subjects.get(subject)
    }

    /// Whether either the subject's layer or the global layer answers yes.
    fn allowed(&self, subject: &str, f: impl Fn(&Allowlist) -> bool) -> bool {
        self.subject_of(subject).is_some_and(|s| f(&s.allowlist)) || f(&self.allowlist)
    }

    /// Whether `chain` is on the effective allowlist.
    #[must_use]
    pub fn chain_allowed(&self, subject: &str, chain: &Chain) -> bool {
        self.allowed(subject, |l| l.chains.contains(chain))
    }

    /// Whether `contract` is known to the effective allowlist, for any
    /// selector.
    #[must_use]
    pub fn contract_known(&self, subject: &str, contract: &str) -> bool {
        let lower = contract.to_ascii_lowercase();
        self.allowed(subject, |l| l.evm_contracts.contains_key(&lower))
    }

    /// Whether the effective allowlist lets `subject` call `selector` on
    /// `contract`.
    #[must_use]
    pub fn selector_allowed(&self, subject: &str, contract: &str, selector: u32) -> bool {
        let lower = contract.to_ascii_lowercase();
        self.allowed(subject, |l| {
            l.evm_contracts
                .get(&lower)
                .is_some_and(|sels| sels.contains(&selector))
        })
    }

    /// Whether `program` is on the effective allowlist.
    #[must_use]
    pub fn program_allowed(&self, subject: &str, program: &str) -> bool {
        self.allowed(subject, |l| l.solana_programs.contains(program))
    }

    /// Whether `address` is an allowed destination. EVM comparisons are
    /// case-insensitive, Solana exact.
    #[must_use]
    pub fn destination_allowed(&self, subject: &str, address: &str, evm: bool) -> bool {
        self.allowed(subject, |l| l.names_destination(address, evm))
    }

    /// Whether `spender` is an allowed spender. EVM comparisons are
    /// case-insensitive.
    #[must_use]
    pub fn spender_allowed(&self, subject: &str, spender: &str) -> bool {
        self.allowed(subject, |l| l.names_spender(spender))
    }

    /// The subject's caps, which must exist for anything to move.
    #[must_use]
    pub fn caps_for(&self, subject: &str) -> Option<&Caps> {
        self.subject_of(subject).and_then(|s| s.caps.as_ref())
    }

    /// Whether the subject's hygiene scan revokes automatically.
    #[must_use]
    pub fn auto_revokes(&self, subject: &str) -> bool {
        self.subject_of(subject).is_some_and(|s| s.auto_revoke)
    }
}

/// The allowlist half of the engine: everything that is refused because the
/// policy does not name it. Runs after the hard denies, which is why it may
/// assume the request's shape is not itself dangerous.
pub fn allowlist_denies(req: &Request, policy: &Policy) -> Vec<DenyReason> {
    let subject = &req.subject;
    let mut out = Vec::new();
    if !policy.chain_allowed(subject, &req.chain()) {
        out.push(DenyReason::NotAllowlisted(NotAllowlisted::Chain));
        return out;
    }
    match &req.action {
        Action::EvmTx {
            to,
            data,
            authorizations,
            ..
        } => {
            match to {
                None => out.push(DenyReason::NotAllowlisted(NotAllowlisted::Contract(
                    "<contract creation>".to_owned(),
                ))),
                Some(target) if data.is_empty() => {
                    if !policy.destination_allowed(subject, target, true) {
                        out.push(DenyReason::NotAllowlisted(NotAllowlisted::Destination(
                            target.clone(),
                        )));
                    }
                }
                Some(target) => {
                    let Some(sel) = selector_of(data) else {
                        // Shorter than a selector and not empty: malformed.
                        out.push(DenyReason::NotAllowlisted(NotAllowlisted::Selector(
                            "<malformed calldata>".to_owned(),
                        )));
                        return out;
                    };
                    if !policy.contract_known(subject, target) {
                        out.push(DenyReason::NotAllowlisted(NotAllowlisted::Contract(
                            target.clone(),
                        )));
                    } else if !policy.selector_allowed(subject, target, sel) {
                        out.push(DenyReason::NotAllowlisted(NotAllowlisted::Selector(
                            format!("0x{sel:08x}"),
                        )));
                    }
                    // A transfer that hides inside an allowlisted call still
                    // lands somewhere: its recipient is a destination.
                    // Calldata: selector (4 bytes), then words — so
                    // `transfer(to, amount)` carries `to` at byte 4, and
                    // `transferFrom(from, to, amount)` carries it at 36.
                    let recipient_at: Option<usize> = match sel {
                        SEL_TRANSFER => Some(4),
                        SEL_TRANSFER_FROM => Some(36),
                        _ => None,
                    };
                    if let Some(at) = recipient_at
                        && let Some(addr) = word_addr(data, at)
                        && !policy.destination_allowed(subject, &addr, true)
                    {
                        out.push(DenyReason::NotAllowlisted(NotAllowlisted::Destination(
                            addr,
                        )));
                    }
                }
            }
            for a in authorizations {
                if !policy.contract_known(subject, &a.address) {
                    out.push(DenyReason::NotAllowlisted(NotAllowlisted::Delegate(
                        a.address.clone(),
                    )));
                }
            }
        }
        Action::EvmTypedData {
            verifying_contract, ..
        } => {
            if !policy.contract_known(subject, verifying_contract) {
                out.push(DenyReason::NotAllowlisted(NotAllowlisted::Contract(
                    verifying_contract.clone(),
                )));
            }
        }
        Action::SolanaTx { instructions, .. } => {
            for ins in instructions {
                if !policy.program_allowed(subject, &ins.program_id) {
                    out.push(DenyReason::NotAllowlisted(NotAllowlisted::Program(
                        ins.program_id.clone(),
                    )));
                    continue;
                }
                if let Some(dest) = solana_destination(ins)
                    && !policy.destination_allowed(subject, &dest, false)
                {
                    out.push(DenyReason::NotAllowlisted(NotAllowlisted::Destination(
                        dest,
                    )));
                }
            }
        }
    }
    out
}

fn selector_of(data: &[u8]) -> Option<u32> {
    data.first_chunk::<4>().map(|s| u32::from_be_bytes(*s))
}

/// The destination account a Solana instruction moves funds to, if it is a
/// move-funds instruction the policy knows: System `Transfer` (to is
/// account 1), SPL `Transfer` (account 1) and `TransferChecked` (account 2).
#[must_use]
pub fn solana_destination(ins: &crate::action::SolanaInstruction) -> Option<String> {
    if ins.program_id == crate::deny::SYSTEM_PROGRAM {
        if system_discriminant(ins) == SYS_TRANSFER {
            return ins.accounts.get(1).cloned();
        }
        return None;
    }
    if ins.program_id == crate::deny::SPL_TOKEN_PROGRAM
        || ins.program_id == crate::deny::SPL_TOKEN_2022_PROGRAM
    {
        return match tok_discriminant(ins) {
            d if d == TOK_TRANSFER => ins.accounts.get(1).cloned(),
            d if d == TOK_TRANSFER_CHECKED => ins.accounts.get(2).cloned(),
            _ => None,
        };
    }
    None
}
