//! The hard denies: shapes that are refused on the request alone, before
//! any allowlist is consulted and whatever the allowlist says.
//!
//! Two families:
//!
//! - **EVM, by calldata selector.** `setApprovalForAll` always. The
//!   approval selectors (`approve`, `increaseAllowance`, Permit2's
//!   `approve`) when the amount crosses the unlimited line. The permit
//!   selectors (EIP-2612, DAI-style, and Permit2's `AllowanceTransfer`
//!   `permit`, single and batch) when the spender is not allowlisted or the
//!   amount is unlimited. An EIP-7702 authorization with `chain_id == 0`
//!   (replayable on every chain) always.
//! - **Solana, by program and discriminant.** System `Assign` /
//!   `AssignWithSeed` (owner reassignment) and `AdvanceNonceAccount`
//!   (durable-nonce use) always; SPL Token and Token-2022 `SetAuthority`
//!   always, and `Approve` / `ApproveChecked` at `u64::MAX` (Solana's
//!   unlimited).
//!
//! The selector constants below are verified against keccak-256 of their
//! signature strings by a unit test in this module.

use crate::action::{Action, Request, SolanaInstruction, u256_is_unlimited};
use crate::audit::{DenyReason, HardDeny};
use crate::policy::Policy;

// --- EVM selectors (keccak256(signature)[..4]) ---

/// `approve(address,uint256)` — the classic ERC-20 approval.
pub const SEL_APPROVE: u32 = 0x095e_a7b3;
/// `setApprovalForAll(address,bool)` — every token, now and in the future.
pub const SEL_SET_APPROVAL_FOR_ALL: u32 = 0xa22c_b465;
/// `increaseAllowance(address,uint256)`.
pub const SEL_INCREASE_ALLOWANCE: u32 = 0x3950_9351;
/// `approve(address,address,uint160,uint48)` — Permit2's `AllowanceTransfer`
/// approval: token, spender, amount, expiration.
pub const SEL_PERMIT2_APPROVE: u32 = 0x8751_7c45;
/// `permit(address,address,uint256,uint256,uint8,bytes32,bytes32)` —
/// EIP-2612: owner, spender, value, deadline, then the signature.
pub const SEL_PERMIT_2612: u32 = 0xd505_accf;
/// `permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)` —
/// DAI's non-standard permit: owner, spender, value, deadline, allowed, then
/// the signature.
pub const SEL_PERMIT_DAI: u32 = 0x8fcb_af0c;
/// `permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)`
/// — Permit2 `AllowanceTransfer`, single: owner, details (token, amount,
/// expiration, nonce), spender, deadline, signature.
pub const SEL_PERMIT2_SINGLE: u32 = 0x2b67_b570;
/// `permit(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)`
/// — Permit2 `AllowanceTransfer`, batch. The amounts live in a dynamic array,
/// so no static bound exists and the form is refused outright.
pub const SEL_PERMIT2_BATCH: u32 = 0x2a2d_80d1;
/// `transfer(address,uint256)` — decoded for its recipient, not denied.
pub const SEL_TRANSFER: u32 = 0xa905_9cbb;
/// `transferFrom(address,address,uint256)` — decoded for its recipient.
pub const SEL_TRANSFER_FROM: u32 = 0x23b8_72dd;

// --- Solana programs and discriminants ---

/// The Solana System program.
pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
/// The SPL Token program.
pub const SPL_TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// The Token-2022 program.
pub const SPL_TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

/// System `Assign` (u32 little-endian discriminant): reassigns account
/// owner.
pub const SYS_ASSIGN: u32 = 1;
/// System `Transfer` (decoded for its destination, not denied).
pub const SYS_TRANSFER: u32 = 2;
/// System `AdvanceNonceAccount`: advances a durable nonce.
pub const SYS_ADVANCE_NONCE: u32 = 4;
/// System `AssignWithSeed`: reassigns account owner, seeded form.
pub const SYS_ASSIGN_WITH_SEED: u32 = 10;

/// SPL Token `Transfer` (u8 discriminant).
pub const TOK_TRANSFER: u8 = 3;
/// SPL Token `Approve`.
pub const TOK_APPROVE: u8 = 4;
/// SPL Token `Revoke`.
pub const TOK_REVOKE: u8 = 5;
/// SPL Token `SetAuthority`.
pub const TOK_SET_AUTHORITY: u8 = 6;
/// SPL Token `TransferChecked`.
pub const TOK_TRANSFER_CHECKED: u8 = 12;
/// SPL Token `ApproveChecked`.
pub const TOK_APPROVE_CHECKED: u8 = 13;

/// The System program's u32 little-endian instruction discriminant.
#[must_use]
pub fn system_discriminant(ins: &crate::action::SolanaInstruction) -> u32 {
    ins.data
        .first_chunk::<4>()
        .map_or(0, |b| u32::from_le_bytes(*b))
}

/// The SPL Token programs' u8 instruction discriminant.
#[must_use]
pub fn tok_discriminant(ins: &crate::action::SolanaInstruction) -> u8 {
    ins.data.first().copied().unwrap_or(0)
}

/// Whether a SPL Token `Approve` / `ApproveChecked` instruction approves
/// Solana's unlimited: `u64::MAX`, little-endian at byte 1. Malformed data
/// proves nothing and denies nothing here — the static pass only refuses
/// what it can see.
#[must_use]
fn tok_max_approve(ins: &SolanaInstruction) -> bool {
    ins.data
        .get(1..9)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(u64::from_le_bytes)
        == Some(u64::MAX)
}

/// The 32-byte word at `at` (byte offset from the start of `data`), when
/// present.
#[must_use]
pub fn word(data: &[u8], at: usize) -> Option<&[u8]> {
    data.get(at..at + 32)
}

/// The lowercase `0x`-hex address in the 32-byte word at `at` (the word's
/// last 20 bytes), when present.
#[must_use]
pub fn word_addr(data: &[u8], at: usize) -> Option<String> {
    let w = word(data, at)?;
    Some(format!("0x{}", hex::encode(&w[12..])))
}

/// Whether the word at `at` crosses the unlimited line (any of its high 16
/// bytes set). Missing calldata proves nothing and denies nothing here:
/// malformed input is caught downstream, and the static pass only refuses
/// what it can see.
#[must_use]
fn word_unlimited(data: &[u8], at: usize) -> bool {
    word(data, at).is_some_and(|w| w[..16].iter().any(|&b| b != 0))
}

/// The EVM primary types that hand out spending power by signature. A
/// typed-data request with one of these primary types is a permit, whatever
/// the domain calls it.
const PERMIT_PRIMARY_TYPES: [&str; 5] = [
    "Permit",
    "PermitSingle",
    "PermitBatch",
    "PermitTransferFrom",
    "PermitBatchTransferFrom",
];

/// Every hard deny the request itself carries. Cheap: no port, no I/O — the
/// engine runs this before anything that can fail, and a non-empty answer
/// means the simulator is never called.
pub fn hard_denies(req: &Request, policy: &Policy) -> Vec<DenyReason> {
    match &req.action {
        Action::EvmTx {
            to,
            data,
            authorizations,
            ..
        } => {
            let mut out = Vec::new();
            for a in authorizations {
                if a.chain_id == 0 {
                    out.push(DenyReason::HardDeny(HardDeny::Eip7702ZeroChain));
                }
            }
            // `to` is unused by the selector scan (the Permit2 spender for
            // the single form is *in* the calldata); named to keep the
            // destructure total.
            let _ = to;
            if let Some(sel) = data.first_chunk::<4>().map(|b| u32::from_be_bytes(*b)) {
                out.extend(evmdeny(req, policy, sel, data));
            }
            out
        }
        Action::EvmTypedData {
            primary_type,
            spender,
            amount,
            ..
        } => {
            if !PERMIT_PRIMARY_TYPES.contains(&primary_type.as_str()) {
                return Vec::new();
            }
            match spender {
                None => vec![unknown_spender("<unset>".to_owned())],
                Some(s) if !policy.spender_allowed(&req.subject, s) => {
                    vec![unknown_spender(s.clone())]
                }
                Some(_) if amount.is_none_or(|a| u256_is_unlimited(&a)) => {
                    // `None` is "the amount is not statically known": the
                    // same answer as unlimited, because both mean the
                    // signature's reach cannot be bounded here.
                    vec![DenyReason::HardDeny(HardDeny::PermitUnlimited)]
                }
                Some(_) => Vec::new(),
            }
        }
        Action::SolanaTx { instructions, .. } => {
            let mut out = Vec::new();
            for ins in instructions {
                match ins.program_id.as_str() {
                    SYSTEM_PROGRAM => match system_discriminant(ins) {
                        d if d == SYS_ASSIGN || d == SYS_ASSIGN_WITH_SEED => {
                            out.push(DenyReason::HardDeny(HardDeny::OwnerReassignment));
                        }
                        d if d == SYS_ADVANCE_NONCE => {
                            out.push(DenyReason::HardDeny(HardDeny::NonceAdvance));
                        }
                        _ => {}
                    },
                    p if p == SPL_TOKEN_PROGRAM || p == SPL_TOKEN_2022_PROGRAM => {
                        match tok_discriminant(ins) {
                            d if d == TOK_SET_AUTHORITY => {
                                out.push(DenyReason::HardDeny(HardDeny::OwnerReassignment));
                            }
                            d if (d == TOK_APPROVE || d == TOK_APPROVE_CHECKED)
                                && tok_max_approve(ins) =>
                            {
                                out.push(DenyReason::HardDeny(HardDeny::UnlimitedApproval));
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
            out
        }
    }
}

fn unknown_spender(addr: String) -> DenyReason {
    DenyReason::HardDeny(HardDeny::PermitUnknownSpender(addr))
}

/// The calldata half of [`hard_denies`], once the selector is known.
fn evmdeny(req: &Request, policy: &Policy, sel: u32, data: &[u8]) -> Vec<DenyReason> {
    match sel {
        SEL_SET_APPROVAL_FOR_ALL => vec![DenyReason::HardDeny(HardDeny::ApprovalForAll)],
        SEL_APPROVE | SEL_INCREASE_ALLOWANCE => {
            // spender (32 bytes) then amount.
            unlimited(data, 36)
        }
        SEL_PERMIT2_APPROVE => {
            // token, spender, then amount.
            unlimited(data, 68)
        }
        SEL_PERMIT_2612 | SEL_PERMIT_DAI => {
            // owner, spender, value.
            permit(req, policy, data, 36, 68)
        }
        SEL_PERMIT2_SINGLE => {
            // owner, details(token, amount, expiration, nonce), spender,
            // deadline, signature bytes.
            permit(req, policy, data, 164, 68)
        }
        SEL_PERMIT2_BATCH => {
            // owner, offset, spender, deadline. The amounts are in the
            // dynamic array the offset points at: no static bound exists,
            // so the form is refused outright — and a truncated spender
            // word refuses too, since nothing downstream can bound a
            // signature's reach.
            match word_addr(data, 68) {
                Some(spender) if !policy.spender_allowed(&req.subject, &spender) => {
                    vec![unknown_spender(spender)]
                }
                _ => vec![DenyReason::HardDeny(HardDeny::PermitUnlimited)],
            }
        }
        _ => Vec::new(),
    }
}

fn unlimited(data: &[u8], amount_at: usize) -> Vec<DenyReason> {
    if word_unlimited(data, amount_at) {
        vec![DenyReason::HardDeny(HardDeny::UnlimitedApproval)]
    } else {
        Vec::new()
    }
}

/// A permit's spender-and-amount check at fixed calldata offsets. An
/// unbounded amount on a *permit* is its own reason: the reach comes from
/// a signature, not from an approval the owner wrote. Unlike the approve
/// family, a permit whose words cannot be read is refused here — a
/// simulation report shows approvals, never signature reach, so this pass
/// is the only bound a permit gets and it fails closed.
fn permit(
    req: &Request,
    policy: &Policy,
    data: &[u8],
    spender_at: usize,
    amount_at: usize,
) -> Vec<DenyReason> {
    match word_addr(data, spender_at) {
        Some(spender) if !policy.spender_allowed(&req.subject, &spender) => {
            vec![unknown_spender(spender)]
        }
        Some(_) if word(data, amount_at).is_none() || word_unlimited(data, amount_at) => {
            vec![DenyReason::HardDeny(HardDeny::PermitUnlimited)]
        }
        Some(_) => Vec::new(),
        None => vec![unknown_spender("<truncated calldata>".to_owned())],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{u256_from_u128, u256_to_u128};
    use sha3::{Digest, Keccak256};

    #[test]
    fn every_selector_constant_is_its_signature() {
        for (constant, signature) in [
            (SEL_APPROVE, "approve(address,uint256)"),
            (SEL_SET_APPROVAL_FOR_ALL, "setApprovalForAll(address,bool)"),
            (SEL_INCREASE_ALLOWANCE, "increaseAllowance(address,uint256)"),
            (
                SEL_PERMIT2_APPROVE,
                "approve(address,address,uint160,uint48)",
            ),
            (
                SEL_PERMIT_2612,
                "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
            ),
            (
                SEL_PERMIT_DAI,
                "permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)",
            ),
            (
                SEL_PERMIT2_SINGLE,
                "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)",
            ),
            (
                SEL_PERMIT2_BATCH,
                "permit(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)",
            ),
            (SEL_TRANSFER, "transfer(address,uint256)"),
            (SEL_TRANSFER_FROM, "transferFrom(address,address,uint256)"),
        ] {
            let d = Keccak256::digest(signature.as_bytes());
            let selector = u32::from_be_bytes(d[..4].try_into().expect("4 bytes"));
            assert_eq!(constant, selector, "{signature}");
        }
    }

    #[test]
    fn u256_helpers_agree_on_the_unlimited_line() {
        // A [u8; 32] big-endian word: bytes 0..16 are the high half, and
        // only the high half counts.
        assert!(!u256_is_unlimited(&u256_from_u128(u128::MAX)));
        let mut low_half_only = [0_u8; 32];
        low_half_only[16] = 1; // 2^120: low half only, below the line
        assert!(!u256_is_unlimited(&low_half_only));
        let mut across = [0_u8; 32];
        across[16] = 1;
        across[0] = 1; // 2^120 + 2^248: high half set, over the line
        assert!(u256_is_unlimited(&across));
        assert_eq!(u256_to_u128(&u256_from_u128(12_345)), Some(12_345));
        assert_eq!(u256_to_u128(&across), None);
    }
}
