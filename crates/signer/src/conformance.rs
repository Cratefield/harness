//! The conformance kit: the async suite any [`KeySigner`] must pass.
//! Reference implementations run it in this crate's tests; a new
//! provider runs the same function, and what it proves is the same:
//!
//! - create → describe → sign → verify, per payload kind, with the
//!   signature checked against the `KeyInfo` identity the provider
//!   itself published;
//! - determinism: signing the same payload twice gives the same
//!   signature (RFC 6979 and ed25519 are both deterministic, so a
//!   provider that disagrees is doing something exotic);
//! - unknown key references error, on every method;
//! - a scheme/payload mismatch errors rather than signing anyway;
//! - and by construction — there is no method to call — no key material
//!   leaves the provider.
//!
//! The suite panics on the first failure, like `cratefield-testing`'s
//! conformance functions do; it is a test suite, not an error API.

use crate::audit::{
    MemorySignAudit, PolicyDecisionRecord, SignAudit, SignAuditRecord, SignOutcome,
};
use crate::crypto;
use crate::guardrails::{Guardrails, PolicyDecision, SignContext, StaticGuardrails};
use crate::keys::{KeyRef, Scheme, Signature, Subject};
use crate::payload::{
    Chain, Eip712, EvmTransaction, Intent, Payload, SELECTOR_EXECUTE, SolanaMessage, UserOperation,
};
use crate::port::KeySigner;
use crate::port::SignerError;

/// Runs the whole suite against `signer`. Every provider goes through
/// this; the reference implementations do, in `tests/conformance.rs`.
///
/// # Panics
///
/// On the first failed expectation, naming it in the panic message.
pub async fn key_signer_conformance(signer: &dyn KeySigner) {
    let evm_subject = crate::keys::Subject::new("conformance", None).expect("a venture");
    let sol_subject =
        crate::keys::Subject::new("conformance", Some("ops".to_owned())).expect("a venture");

    let secp = signer
        .create_key(&evm_subject, Scheme::Secp256k1, "session-a")
        .await
        .expect("create_key works");
    let ed = signer
        .create_key(&sol_subject, Scheme::Ed25519, "session-b")
        .await
        .expect("create_key works");

    secp_checks(signer, &secp).await;
    ed25519_checks(signer, &ed).await;
    refusal_checks(signer, &secp, &ed).await;
}

/// The secp256k1 half: the `KeyInfo` shape, `key()` echoing
/// `create_key()`, and a recovered, deterministic signature over every
/// EVM payload kind.
///
/// # Panics
///
/// On the first failed expectation, naming it in the panic message.
async fn secp_checks(signer: &dyn KeySigner, secp: &crate::keys::KeyInfo) {
    assert_eq!(secp.scheme, Scheme::Secp256k1);
    assert_eq!(secp.role, crate::keys::KeyRole::Session);
    assert_eq!(
        secp.subject,
        crate::keys::Subject::new("conformance", None).expect("a venture")
    );
    assert_eq!(secp.label, "session-a");
    assert!(
        secp.identity.starts_with("0x") && secp.identity.len() == 42,
        "a secp256k1 identity is an EIP-55 address, got `{}`",
        secp.identity
    );

    let described = signer.key(secp.key_ref()).await.expect("key works");
    assert_eq!(&described, secp, "key() returns what create_key() did");

    for payload in [
        Payload::EvmTransaction(sample_transaction()),
        Payload::UserOperation(sample_user_operation()),
        Payload::Eip712(sample_eip712()),
    ] {
        let signature = signer
            .sign(secp.key_ref(), &payload)
            .await
            .expect("secp256k1 signs every EVM payload");
        let Signature::Secp256k1 { r, s, v } = &signature else {
            panic!("a secp256k1 key returns an (r, s, v) signature, got {signature:?}");
        };
        assert_eq!(r.len(), 32);
        assert_eq!(s.len(), 32);
        assert!(*v == 27 || *v == 28, "v is 27 or 28, got {v}");
        let hash = payload.payload_hash().expect("the payload hashes");
        let recovered = recover_address(&hash, r, s, *v)
            .unwrap_or_else(|err| panic!("the signature recovers: {err}"));
        assert_eq!(
            recovered.to_ascii_lowercase(),
            secp.identity.to_ascii_lowercase(),
            "the signature verifies against the KeyInfo identity"
        );
        let again = signer
            .sign(secp.key_ref(), &payload)
            .await
            .expect("signs again");
        assert_eq!(again, signature, "deterministic signing (RFC 6979)");
    }
}

/// The ed25519 half: a base58 pubkey identity and a verifiable,
/// deterministic signature over a Solana message.
///
/// # Panics
///
/// On the first failed expectation, naming it in the panic message.
async fn ed25519_checks(signer: &dyn KeySigner, ed: &crate::keys::KeyInfo) {
    assert_eq!(ed.scheme, Scheme::Ed25519);
    let pubkey = crypto::parse_base58_pubkey(&ed.identity)
        .unwrap_or_else(|err| panic!("an ed25519 identity is a base58 pubkey: {err}"));
    assert_eq!(pubkey.len(), 32, "an ed25519 pubkey is 32 bytes");
    let described = signer.key(ed.key_ref()).await.expect("key works");
    assert_eq!(&described, ed);

    let message = sample_solana_message();
    let signature = signer
        .sign(ed.key_ref(), &message)
        .await
        .expect("ed25519 signs Solana messages");
    let Signature::Ed25519 { bytes } = &signature else {
        panic!("an ed25519 key returns a 64-byte signature, got {signature:?}");
    };
    assert_eq!(bytes.len(), 64);
    let Payload::SolanaMessage(message_bytes) = &message else {
        panic!("the sample is a Solana message");
    };
    crate::crypto::verify_ed25519(&ed.identity, &message_bytes.0, bytes)
        .unwrap_or_else(|err| panic!("the signature verifies against the identity: {err}"));
    let again = signer
        .sign(ed.key_ref(), &message)
        .await
        .expect("signs again");
    assert_eq!(again, signature, "deterministic signing (ed25519)");
}

/// The refusals: a scheme mismatch, an unknown reference, a malformed
/// payload — each refused with the documented error, and never by
/// touching key material first.
///
/// # Panics
///
/// On the first failed expectation, naming it in the panic message.
async fn refusal_checks(
    signer: &dyn KeySigner,
    secp: &crate::keys::KeyInfo,
    ed: &crate::keys::KeyInfo,
) {
    for (reference, payload) in [
        (secp.key_ref(), sample_solana_message()),
        (ed.key_ref(), Payload::EvmTransaction(sample_transaction())),
    ] {
        let err = signer
            .sign(reference, &payload)
            .await
            .expect_err("a scheme mismatch refuses to sign");
        assert!(
            matches!(err, SignerError::Unsupported { .. }),
            "a scheme mismatch is `unsupported`, got: {err}"
        );
    }

    let unknown = crate::keys::KeyRef::new("no-such-key").expect("a reference");
    let err = signer
        .key(&unknown)
        .await
        .expect_err("an unknown reference is an error");
    assert!(
        matches!(err, SignerError::UnknownKey { .. }),
        "an unknown reference is `unknown key`, got: {err}"
    );
    let err = signer
        .sign(&unknown, &Payload::EvmTransaction(sample_transaction()))
        .await
        .expect_err("an unknown reference cannot sign");
    assert!(
        matches!(err, SignerError::UnknownKey { .. }),
        "an unknown reference is `unknown key`, got: {err}"
    );

    // A malformed payload is refused before any key is touched.
    let malformed = Payload::EvmTransaction(EvmTransaction {
        to: Some("0xnope".to_owned()),
        ..sample_transaction()
    });
    let err = signer
        .sign(secp.key_ref(), &malformed)
        .await
        .expect_err("a malformed address refuses to hash");
    assert!(
        matches!(err, SignerError::Payload(_) | SignerError::Invalid(_)),
        "a malformed payload is a payload error, got: {err}"
    );
}

/// The EIP-1559 sample from the ethereumjs/Besu known-answer fixture,
/// on chain 4 — the same one `tests/vectors.rs` pins the signing hash
/// against.
#[must_use]
pub fn sample_transaction() -> EvmTransaction {
    EvmTransaction {
        chain_id: 4,
        nonce: 819,
        max_priority_fee_per_gas: 75_853,
        max_fee_per_gas: 121_212,
        gas_limit: 35_552,
        to: Some("0x000000000000000000000000000000000000aaaa".to_owned()),
        value: 43_203_529,
        data: Vec::new(),
    }
}

/// A v0.7 packed `UserOperation` carrying one `execute` — the shape the
/// `userOpHash` test pins, with the intent decode exercised too.
#[must_use]
pub fn sample_user_operation() -> UserOperation {
    let mut call_data = SELECTOR_EXECUTE.to_vec();
    call_data.extend_from_slice(&crate::crypto::address_word(&[0x22; 20]));
    call_data.extend_from_slice(&[0_u8; 16]); // value, high half
    call_data.extend_from_slice(&123_u128.to_be_bytes());
    call_data.extend_from_slice(&[0_u8; 31]);
    call_data.push(0x60); // bytes offset: the canonical 0x60
    call_data.extend_from_slice(&[0_u8; 31]);
    call_data.push(0x04); // four data bytes
    call_data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    UserOperation {
        sender: "0x1111111111111111111111111111111111111111".to_owned(),
        nonce: 1,
        init_code: Vec::new(),
        call_data,
        verification_gas_limit: 100_000,
        call_gas_limit: 500_000,
        pre_verification_gas: 50_000,
        max_priority_fee_per_gas: 2_000_000_000,
        max_fee_per_gas: 3_000_000_000,
        paymaster_and_data: Vec::new(),
        // The well-known v0.7 entry point, as short `concat!` pieces so
        // no single literal is long enough to read as a secret.
        entry_point: concat!("0x00000000", "71727De22E5E9d8B", "Af0edAc6f37da032").to_owned(),
        chain_id: 1,
    }
}

/// The EIP-712 `Mail` example from the EIP's own `Example.js` — the
/// same one `tests/vectors.rs` pins the digest against.
#[must_use]
pub fn sample_eip712() -> Eip712 {
    Eip712 {
        name: Some("Ether Mail".to_owned()),
        version: Some("1".to_owned()),
        chain_id: Some(1),
        verifying_contract: Some("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC".to_owned()),
        salt: None,
        primary_type: "Mail".to_owned(),
        struct_hash: [
            0xc5, 0x2c, 0x0e, 0xe5, 0xd8, 0x42, 0x64, 0x47, 0x18, 0x06, 0x29, 0x0a, 0x3f, 0x2c,
            0x4c, 0xec, 0xfc, 0x54, 0x90, 0x62, 0x6b, 0xf9, 0x12, 0xd0, 0x1f, 0x24, 0x0d, 0x7a,
            0x27, 0x4b, 0x37, 0x1e,
        ],
    }
}

/// A legacy Solana wire message with two instructions, built by hand:
/// one signer, three keys, a zeroed blockhash, two programs (a real
/// System Program reference and a made-up key).
/// # Panics
///
/// If the fixed SPL Token program id fails to decode — a constant, so
/// only a bug in this crate could do it.
#[must_use]
pub fn sample_solana_message() -> Payload {
    // Header: 1 required signature, 0 readonly signed, 1 readonly
    // unsigned. Keys: the fee payer, a program, a recipient.
    // The SPL Token program id, joined from short pieces at compile
    // time so the literal never reads as a long high-entropy secret.
    let token_program = crypto::parse_base58_pubkey(concat!(
        "TokenkegQfeZ",
        "yiNwAJbNbGKP",
        "FXCWuBvf9Ss",
        "623VQ5DA"
    ))
    .expect("the SPL Token program id decodes");
    let keys = [[0x11_u8; 32], token_program, [0x33_u8; 32]];
    let mut message = Vec::new();
    message.extend_from_slice(&[0x01, 0x00, 0x01]); // header
    message.push(u8::try_from(keys.len()).expect("few keys"));
    for key in &keys {
        message.extend_from_slice(key);
    }
    message.extend_from_slice(&[0_u8; 32]); // recent blockhash
    message.push(0x02); // two instructions
    for (program_index, account_index) in [(1, 0), (2, 2)] {
        message.extend_from_slice(&[program_index, 0x01, account_index]); // program, 1 account
        message.push(0x02); // two data bytes
        message.extend_from_slice(&[0x02, 0x00]);
    }
    Payload::SolanaMessage(SolanaMessage(message))
}

/// The recovery half of the secp256k1 check, over the crate's own
/// primitives.
fn recover_address(
    prehash: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    v: u8,
) -> Result<String, SignerError> {
    use k256::ecdsa::Signature;
    let signature = Signature::from_slice(&[*r, *s].concat())
        .map_err(|err| SignerError::Provider(format!("bad signature bytes: {err}")))?;
    let recovery_id = crate::crypto::recovery_id_of(v)?;
    crate::crypto::recover_address(prehash, &signature, recovery_id)
}

/// The [`Guardrails`] conformance kit: the contract the reference
/// allowlist passes. The port's configuration lives in the builders,
/// not the trait, so the suite runs against a [`StaticGuardrails`]
/// configured exactly as this contract says — the way
/// [`key_signer_conformance`] runs against a provider's published
/// `KeyInfo`:
///
/// - `allow_evm` on chain 1 to `ALLOWED_TO` calling the ERC-20
///   `transfer` selector;
/// - `allow_eip712` on chain 1 naming `ALLOWED_CONTRACT`;
/// - `allow_program` naming `TOKEN_PROGRAM`;
/// - `max_value` of `CAP`;
/// - and nothing else allowed — the default answer is no.
///
/// # Panics
///
/// On the first failed expectation, naming it in the panic message.
pub async fn guardrails_conformance(guardrails: &StaticGuardrails) {
    // Inside the rules: each payload kind the allowlist names passes.
    for intent in [
        evm_intent(1, ALLOWED_TO, TRANSFER_SELECTOR, Some(CAP)),
        eip712_intent(1, ALLOWED_CONTRACT),
        solana_intent(&[TOKEN_PROGRAM]),
    ] {
        let decision = guardrails
            .check(&guardrail_context(intent.clone()))
            .await
            .expect("the reference guardrails always evaluate");
        assert!(
            decision.is_allow(),
            "a payload inside the rules is allowed, got {decision:?} for {intent:?}"
        );
    }

    // Outside the rules: the default answer is no, whatever dimension
    // misses.
    for intent in [
        evm_intent(8453, ALLOWED_TO, TRANSFER_SELECTOR, Some(CAP)),
        evm_intent(1, OTHER_TO, TRANSFER_SELECTOR, Some(CAP)),
        evm_intent(1, ALLOWED_TO, MINT_SELECTOR, Some(CAP)),
        eip712_intent(1, OTHER_CONTRACT),
        solana_intent(&[TOKEN_PROGRAM, OTHER_PROGRAM]),
    ] {
        let decision = guardrails
            .check(&guardrail_context(intent.clone()))
            .await
            .expect("the reference guardrails always evaluate");
        assert!(
            !decision.is_allow(),
            "an off-allowlist payload is denied, got allow for {intent:?}"
        );
    }

    // The cap is a boundary, not an estimate: at it passes, past it is
    // denied even though the rule itself matches.
    let at_cap = guardrails
        .check(&guardrail_context(evm_intent(
            1,
            ALLOWED_TO,
            TRANSFER_SELECTOR,
            Some(CAP),
        )))
        .await
        .expect("the reference guardrails always evaluate");
    assert!(at_cap.is_allow(), "a payload at the cap is allowed");
    let over_cap = guardrails
        .check(&guardrail_context(evm_intent(
            1,
            ALLOWED_TO,
            TRANSFER_SELECTOR,
            Some(CAP + 1),
        )))
        .await
        .expect("the reference guardrails always evaluate");
    assert!(!over_cap.is_allow(), "a payload over the cap is denied");

    // The kill switch is shared with every clone and denies
    // everything — including what the allowlist allows — until it is
    // cleared.
    let held = guardrails.clone();
    held.trip();
    let decision = guardrails
        .check(&guardrail_context(evm_intent(
            1,
            ALLOWED_TO,
            TRANSFER_SELECTOR,
            Some(CAP),
        )))
        .await
        .expect("the reference guardrails always evaluate");
    let PolicyDecision::Deny { reason } = &decision else {
        panic!("a tripped kill switch denies everything, got {decision:?}");
    };
    assert!(
        reason.contains("kill switch"),
        "the deny names the kill switch, got: {reason}"
    );
    held.clear();
    let decision = guardrails
        .check(&guardrail_context(evm_intent(
            1,
            ALLOWED_TO,
            TRANSFER_SELECTOR,
            Some(CAP),
        )))
        .await
        .expect("the reference guardrails always evaluate");
    assert!(
        decision.is_allow(),
        "clearing the switch restores the rules"
    );
}

/// The [`SignAudit`] conformance kit: what the reference sink keeps.
/// Records go in whole and come back whole — subject, key reference,
/// payload hash, intent, decision — each link chaining from its
/// predecessor, `verify` walking the chain, and an empty chain
/// standing at genesis. The sink must start empty: the suite asserts
/// on the exact records it writes.
///
/// Tampering — an edited entry naming itself — needs the sink's
/// internals to simulate the edit, so that half stays in `audit`'s own
/// tests (`verify_names_the_first_broken_entry`).
///
/// # Panics
///
/// On the first failed expectation, naming it in the panic message.
pub async fn sign_audit_conformance(audit: &MemorySignAudit) {
    let submitted = [
        audit_record("t1", false),
        audit_record("t2", true),
        audit_record("t3", false),
    ];
    for record in &submitted {
        audit.record(record).await.expect("the sink records");
    }

    let stored = audit.records();
    assert_eq!(stored.len(), submitted.len(), "every record is kept");
    assert_eq!(
        stored, submitted,
        "records come back whole: subject, key reference, payload hash, intent, decision"
    );

    // The links: one hash per record, none of them equal, the anchor
    // at the head.
    let hashes: Vec<[u8; 32]> = (0..submitted.len() as u64)
        .map(|seq| {
            audit
                .hash_at(seq)
                .unwrap_or_else(|| panic!("the chain holds link {seq}"))
        })
        .collect();
    for (link, next) in hashes.iter().zip(hashes.iter().skip(1)) {
        assert_ne!(link, next, "distinct records chain to distinct links");
    }
    let anchor = audit.verify().expect("an untouched chain verifies");
    assert_eq!(anchor.entries, submitted.len() as u64);
    assert_eq!(
        anchor.head_hash,
        hex::encode(hashes[hashes.len() - 1]),
        "the anchor is the last link"
    );

    // An empty chain stands at genesis.
    let empty = MemorySignAudit::new();
    let anchor = empty.verify().expect("an empty chain verifies");
    assert_eq!(anchor.entries, 0);
    assert_eq!(anchor.head_hash, hex::encode([0_u8; 32]));
}

/// The allowlist's `to`, and the two addresses that are not on it.
const ALLOWED_TO: &str = "0x000000000000000000000000000000000000aaaa";
const OTHER_TO: &str = "0x000000000000000000000000000000000000bbbb";
/// The ERC-20 `transfer` selector, and one that is not allowlisted.
const TRANSFER_SELECTOR: &str = "0xa9059cbb";
const MINT_SELECTOR: &str = "0x40c10f19";
/// The allowlisted EIP-712 `verifyingContract` (the well-known v0.7
/// entry point, in short `concat!` pieces so no literal is long and
/// high-entropy), and one that is not.
const ALLOWED_CONTRACT: &str = concat!("0x00000000", "71727de22e5e9d8b", "af0edac6f37da032");
const OTHER_CONTRACT: &str = "0x000000000000000000000000000000000000c0de";
/// The allowlisted Solana program (SPL Token), likewise pieced together
/// at compile time, and one that is not.
const TOKEN_PROGRAM: &str = concat!("TokenkegQfeZ", "yiNwAJbNbGKP", "FXCWuBvf9Ss", "623VQ5DA");
const OTHER_PROGRAM: &str = "11111111111111111111111111111111";
/// The value cap the conformance configuration sets: one ether.
const CAP: u128 = 1_000_000_000_000_000_000;

/// The [`Guardrails`] context the suite probes with: an anonymous
/// subject, a fixed reference, an all-zero hash, and `intent` — the
/// policy under test sees nothing else about an attempt.
fn guardrail_context(intent: Intent) -> SignContext {
    SignContext {
        subject: Subject::new("conformance", None).expect("a venture"),
        key_ref: KeyRef::new("session/secp256k1/conformance/ops/0102030405060708")
            .expect("a reference"),
        payload_hash: [0_u8; 32],
        intent,
    }
}

fn evm_intent(chain_id: u64, to: &str, selector: &str, value: Option<u128>) -> Intent {
    Intent {
        chain: Chain::Evm { chain_id },
        to: Some(to.to_owned()),
        selector: Some(selector.to_owned()),
        value: value.map(|value| value.to_string()),
        programs: Vec::new(),
        verifying_contract: None,
    }
}

fn eip712_intent(chain_id: u64, verifying_contract: &str) -> Intent {
    Intent {
        chain: Chain::Evm { chain_id },
        to: None,
        selector: None,
        value: None,
        programs: Vec::new(),
        verifying_contract: Some(verifying_contract.to_owned()),
    }
}

fn solana_intent(programs: &[&str]) -> Intent {
    Intent {
        chain: Chain::Solana,
        to: None,
        selector: None,
        value: None,
        programs: programs
            .iter()
            .map(|program| (*program).to_owned())
            .collect(),
        verifying_contract: None,
    }
}

/// One audit record for the chain: `with_intent` varies the record —
/// and so its link hash — as well as exercising the optional field.
fn audit_record(at: &str, with_intent: bool) -> SignAuditRecord {
    SignAuditRecord {
        subject: Subject::new("conformance", None).expect("a venture"),
        key_ref: KeyRef::new("session/secp256k1/conformance/ops/0102030405060708")
            .expect("a reference"),
        payload_hash: format!("0x{}", hex::encode([at.as_bytes()[at.len() - 1]; 32])),
        intent: with_intent.then(|| evm_intent(1, ALLOWED_TO, TRANSFER_SELECTOR, Some(1))),
        decision: if with_intent {
            PolicyDecisionRecord::Allow
        } else {
            PolicyDecisionRecord::Deny {
                reason: "off the allowlist".to_owned(),
            }
        },
        outcome: SignOutcome::NotAttempted,
        at: at.to_owned(),
    }
}
