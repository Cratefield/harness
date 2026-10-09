//! The conformance suites, where their doc comments say they run: the
//! reference implementations pass them, and the fakes that stand in
//! for untested providers get their own scripted-contract checks.

use cratefield_signer::{
    FakeGuardrails, FakeSigner, GuardedSigner, Guardrails, KeyRef, MemorySignAudit, PolicyDecision,
    RefusingAudit, SignAudit, SignAuditRecord, SignContext, SignerError, StaticGuardrails, Subject,
    guardrails_conformance, sign_audit_conformance,
};

/// The allowlist configuration `guardrails_conformance` pins: the
/// contract is in the suite's doc comment.
fn reference_guardrails() -> StaticGuardrails {
    StaticGuardrails::new()
        .allow_evm(
            1,
            "0x000000000000000000000000000000000000aaaa",
            [0xa9, 0x05, 0x9c, 0xbb],
        )
        .expect("a valid address")
        .allow_eip712(1, "0x0000000071727De22E5E9d8BAf0edAc6f37da032")
        .expect("a valid address")
        .allow_program("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
        .expect("a valid program id")
        .max_value(1_000_000_000_000_000_000)
}

#[test]
fn the_reference_guardrails_pass_conformance() {
    pollster::block_on(guardrails_conformance(&reference_guardrails()));
}

#[test]
fn the_scripted_guardrails_answer_in_order_then_deny() {
    let fake = FakeGuardrails::new([
        Ok(PolicyDecision::Allow),
        Ok(PolicyDecision::Deny {
            reason: "not on the list".to_owned(),
        }),
        Err(SignerError::Provider("the policy store is down".to_owned())),
    ]);
    let decision = pollster::block_on(fake.check(&any_context())).expect("the script's allow");
    assert!(decision.is_allow());
    let decision = pollster::block_on(fake.check(&any_context())).expect("the script's deny");
    assert!(!decision.is_allow());
    let err = pollster::block_on(fake.check(&any_context()))
        .expect_err("the script's error propagates, so the caller fails closed");
    assert!(
        matches!(err, SignerError::Provider(_)),
        "a broken guardrail is an error, got: {err}"
    );
    let decision =
        pollster::block_on(fake.check(&any_context())).expect("a spent script still decides");
    assert!(
        !decision.is_allow(),
        "an exhausted script denies rather than lets a test pass by accident"
    );
}

#[test]
fn a_scripted_deny_reaches_the_guarded_signer() {
    let audit = MemorySignAudit::new();
    let signer = GuardedSigner::new(
        FakeSigner::new(),
        FakeGuardrails::new([Ok(PolicyDecision::Deny {
            reason: "not on the list".to_owned(),
        })]),
        &audit,
    );
    let subject = Subject::new("acme", None).expect("a venture");
    let key = pollster::block_on(async {
        signer
            .create_key(&subject, cratefield_signer::Scheme::Secp256k1, "session-1")
            .await
            .expect("a key")
    });
    let err = pollster::block_on(async {
        signer
            .sign(
                &subject,
                key.key_ref(),
                &cratefield_signer::Payload::Eip712(cratefield_signer::Eip712 {
                    name: None,
                    version: None,
                    chain_id: Some(1),
                    verifying_contract: Some(
                        "0x0000000071727De22E5E9d8BAf0edAc6f37da032".to_owned(),
                    ),
                    salt: None,
                    primary_type: "Mail".to_owned(),
                    struct_hash: [0_u8; 32],
                }),
            )
            .await
    })
    .expect_err("the scripted deny");
    assert!(
        matches!(err, SignerError::Denied { .. }),
        "the caller sees the deny, got: {err}"
    );
    // The deny is on the record, the provider was never reached.
    let records = audit.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].subject, subject);
    assert_eq!(records[0].key_ref, *key.key_ref());
    assert!(matches!(
        &records[0].decision,
        cratefield_signer::PolicyDecisionRecord::Deny { .. }
    ));
    assert_eq!(
        records[0].outcome,
        cratefield_signer::SignOutcome::NotAttempted
    );
}

#[test]
fn the_reference_audit_passes_conformance() {
    pollster::block_on(sign_audit_conformance(&MemorySignAudit::new()));
}

#[test]
fn the_refusing_audit_refuses_every_record() {
    let audit = RefusingAudit::new("the audit sink is down");
    let err = pollster::block_on(audit.record(&a_record())).expect_err("a refusing sink refuses");
    assert!(
        matches!(err, SignerError::Audit(_)),
        "a refusal is an audit error, got: {err}"
    );
}

/// Any context will do: the scripted fake does not read it.
fn any_context() -> SignContext {
    SignContext {
        subject: Subject::new("acme", None).expect("a venture"),
        key_ref: KeyRef::new("fake-secp256k1-1").expect("a reference"),
        payload_hash: [0_u8; 32],
        intent: cratefield_signer::Intent {
            chain: cratefield_signer::Chain::Evm { chain_id: 1 },
            to: None,
            selector: None,
            value: None,
            programs: Vec::new(),
            verifying_contract: None,
        },
    }
}

fn a_record() -> SignAuditRecord {
    SignAuditRecord {
        subject: Subject::new("acme", None).expect("a venture"),
        key_ref: KeyRef::new("fake-secp256k1-1").expect("a reference"),
        payload_hash: format!("0x{}", "ab".repeat(32)),
        intent: None,
        decision: cratefield_signer::PolicyDecisionRecord::Allow,
        outcome: cratefield_signer::SignOutcome::Signed,
        at: "t1".to_owned(),
    }
}
