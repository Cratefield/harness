//! The `GuardedSigner` behaviour: what can and cannot get through it.
//! Everything here runs on the deterministic [`FakeSigner`], with a
//! counting wrapper so "the provider was never called" is an
//! observation, not an inference.

use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;

use cratefield_signer::{
    EvmTransaction, FakeSigner, GuardedSigner, Guardrails, KeyInfo, KeyRef, MemorySignAudit,
    Payload, PolicyDecision, Scheme, SignAudit, SignAuditRecord, SignOutcome, Signature,
    SignerError, StaticGuardrails, Subject,
};

fn allowed_tx() -> Payload {
    Payload::EvmTransaction(EvmTransaction {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 2_000_000_000,
        gas_limit: 21_000,
        to: Some("0x000000000000000000000000000000000000aaaa".to_owned()),
        value: 1_000_000_000_000_000_000,
        data: vec![0xa9, 0x05, 0x9c, 0xbb],
    })
}

fn guardrails() -> StaticGuardrails {
    StaticGuardrails::new()
        .allow_evm(
            1,
            "0x000000000000000000000000000000000000aaaa",
            [0xa9, 0x05, 0x9c, 0xbb],
        )
        .expect("a valid address")
        .max_value(2_000_000_000_000_000_000)
}

/// Counts provider `sign` calls, delegating to a fake — so a test can
/// assert the provider was (or was not) reached.
struct Counting {
    inner: FakeSigner,
    calls: AtomicUsize,
}

#[async_trait]
impl cratefield_signer::KeySigner for Counting {
    async fn create_key(
        &self,
        subject: &Subject,
        scheme: Scheme,
        label: &str,
    ) -> Result<KeyInfo, SignerError> {
        self.inner.create_key(subject, scheme, label).await
    }

    async fn key(&self, key_ref: &KeyRef) -> Result<KeyInfo, SignerError> {
        self.inner.key(key_ref).await
    }

    async fn sign(&self, key_ref: &KeyRef, payload: &Payload) -> Result<Signature, SignerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.sign(key_ref, payload).await
    }
}

/// An audit sink that refuses everything — the fail-closed case.
struct Refusing;

#[async_trait]
impl SignAudit for Refusing {
    async fn record(&self, _record: &SignAuditRecord) -> Result<(), SignerError> {
        Err(SignerError::Audit("the sink is down".to_owned()))
    }
}

/// A guardrail that errors instead of deciding.
struct Broken;

#[async_trait]
impl Guardrails for Broken {
    async fn check(
        &self,
        _context: &cratefield_signer::SignContext,
    ) -> Result<PolicyDecision, SignerError> {
        Err(SignerError::Provider(
            "the policy store is unreachable".to_owned(),
        ))
    }
}

#[test]
fn an_allowed_payload_signs_and_is_recorded_twice() {
    let provider = Counting {
        inner: FakeSigner::new(),
        calls: AtomicUsize::new(0),
    };
    let audit = MemorySignAudit::new();
    let signer = GuardedSigner::new(&provider, guardrails(), &audit);
    let subject = Subject::new("acme", None).expect("a venture");
    let key = pollster::block_on(async {
        signer
            .create_key(&subject, Scheme::Secp256k1, "session-1")
            .await
            .expect("a key")
    });
    let signature = pollster::block_on(async {
        signer
            .sign(&subject, key.key_ref(), &allowed_tx())
            .await
            .expect("allowed")
    });
    assert!(matches!(signature, Signature::Secp256k1 { .. }));

    // Two records: the decision taken before the provider ran, then the
    // outcome.
    let records = audit.records();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records[0].decision,
        cratefield_signer::PolicyDecisionRecord::Allow
    );
    assert_eq!(records[0].outcome, SignOutcome::NotAttempted);
    assert_eq!(records[1].outcome, SignOutcome::Signed);
    // The record names what the issue says every signature carries.
    assert_eq!(records[0].subject, subject);
    assert_eq!(records[0].key_ref, *key.key_ref());
    let intent = records[0].intent.as_ref().expect("the intent decoded");
    assert_eq!(
        intent.to.as_deref(),
        Some("0x000000000000000000000000000000000000aaaa")
    );
    assert_eq!(intent.selector.as_deref(), Some("0xa9059cbb"));
    assert_ne!(records[0].payload_hash, format!("0x{}", "00".repeat(32)));
    // And the chain over them verifies.
    audit.verify().expect("the chain holds");
}

#[test]
fn a_deny_never_calls_the_provider() {
    let provider = Counting {
        inner: FakeSigner::new(),
        calls: AtomicUsize::new(0),
    };
    let audit = MemorySignAudit::new();
    // No rules at all: everything is denied.
    let signer = GuardedSigner::new(&provider, StaticGuardrails::new(), &audit);
    let subject = Subject::new("acme", None).expect("a venture");
    let key = pollster::block_on(async {
        signer
            .create_key(&subject, Scheme::Secp256k1, "session-1")
            .await
            .expect("a key")
    });
    let err =
        pollster::block_on(async { signer.sign(&subject, key.key_ref(), &allowed_tx()).await })
            .expect_err("denied");
    let SignerError::Denied { reason } = err else {
        panic!("a deny is `denied`, got: {err:?}");
    };
    assert!(
        reason.contains("no allowlist entry"),
        "the reason says why: {reason}"
    );
    assert_eq!(
        provider.calls.load(Ordering::SeqCst),
        0,
        "the provider never saw it"
    );
    let records = audit.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].outcome, SignOutcome::NotAttempted);
    assert!(matches!(
        records[0].decision,
        cratefield_signer::PolicyDecisionRecord::Deny { .. }
    ));
    audit.verify().expect("the chain holds");
}

#[test]
fn the_value_cap_denies_above_it() {
    let audit = MemorySignAudit::new();
    let signer = GuardedSigner::new(FakeSigner::new(), guardrails(), &audit);
    let subject = Subject::new("acme", None).expect("a venture");
    let key = pollster::block_on(async {
        signer
            .create_key(&subject, Scheme::Secp256k1, "session-1")
            .await
            .expect("a key")
    });
    let Payload::EvmTransaction(mut tx) = allowed_tx() else {
        unreachable!()
    };
    tx.value = 3_000_000_000_000_000_000; // above the 2 ETH cap
    let err = pollster::block_on(async {
        signer
            .sign(&subject, key.key_ref(), &Payload::EvmTransaction(tx))
            .await
    })
    .expect_err("over the cap");
    let SignerError::Denied { reason } = err else {
        panic!("over the cap is `denied`, got: {err:?}");
    };
    assert!(
        reason.contains("cap"),
        "the reason mentions the cap: {reason}"
    );
}

#[test]
fn the_kill_switch_denies_everything_including_olds_and_clones() {
    let audit = MemorySignAudit::new();
    let guardrails = guardrails();
    let signer = GuardedSigner::new(FakeSigner::new(), guardrails.clone(), &audit);
    guardrails.trip();
    assert!(guardrails.tripped());
    let subject = Subject::new("acme", None).expect("a venture");
    let key = pollster::block_on(async {
        signer
            .create_key(&subject, Scheme::Secp256k1, "session-1")
            .await
            .expect("a key")
    });
    // The signer holds a clone of the guardrails; the switch is shared.
    let err =
        pollster::block_on(async { signer.sign(&subject, key.key_ref(), &allowed_tx()).await })
            .expect_err("killed");
    let SignerError::Denied { reason } = err else {
        panic!("killed is `denied`, got: {err:?}");
    };
    assert!(reason.contains("kill switch"), "{reason}");
    guardrails.clear();
    pollster::block_on(async { signer.sign(&subject, key.key_ref(), &allowed_tx()).await })
        .expect("signs again after the switch clears");
}

#[test]
fn an_undecodable_payload_is_denied_on_the_record() {
    let provider = Counting {
        inner: FakeSigner::new(),
        calls: AtomicUsize::new(0),
    };
    let audit = MemorySignAudit::new();
    let signer = GuardedSigner::new(&provider, guardrails(), &audit);
    let subject = Subject::new("acme", None).expect("a venture");
    let key = pollster::block_on(async {
        signer
            .create_key(&subject, Scheme::Secp256k1, "session-1")
            .await
            .expect("a key")
    });
    let malformed = Payload::EvmTransaction(EvmTransaction {
        to: Some("0xnope".to_owned()),
        ..allowed_tx_payload()
    });
    let err = pollster::block_on(async { signer.sign(&subject, key.key_ref(), &malformed).await })
        .expect_err("malformed");
    assert!(matches!(err, SignerError::Payload(_)), "got: {err:?}");
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    let records = audit.records();
    assert_eq!(records.len(), 1);
    let cratefield_signer::PolicyDecisionRecord::Deny { reason } = &records[0].decision else {
        panic!("undecodable is denied on the record");
    };
    assert!(reason.contains("did not decode"), "{reason}");
    assert!(records[0].intent.is_none());
    assert_eq!(records[0].payload_hash, format!("0x{}", "00".repeat(32)));
    audit.verify().expect("the chain holds");
}

fn allowed_tx_payload() -> EvmTransaction {
    match allowed_tx() {
        Payload::EvmTransaction(tx) => tx,
        _ => unreachable!(),
    }
}

#[test]
fn a_refusing_audit_sink_fails_closed() {
    let provider = Counting {
        inner: FakeSigner::new(),
        calls: AtomicUsize::new(0),
    };
    let signer = GuardedSigner::new(&provider, guardrails(), Refusing);
    let subject = Subject::new("acme", None).expect("a venture");
    let key = pollster::block_on(async {
        signer
            .create_key(&subject, Scheme::Secp256k1, "session-1")
            .await
            .expect("a key")
    });
    let err =
        pollster::block_on(async { signer.sign(&subject, key.key_ref(), &allowed_tx()).await })
            .expect_err("the sink is down");
    assert!(
        matches!(err, SignerError::Audit(_)),
        "an audit refusal is an audit error, got: {err:?}"
    );
    assert_eq!(
        provider.calls.load(Ordering::SeqCst),
        0,
        "no record, no signature"
    );
}

#[test]
fn a_broken_guardrail_fails_closed() {
    let provider = Counting {
        inner: FakeSigner::new(),
        calls: AtomicUsize::new(0),
    };
    let audit = MemorySignAudit::new();
    let signer = GuardedSigner::new(&provider, Broken, &audit);
    let subject = Subject::new("acme", None).expect("a venture");
    let key = pollster::block_on(async {
        signer
            .create_key(&subject, Scheme::Secp256k1, "session-1")
            .await
            .expect("a key")
    });
    let err =
        pollster::block_on(async { signer.sign(&subject, key.key_ref(), &allowed_tx()).await })
            .expect_err("the guard cannot evaluate");
    assert!(
        matches!(err, SignerError::Provider(_)),
        "the guard's own error surfaces, got: {err:?}"
    );
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    let records = audit.records();
    assert_eq!(records.len(), 1);
    let cratefield_signer::PolicyDecisionRecord::Deny { reason } = &records[0].decision else {
        panic!("a broken guard is denied on the record");
    };
    assert!(reason.contains("guardrails failed"), "{reason}");
}

#[test]
fn a_provider_error_is_recorded_and_then_propagated() {
    // A key that does not exist makes the provider fail; the error is
    // on the record, the chain still verifies, and the caller sees the
    // provider's error rather than a success.
    let audit = MemorySignAudit::new();
    let signer = GuardedSigner::new(FakeSigner::new(), guardrails(), &audit);
    let subject = Subject::new("acme", None).expect("a venture");
    let unknown = KeyRef::new("fake-secp256k1-999").expect("a reference");
    let err = pollster::block_on(async { signer.sign(&subject, &unknown, &allowed_tx()).await })
        .expect_err("unknown key");
    assert!(
        matches!(err, SignerError::UnknownKey { .. }),
        "got: {err:?}"
    );
    let records = audit.records();
    assert_eq!(records.len(), 2, "decision, then the provider's failure");
    assert_eq!(
        records[1].outcome,
        SignOutcome::ProviderError {
            error: "unknown key `fake-secp256k1-999`".to_owned()
        }
    );
    audit.verify().expect("the chain still holds");
}

#[test]
fn the_fake_signer_passes_conformance() {
    pollster::block_on(async {
        cratefield_signer::key_signer_conformance(&cratefield_signer::FakeSigner::new()).await;
    });
}

#[test]
fn guardrail_rules_only_match_what_they_name() {
    // A rule for chain 1 does not match chain 137; a rule for one
    // recipient does not match another; an EIP-712 allowance does not
    // open transactions.
    let guardrails = guardrails()
        .allow_eip712(1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
        .expect("a valid address");
    let subject = Subject::new("acme", None).expect("a venture");
    let context = |intent| cratefield_signer::SignContext {
        subject: subject.clone(),
        key_ref: KeyRef::new("k").expect("a reference"),
        payload_hash: [0; 32],
        intent,
    };
    let decision_for = |payload: Payload| {
        pollster::block_on(async {
            guardrails
                .check(&context(payload.intent().expect("decodes")))
                .await
                .expect("decides")
        })
    };

    assert!(decision_for(allowed_tx()).is_allow());

    let mut other_chain = allowed_tx_payload();
    other_chain.chain_id = 137;
    assert!(!decision_for(Payload::EvmTransaction(other_chain)).is_allow());

    let mut other_recipient = allowed_tx_payload();
    other_recipient.to = Some("0x000000000000000000000000000000000000bbbb".to_owned());
    assert!(!decision_for(Payload::EvmTransaction(other_recipient)).is_allow());

    let eip712 = Payload::Eip712(cratefield_signer::Eip712 {
        name: Some("Ether Mail".into()),
        version: Some("1".into()),
        chain_id: Some(1),
        verifying_contract: Some("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC".into()),
        salt: None,
        primary_type: "Mail".into(),
        struct_hash: [0; 32],
    });
    assert!(decision_for(eip712.clone()).is_allow());
    let Payload::Eip712(mut other_domain) = eip712 else {
        unreachable!()
    };
    other_domain.verifying_contract = Some("0x0000000071727De22E5E9d8BAf0edAc6f37da032".into());
    assert!(
        !decision_for(Payload::Eip712(other_domain)).is_allow(),
        "a different verifying contract is not covered"
    );
}

#[test]
fn solana_allowlist_requires_every_program() {
    let guardrails = StaticGuardrails::new()
        .allow_program("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
        .expect("a valid program id");
    let intent = cratefield_signer::Intent {
        chain: cratefield_signer::Chain::Solana,
        to: None,
        selector: None,
        value: None,
        // The SPL Token program plus an unresolvable lookup-table
        // reference: never allowed through by the token entry.
        programs: vec![
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_owned(),
            "lt:9".to_owned(),
        ],
        verifying_contract: None,
    };
    let subject = Subject::new("acme", None).expect("a venture");
    let context = cratefield_signer::SignContext {
        subject,
        key_ref: KeyRef::new("k").expect("a reference"),
        payload_hash: [0; 32],
        intent,
    };
    let decision = pollster::block_on(async { guardrails.check(&context).await.expect("decides") });
    let PolicyDecision::Deny { reason } = decision else {
        panic!("an unresolvable program cannot be absorbed by the allowlist");
    };
    assert!(reason.contains("lt:9"), "{reason}");

    let resolved = cratefield_signer::Intent {
        programs: vec!["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_owned()],
        ..context.intent
    };
    let context = cratefield_signer::SignContext {
        intent: resolved,
        ..context
    };
    let decision = pollster::block_on(async { guardrails.check(&context).await.expect("decides") });
    assert!(decision.is_allow());
}
