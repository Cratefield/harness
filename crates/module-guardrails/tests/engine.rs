//! The engine end to end: gate order, the kill switch at every scope,
//! fail-closed on every port, the audit trail, the guarded signer, the
//! Turnkey deny-policy shape and the hygiene scan. The hard-deny shapes are
//! exercised through the engine because their integration property is the
//! point: a refused shape must never reach the simulator.

mod support;

use async_trait::async_trait;
use cratefield_module_guardrails::{
    Action, Allowance, Authorization7702, CallFrame, CallKind, Caps, Chain, DenyReason,
    FailingAudit, GuardedSigner, HardDeny, HygieneReason, KillSwitch, KillSwitchError,
    MemoryAllowances, NotAllowlisted, Policy, Prices, PricesError, RecordingSigner, Remedy,
    SEL_APPROVE, SEL_PERMIT_2612, SEL_PERMIT2_BATCH, SEL_SET_APPROVAL_FOR_ALL,
    SPL_TOKEN_2022_PROGRAM, SPL_TOKEN_PROGRAM, SYS_ADVANCE_NONCE, SYS_ASSIGN, SYS_ASSIGN_WITH_SEED,
    SYSTEM_PROGRAM, Scope, ScriptedSimulator, Severity, SimError, SimulationReport, SubjectPolicy,
    TOK_APPROVE, TOK_APPROVE_CHECKED, TOK_SET_AUTHORITY, U256, Verdict, WalletSigner,
    revoke_action, turnkey_deny_policy, u256_from_u128,
};
use std::sync::Arc;

use support::*;

// --- the gates in order -------------------------------------------------

#[test]
fn allows_the_canonical_approve() {
    let rig = rig();
    let approval = allow(&rig.engine, approve(1_000));
    assert_eq!(approval.request().subject, SUBJECT);
    // One audit entry, an allow, from the check stage.
    let entries = rig.audit.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].stage, "check");
    assert_eq!(entries[0].verdict, Verdict::Allow);
    assert_eq!(entries[0].venture, VENTURE);
    assert_eq!(entries[0].subject, SUBJECT);
    // An allow is not a warn.
    assert_eq!(entries[0].severity, Severity::Info);
}

#[test]
fn a_hard_deny_never_reaches_the_simulator() {
    let rig = rig();
    // setApprovalForAll is a hard deny whatever the allowlist says.
    let req = with_calldata(
        approve(1_000),
        calldata(
            SEL_SET_APPROVAL_FOR_ALL,
            &[addr_word(SPENDER), u256_from_u128(1)],
        ),
    );
    let denied = deny(&rig.engine, req);
    assert_eq!(
        denied.reasons,
        vec![DenyReason::HardDeny(HardDeny::ApprovalForAll)]
    );
    assert!(rig.sim.calls().is_empty());
    // And the decision was audited anyway: exactly one entry, critical.
    let entries = rig.audit.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].verdict, Verdict::Deny(denied.reasons.clone()));
    assert_eq!(entries[0].severity, Severity::Critical);
}

#[test]
fn an_unlimited_approve_is_a_hard_deny_a_bounded_one_is_not() {
    let rig = rig();
    let mut data = calldata(SEL_APPROVE, &[addr_word(SPENDER), u256_from_u128(0)]);
    data[36] = 1; // one bit into the high half: over the line
    let denied = deny(&rig.engine, with_calldata(approve(1_000), data));
    assert_eq!(
        denied.reasons,
        vec![DenyReason::HardDeny(HardDeny::UnlimitedApproval)]
    );
    // u128::MAX fills the low half exactly: below the line.
    allow(&rig.engine, approve(u128::MAX));
}

#[test]
fn an_unknown_chain_is_denied_without_touching_anything() {
    let rig = rig();
    let denied = deny(&rig.engine, with_chain(approve(1_000), 137));
    assert!(matches!(
        denied.reasons.as_slice(),
        [DenyReason::NotAllowlisted(NotAllowlisted::Chain)]
    ));
    assert!(rig.sim.calls().is_empty());
}

#[test]
fn an_unknown_contract_is_denied() {
    let rig = rig();
    let denied = deny(&rig.engine, with_to(approve(1_000), STRANGER));
    assert!(matches!(
        denied.reasons.as_slice(),
        [DenyReason::NotAllowlisted(NotAllowlisted::Contract(c))] if c == STRANGER
    ));
}

#[test]
fn an_unknown_selector_on_a_known_contract_is_denied() {
    let rig = rig();
    let mut data = calldata(SEL_APPROVE, &[addr_word(SPENDER), u256_from_u128(1_000)]);
    data[0..4].copy_from_slice(&0xDEAD_BEEF_u32.to_be_bytes());
    let denied = deny(&rig.engine, with_calldata(approve(1_000), data));
    assert!(matches!(
        denied.reasons.as_slice(),
        [DenyReason::NotAllowlisted(NotAllowlisted::Selector(s))] if s == "0xdeadbeef"
    ));
}

#[test]
fn a_transfer_to_a_stranger_is_denied() {
    let rig = rig();
    let denied = deny(&rig.engine, token_transfer(STRANGER, 5));
    assert!(
        matches!(
            denied.reasons.as_slice(),
            [DenyReason::NotAllowlisted(NotAllowlisted::Destination(d))]
                if d == STRANGER
        ),
        "reasons: {denied}"
    );
}

#[test]
fn contract_creation_is_denied() {
    let rig = rig();
    let denied = deny(&rig.engine, evm_tx(1, None, 0, vec![0x60, 0x80]));
    assert!(matches!(
        denied.reasons.as_slice(),
        [DenyReason::NotAllowlisted(NotAllowlisted::Contract(c))] if c == "<contract creation>"
    ));
}

#[test]
fn a_checksummed_address_is_the_same_contract() {
    let rig = rig();
    allow(
        &rig.engine,
        with_to(approve(1_000), "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    );
}

// --- permits -------------------------------------------------------------

/// A full EIP-2612 `permit(owner, spender, value, deadline, v, r, s)`.
fn permit_2612(spender: &str, amount: U256) -> Request {
    let zero = [0_u8; 32];
    with_calldata(
        evm_tx(1, Some(ROUTER), 0, Vec::new()),
        calldata(
            SEL_PERMIT_2612,
            &[zero, addr_word(spender), amount, zero, zero, zero, zero],
        ),
    )
}

#[test]
fn a_permit_to_an_unknown_spender_is_a_hard_deny() {
    let rig = rig();
    let denied = deny(&rig.engine, permit_2612(STRANGER, u256_from_u128(5)));
    assert!(matches!(
        denied.reasons.as_slice(),
        [DenyReason::HardDeny(HardDeny::PermitUnknownSpender(_))]
    ));
    assert!(rig.sim.calls().is_empty());
}

#[test]
fn a_permit_with_an_unbounded_amount_is_a_hard_deny_a_bounded_one_is_not() {
    let rig = rig();
    let denied = deny(&rig.engine, permit_2612(SPENDER, unlimited_word()));
    assert_eq!(
        denied.reasons,
        vec![DenyReason::HardDeny(HardDeny::PermitUnlimited)]
    );
    allow(&rig.engine, permit_2612(SPENDER, u256_from_u128(5)));
}

#[test]
fn a_truncated_permit_fails_closed() {
    let rig = rig();
    let zero = [0_u8; 32];
    let full = calldata(
        SEL_PERMIT_2612,
        &[
            zero,
            addr_word(SPENDER),
            u256_from_u128(5),
            zero,
            zero,
            zero,
            zero,
        ],
    );
    // The spender word cut in half: no spender can be read, so nothing
    // downstream can bound the signature's reach.
    let mut cut = full.clone();
    cut.truncate(50);
    let denied = deny(&rig.engine, with_calldata(approve(1_000), cut));
    assert!(matches!(
        denied.reasons.as_slice(),
        [DenyReason::HardDeny(HardDeny::PermitUnknownSpender(_))]
    ));
    // The spender readable but the amount word cut: unboundable.
    let mut cut = full;
    cut.truncate(90);
    let denied = deny(&rig.engine, with_calldata(approve(1_000), cut));
    assert_eq!(
        denied.reasons,
        vec![DenyReason::HardDeny(HardDeny::PermitUnlimited)]
    );
    assert!(rig.sim.calls().is_empty());
}

#[test]
fn a_truncated_permit2_batch_fails_closed() {
    let rig = rig();
    // owner, offset, then half a spender word.
    let mut cut = calldata(
        SEL_PERMIT2_BATCH,
        &[u256_from_u128(0), u256_from_u128(0x180)],
    );
    cut.truncate(80);
    let denied = deny(&rig.engine, with_calldata(approve(1_000), cut));
    // Refused on the calldata alone, whatever the truncation hides: the
    // amounts live in a dynamic array no static check can bound.
    assert!(matches!(
        denied.reasons.as_slice(),
        [DenyReason::HardDeny(_)]
    ));
    assert!(rig.sim.calls().is_empty());
}

#[test]
fn typed_data_permits_fail_closed() {
    let rig = rig();
    let typed = |spender: Option<String>, amount: Option<U256>| {
        request(Action::EvmTypedData {
            chain_id: 1,
            primary_type: "PermitSingle".to_owned(),
            verifying_contract: ROUTER.to_owned(),
            spender,
            amount,
        })
    };
    allow(
        &rig.engine,
        typed(Some(SPENDER.to_owned()), Some(u256_from_u128(7))),
    );
    assert!(matches!(
        deny(
            &rig.engine,
            typed(Some(STRANGER.to_owned()), Some(u256_from_u128(7)))
        )
        .reasons
        .as_slice(),
        [DenyReason::HardDeny(HardDeny::PermitUnknownSpender(_))]
    ));
    // An amount the request does not carry is not statically known — the
    // same answer as unlimited.
    assert_eq!(
        deny(&rig.engine, typed(Some(SPENDER.to_owned()), None)).reasons,
        vec![DenyReason::HardDeny(HardDeny::PermitUnlimited)]
    );
    assert_eq!(
        deny(
            &rig.engine,
            typed(Some(SPENDER.to_owned()), Some(unlimited_word()))
        )
        .reasons,
        vec![DenyReason::HardDeny(HardDeny::PermitUnlimited)]
    );
    // A non-permit primary type is none of the above.
    let order = request(Action::EvmTypedData {
        chain_id: 1,
        primary_type: "Order".to_owned(),
        verifying_contract: ROUTER.to_owned(),
        spender: Some(STRANGER.to_owned()),
        amount: None,
    });
    allow(&rig.engine, order);
}

// --- more hard-deny shapes -------------------------------------------------

#[test]
fn an_eip7702_authorization_for_chain_zero_is_a_hard_deny() {
    let rig = rig();
    let req = request(Action::EvmTx {
        chain_id: 1,
        to: None,
        value: u256_from_u128(0),
        data: Vec::new(),
        authorizations: vec![Authorization7702 {
            chain_id: 0,
            address: STRANGER.to_owned(),
        }],
    });
    assert_eq!(
        deny(&rig.engine, req).reasons,
        vec![DenyReason::HardDeny(HardDeny::Eip7702ZeroChain)]
    );
}

#[test]
fn solana_owner_reassignment_and_nonce_use_are_hard_denies() {
    let rig = rig();
    let le = u32::to_le_bytes;
    for (data, reason) in [
        (le(SYS_ASSIGN).to_vec(), HardDeny::OwnerReassignment),
        (
            le(SYS_ASSIGN_WITH_SEED).to_vec(),
            HardDeny::OwnerReassignment,
        ),
        (le(SYS_ADVANCE_NONCE).to_vec(), HardDeny::NonceAdvance),
    ] {
        let denied = deny(&rig.engine, solana_tx(SYSTEM_PROGRAM, data));
        assert_eq!(denied.reasons, vec![DenyReason::HardDeny(reason)]);
    }
    let denied = deny(
        &rig.engine,
        solana_tx(SPL_TOKEN_PROGRAM, vec![TOK_SET_AUTHORITY, 0]),
    );
    assert_eq!(
        denied.reasons,
        vec![DenyReason::HardDeny(HardDeny::OwnerReassignment)]
    );
    // A plain System Transfer is none of these: the deny it eventually gets
    // is the allowlist's, not a hard deny.
    assert!(matches!(
        deny(&rig.engine, solana_tx(SYSTEM_PROGRAM, le(2).to_vec()))
            .reasons
            .as_slice(),
        [DenyReason::NotAllowlisted(_)]
    ));
}

#[test]
fn a_solana_max_approve_is_a_hard_deny_a_bounded_one_is_not() {
    let rig = rig();
    let mut max = vec![TOK_APPROVE];
    max.extend_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(
        deny(&rig.engine, solana_tx(SPL_TOKEN_PROGRAM, max)).reasons,
        vec![DenyReason::HardDeny(HardDeny::UnlimitedApproval)]
    );
    let mut checked = vec![TOK_APPROVE_CHECKED];
    checked.extend_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(
        deny(&rig.engine, solana_tx(SPL_TOKEN_2022_PROGRAM, checked)).reasons,
        vec![DenyReason::HardDeny(HardDeny::UnlimitedApproval)]
    );
    let mut bounded = vec![TOK_APPROVE];
    bounded.extend_from_slice(&1_000_u64.to_le_bytes());
    assert!(matches!(
        deny(&rig.engine, solana_tx(SPL_TOKEN_PROGRAM, bounded))
            .reasons
            .as_slice(),
        [DenyReason::NotAllowlisted(_)]
    ));
}

// --- simulation is required ---------------------------------------------

#[test]
fn a_reverting_simulation_denies() {
    let mut rig = rig();
    rig.sim = rig.sim.respond(SimulationReport::reverted());
    let denied = deny(&rig.engine, approve(1_000));
    assert_eq!(denied.reasons, vec![DenyReason::SimulationReverted]);
    assert_eq!(rig.audit.entries()[0].severity, Severity::Critical);
}

#[test]
fn an_unreachable_simulator_denies() {
    let mut rig = rig();
    rig.sim = rig.sim.fail(SimError::Unavailable("fork down".to_owned()));
    let denied = deny(&rig.engine, approve(1_000));
    assert_eq!(denied.reasons, vec![DenyReason::SimulationFailed]);
}

#[test]
fn an_unscripted_simulator_denies_too() {
    // `ScriptedSimulator::new()` has no script: fail closed, not crash.
    let rig = rig_with(policy(), ScriptedSimulator::new(), FixedPrices::new());
    let denied = deny(&rig.engine, approve(1_000));
    assert_eq!(denied.reasons, vec![DenyReason::SimulationFailed]);
}

#[test]
fn report_denies_collect_in_report_order() {
    let mut rig = rig();
    let mut over_line = u256_from_u128(0);
    over_line[0] = 1; // over the unlimited line
    rig.sim = rig.sim.respond(report(
        vec![balance_change(STRANGER, TOKEN, 5)],
        vec![approval_change(FROM, TOKEN, STRANGER, over_line)],
        vec![CallFrame {
            kind: CallKind::DelegateCall,
            to: STRANGER.to_owned(),
        }],
    ));
    let denied = deny(&rig.engine, approve(1_000));
    // Four reasons: the unlimited line, the stranger spender, the stranger
    // credit, the delegatecall — in that order.
    assert_eq!(denied.reasons.len(), 4);
    assert!(
        denied
            .reasons
            .contains(&DenyReason::HardDeny(HardDeny::UnlimitedApproval))
    );
    assert!(
        denied
            .reasons
            .contains(&DenyReason::NotAllowlisted(NotAllowlisted::Spender(
                STRANGER.to_owned()
            )))
    );
    assert!(
        denied
            .reasons
            .contains(&DenyReason::NotAllowlisted(NotAllowlisted::Destination(
                STRANGER.to_owned()
            )))
    );
    assert!(
        denied
            .reasons
            .contains(&DenyReason::HardDeny(HardDeny::DelegateCall(
                STRANGER.to_owned()
            )))
    );
}

#[test]
fn a_zero_approval_in_the_report_is_a_revoke_not_a_grant() {
    // approve(spender, 0) revokes; it may name a spender the policy no
    // longer allows — the hygiene scan's auto-revoke depends on it.
    let mut rig = rig();
    rig.sim = rig.sim.respond(report(
        Vec::new(),
        vec![approval_change(FROM, TOKEN, STRANGER, [0_u8; 32])],
        Vec::new(),
    ));
    allow(&rig.engine, approve(1_000));
}

#[test]
fn an_approval_just_below_the_line_is_bounded() {
    let mut rig = rig();
    // The largest power of two below the line: byte 16 is the top bit of
    // the low half, and the high half is zero.
    let mut below_line = [0_u8; 32];
    below_line[16] = 1;
    rig.sim = rig.sim.respond(report(
        Vec::new(),
        vec![approval_change(FROM, TOKEN, SPENDER, below_line)],
        Vec::new(),
    ));
    allow(&rig.engine, approve(1_000));
}

// --- the kill switch ------------------------------------------------------

#[test]
fn a_global_kill_switch_blocks_everything() {
    let rig = rig();
    pollster::block_on(rig.kill.engage(Scope::Global, "incident")).expect("engage");
    let denied = deny(&rig.engine, approve(1_000));
    assert!(matches!(
        denied.reasons.as_slice(),
        [DenyReason::KillSwitch(Scope::Global)]
    ));
    assert!(!pollster::block_on(
        rig.engine.job_allowed(VENTURE, SUBJECT)
    ));
}

#[test]
fn a_venture_kill_switch_blocks_only_that_venture() {
    let rig = rig();
    pollster::block_on(
        rig.kill
            .engage(Scope::Venture(VENTURE.to_owned()), "incident"),
    )
    .expect("engage");
    // This venture's jobs are stopped at scheduling time...
    assert!(!pollster::block_on(
        rig.engine.job_allowed(VENTURE, SUBJECT)
    ));
    // ...another venture's are not...
    assert!(pollster::block_on(rig.engine.job_allowed("other", SUBJECT)));
    // ...and this venture's checks name the scope that refused.
    let denied = deny(&rig.engine, approve(1_000));
    assert!(matches!(
        denied.reasons.as_slice(),
        [DenyReason::KillSwitch(Scope::Venture(v))] if v == VENTURE
    ));
}

#[test]
fn a_subject_kill_switch_blocks_only_that_subject() {
    let rig = rig();
    pollster::block_on(
        rig.kill
            .engage(Scope::Subject(SUBJECT.to_owned()), "compromised key"),
    )
    .expect("engage");
    assert!(!pollster::block_on(
        rig.engine.job_allowed(VENTURE, SUBJECT)
    ));
    assert!(pollster::block_on(rig.engine.job_allowed(VENTURE, "job-8")));

    let mut other = approve(1_000);
    other.subject = "job-8".to_owned();
    // job-8 has no caps: a different deny, but it got past the switch.
    let denied = deny(&rig.engine, other);
    assert_eq!(denied.reasons, vec![DenyReason::NoCaps]);
}

#[test]
fn a_killed_subject_is_denied_before_the_simulator_runs() {
    let rig = rig();
    pollster::block_on(
        rig.kill
            .engage(Scope::Subject(SUBJECT.to_owned()), "compromised key"),
    )
    .expect("engage");
    deny(&rig.engine, approve(1_000));
    assert!(rig.sim.calls().is_empty());
}

// --- fail closed ----------------------------------------------------------

struct DeadSwitch;

#[async_trait]
impl KillSwitch for DeadSwitch {
    async fn engaged(&self, _scope: &Scope) -> Result<bool, KillSwitchError> {
        Err(KillSwitchError("down".to_owned()))
    }
    async fn engage(&self, _scope: Scope, _reason: &str) -> Result<(), KillSwitchError> {
        Err(KillSwitchError("down".to_owned()))
    }
    async fn release(&self, _scope: &Scope) -> Result<(), KillSwitchError> {
        Err(KillSwitchError("down".to_owned()))
    }
}

struct DeadPrices;

#[async_trait]
impl Prices for DeadPrices {
    async fn micro_usd(
        &self,
        _chain: &Chain,
        _token: &str,
        _raw_amount: u128,
    ) -> Result<Option<u128>, PricesError> {
        Err(PricesError("down".to_owned()))
    }
}

#[test]
fn a_failing_audit_sink_denies() {
    // No allow may leave the building unaudited.
    let engine = builder_with(policy())
        .audit(FailingAudit)
        .build()
        .expect("ports wired");
    assert!(matches!(
        deny(&engine, approve(1_000)).reasons.as_slice(),
        [DenyReason::Port("audit")]
    ));
}

#[test]
fn a_failing_kill_switch_port_denies() {
    let engine = builder_with(policy())
        .kill_switch(DeadSwitch)
        .build()
        .expect("ports wired");
    assert!(
        deny(&engine, approve(1_000))
            .reasons
            .contains(&DenyReason::Port("kill switch"))
    );
}

#[test]
fn a_failing_price_port_denies_the_spend() {
    let engine = builder_with(policy())
        .simulator(ScriptedSimulator::new().respond(spend_report(TOKEN, -1_000)))
        .prices(DeadPrices)
        .build()
        .expect("ports wired");
    assert!(
        deny(&engine, approve(1_000))
            .reasons
            .contains(&DenyReason::Port("prices"))
    );
}

// --- the audit trail ------------------------------------------------------

#[test]
fn every_check_leaves_exactly_one_audit_entry() {
    let mut rig = rig();
    allow(&rig.engine, approve(1_000));
    deny(&rig.engine, token_transfer(STRANGER, 1));
    // A real outflow, but the token has no price: denied, not waved through.
    rig.sim = rig.sim.respond(spend_report(TOKEN, -1_000));
    deny(&rig.engine, native_transfer(1_000));
    let entries = rig.audit.entries();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].verdict, Verdict::Allow);
    assert_eq!(entries[0].severity, Severity::Info);
    assert!(matches!(entries[1].verdict, Verdict::Deny(_)));
    assert_eq!(entries[1].severity, Severity::Warn);
    assert!(matches!(entries[2].verdict, Verdict::Deny(_)));
}

// --- the guarded signer -----------------------------------------------------

#[test]
fn the_guarded_signer_signs_an_approval() {
    let rig = rig();
    let engine = Arc::new(rig.engine);
    let signer = Arc::new(RecordingSigner::default().signing(vec![1, 2, 3]));
    let guarded = GuardedSigner::new(Arc::clone(&engine), signer.clone());
    let approval = allow(&engine, approve(1_000));
    let signature = pollster::block_on(guarded.sign(approval)).expect("signs");
    assert_eq!(signature, vec![1, 2, 3]);
    assert_eq!(signer.signed().len(), 1);
    // The sign decision was audited too.
    let entries = rig.audit.entries();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].stage, "sign");
    assert_eq!(entries[1].verdict, Verdict::Allow);
}

#[test]
fn the_guarded_signer_stops_when_the_switch_engages_after_check() {
    let rig = rig();
    let engine = Arc::new(rig.engine);
    let signer = Arc::new(RecordingSigner::default().signing(vec![1]));
    let guarded = GuardedSigner::new(Arc::clone(&engine), signer.clone());
    let approval = allow(&engine, approve(1_000));
    pollster::block_on(
        rig.kill
            .engage(Scope::Subject(SUBJECT.to_owned()), "compromised key"),
    )
    .expect("engage");
    let denied = pollster::block_on(guarded.sign(approval)).expect_err("stopped");
    assert!(matches!(
        denied.reasons.as_slice(),
        [DenyReason::KillSwitch(Scope::Subject(_))]
    ));
    // Nothing reached the provider.
    assert!(signer.signed().is_empty());
}

#[test]
fn a_failing_provider_is_a_port_deny() {
    let rig = rig();
    let engine = Arc::new(rig.engine);
    let signer: Arc<dyn WalletSigner> = Arc::new(RecordingSigner::default().failing("kms 503"));
    let guarded = GuardedSigner::new(Arc::clone(&engine), signer);
    let approval = allow(&engine, approve(1_000));
    let denied = pollster::block_on(guarded.sign(approval)).expect_err("deny");
    assert!(denied.reasons.contains(&DenyReason::Port("signer")));
}

// --- the Turnkey deny policy --------------------------------------------------

#[test]
fn the_turnkey_policy_shape_matches_each_scope() {
    assert_eq!(
        turnkey_deny_policy(&Scope::Global),
        Some(serde_json::json!({ "effect": "EFFECT_DENY", "condition": "true" }))
    );
    assert_eq!(
        turnkey_deny_policy(&Scope::Venture("acme".to_owned())),
        Some(serde_json::json!({
            "effect": "EFFECT_DENY",
            "condition": r#"TRACING_TAGS.venture == "acme""#
        }))
    );
    assert_eq!(
        turnkey_deny_policy(&Scope::Subject("job-7".to_owned())),
        Some(serde_json::json!({
            "effect": "EFFECT_DENY",
            "condition": r#"TRACING_TAGS.subject == "job-7""#
        }))
    );
}

#[test]
fn the_turnkey_policy_refuses_an_id_that_could_inject() {
    // The id lands inside a quoted condition string; anything that could
    // close it rewrites the policy, so it is refused instead of escaped.
    assert_eq!(
        turnkey_deny_policy(&Scope::Venture(r#"acme" OR "x" == "x"#.to_owned())),
        None
    );
    assert_eq!(
        turnkey_deny_policy(&Scope::Subject("job 7".to_owned())),
        None
    );
    assert_eq!(turnkey_deny_policy(&Scope::Subject(String::new())), None);
    // The separators ids legitimately carry are fine.
    assert!(
        turnkey_deny_policy(&Scope::Subject("job-7:prod_v1.2".to_owned())).is_some(),
        "plain ids with . _ : - are accepted"
    );
}

// --- the hygiene scan -----------------------------------------------------------

#[test]
fn the_scan_reports_what_todays_policy_would_not_issue() {
    let allowances = MemoryAllowances::new().with(vec![
        Allowance {
            token: TOKEN.to_owned(),
            spender: SPENDER.to_owned(),
            amount: u256_from_u128(1_000),
        },
        Allowance {
            token: TOKEN.to_owned(),
            spender: STRANGER.to_owned(),
            amount: u256_from_u128(1_000),
        },
        Allowance {
            token: TOKEN.to_owned(),
            spender: SPENDER.to_owned(),
            amount: unlimited_word(),
        },
    ]);
    let rig = rig_with_allowances(policy(), ScriptedSimulator::new().clean(), allowances);
    let findings = scan(&rig);
    // The bounded, allowlisted allowance is fine; the other two are not.
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].reason, HygieneReason::SpenderNotAllowlisted);
    assert_eq!(findings[1].reason, HygieneReason::Unlimited);
    for finding in &findings {
        let Remedy::Suggest(action) = &finding.remedy else {
            panic!("expected a suggestion");
        };
        // The remedy revokes exactly this allowance: approve(spender, 0).
        assert_eq!(
            *action,
            revoke_action(1, &finding.allowance).expect("fixture spenders are hex"),
            "remedy matches the finding"
        );
    }
}

/// The policy the auto-revoke tests run: one contract, one spender, and a
/// subject with `auto_revoke` and caps.
fn policy_with_auto_revoke() -> Policy {
    Policy::new()
        .chain(Chain::Evm { chain_id: 1 })
        .contract(ROUTER, &[SEL_APPROVE])
        .spender(SPENDER)
        .subject(
            SUBJECT,
            SubjectPolicy::new()
                .caps(Caps::uniform(
                    &token_key(),
                    10_000_000,
                    50_000_000,
                    50_000_000,
                    time::Duration::hours(24),
                    200,
                ))
                .auto_revoke(true),
        )
}

#[test]
fn auto_revoke_sends_the_revoke_through_the_engine() {
    let allowances = MemoryAllowances::new().with(vec![Allowance {
        token: ROUTER.to_owned(),
        spender: STRANGER.to_owned(), // not on the spender allowlist
        amount: unlimited_word(),
    }]);
    // The revoke's own simulation reports approve(STRANGER, 0). A zero
    // amount is a revoke, not a grant: it must not deny as a
    // non-allowlisted spender, or an honest simulator could never allow a
    // revoke.
    let sim = ScriptedSimulator::new().respond(report(
        Vec::new(),
        vec![approval_change(FROM, ROUTER, STRANGER, [0_u8; 32])],
        Vec::new(),
    ));
    let rig = rig_with_allowances(policy_with_auto_revoke(), sim, allowances);
    let findings = scan(&rig);
    assert_eq!(findings.len(), 1);
    assert!(matches!(findings[0].remedy, Remedy::Revoked(_)));
    // The revoke itself went through the full gauntlet: the simulator saw it.
    assert_eq!(rig.sim.calls().len(), 1);
    // And its allow was audited.
    assert!(
        rig.audit
            .entries()
            .iter()
            .any(|e| e.stage == "check" && e.verdict == Verdict::Allow)
    );
}

#[test]
fn auto_revoke_reports_suggest_when_the_engine_refuses() {
    let allowances = MemoryAllowances::new().with(vec![Allowance {
        token: ROUTER.to_owned(),
        spender: SPENDER.to_owned(),
        amount: unlimited_word(),
    }]);
    // The simulator is down: the revoke is denied like anything else.
    let sim = ScriptedSimulator::new().fail(SimError::Unavailable("down".to_owned()));
    let rig = rig_with_allowances(policy_with_auto_revoke(), sim, allowances);
    let findings = scan(&rig);
    assert_eq!(findings.len(), 1);
    assert!(matches!(findings[0].remedy, Remedy::Suggest(_)));
}

#[test]
fn a_malformed_spender_is_reported_but_never_revoked() {
    // "0x1234" is not an address: the revoke calldata cannot name it, so
    // the finding is reported unremediable rather than "revoked" to a
    // zero-address approve that would change nothing.
    let allowances = MemoryAllowances::new().with(vec![Allowance {
        token: ROUTER.to_owned(),
        spender: "0x1234".to_owned(),
        amount: u256_from_u128(1_000),
    }]);
    let rig = rig_with_allowances(
        policy_with_auto_revoke(),
        ScriptedSimulator::new().clean(),
        allowances,
    );
    let findings = scan(&rig);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].reason, HygieneReason::SpenderNotAllowlisted);
    assert_eq!(findings[0].remedy, Remedy::Unremediable);
    // Nothing was simulated, so nothing was sent.
    assert!(rig.sim.calls().is_empty());
}

#[test]
fn the_scan_is_silent_for_solana_wallets() {
    let rig = rig();
    let findings = pollster::block_on(rig.engine.scan_allowances(
        VENTURE,
        SUBJECT,
        &Chain::Solana {
            cluster: "mainnet-beta".to_owned(),
        },
        FROM,
    ));
    assert!(findings.is_empty());
    assert!(rig.audit.is_empty());
}
