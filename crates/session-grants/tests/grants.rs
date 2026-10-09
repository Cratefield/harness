//! The issue #762 behaviours, end to end over the fakes: the pre-signing
//! summary, the `chain_id = 0` refusal, the grant flow with the
//! serialized permission account, the caps and the rate limit, the
//! two-layer revocation, expiry, and the Swig and Squads limits.

use cratefield_session_grants::{
    Address, Bundler, BundlerClient, Decision, DenyReason, Enforcer, FakeRpc, GrantRecord,
    GrantStatus, GrantStore, IntendedAction, KernelPermissions, MutableClock, Selector,
    SquadsLimits, SwigSessions, Usage, UserOperation, WINDOW_START, destination, evm_spec,
    evm_target, passkey_signature, squads_spec, swig_session_key, swig_spec, token_program,
    transfer_selector, usdc_mint,
};
use std::sync::Arc;

/// Moves `value` (wei) in a `transfer` call to the spec's target.
fn evm_call(value: u128) -> IntendedAction {
    IntendedAction::EvmCall {
        chain_id: 8453,
        target: evm_target(),
        selector: transfer_selector(),
        args: Vec::new(),
        value,
        token: None,
    }
}

/// Moves `lamports` from the Swig wallet to `to` via the token program.
fn swig_transfer(lamports: u128, to: &cratefield_session_grants::Pubkey) -> IntendedAction {
    IntendedAction::SolanaTransfer {
        cluster: cratefield_session_grants::Cluster::Mainnet,
        program: token_program(),
        lamports,
        destination: to.clone(),
        token: None,
    }
}

/// Moves `amount` of USDC from the vault to `to`.
fn squads_transfer(amount: u128, to: &cratefield_session_grants::Pubkey) -> IntendedAction {
    IntendedAction::SolanaTransfer {
        cluster: cratefield_session_grants::Cluster::Mainnet,
        program: token_program(),
        lamports: 0,
        destination: to.clone(),
        token: Some((usdc_mint(), amount)),
    }
}

#[test]
fn the_summary_names_contracts_caps_and_expiry_before_the_owner_signs() {
    let summary = cratefield_session_grants::summarize(&evm_spec("grant-1", WINDOW_START));

    assert_eq!(summary.grant_id, "grant-1");
    assert_eq!(summary.chain, "EVM · chain 8453");
    assert_eq!(summary.entries.len(), 1, "one contract named");
    let entry = &summary.entries[0];
    assert_eq!(entry.kind, "contract");
    assert_eq!(entry.name, evm_target().to_string());
    assert!(
        entry
            .actions
            .iter()
            .any(|action| action.contains(&transfer_selector().to_string()))
    );
    assert!(
        summary
            .caps
            .iter()
            .any(|cap| cap.contains("1 ETH in total")),
        "the recurring value cap is in the summary: {:?}",
        summary.caps
    );
    assert!(
        summary
            .rate_limit
            .as_deref()
            .is_some_and(|rate| rate.contains("10 calls"))
    );
    assert!(
        summary.valid_until.contains("2026"),
        "the expiry is rendered"
    );

    // And the text the confirm prompt shows carries the same facts.
    let text = summary.render();
    assert!(text.contains("signed by: your passkey cred-762"));
    assert!(text.contains("never leaves your authenticator"));

    // A grant with no value caps at all says so plainly.
    let mut bare = evm_spec("grant-bare", WINDOW_START);
    if let cratefield_session_grants::GrantScope::EvmKernel(ref mut grant) = bare.scope {
        grant.value_limit = None;
        grant.calls[0].value_cap = None;
    }
    let bare_text = cratefield_session_grants::summarize(&bare).render();
    assert!(
        bare_text.contains("no value may be sent"),
        "a call policy with no cap says so: {bare_text}"
    );

    // The summary is serde, so it travels to the UI as JSON.
    let json = serde_json::to_value(&summary).expect("serializes");
    assert!(json["entries"][0]["name"].is_string());
    assert!(json["valid_until"].as_str().is_some());
}

#[test]
fn chain_id_zero_is_refused_by_the_constructor_the_wire_and_the_spec() {
    use cratefield_session_grants::{AuthorizationError, Eip7702Authorization};

    let delegate = Address::parse("0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789").expect("parses");
    // The constructor.
    assert_eq!(
        Eip7702Authorization::new(0, delegate.clone(), 1).expect_err("chain 0 is refused"),
        AuthorizationError::ChainIdZero
    );
    // The wire format: an authorization that arrives with chain 0 never
    // deserializes into the type.
    let error = serde_json::from_str::<Eip7702Authorization>(
        r#"{"chain_id":0,"delegate":"0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789","nonce":1}"#,
    )
    .expect_err("chain 0 does not deserialize");
    assert!(error.to_string().contains("chain_id = 0"));

    // And a spec mutated to chain 0 fails validation, like any grant
    // that would outlive the chain its limits were signed under.
    let mut spec = evm_spec("grant-zero", WINDOW_START);
    if let cratefield_session_grants::GrantScope::EvmKernel(grant) = &mut spec.scope {
        grant.chain_id = 0;
    }
    assert!(matches!(
        spec.validate(),
        Err(cratefield_session_grants::SpecError::ChainIdZero)
    ));
}

#[pollster::test]
async fn a_grant_installs_keeps_its_serialized_permission_account_and_authorizes() {
    let store = cratefield_session_grants::MemoryGrantStore::new();
    let clock = Arc::new(MutableClock::new(WINDOW_START));
    let kernel = cratefield_session_grants::FakeKernelPermissions::new();
    let spec = evm_spec("grant-flow", WINDOW_START);

    // The owner signs once; the install returns the serialized permission
    // account to keep.
    let binding = kernel
        .grant(&spec, &passkey_signature())
        .await
        .expect("the owner's signature installs the permission");
    let cratefield_session_grants::OnChainBinding::KernelPermission {
        permission_id,
        serialized,
    } = &binding
    else {
        panic!("a Kernel grant returns a KernelPermission binding");
    };
    assert!(!permission_id.is_empty());
    assert!(
        serialized.starts_with("0x"),
        "serializePermissionAccount output"
    );

    // The record keeps the on-chain id and the status.
    let mut record = GrantRecord::pending(spec.clone(), clock.now());
    record.attach(binding).expect("attaches");
    store.save(record).await.expect("saves");

    // The server acts inside the caps.
    let enforcer = Enforcer::new(&store, clock.as_ref());
    let decision = enforcer
        .authorize("grant-flow", &evm_call(0))
        .await
        .expect("checks");
    assert_eq!(decision, Decision::Allow);

    // The usage ledger recorded the call, so the caps and the rate
    // limit see it.
    let usage = store
        .usage_since("grant-flow", WINDOW_START)
        .await
        .expect("folds");
    assert_eq!(usage.calls, 1);
    assert_eq!(
        store.list("user-762").await.expect("lists").len(),
        1,
        "the grant is listed under its owner"
    );
}

#[pollster::test]
async fn out_of_limit_actions_are_refused_before_any_port_call() {
    let store = cratefield_session_grants::MemoryGrantStore::new();
    let clock = Arc::new(MutableClock::new(WINDOW_START));
    let mut spec = evm_spec("grant-limits", WINDOW_START);
    spec.rate_limit = None; // the caps are under test, not the rate limit
    store
        .save(GrantRecord::pending(spec.clone(), clock.now()))
        .await
        .expect("saves");

    let enforcer = Enforcer::new(&store, clock.as_ref());

    // No call policy names this contract.
    let stranger = IntendedAction::EvmCall {
        chain_id: 8453,
        target: Address::parse("0x9999999999999999999999999999999999999999").expect("a literal"),
        selector: Selector::parse("0xa9059cbb").expect("a selector"),
        args: Vec::new(),
        value: 0,
        token: None,
    };
    assert_eq!(
        enforcer
            .check("grant-limits", &stranger)
            .await
            .expect("checks"),
        Decision::Deny(DenyReason::CallNotAllowed {
            target: "0x9999999999999999999999999999999999999999".to_owned(),
            selector: "0xa9059cbb".to_owned(),
        })
    );

    // The per-call cap: 0.1 ETH per call in the builder spec.
    assert_eq!(
        enforcer
            .check("grant-limits", &evm_call(200_000_000_000_000_000))
            .await
            .expect("checks"),
        Decision::Deny(DenyReason::CallValueOverCap {
            requested: 200_000_000_000_000_000,
            cap: 100_000_000_000_000_000,
        })
    );

    // The recurring cap: drop the per-call cap and 0.7 ETH pushes the
    // day's 1 ETH total only when reached; 1.1 ETH passes it.
    if let cratefield_session_grants::GrantScope::EvmKernel(grant) = &mut spec.scope {
        grant.calls[0].value_cap = None;
    }
    store
        .save(GrantRecord::pending(spec, clock.now()))
        .await
        .expect("saves");
    assert_eq!(
        enforcer
            .check("grant-limits", &evm_call(1_100_000_000_000_000_000))
            .await
            .expect("checks"),
        Decision::Deny(DenyReason::NativeOverCap {
            requested: 1_100_000_000_000_000_000,
            cap: 1_000_000_000_000_000_000,
        })
    );

    // A different chain than the grant lives on is a server bug,
    // refused outright.
    let other_chain = IntendedAction::EvmCall {
        chain_id: 1,
        target: evm_target(),
        selector: transfer_selector(),
        args: Vec::new(),
        value: 0,
        token: None,
    };
    assert_eq!(
        enforcer
            .check("grant-limits", &other_chain)
            .await
            .expect("checks"),
        Decision::Deny(DenyReason::ChainMismatch)
    );
    assert_eq!(
        enforcer
            .check("no-such-grant", &evm_call(0))
            .await
            .expect("checks"),
        Decision::Deny(DenyReason::UnknownGrant("no-such-grant".to_owned()))
    );
}

#[pollster::test]
async fn the_rate_limit_stops_the_server_after_ten_calls_an_hour() {
    let store = cratefield_session_grants::MemoryGrantStore::new();
    let clock = Arc::new(MutableClock::new(WINDOW_START));
    let spec = evm_spec("grant-rate", WINDOW_START);
    store
        .save(GrantRecord::pending(spec, clock.now()))
        .await
        .expect("saves");
    let enforcer = Enforcer::new(&store, clock.as_ref());

    for call in 0..10 {
        let decision = enforcer
            .authorize("grant-rate", &evm_call(0))
            .await
            .expect("checks");
        assert_eq!(
            decision,
            Decision::Allow,
            "call {call} is inside the rate limit"
        );
    }
    assert_eq!(
        enforcer
            .authorize("grant-rate", &evm_call(0))
            .await
            .expect("checks"),
        Decision::Deny(DenyReason::RateLimited {
            max_calls: 10,
            period_secs: 3_600,
        })
    );

    // The next hour the window rolls and the server may act again.
    clock.advance_seconds(3_600);
    assert_eq!(
        enforcer
            .authorize("grant-rate", &evm_call(0))
            .await
            .expect("checks"),
        Decision::Allow
    );
}

#[pollster::test]
async fn the_offchain_deny_stops_the_server_before_the_onchain_revoke() {
    let store = cratefield_session_grants::MemoryGrantStore::new();
    let clock = Arc::new(MutableClock::new(WINDOW_START));
    let kernel = cratefield_session_grants::FakeKernelPermissions::new();
    let spec = evm_spec("grant-deny", WINDOW_START);

    let binding = kernel
        .grant(&spec, &passkey_signature())
        .await
        .expect("grants");
    let mut record = GrantRecord::pending(spec.clone(), clock.now());
    record.attach(binding.clone()).expect("attaches");
    store.save(record).await.expect("saves");
    let enforcer = Enforcer::new(&store, clock.as_ref());
    assert!(
        enforcer
            .check("grant-deny", &evm_call(0))
            .await
            .expect("checks")
            .is_allow()
    );

    // Layer one: the off-chain deny. No signature, no chain, one write.
    let mut record = store
        .get("grant-deny")
        .await
        .expect("gets")
        .expect("stored");
    record.deny();
    store.save(record).await.expect("saves");
    assert_eq!(
        enforcer
            .check("grant-deny", &evm_call(0))
            .await
            .expect("checks"),
        Decision::Deny(DenyReason::Denied),
        "the deny takes effect immediately"
    );
    // ...while the permission is still installed on chain: the two
    // layers are independent.
    assert_eq!(
        kernel.installed().len(),
        1,
        "the on-chain permission still exists"
    );

    // Layer two: the owner signs the on-chain revoke.
    kernel
        .revoke(&binding, &passkey_signature())
        .await
        .expect("the owner-signed uninstallPlugin");
    assert_eq!(kernel.uninstalled().len(), 1);
    let mut record = store
        .get("grant-deny")
        .await
        .expect("gets")
        .expect("stored");
    record.mark_revoked();
    store.save(record).await.expect("saves");
    assert_eq!(
        enforcer
            .check("grant-deny", &evm_call(0))
            .await
            .expect("checks"),
        Decision::Deny(DenyReason::Revoked)
    );
}

#[pollster::test]
async fn a_pause_stops_the_server_and_a_resume_restores_it() {
    let store = cratefield_session_grants::MemoryGrantStore::new();
    let clock = Arc::new(MutableClock::new(WINDOW_START));
    let mut spec = evm_spec("grant-pause", WINDOW_START);
    spec.rate_limit = None;
    store
        .save(GrantRecord::pending(spec, clock.now()))
        .await
        .expect("saves");
    let enforcer = Enforcer::new(&store, clock.as_ref());

    let mut record = store
        .get("grant-pause")
        .await
        .expect("gets")
        .expect("stored");
    record.pause();
    store.save(record).await.expect("saves");
    assert_eq!(
        enforcer
            .check("grant-pause", &evm_call(0))
            .await
            .expect("checks"),
        Decision::Deny(DenyReason::Paused)
    );

    let mut record = store
        .get("grant-pause")
        .await
        .expect("gets")
        .expect("stored");
    record.resume();
    store.save(record).await.expect("saves");
    assert!(
        enforcer
            .check("grant-pause", &evm_call(0))
            .await
            .expect("checks")
            .is_allow()
    );
    assert_eq!(
        store
            .get("grant-pause")
            .await
            .expect("gets")
            .expect("stored")
            .status,
        GrantStatus::Active
    );
}

#[pollster::test]
async fn an_expired_grant_is_refused_while_its_onchain_permission_lives() {
    let store = cratefield_session_grants::MemoryGrantStore::new();
    let clock = Arc::new(MutableClock::new(WINDOW_START));
    let kernel = cratefield_session_grants::FakeKernelPermissions::new();
    let spec = evm_spec("grant-expiry", WINDOW_START);
    let binding = kernel
        .grant(&spec, &passkey_signature())
        .await
        .expect("grants");
    let mut record = GrantRecord::pending(spec, clock.now());
    record.attach(binding).expect("attaches");
    store.save(record).await.expect("saves");
    let enforcer = Enforcer::new(&store, clock.as_ref());

    assert!(
        enforcer
            .check("grant-expiry", &evm_call(0))
            .await
            .expect("checks")
            .is_allow()
    );
    // The window in the builder is 30 days; the 31st day is past it.
    clock.advance_seconds(31 * 86_400);
    assert_eq!(
        enforcer
            .check("grant-expiry", &evm_call(0))
            .await
            .expect("checks"),
        Decision::Deny(DenyReason::Expired {
            at: WINDOW_START + time::Duration::days(30),
        })
    );
    // Not yet valid is the mirror case.
    clock.advance_seconds(-40 * 86_400);
    assert!(matches!(
        enforcer
            .check("grant-expiry", &evm_call(0))
            .await
            .expect("checks"),
        Decision::Deny(DenyReason::NotYetValid { .. })
    ));
}

#[pollster::test]
async fn swig_limits_are_recurring_and_per_destination() {
    let store = cratefield_session_grants::MemoryGrantStore::new();
    let clock = Arc::new(MutableClock::new(WINDOW_START));
    let swig = Arc::new(cratefield_session_grants::FakeSwig::new());
    let spec = swig_spec("grant-swig", WINDOW_START);

    let binding = swig
        .create_role(&spec, &passkey_signature())
        .await
        .expect("creates the role");
    let mut record = GrantRecord::pending(spec, clock.now());
    record.attach(binding).expect("attaches");
    store.save(record).await.expect("saves");
    let enforcer = Enforcer::new(&store, clock.as_ref());

    let here = destination();
    let there = cratefield_session_grants::second_destination();

    // 0.4 SOL to `here`: inside the 0.5 SOL per-destination cap.
    assert!(
        enforcer
            .authorize("grant-swig", &swig_transfer(400_000_000, &here))
            .await
            .expect("checks")
            .is_allow()
    );
    // Another 0.4 SOL to `here` passes the per-destination cap.
    assert_eq!(
        enforcer
            .authorize("grant-swig", &swig_transfer(400_000_000, &here))
            .await
            .expect("checks"),
        Decision::Deny(DenyReason::NativeOverCap {
            requested: 800_000_000,
            cap: 500_000_000,
        })
    );
    // The same amount to `there` is inside its own per-destination cap
    // and inside the 2 SOL recurring total.
    assert!(
        enforcer
            .authorize("grant-swig", &swig_transfer(400_000_000, &there))
            .await
            .expect("checks")
            .is_allow()
    );
    // 1.4 SOL to `there` passes the recurring total (0.8 spent + 1.4).
    assert_eq!(
        enforcer
            .authorize("grant-swig", &swig_transfer(1_400_000_000, &there))
            .await
            .expect("checks"),
        Decision::Deny(DenyReason::NativeOverCap {
            requested: 2_200_000_000,
            cap: 2_000_000_000,
        })
    );

    // The hour rolls: the recurring window resets and the same transfer
    // fits again.
    clock.advance_seconds(3_600);
    assert!(
        enforcer
            .authorize("grant-swig", &swig_transfer(400_000_000, &here))
            .await
            .expect("checks")
            .is_allow()
    );
}

#[pollster::test]
async fn the_swig_session_expires_one_ttl_after_creation() {
    let clock = Arc::new(MutableClock::new(WINDOW_START));
    let swig = cratefield_session_grants::FakeSwig::new();
    swig.with_clock(clock.clone());
    let spec = swig_spec("grant-session", WINDOW_START);

    swig.create_role(&spec, &passkey_signature())
        .await
        .expect("creates");
    let (_, grant_id, session_key, expires_at) = swig.roles()[0].clone();
    assert_eq!(grant_id, "grant-session");
    assert_eq!(session_key, swig_session_key());
    assert_eq!(
        expires_at,
        WINDOW_START + time::Duration::seconds(86_400),
        "the session authority expires one TTL after creation"
    );

    // The on-chain session expiry is the tighter of the two bounds: the
    // builder's window runs 30 days, the session a day — the summary the
    // owner signs shows the window, and the role keeps the session
    // expiry the wallet enforces.
    assert!(expires_at < spec.window.valid_until);
}

#[pollster::test]
async fn squads_spending_limits_cap_treasury_transfers() {
    let store = cratefield_session_grants::MemoryGrantStore::new();
    let clock = Arc::new(MutableClock::new(WINDOW_START));
    let squads = cratefield_session_grants::FakeSquads::new();
    let spec = squads_spec("grant-squads", WINDOW_START);

    let binding = squads
        .create_spending_limit(&spec, &passkey_signature())
        .await
        .expect("creates the limit");
    let mut record = GrantRecord::pending(spec, clock.now());
    record.attach(binding.clone()).expect("attaches");
    store.save(record).await.expect("saves");
    let enforcer = Enforcer::new(&store, clock.as_ref());

    // 4 USDC to the allowed recipient: inside the weekly 5 USDC limit.
    assert!(
        enforcer
            .authorize(
                "grant-squads",
                &squads_transfer(4_000_000_000, &destination())
            )
            .await
            .expect("checks")
            .is_allow()
    );
    // Two more passes the limit (4 + 2 > 5).
    assert_eq!(
        enforcer
            .authorize(
                "grant-squads",
                &squads_transfer(2_000_000_000, &destination())
            )
            .await
            .expect("checks"),
        Decision::Deny(DenyReason::TokenOverCap {
            requested: 6_000_000_000,
            cap: 5_000_000_000,
        })
    );
    // A different recipient is not in the limit's allowlist.
    let stranger = cratefield_session_grants::second_destination();
    assert_eq!(
        enforcer
            .authorize("grant-squads", &squads_transfer(1_000_000_000, &stranger))
            .await
            .expect("checks"),
        Decision::Deny(DenyReason::DestinationNotAllowed(stranger.to_string()))
    );
    // A native movement has no limit in this spec, so it is refused.
    let native = IntendedAction::SolanaTransfer {
        cluster: cratefield_session_grants::Cluster::Mainnet,
        program: token_program(),
        lamports: 1_000,
        destination: destination(),
        token: None,
    };
    assert!(matches!(
        enforcer
            .check("grant-squads", &native)
            .await
            .expect("checks"),
        Decision::Deny(DenyReason::CallNotAllowed { .. })
    ));

    // The owner-signed revoke deactivates the limit; the server stops.
    squads
        .revoke_spending_limit(&binding, &passkey_signature())
        .await
        .expect("revokes");
    let mut record = store
        .get("grant-squads")
        .await
        .expect("gets")
        .expect("stored");
    record.mark_revoked();
    store.save(record).await.expect("saves");
    assert_eq!(
        enforcer
            .check(
                "grant-squads",
                &squads_transfer(1_000_000_000, &destination())
            )
            .await
            .expect("checks"),
        Decision::Deny(DenyReason::Revoked)
    );
}

#[pollster::test]
async fn the_bundler_client_speaks_the_pimlico_and_zerodev_method_names() {
    let bundler = BundlerClient::new(FakeRpc::new());
    let sender = Address::parse("0x1111111111111111111111111111111111111111").expect("a literal");

    assert_eq!(bundler.chain_id().await.expect("chain id"), 8453);
    let op = UserOperation::zero(sender, "0xdeadbeef".to_owned());
    let estimate = bundler.estimate_gas(&op).await.expect("estimates");
    assert_eq!(estimate.call_gas_limit, "60000");
    let sponsorship = bundler.sponsor(&op).await.expect("sponsors");
    assert!(sponsorship.paymaster_and_data.starts_with("0x"));
    let mut sponsored = op.clone();
    sponsored.paymaster_data = sponsorship.paymaster_and_data;
    let hash = bundler.send(&sponsored).await.expect("sends");
    let receipt = bundler
        .receipt(&hash)
        .await
        .expect("receipts")
        .expect("receipt");
    assert!(receipt.success);

    // The methods went out in the ERC-4337 order, with camelCase wire
    // fields and the v0.7 entry point in the params.
    let sent = bundler_captured(&bundler);
    assert_eq!(
        sent.iter()
            .map(|(method, _)| method.as_str())
            .collect::<Vec<_>>(),
        [
            "eth_chainId",
            "eth_estimateUserOperationGas",
            "pm_sponsorUserOperation",
            "eth_sendUserOperation",
            "eth_getUserOperationReceipt",
        ]
    );
    let (_, send_params) = sent[3].clone();
    assert!(
        send_params.contains("callData"),
        "the wire field is camelCase"
    );
    assert!(
        send_params.contains(cratefield_session_grants::ENTRY_POINT_V07),
        "the params name the entry point"
    );
}

/// The captured calls behind a `BundlerClient` over `FakeRpc`.
fn bundler_captured(
    bundler: &BundlerClient<cratefield_session_grants::FakeRpc>,
) -> Vec<(String, String)> {
    bundler.transport().captured()
}

#[pollster::test]
async fn usage_ledger_entries_fold_across_the_window_boundary() {
    let store = cratefield_session_grants::MemoryGrantStore::new();
    let clock = Arc::new(MutableClock::new(WINDOW_START));
    let mut spec = evm_spec("grant-ledger", WINDOW_START);
    spec.rate_limit = None;
    store
        .save(GrantRecord::pending(spec, clock.now()))
        .await
        .expect("saves");
    let enforcer = Enforcer::new(&store, clock.as_ref());

    // Two actions move 0.1 ETH total in the first hour.
    assert!(
        enforcer
            .authorize("grant-ledger", &evm_call(50_000_000_000_000_000))
            .await
            .expect("checks")
            .is_allow()
    );
    clock.advance_seconds(3_600);
    assert!(
        enforcer
            .authorize("grant-ledger", &evm_call(50_000_000_000_000_000))
            .await
            .expect("checks")
            .is_allow()
    );

    let usage: Usage = store
        .usage_since(
            "grant-ledger",
            WINDOW_START + time::Duration::seconds(3_600),
        )
        .await
        .expect("folds");
    assert_eq!(
        usage.calls, 1,
        "the second hour's window holds only its call"
    );
    let all = store
        .usage_since("grant-ledger", WINDOW_START)
        .await
        .expect("folds");
    assert_eq!(all.calls, 2);
    assert_eq!(all.native_total(), 100_000_000_000_000_000);
}
