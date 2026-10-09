//! The per-port conformance suites. The crate's own fakes run them (in
//! `tests/`), and so does any later adapter that implements a port for
//! real — one contract per port, asserted the same way everywhere.

use time::OffsetDateTime;

use crate::evm::{Bundler, KernelPermissions};
use crate::grant::{GrantSpec, GrantStatus, OnChainBinding};
use crate::solana::{Signature, SquadsError, SquadsLimits, SwigError, SwigSessions};
use crate::store::GrantStore;
use crate::types::OwnerSignature;

/// The [`GrantStore`] contract: a save/get roundtrip, owner listing,
/// conflict on a binding swap, and a ledger that folds on read and
/// filters by instant.
///
/// # Panics
/// By assertion, when the store breaks the contract.
pub async fn grant_store_conformance(store: &dyn GrantStore) {
    let target = crate::types::Address::parse("0x0000000000000000000000000000000000000001")
        .expect("a literal");
    let at = OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1_700_000_000);
    let mut spec = crate::fakes::evm_spec("conf-store-1", at);
    if let crate::grant::GrantScope::EvmKernel(grant) = &mut spec.scope {
        grant.account = target.clone();
    }
    let mut record = crate::grant::GrantRecord::pending(spec.clone(), at);

    // Before the grant call confirms, the record has no binding.
    store.save(record.clone()).await.expect("saves");
    let loaded = store
        .get("conf-store-1")
        .await
        .expect("gets")
        .expect("stored");
    assert_eq!(loaded.status, GrantStatus::Active);
    assert!(loaded.on_chain.is_none());

    // Attach, idempotently; a different binding conflicts.
    let binding = OnChainBinding::KernelPermission {
        permission_id: "0xperm".to_owned(),
        serialized: "0xserialized".to_owned(),
    };
    record.attach(binding.clone()).expect("attaches");
    record
        .attach(binding)
        .expect("attaching again is idempotent");
    let other = OnChainBinding::KernelPermission {
        permission_id: "0xother".to_owned(),
        serialized: "0xserialized".to_owned(),
    };
    assert!(record.attach(other).is_err(), "a binding swap conflicts");
    store
        .save(record.clone())
        .await
        .expect("saves with binding");
    let loaded = store
        .get("conf-store-1")
        .await
        .expect("gets")
        .expect("stored");
    assert!(
        loaded.on_chain.is_some(),
        "the on-chain id is kept with the grant"
    );

    // The usage ledger folds on read, at or after the instant: one call
    // just before the window, one inside it.
    let call = |value: u128| {
        crate::grant::Usage::of(&crate::grant::IntendedAction::EvmCall {
            chain_id: 8453,
            target: target.clone(),
            selector: crate::types::Selector::parse("0xa9059cbb").expect("a selector"),
            args: Vec::new(),
            value,
            token: None,
        })
    };
    store
        .record_usage("conf-store-1", &call(100), at - time::Duration::seconds(5))
        .await
        .expect("records");
    store
        .record_usage("conf-store-1", &call(300), at)
        .await
        .expect("records");
    let since_window_start = store.usage_since("conf-store-1", at).await.expect("folds");
    assert_eq!(since_window_start.calls, 1, "only the entry at `at` counts");
    assert_eq!(since_window_start.native_total(), 300);
    let all = store
        .usage_since("conf-store-1", at - time::Duration::seconds(6))
        .await
        .expect("folds");
    assert_eq!(all.calls, 2, "both entries count from before the first");
    assert_eq!(all.native_total(), 400, "the fold sums the native value");
    assert!(store.get("absent").await.expect("gets").is_none());
}

/// The [`Bundler`] contract: the chain id is honest, gas comes back
/// estimated, sponsorship carries a paymaster context, a sent operation
/// gets a hash and then a receipt.
///
/// # Panics
/// By assertion, when the bundler breaks the contract.
pub async fn bundler_conformance(bundler: &dyn Bundler, expected_chain_id: u64) {
    let chain_id = bundler.chain_id().await.expect("chain id");
    assert_eq!(
        chain_id, expected_chain_id,
        "the bundler serves the chain it says"
    );

    let sender = crate::types::Address::parse("0x00000000000000000000000000000000000000aa")
        .expect("a literal");
    let op = crate::evm::UserOperation::zero(sender, "0xdeadbeef".to_owned());
    let estimate = bundler.estimate_gas(&op).await.expect("estimates");
    assert!(!estimate.call_gas_limit.is_empty());
    let sponsorship = bundler.sponsor(&op).await.expect("sponsors");
    assert!(
        sponsorship.paymaster_and_data.starts_with("0x"),
        "the paymaster context is wire-shaped"
    );

    let hash = bundler.send(&op).await.expect("sends");
    let receipt = bundler.receipt(&hash).await.expect("receipts");
    let receipt = receipt.expect("a sent operation has a receipt");
    assert!(receipt.success, "the conformance op executes");

    // Unknown hashes are a None, not an error: the op may simply not be
    // on chain yet.
    assert!(
        bundler
            .receipt("0xunknown")
            .await
            .expect("receipts")
            .is_none()
    );
}

/// The [`KernelPermissions`] contract: the grant installs and returns the
/// serialized permission account, a second grant for the same spec is
/// idempotent, and the revoke — owner-signed — uninstalls and then
/// reports the permission as gone.
///
/// # Panics
/// By assertion, when the port breaks the contract.
pub async fn kernel_permissions_conformance(
    kernel: &dyn KernelPermissions,
    spec: &GrantSpec,
    owner_signature: &OwnerSignature,
) {
    let binding = kernel.grant(spec, owner_signature).await.expect("grants");
    let OnChainBinding::KernelPermission {
        permission_id,
        serialized,
    } = &binding
    else {
        panic!("a Kernel grant returns a KernelPermission binding");
    };
    assert!(
        !permission_id.is_empty(),
        "the permission id is on the binding"
    );
    assert!(
        serialized.starts_with("0x") && serialized.len() > 2,
        "`serializePermissionAccount`'s output is kept on the binding"
    );

    let again = kernel
        .grant(spec, owner_signature)
        .await
        .expect("grants again");
    assert_eq!(again, binding, "re-granting the same spec is idempotent");

    kernel
        .revoke(&binding, owner_signature)
        .await
        .expect("revokes");
    assert!(
        kernel.revoke(&binding, owner_signature).await.is_err(),
        "revoking twice reports the permission as gone"
    );
}

/// The [`SwigSessions`] contract: the role is created with its session
/// expiry, and revoking removes it — the second revoke reports the role
/// as gone.
///
/// # Panics
/// By assertion, when the port breaks the contract.
pub async fn swig_sessions_conformance(
    swig: &dyn SwigSessions,
    spec: &GrantSpec,
    owner_signature: &OwnerSignature,
) {
    let binding = swig
        .create_role(spec, owner_signature)
        .await
        .expect("creates");
    let OnChainBinding::SwigRole { role_id } = &binding else {
        panic!("a Swig grant returns a SwigRole binding");
    };
    assert!(*role_id > 0, "the wallet assigned a role id");
    let signature = swig
        .revoke_role(&binding, owner_signature)
        .await
        .expect("revokes");
    assert!(
        !signature.is_empty(),
        "the removal transaction has a signature"
    );
    assert!(
        matches!(
            swig.revoke_role(&binding, owner_signature).await,
            Err(SwigError::UnknownRole(_))
        ),
        "revoking twice reports the role as gone"
    );
}

/// The [`SquadsLimits`] contract: the spending limit is created, the
/// revoke signs and deactivates it, and a second revoke reports it gone.
///
/// # Panics
/// By assertion, when the port breaks the contract.
pub async fn squads_limits_conformance(
    squads: &dyn SquadsLimits,
    spec: &GrantSpec,
    owner_signature: &OwnerSignature,
) {
    let binding = squads
        .create_spending_limit(spec, owner_signature)
        .await
        .expect("creates");
    let OnChainBinding::SquadsLimit { spending_limit } = &binding else {
        panic!("a Squads grant returns a SquadsLimit binding");
    };
    assert!(
        !spending_limit.as_str().is_empty(),
        "the limit has an address"
    );
    let signature: Signature = squads
        .revoke_spending_limit(&binding, owner_signature)
        .await
        .expect("revokes");
    assert!(
        !signature.is_empty(),
        "the revoke transaction has a signature"
    );
    assert!(
        matches!(
            squads
                .revoke_spending_limit(&binding, owner_signature)
                .await,
            Err(SquadsError::UnknownLimit(_))
        ),
        "revoking twice reports the limit as gone"
    );
}
