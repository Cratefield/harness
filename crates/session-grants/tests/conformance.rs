//! The crate's own fakes run the conformance suites — the same suites a
//! real Pimlico/ZeroDev/Swig/Squads adapter will run against, so the
//! contract is pinned here before any adapter exists.

use cratefield_session_grants::conformance::{
    bundler_conformance, grant_store_conformance, kernel_permissions_conformance,
    squads_limits_conformance, swig_sessions_conformance,
};
use cratefield_session_grants::{
    BundlerClient, FakeBundler, FakeKernelPermissions, FakeRpc, FakeSquads, FakeSwig,
    MemoryGrantStore, evm_spec, passkey_signature, squads_spec, swig_spec,
};

/// One instant every spec builder sits its window on.
const AT: time::OffsetDateTime = cratefield_session_grants::WINDOW_START;

#[pollster::test]
async fn the_memory_store_conforms_to_the_grant_store_port() {
    grant_store_conformance(&MemoryGrantStore::new()).await;
}

#[pollster::test]
async fn the_fake_bundler_conforms_to_the_bundler_port() {
    bundler_conformance(&FakeBundler::new(8453), 8453).await;
}

#[pollster::test]
async fn the_client_over_the_fake_rpc_conforms_to_the_bundler_port() {
    // The adapter is conformed through the same port suite, over the
    // JSON-RPC fake — the method names and the wire mapping are the
    // thing under test.
    bundler_conformance(&BundlerClient::new(FakeRpc::new()), 8453).await;
}

#[pollster::test]
async fn the_fake_kernel_conforms_to_the_kernel_permissions_port() {
    let spec = evm_spec("conf-kernel", AT);
    kernel_permissions_conformance(&FakeKernelPermissions::new(), &spec, &passkey_signature())
        .await;
}

#[pollster::test]
async fn the_fake_swig_conforms_to_the_swig_sessions_port() {
    let spec = swig_spec("conf-swig", AT);
    swig_sessions_conformance(&FakeSwig::new(), &spec, &passkey_signature()).await;
}

#[pollster::test]
async fn the_fake_squads_conforms_to_the_squads_limits_port() {
    let spec = squads_spec("conf-squads", AT);
    squads_limits_conformance(&FakeSquads::new(), &spec, &passkey_signature()).await;
}
