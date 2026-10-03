//! The shared conformance suite (issue #9) plus the wasm dependency
//! boundary (ADR 0001) for `cratefield-module-device-auth`.

mod support;

use cratefield_module_device_auth::{DeviceAuth, DeviceClient};
use cratefield_testing::{assert_wasm_safe_deps, conformance};

use support::{CountingIssuer, SeqRandom};

fn module() -> DeviceAuth {
    DeviceAuth::builder()
        .client(DeviceClient::new("sealb-cli").scopes(["read", "write"]))
        .issuer(CountingIssuer::new())
        .random(SeqRandom::new())
        .build()
}

#[test]
fn device_auth_conforms() {
    conformance(Box::new(module()));
}

#[test]
fn device_auth_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
