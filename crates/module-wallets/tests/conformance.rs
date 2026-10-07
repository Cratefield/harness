//! The shared conformance suite (issue #9) plus the wasm dependency
//! boundary (ADR 0001) for `cratefield-module-wallets`.
//!
//! The wasm check is the one that matters here: this crate reaches for
//! secp256k1, keccak and base58, and every one of those has a version that
//! pulls in a C toolchain. The assertion is what keeps the picks wasm-safe.

mod support;

use cratefield_module_wallets::Wallets;
use cratefield_testing::{assert_wasm_safe_deps, conformance};

use support::{DOMAIN, SeqRandom};

fn module() -> Wallets {
    Wallets::builder()
        .domain(DOMAIN)
        .statement("Link this wallet to your account.")
        .random(SeqRandom::new())
        .build()
}

#[test]
fn wallets_conforms() {
    conformance(Box::new(module()));
}

#[test]
fn wallets_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
