# Crypto crate spike (#38)

Time-boxed spike that implements the secrets design's encrypt/decrypt path
(#37, `docs/SECRETS-DESIGN.md`) against every candidate AEAD crate and
scores them. The result is `docs/adr/0102-crypto-crate.md`.

**Scratch crate — not part of the harness workspace.** The empty
`[workspace]` table in `Cargo.toml` detaches it from the root manifest, so
it can never enter the workspace build or the wasm build path of
`examples/venture`. It depends on no `cratefield-*` crate and nothing depends
on it.

## Layout

| Path | What it is |
|---|---|
| `src/lib.rs` | `SecretContext` (the AAD binding), `Dek`, `Envelope`, the backend-neutral `EnvelopeAead` trait |
| `src/backends.rs` | one backend per candidate, feature-gated: `aws-lc-backend`, `ring-backend`, `rustcrypto`, `age-backend` |
| `src/store.rs` | the envelope path, native-only (cfg-gated off wasm): DEK provision/wrap, `Kms` trait + local stand-in, TTL `DekCache` with zeroisation, `SecretsStore` |
| `tests/roundtrip.rs` | the full binding matrix per candidate: round trip, tamper, wrong store / name / version / key id, empty AAD |
| `tests/store.rs` | end-to-end store behaviour: cache miss/TTL, KMS outage warm vs cold, cross-store copy, crypto-shred |
| `examples/size.rs` | binary-size probe: one seal+open per enabled backend |

Test keys are generated in the tests (`generate_key`); no key is written
anywhere.

## Commands (all run from this directory)

Per-candidate tests — the reviewer runs these:

```sh
cargo test --features rustcrypto     # XChaCha20-Poly1305 + AES-256-GCM
cargo test --features ring-backend   # AES-256-GCM + ChaCha20-Poly1305
cargo test --features aws-lc-backend # AES-256-GCM + ChaCha20-Poly1305
cargo test --features age-backend    # the elimination demo
cargo test --features all
```

wasm32-unknown-unknown proof (the decisive criterion, as in the auth
spike). ring needs a clang with a WebAssembly backend — Apple clang has
none (`error: unable to create target: 'No available targets are
compatible with triple "wasm32-unknown-unknown"'`), so point cc-rs at
Homebrew LLVM for the target:

```sh
brew install llvm   # once
export CC_wasm32_unknown_unknown=$(brew --prefix llvm)/bin/clang
export AR_wasm32_unknown_unknown=$(brew --prefix llvm)/bin/llvm-ar

cargo build --target wasm32-unknown-unknown --features rustcrypto   # ok
cargo build --target wasm32-unknown-unknown --features ring-backend # ok (with the clang above)
cargo build --target wasm32-unknown-unknown --features age-backend  # ok
cargo build --target wasm32-unknown-unknown --features aws-lc-backend # FAILS — aws-lc-sys compiles C for the target; recorded in ADR 0102
```

Binary-size probe (`stat -f%z` on macOS; `stat -c%s` on Linux):

```sh
cargo build --release --example size                      # baseline
cargo build --release --example size --features <feature> # then stat target/release/examples/size
```

Recorded sizes and the scored rubric live in ADR 0102.
