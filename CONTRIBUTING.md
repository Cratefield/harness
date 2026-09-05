# Contributing to the Factory Zero harness

Read [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) first — the design is
decided and recorded in [`docs/adr`](docs/adr). If you disagree with a
decision, open an issue; do not silently deviate.

## Toolchain

- Rust stable, pinned in [`rust-toolchain.toml`](rust-toolchain.toml)
  (installs automatically via rustup, includes the
  `wasm32-unknown-unknown` target).
- `worker-build` for the wasm build (`cargo install worker-build`).
- `cargo-deny` for license/advisory checks.

## Before every commit

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
(cd examples/venture && worker-build --release)
```

CI runs all of the above on every PR.

## Rules

- `crates/core` and module crates must stay wasm-safe: no `worker`,
  `wasm-bindgen`, `tokio`, `reqwest`, `sqlx`, `rusqlite`, no `std::fs` /
  `std::net` at runtime.
- `#![forbid(unsafe_code)]` everywhere except `factory0-runtime-cloudflare`
  (ADR 0002).
- No `thread_local!`, no `static mut`, no ambient request state (ADR 0007).
- Never commit real secrets; test fixtures use obvious dummies.
- One commit per issue, conventional-commit format, issue number last:
  `feat(core): Module trait and Harness builder (#2)`.
