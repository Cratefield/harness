# ADR 0001: workers-rs on Cloudflare, axum as the router, runtime-agnostic core

Status: accepted, 2026-09-05

## Context
Ventures need a stateless backend with near-zero ops. Compute must be able to
move to self-hosted infrastructure later without touching modules.

## Decision
- v1 runtime is Cloudflare Workers via `workers-rs` (`worker` crate, `http`
  and `d1` features), built with `worker-build`, deployed with wrangler.
- The router is axum (`default-features = false`). workers-rs can serve an
  axum `Router` directly, and the same `Router` runs on tokio natively.
- `factory0-core` depends on `http`, `axum`, `serde`, `tracing` and pure-Rust
  crypto only. No `worker`, `wasm-bindgen`, `tokio`, `std::fs` or `std::net`
  in core or in modules. Runtime crates own those.

## Consequences
- A dependency that only works natively (tokio runtime, mio, native TLS)
  cannot enter core or a module; CI's `worker-build` step catches it.
- `factory0-runtime-native` is a thin crate: axum on tokio plus native adapters.
