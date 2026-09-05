# ADR 0000: The harness is written in Rust

Status: accepted, 2026-09-05

## Context
A first version of this harness was designed and built in TypeScript (Hono,
Kysely, bun) on 2026-09-05. It reached a green foundation PR and was then
discarded the same day. Factory Zero's own projects are Rust; TypeScript was
carried over from an unrelated organisation's defaults.

## Decision
Everything in this repository is Rust. Cloudflare Workers are targeted through
`workers-rs` (Rust compiled to wasm32). The self-hosted future is a native Rust
binary from the same crates.

## Consequences
- Modules are crates; composition is `Cargo.toml` plus one builder call.
- Contributors need `rustup`, the `wasm32-unknown-unknown` target and
  `worker-build`. The template's CI proves the wasm build on every PR.
- The archived TypeScript repositories (`*-ts-archived`) are reference only.
