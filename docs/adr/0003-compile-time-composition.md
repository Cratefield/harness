# ADR 0003: Compile-time composition, one Worker per venture

Status: accepted, 2026-09-05

## Context
Requirements: modules are packages used while compiling; each venture is
independent; the harness is open source, some modules private.

## Decision
A venture backend is a Cargo project (from `venture-backend-template`) whose
`src/harness.rs` builds a `Harness` from module crates. The wasm binary
contains exactly those modules. There is no runtime plugin loading and no
multi-tenant deployment.

## Consequences
- Private modules are private crates pulled by git dependency; the harness does not know or care.
- Each venture has its own D1 database, secrets and custom domain.
- Route prefix, table name and `HARNESS_API` mismatches are caught by `Harness::build()`, which the template runs under `cargo test`.
