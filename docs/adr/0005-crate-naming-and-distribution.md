# ADR 0005: `factory0-*` public on crates.io, `fz-*` private via git dependencies

Status: accepted, 2026-09-05

## Context
crates.io has no scopes and no private crates. Public crates must install
with plain `cargo add`. Private crates must not require running a registry.

## Decision
- Open-source crates: prefix `factory0-`, published to crates.io from
  `Cratefield/harness` with trusted publishing (GitHub OIDC).
- Private crates: prefix `fz-`, never published; consumed as
  `fz-module-admin = { git = "ssh://git@github.com/Factory-Zero/harness-private", tag = "fz-module-admin-v0.3.0" }`.
- Version tags in the private repo follow `<crate>-v<semver>` so one repo can carry many crates.

## Consequences
- The prefix tells you the visibility and where it comes from.
- The crates.io names `factory0-*` must be reserved once (manual, by the owner); the `fz` binary is `factory0-cli`.
- Venture CI needs an SSH deploy key or a fine-grained token with read access to `harness-private` only when it uses a private module.
