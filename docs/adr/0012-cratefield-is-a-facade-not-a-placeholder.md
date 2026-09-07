# ADR 0012: the bare `cratefield` name is a facade crate, not a placeholder

Status: accepted, 2026-09-07. Extends
[0011](0011-crates-are-published-as-cratefield.md).

## Context
Renaming the crates to `cratefield-*` (ADR 0011) left the bare name
`cratefield` unclaimed on crates.io, and ADR 0011 argued against taking it:
"squatting them defensively would mean publishing crates we do not intend to
maintain, which is worse than the name being free."

That reasoning is right about placeholders and wrong about this name, for
two reasons.

**The asymmetry is not symmetric.** crates.io names are first come, first
served and effectively permanent; there is no reclaim short of a trademark
dispute. If somebody else publishes `cratefield`, every reader who types the
obvious thing lands on a crate we do not control, next to documentation that
tells them this is the product's name. The cost of not holding it is
unbounded and outside our control. The cost of holding it is one crate to
maintain.

**The name already has a job.** The smallest useful venture in this
repository depended on six crates: core, a runtime, an adapter, the UI
renderer and two modules — six version requirements that have to agree,
which is the entire reason `docs/COMPATIBILITY.md` exists. Rust's answer to
that is a facade, and the ecosystem is full of them: `tokio`, `bevy`,
`embassy`, `sea-orm`. We were going to want one regardless of what the name
situation was.

## Decision
- Publish `cratefield` as a **facade**: `cratefield-core` re-exported at the
  root, every other library crate behind a feature named after it. No code
  of its own, so the types are identical and a venture can move between the
  facade and the parts without rewriting anything.
- No default features. A runtime is a deliberate choice, and an empty
  default is what keeps `tokio` and `sqlx` out of a Workers build (ADR 0001).
- `cratefield-cli` is not in the facade. It is the `fz` binary; nothing
  `use`s it.
- `examples/venture` — the wasm canary CI boots under `wrangler dev` — is
  built on the facade. A facade that only unit tests can reach is a facade
  nobody has proven works.
- The `factory0-*` names stay unclaimed. That part of ADR 0011 stands: those
  really would be placeholders.

## Consequences
- The published set is 16 crates, and `cratefield` publishes last because it
  depends on all of them.
- The facade is a real maintenance obligation: a new publishable library
  crate has to be added to it, or `cargo add cratefield` quietly stops being
  the whole harness. A test reads the workspace manifest and fails when a
  publishable crate is not reachable from the facade, so this is caught
  rather than remembered.
- It becomes the natural home for the compatible-version set that
  `COMPATIBILITY.md` currently asks the reader to assemble by hand.
- Three features (`native`, `postgres`, `sqlite`) cannot build for wasm, for
  reasons that predate the facade. A `compile_error!` guard for these was
  written and then removed: the dependency's own errors arrive first, so the
  guard never fired. It is documented instead.
