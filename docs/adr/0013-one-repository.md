# ADR 0013: One repository — modules, ventures and the control plane live here

Status: accepted, 2026-09-08. Supersedes the *distribution* half of
[0005](0005-crate-naming-and-distribution.md) and the private-crate
paragraph of [0011](0011-crates-are-published-as-cratefield.md). The
*naming* decisions in both stand unchanged.

## Context

The harness had grown six sibling repositories:

| Repository | Held |
|---|---|
| `Factory-Zero/auth` | 9 login crates and the auth Worker |
| `Factory-Zero/harness-private` | `fz-module-linkedin` |
| `Cratefield/control-plane` | 10 crates for the managed service |
| `Cratefield/waitlist-backend` | the `api.cratefield.com` venture |
| `Factory-Zero/factory0-backend` | a README and a banner, no code |
| `Factory-Zero/venture-backend-template` | a README and a banner, no code |

ADR 0005 split them for a real reason: crates.io has no private crates, so
anything unpublished had to be a git dependency, and a git dependency is a
pin. The cost of that pin came due within two days of the first release:

- `harness-private` pinned `factory0-core` at a revision from **before**
  the ADR 0011 rename. It could not build against `main` at all.
- `waitlist-backend` pinned the same dead names. The venture serving
  `api.cratefield.com` could not be rebuilt from its own repository.
- `control-plane` pinned rev `b085800` and had no CI whatsoever, so
  nothing noticed.
- Three of the four had a `cratefield-core` a different age from the
  harness they were built against. Two `cratefield_core` versions in one
  graph is not a version skew, it is a type error: `SqliteDatabase` does
  not implement `cratefield_core::Database` when the trait comes from a
  different copy of the crate.

Each pin was individually defensible and collectively the modules drifted
out of the harness. A pin only protects you if somebody moves it.

## Decision

One repository. `Cratefield/harness` holds every crate — public and
private, library and venture — as workspace members with **path**
dependencies.

- Publication is decided per crate by `publish = false`, not by which
  repository the crate sits in. All 20 crates that moved carry it already.
  The 18 published `cratefield-*` crates are unaffected.
- Private-by-repository is replaced by public-by-default. The control
  plane and the LinkedIn module are now readable source. That is a
  deliberate trade: their value is the running service and the Page
  connection, not the source text, and it is worth less than the drift.
- Venture-side `fz` binaries stay **excluded** from the workspace
  (`crates/auth-fz`, `crates/control-plane-fz`, `crates/control-plane-dev`)
  for the reason their own manifests already gave: they are native builds
  and their `clap`/`rusqlite` dependencies must never reach a wasm graph.
- Spikes stay detached with an empty `[workspace]` table, as
  `spikes/crypto` already was.
- Package names do not change. `factory0-auth-*` is still a Factory Zero
  service and `fz-module-linkedin` is still a Factory Zero module; ADR
  0011's reasoning for their names survives the move, and neither is
  published, so a rename would buy nothing.
- ADRs are numbered in blocks so two repositories can never claim one
  number again, which is exactly what happened to 0102:

  | Block | Subject |
  |---|---|
  | 0000–0099 | the harness |
  | 0100–0199 | cross-cutting harness concerns (crypto, 0102) |
  | 0200–0299 | the auth service |
  | 0300–0399 | the control plane |

  The auth ADRs move 0100–0104 → 0200–0204. `0102-crypto-crate.md` keeps
  its number: it is referenced from published crates.

## Consequences

- The two crates that could not build against `main` build against it now,
  because "against `main`" is the only thing they can build against.
- `fz-module-linkedin` runs the conformance kit in this repo's own CI
  instead of through a cross-repository reusable workflow call. The
  reusable `conformance.yml` stays for anyone building modules out of
  tree.
- One `Cargo.lock`, one `docs/COMPATIBILITY.md` (39 crates), one clippy
  configuration. The merged `doc-valid-idents` list is the union of the
  three that existed; `control-plane` had no clippy config and no CI, and
  its four `std::sync::Mutex` test fakes needed the annotation ADR 0007's
  ban has always required.
- CI gets slower and touches everything. That is the price of the
  guarantee and it is the right way round: a slow check that runs beats a
  fast one that was never wired up.
- `p256` is duplicated: 0.13.2 for `cratefield-adapter-apns`, 0.14.0 for
  the four auth crates that pin it directly. Unifying it means a major
  bump on a published crate and is deliberately not part of this move.
- Anyone who cloned one of the six repositories now clones this one. The
  originals are archived read-only, not deleted, so their issue history
  and every link into it still resolve.
