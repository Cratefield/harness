# ADR 0011: public crates are `cratefield-*`, not `factory0-*`

Status: accepted, 2026-09-07. Supersedes the naming half of
[0005](0005-crate-naming-and-distribution.md).

## Context
ADR 0005 chose the `factory0-` prefix when this repository lived in the
Factory Zero organisation. The repository is now `Cratefield/harness` and
the product it is sold as is Cratefield; Factory Zero is the parent that
owns the ventures, not the name a person types into `cargo add`.

The prefix survived the move for one reason: renaming a published crate is
a breaking change for every consumer, and no rename is worth that on its
own. That argument expires exactly once — **before the first publish**.
Nothing is on crates.io yet, so the rename costs nothing today and costs
every downstream `Cargo.toml` on any later day.

## Decision
- Public crates take the prefix `cratefield-`; library paths follow as
  `cratefield_*`. The binary keeps its short name `fz`.
- Private crates are unchanged: still `fz-*`, still git dependencies, still
  in `Factory-Zero/harness-private`. They are Factory Zero's, not
  Cratefield's, and they are never published.
- `Factory-Zero/auth` keeps its own `factory0-auth-*` package names for the
  same reason: it is an unpublished Factory Zero service, not a Cratefield
  crate. It depends on the harness by the new names.
- Everything else ADR 0005 decided stands: crates.io for public, git tags
  `<crate>-v<semver>` for private, trusted publishing over OIDC.

## Consequences
- The 15 publishable crates are renamed in one commit, before any release.
  There is no compatibility shim and none is needed: no version of any
  `factory0-*` crate ever existed on crates.io.
- The `factory0-*` names stay unclaimed. Squatting them defensively would
  mean publishing crates we do not intend to maintain, which is worse than
  the name being free.
- Problem-type URIs (`https://factory0.ventures/problems/...`), the
  `factory0.ventures` domains and the example venture named `factory0` are
  untouched. They are Factory Zero's, they are a wire contract, and they
  are not package names.
