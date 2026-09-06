<p align="center">
  <img src="assets/readme-banner.png" alt="Factory Zero Harness, private. The modules that encode how Factory Zero runs." width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/VISIBILITY-PRIVATE-FF5A36?style=flat-square&labelColor=0A0A0B" alt="Visibility: private">
  <img src="https://img.shields.io/badge/CRATES-fz--*-EDEBE6?style=flat-square&labelColor=0A0A0B" alt="Crates: fz-*">
  <img src="https://img.shields.io/badge/DISTRIBUTION-GIT%20DEPENDENCY-EDEBE6?style=flat-square&labelColor=0A0A0B" alt="Distribution: git dependency">
  <img src="https://img.shields.io/badge/PUBLISHED-NEVER-EDEBE6?style=flat-square&labelColor=0A0A0B" alt="Published: never">
  <img src="https://img.shields.io/badge/CONTRACT-factory0--core-FF5A36?style=flat-square&labelColor=0A0A0B" alt="Contract: factory0-core">
</p>

<p align="center">
  <b>Factory Zero</b> · HARNESS / PRIVATE
</p>

---

# The private modules

The [harness](https://github.com/Factory-Zero/harness) is open source. The
modules that encode how Factory Zero actually runs its ventures are not: what
gets exported, to whom, how deletion requests are handled, what the weekly
digest says. Those live here.

> **Same trait. Same tests. Different shelf.**
> A private module implements the public `Module` trait and passes the public
> conformance kit. The only things that differ are the crate prefix and how a
> venture pulls it in.

## Naming and distribution

Crates here are `fz-*` and are **never published**. Ventures consume them as
pinned git dependencies (harness ADR 0005):

```toml
[dependencies]
fz-module-admin = { git = "ssh://git@github.com/Factory-Zero/harness-private", tag = "fz-module-admin-v0.1.0" }
```

Tags follow `<crate>-v<semver>` so one repository carries many crates with
independent versions.

## Consuming from a venture

- **Locally:** an SSH key with read access to this repository.
- **In GitHub Actions:** a read-only deploy key for this repository stored as a
  secret in the venture repo, loaded with `webfactory/ssh-agent`, and
  `CARGO_NET_GIT_FETCH_WITH_CLI=true` so Cargo uses that agent.

## Crates

| Crate | Role | Status |
|---|---|---|
| `fz-module-admin` | Cross-module ops endpoints: stats, CSV exports, deletion requests, weekly digest | proposed, [#3](../../issues/3) |
| `fz-module-linkedin` | Runs a LinkedIn Company Page: OAuth connect, posts, media, showcase pages | proposed, [#4](../../issues/4) |

## Rules

- Never import another module's internals. Shared helpers go into
  `factory0-core` upstream.
- Every crate runs the public conformance workflow from the harness in CI.
- Same toolchain, lints and `cargo deny` policy as the public repository, kept
  in sync by hand.

## Layout

```
crates/
  _template/       copy me to start a new private module
  module-admin/    fz-module-admin
tools/
  banner-render.html
  render-banner.sh
```

Private to Factory Zero. Not for redistribution.
