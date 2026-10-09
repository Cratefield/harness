# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2](https://github.com/Cratefield/harness/compare/cratefield-adapter-owlpost-v0.2.1...cratefield-adapter-owlpost-v0.2.2) - 2026-10-09

### Added

- *(core)* report per-provider mailer status in /__health ([#793](https://github.com/Cratefield/harness/pull/793)) ([#845](https://github.com/Cratefield/harness/pull/845))

### Added

- `providers()` reports the one provider behind the adapter — `owlpost`,
  configured or not, with health left unknown when the adapter carries no
  probe (issue #793).

## [0.2.1](https://github.com/Cratefield/harness/compare/cratefield-adapter-owlpost-v0.2.0...cratefield-adapter-owlpost-v0.2.1) - 2026-10-06

### Added

- *(adapter-owlpost)* sending domains — create, list, get, verify, delete ([#681](https://github.com/Cratefield/harness/pull/681)) ([#797](https://github.com/Cratefield/harness/pull/797))
- *(adapter-owlpost)* suppressions and topic naming ([#669](https://github.com/Cratefield/harness/pull/669)) ([#795](https://github.com/Cratefield/harness/pull/795))
- *(adapter-owlpost)* typed webhook events and a verify-then-parse entry point ([#668](https://github.com/Cratefield/harness/pull/668)) ([#796](https://github.com/Cratefield/harness/pull/796))
- *(adapter-owlpost)* inbound messages — list/search, held, get, raw, reply, release ([#682](https://github.com/Cratefield/harness/pull/682)) ([#798](https://github.com/Cratefield/harness/pull/798))

## [0.2.0](https://github.com/Cratefield/harness/compare/cratefield-adapter-owlpost-v0.1.0...cratefield-adapter-owlpost-v0.2.0) - 2026-10-04

### Changed

- **Breaking:** requires `cratefield-core` 0.8 (was 0.7), and so a minor rather than a patch bump: a venture still on core 0.7 does not pick this release up through a caret requirement and end up with two copies of core ([#712](https://github.com/Cratefield/harness/issues/712)).

### Other

- updated the following local packages: cratefield-core

## [0.1.0](https://github.com/Cratefield/harness/releases/tag/cratefield-adapter-owlpost-v0.1.0) - 2026-10-03

### Added

- *(adapter-owlpost)* shared client, send options, batch and read ([#667](https://github.com/Cratefield/harness/pull/667)) ([#685](https://github.com/Cratefield/harness/pull/685))

### Other

- a Mailer over the Owlpost API ([#591](https://github.com/Cratefield/harness/pull/591)) ([#629](https://github.com/Cratefield/harness/pull/629))
