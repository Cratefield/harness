# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.2](https://github.com/Cratefield/harness/compare/cratefield-adapter-resend-v0.4.1...cratefield-adapter-resend-v0.4.2) - 2026-10-09

### Added

- *(core)* report per-provider mailer status in /__health ([#793](https://github.com/Cratefield/harness/pull/793)) ([#845](https://github.com/Cratefield/harness/pull/845))

### Added

- `providers()` reports the one provider behind the adapter — `resend`,
  configured or not, with health left unknown because whether the key
  works is only learned by sending (issue #793).

## [0.4.1](https://github.com/Cratefield/harness/compare/cratefield-adapter-resend-v0.4.0...cratefield-adapter-resend-v0.4.1) - 2026-10-05

### Other

- Inbound mail: a verify-then-parse source in core, a Resend inbound adapter, and ADR 0028 for channels ([#563](https://github.com/Cratefield/harness/pull/563)) ([#734](https://github.com/Cratefield/harness/pull/734))

## [0.4.0](https://github.com/Cratefield/harness/compare/cratefield-adapter-resend-v0.3.1...cratefield-adapter-resend-v0.4.0) - 2026-10-04

### Changed

- **Breaking:** requires `cratefield-core` 0.8 (was 0.7), and so a minor rather than a patch bump: a venture still on core 0.7 does not pick this release up through a caret requirement and end up with two copies of core ([#712](https://github.com/Cratefield/harness/issues/712)).

### Other

- updated the following local packages: cratefield-core

## [0.3.1](https://github.com/Cratefield/harness/compare/cratefield-adapter-resend-v0.3.0...cratefield-adapter-resend-v0.3.1) - 2026-10-03

### Other

- updated the following local packages: cratefield-core
