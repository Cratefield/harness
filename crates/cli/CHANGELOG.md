# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.2](https://github.com/Cratefield/harness/compare/cratefield-cli-v0.6.1...cratefield-cli-v0.6.2) - 2026-10-07

### Other

- update Cargo.lock dependencies

## [0.6.1](https://github.com/Cratefield/harness/compare/cratefield-cli-v0.6.0...cratefield-cli-v0.6.1) - 2026-10-07

### Other

- update Cargo.lock dependencies

## [0.6.0](https://github.com/Cratefield/harness/compare/cratefield-cli-v0.5.0...cratefield-cli-v0.6.0) - 2026-10-05

### Other

- Supabase import: plan.json, bare `fz import supabase` dry run, `--apply --plan` drift check and target extension preflight ([#754](https://github.com/Cratefield/harness/pull/754))
- Supabase import: record per-item dispositions (covered/waived) in a file and merge them into the report ([#752](https://github.com/Cratefield/harness/pull/752))

## [0.5.0](https://github.com/Cratefield/harness/compare/cratefield-cli-v0.4.0...cratefield-cli-v0.5.0) - 2026-10-04

### Changed

- **Breaking:** requires `cratefield-core` 0.8 (was 0.7), and so a minor rather than a patch bump: a venture still on core 0.7 does not pick this release up through a caret requirement and end up with two copies of core ([#712](https://github.com/Cratefield/harness/issues/712)).

### Added

- *(import-supabase)* inspect a Supabase project read-only and write the migration report ([#658](https://github.com/Cratefield/harness/pull/658)) ([#697](https://github.com/Cratefield/harness/pull/697))

### Other

- Import users from another provider: bcrypt verified and upgraded on login, `import` identities, `fz auth import` ([#650](https://github.com/Cratefield/harness/pull/650)) ([#700](https://github.com/Cratefield/harness/pull/700))

## [0.4.0](https://github.com/Cratefield/harness/compare/cratefield-cli-v0.3.0...cratefield-cli-v0.4.0) - 2026-10-03

### Added

- *(core)* [**breaking**] name problem `type` URIs under the venture's own base ([#557](https://github.com/Cratefield/harness/pull/557)) ([#581](https://github.com/Cratefield/harness/pull/581))

### Other

- Route policy: let one module declare a signature verifier per webhook route ([#595](https://github.com/Cratefield/harness/pull/595)) ([#632](https://github.com/Cratefield/harness/pull/632))
- Production readiness fails when a module declares RateLimiter and none is mounted; a missing Workers limiter binding fails closed ([#562](https://github.com/Cratefield/harness/pull/562)) ([#569](https://github.com/Cratefield/harness/pull/569))
- Verify the cratefield-core 0.6.0 release round ([#558](https://github.com/Cratefield/harness/pull/558)) and fix a stale client-ts comment in the CLI manifest ([#566](https://github.com/Cratefield/harness/pull/566))
