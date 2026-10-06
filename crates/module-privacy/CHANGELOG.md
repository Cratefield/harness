# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1](https://github.com/Cratefield/harness/compare/cratefield-module-privacy-v0.3.0...cratefield-module-privacy-v0.3.1) - 2026-10-06

### Other

- serve the CF08 provider protocol from a harness deployment, and apply the account provider last ([#792](https://github.com/Cratefield/harness/pull/792))

### Added

- *(provider server)* `Privacy::serve_provider`, so a deployment can answer the same signed protocol it calls out on: `POST /v1/privacy/provider/{export,erase/plan,erase/apply}` over this composition's own declarations, with the HMAC as the authorisation rather than `ADMIN_TOKEN`, and no routes at all where it was not opted in ([#656](https://github.com/Cratefield/harness/issues/656)).
- `HttpProvider::account()`, marking the provider that holds the identity so it is applied last — unmarked providers in registration order, then the marked ones — in all three loops ([#656](https://github.com/Cratefield/harness/issues/656)).

## [0.3.0](https://github.com/Cratefield/harness/compare/cratefield-module-privacy-v0.2.1...cratefield-module-privacy-v0.3.0) - 2026-10-04

### Changed

- **Breaking:** requires `cratefield-core` 0.8 (was 0.7), and so a minor rather than a patch bump: a venture still on core 0.7 does not pick this release up through a caret requirement and end up with two copies of core ([#712](https://github.com/Cratefield/harness/issues/712)).

### Added

- *(import-supabase)* inspect a Supabase project read-only and write the migration report ([#658](https://github.com/Cratefield/harness/pull/658)) ([#697](https://github.com/Cratefield/harness/pull/697))

## [0.2.1](https://github.com/Cratefield/harness/compare/cratefield-module-privacy-v0.2.0...cratefield-module-privacy-v0.2.1) - 2026-10-03

### Other

- updated the following local packages: cratefield-core
