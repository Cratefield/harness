# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/Cratefield/harness/releases/tag/factory0-module-waitlist-v0.1.0) - 2026-09-07

### Added

- *(ui)* factory0-ui renders the surface; /ui pages, fragments, in-process dispatch ([#72](https://github.com/Cratefield/harness/pull/72))
- *(modules)* email-signup, waitlist and module-hello declare their surfaces ([#71](https://github.com/Cratefield/harness/pull/71))
- parity suite — module tests on SQLite and Postgres from one definition ([#20](https://github.com/Cratefield/harness/pull/20))
- *(core,cli,modules)* security baseline - doctor override, redaction rules, retention, privacy/security docs ([#13](https://github.com/Cratefield/harness/pull/13))
- *(module-email-signup,module-waitlist)* askama mail templates, branding, previews ([#12](https://github.com/Cratefield/harness/pull/12))
- *(module-waitlist)* per-product waitlist with atomic positions ([#11](https://github.com/Cratefield/harness/pull/11))

### Fixed

- *(module-waitlist)* guard the referral credit with the confirm flip

### Other

- crate READMEs + rustdoc includes, doc warnings denied in CI ([#16](https://github.com/Cratefield/harness/pull/16))
- release-plz pipeline for crates.io ([#15](https://github.com/Cratefield/harness/pull/15))
