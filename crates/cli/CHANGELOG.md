# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/Cratefield/harness/releases/tag/factory0-cli-v0.1.0) - 2026-09-07

### Added

- fz data export/import — move a venture's D1 data to Postgres ([#21](https://github.com/Cratefield/harness/pull/21))
- adapter-postgres — Database over sqlx with the migration runner
- *(core,ci)* contract versioning and reusable conformance ([#17](https://github.com/Cratefield/harness/pull/17))
- *(core,cli,modules)* security baseline - doctor override, redaction rules, retention, privacy/security docs ([#13](https://github.com/Cratefield/harness/pull/13))
- *(adapter-sqlite,cli)* rusqlite Database, fz migrations collect/doctor/modules ([#8](https://github.com/Cratefield/harness/pull/8))

### Other

- sort export row keys explicitly so the data file format does not follow serde_json's preserve_order
- Rehome the harness under Cratefield
- Merge pull request #52 from Factory-Zero/feat/adapter-postgres
- release-plz pipeline for crates.io ([#15](https://github.com/Cratefield/harness/pull/15))
