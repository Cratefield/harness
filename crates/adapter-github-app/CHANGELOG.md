# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/Cratefield/harness/compare/cratefield-adapter-github-app-v0.1.0...cratefield-adapter-github-app-v0.2.0) - 2026-10-04

### Changed

- **Breaking:** requires `cratefield-core` 0.8 (was 0.7), and so a minor rather than a patch bump: a venture still on core 0.7 does not pick this release up through a caret requirement and end up with two copies of core ([#712](https://github.com/Cratefield/harness/issues/712)).

### Other

- updated the following local packages: cratefield-core

## [0.1.0](https://github.com/Cratefield/harness/releases/tag/cratefield-adapter-github-app-v0.1.0) - 2026-10-03

### Other

- App JWTs, cached installation tokens, and a named GitHub webhook scheme ([#623](https://github.com/Cratefield/harness/pull/623)) ([#637](https://github.com/Cratefield/harness/pull/637))
