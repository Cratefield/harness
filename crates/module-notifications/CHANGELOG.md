# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0](https://github.com/Cratefield/harness/compare/cratefield-module-notifications-v0.2.1...cratefield-module-notifications-v0.3.0) - 2026-10-04

### Added

- *(mail-templates)* branded mail in each venture's own style for every module that sends mail ([#715](https://github.com/Cratefield/harness/pull/715)) ([#716](https://github.com/Cratefield/harness/pull/716))

### Changed

- **Breaking:** requires `cratefield-core` 0.8 (was 0.7), and so a minor rather than a patch bump: a venture still on core 0.7 does not pick this release up through a caret requirement and end up with two copies of core ([#712](https://github.com/Cratefield/harness/issues/712)).
- The notification email renders through the template registry as
  `notifications/email`, in the venture's theme via
  `cratefield-mail-templates`, so a venture can restyle or reword it.
  `default_templates()` and `themed_templates(&theme)` are new; subject
  selection, `lang`/`dir`, `Content-Language` and the one-click unsubscribe
  headers are unchanged ([#715](https://github.com/Cratefield/harness/issues/715)).

## [0.2.1](https://github.com/Cratefield/harness/compare/cratefield-module-notifications-v0.2.0...cratefield-module-notifications-v0.2.1) - 2026-10-03

### Other

- updated the following local packages: cratefield-core
