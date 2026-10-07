# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1](https://github.com/Cratefield/harness/compare/cratefield-module-notifications-v0.3.0...cratefield-module-notifications-v0.3.1) - 2026-10-07

### Fixed

- close five input-validation gaps — an unescaped HTML sink, a javascript: URL, an unvalidated slug, an OAuth token sent to any host, and an unclamped page size ([#826](https://github.com/Cratefield/harness/pull/826))

### Fixed

- `GET /v1/notifications?limit=0` no longer returns an empty inbox. The
  page size is clamped to `1..=INBOX_PAGE_MAX` (the idiom
  `module-orgs` and `module-crm` already use) instead of only capped from
  above, so a zero limit is the default page rather than a page that looks
  full and hands back a next cursor for a page that cannot exist. A limit
  above the ceiling still clamps to `INBOX_PAGE_MAX`.

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
