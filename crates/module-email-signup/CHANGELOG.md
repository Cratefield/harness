# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0](https://github.com/Cratefield/harness/compare/cratefield-module-email-signup-v0.3.0...cratefield-module-email-signup-v0.4.0) - 2026-10-04

### Added

- *(mail-templates)* branded mail in each venture's own style for every module that sends mail ([#715](https://github.com/Cratefield/harness/pull/715)) ([#716](https://github.com/Cratefield/harness/pull/716))

### Changed

- **Breaking:** requires `cratefield-core` 0.8 (was 0.7), and so a minor rather than a patch bump: a venture still on core 0.7 does not pick this release up through a caret requirement and end up with two copies of core ([#712](https://github.com/Cratefield/harness/issues/712)).
- The confirmation and welcome mails render through `cratefield-mail-templates`
  in the venture's theme (layout, dark variant, preheader, text twin),
  replacing the askama templates; subjects are unchanged and the unsubscribe
  link moves to the footer. `themed_templates(&theme)` composes the venture's
  own `MailTheme`; `default_templates()` uses the theme resolved from the
  venture's `Brand` and `MAIL_THEME`
  ([#715](https://github.com/Cratefield/harness/issues/715)).

## [0.3.0](https://github.com/Cratefield/harness/compare/cratefield-module-email-signup-v0.2.0...cratefield-module-email-signup-v0.3.0) - 2026-10-03

### Added

- *(core)* [**breaking**] name problem `type` URIs under the venture's own base ([#557](https://github.com/Cratefield/harness/pull/557)) ([#581](https://github.com/Cratefield/harness/pull/581))
