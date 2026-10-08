# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`MailTheme::header_bg` / `header_text` and `display_font`** (issue
  #840), all opt-in: a solid header band behind the logo row, joined to
  the card (inline, so Gmail keeps it), and a heading font stack. Both are
  sanitised like the other colours and fonts; unset, every mail renders as
  before.

## [0.1.1](https://github.com/Cratefield/harness/compare/cratefield-mail-templates-v0.1.0...cratefield-mail-templates-v0.1.1) - 2026-10-05

### Other

- one branded instance per app; cratefield-auth-* crates; Owlpost mail ([#778](https://github.com/Cratefield/harness/pull/778))

## [0.1.0](https://github.com/Cratefield/harness/releases/tag/cratefield-mail-templates-v0.1.0) - 2026-10-04

### Added

- *(mail-templates)* branded mail in each venture's own style for every module that sends mail ([#715](https://github.com/Cratefield/harness/pull/715)) ([#716](https://github.com/Cratefield/harness/pull/716))
- `MailTheme` (brand name, wordmark, hosted logo and alt text, light and dark
  `Palette`s, font stacks, radii, footer lines, contact), resolved from the
  venture's composition, its `MAIL_THEME` config, or its core `Brand`; and
  `MailTheme::cratefield()`, Cratefield's own theme.
- `Message`, a builder for one mail (heading, paragraphs, facts, primary
  button, fallback link, code, notes, recipient and reason, footer links,
  `lang` and `dir`) rendering an email-client-safe HTML part with a dark
  variant and a plain-text twin, every value escaped
  ([#715](https://github.com/Cratefield/harness/issues/715)).
