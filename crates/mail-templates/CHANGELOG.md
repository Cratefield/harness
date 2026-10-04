# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `MailTheme` (brand name, wordmark, hosted logo and alt text, light and dark
  `Palette`s, font stacks, radii, footer lines, contact), resolved from the
  venture's composition, its `MAIL_THEME` config, or its core `Brand`; and
  `MailTheme::cratefield()`, Cratefield's own theme.
- `Message`, a builder for one mail (heading, paragraphs, facts, primary
  button, fallback link, code, notes, recipient and reason, footer links,
  `lang` and `dir`) rendering an email-client-safe HTML part with a dark
  variant and a plain-text twin, every value escaped
  ([#715](https://github.com/Cratefield/harness/issues/715)).
