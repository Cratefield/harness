# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/Cratefield/harness/releases/tag/factory0-ui-v0.1.0) - 2026-09-07

### Added

- *(core, ui)* merge sidecar surfaces into GET /__surface and the /ui pages ([#76](https://github.com/Cratefield/harness/pull/76))
- *(ui)* UiSpec v1 — copy, order, hidden fields and theme as validated JSON; ui-llms.txt ([#75](https://github.com/Cratefield/harness/pull/75))
- *(ui)* admin pages — token login with a signed session cookie, tables over exports, two-step delete ([#74](https://github.com/Cratefield/harness/pull/74))
- *(ui)* cf.js embed — fetches and swaps /ui fragments, 4 KB gate, jsdom test against wrangler dev ([#73](https://github.com/Cratefield/harness/pull/73))
- *(ui)* factory0-ui renders the surface; /ui pages, fragments, in-process dispatch ([#72](https://github.com/Cratefield/harness/pull/72))

### Other

- example site + venture guide: embed and restyle the forms with only CSS ([#77](https://github.com/Cratefield/harness/pull/77))
- review pass — never log dispatched bodies, keep 429 as 429, drop unused params
