# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/Cratefield/harness/releases/tag/factory0-runtime-cloudflare-v0.1.0) - 2026-09-07

### Added

- *(ui)* factory0-ui renders the surface; /ui pages, fragments, in-process dispatch ([#72](https://github.com/Cratefield/harness/pull/72))
- *(core)* modules declare a UI surface; GET /__surface ([#70](https://github.com/Cratefield/harness/pull/70))
- *(core,runtime,readme)* observability - request span, error taxonomy doc, health detail ([#14](https://github.com/Cratefield/harness/pull/14))
- *(core,cli,modules)* security baseline - doctor override, redaction rules, retention, privacy/security docs ([#13](https://github.com/Cratefield/harness/pull/13))
- *(testing)* conformance kit, fake ports, in-memory Database, request helpers ([#9](https://github.com/Cratefield/harness/pull/9))
- *(runtime-cloudflare)* Workers entry points, bindings to ports, D1, KV, rate limiting, HttpClient ([#5](https://github.com/Cratefield/harness/pull/5))

### Fixed

- *(runtime-cloudflare)* never attach a body to a GET

### Other

- Mount a module on a service binding: Dispatcher port and mount table ([#60](https://github.com/Cratefield/harness/pull/60))
- Rehome the harness under Cratefield
- crate READMEs + rustdoc includes, doc warnings denied in CI ([#16](https://github.com/Cratefield/harness/pull/16))
- release-plz pipeline for crates.io ([#15](https://github.com/Cratefield/harness/pull/15))
