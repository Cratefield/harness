# Changelog

All notable changes to `factory0-core` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0](https://github.com/Cratefield/harness/releases/tag/factory0-core-v0.3.0) - 2026-09-07

### Added

- *(core, ui)* merge sidecar surfaces into GET /__surface and the /ui pages ([#76](https://github.com/Cratefield/harness/pull/76))
- *(ui)* UiSpec v1 — copy, order, hidden fields and theme as validated JSON; ui-llms.txt ([#75](https://github.com/Cratefield/harness/pull/75))
- *(ui)* admin pages — token login with a signed session cookie, tables over exports, two-step delete ([#74](https://github.com/Cratefield/harness/pull/74))
- *(ui)* factory0-ui renders the surface; /ui pages, fragments, in-process dispatch ([#72](https://github.com/Cratefield/harness/pull/72))
- *(modules)* email-signup, waitlist and module-hello declare their surfaces ([#71](https://github.com/Cratefield/harness/pull/71))
- *(core)* modules declare a UI surface; GET /__surface ([#70](https://github.com/Cratefield/harness/pull/70))
- parity suite — module tests on SQLite and Postgres from one definition ([#20](https://github.com/Cratefield/harness/pull/20))
- adapter-postgres — Database over sqlx with the migration runner
- *(core,runtime,readme)* observability - request span, error taxonomy doc, health detail ([#14](https://github.com/Cratefield/harness/pull/14))
- *(core,cli,modules)* security baseline - doctor override, redaction rules, retention, privacy/security docs ([#13](https://github.com/Cratefield/harness/pull/13))
- *(module-email-signup,module-waitlist)* askama mail templates, branding, previews ([#12](https://github.com/Cratefield/harness/pull/12))
- *(module-email-signup)* double opt-in signup ([#10](https://github.com/Cratefield/harness/pull/10))
- *(testing)* conformance kit, fake ports, in-memory Database, request helpers ([#9](https://github.com/Cratefield/harness/pull/9))
- *(adapter-sqlite,cli)* rusqlite Database, fz migrations collect/doctor/modules ([#8](https://github.com/Cratefield/harness/pull/8))
- *(runtime-cloudflare)* Workers entry points, bindings to ports, D1, KV, rate limiting, HttpClient ([#5](https://github.com/Cratefield/harness/pull/5))
- *(core)* in-process event bus and template registry ([#4](https://github.com/Cratefield/harness/pull/4))
- *(core)* port traits complete, typed config, HMAC Signer ([#3](https://github.com/Cratefield/harness/pull/3))
- *(core)* Module trait, Harness builder, axum assembly, problem+json, Scope ([#2](https://github.com/Cratefield/harness/pull/2))
- *(workspace)* scaffold, toolchain pin, lints, deny, example venture, CI ([#1](https://github.com/Cratefield/harness/pull/1))

### Fixed

- two M1 defects that broke every request on Workers

### Other

- Forward the caller's path, not the nest remainder
- Mount a module on a service binding: Dispatcher port and mount table ([#60](https://github.com/Cratefield/harness/pull/60))
- ADR 0010: modules declare a UI surface; the harness renders it
- Style the diagrams instead of leaving them on Mermaid's defaults
- Rehome the harness under Cratefield
- Document the two mounts, and correct a stale status badge
- Merge pull request #52 from Factory-Zero/feat/adapter-postgres
- Merge main into feat/contract-versioning
- Merge main (wasm panic and example mailer hotfix) into feat/well-known-routes
- Merge pull request #45 from Factory-Zero/feat/m0-foundation
- *(core)* assert handler-observed scope in the one-router concurrency test
- Initial design and repo skeleton (Rust)

## [0.2.0] — 2026-09-06

### Added

- `Module::well_known()`: a module can serve routes at `/.well-known` at
  the root (OIDC `openid-configuration`, `jwks.json`), where discovery
  agents look for them. `Harness::build` fails naming every module when
  two both provide one; nothing but `/.well-known` is ever mounted at the
  root. (#46)
- `factory0_core::http::Form`: an `application/x-www-form-urlencoded`
  extractor re-exported beside `Json`, with the same 64 KiB body limit and
  the same problem+json rejections (`400 validation-failed`,
  `413 request-too-large`) — for cross-site `form_post` callbacks such as
  Sign in with Apple. axum's `form` feature is now enabled in the
  workspace dependency. (#46)
- Conformance kit (`factory0-testing`): a module with a well-known router
  is checked to mount at the root under `/.well-known` and never under
  `/v1`. (#46)
