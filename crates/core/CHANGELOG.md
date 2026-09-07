# Changelog

All notable changes to `cratefield-core` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-09-06

### Added

- `Module::well_known()`: a module can serve routes at `/.well-known` at
  the root (OIDC `openid-configuration`, `jwks.json`), where discovery
  agents look for them. `Harness::build` fails naming every module when
  two both provide one; nothing but `/.well-known` is ever mounted at the
  root. (#46)
- `cratefield_core::http::Form`: an `application/x-www-form-urlencoded`
  extractor re-exported beside `Json`, with the same 64 KiB body limit and
  the same problem+json rejections (`400 validation-failed`,
  `413 request-too-large`) — for cross-site `form_post` callbacks such as
  Sign in with Apple. axum's `form` feature is now enabled in the
  workspace dependency. (#46)
- Conformance kit (`cratefield-testing`): a module with a well-known router
  is checked to mount at the root under `/.well-known` and never under
  `/v1`. (#46)
