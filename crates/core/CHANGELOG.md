# Changelog

All notable changes to `cratefield-core` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] — 2026-09-12

A major bump because it has to be: `cargo semver-checks` against the
published 0.3.1 reports **11 major and 0 minor** failures. Under 0.x that is
0.4.0. Every item under *Changed* below is one the tool found, not one read
off the commit log.

Note also that 0.3.0 and 0.3.1 were published without entries here; this one
covers the surface as it stands against 0.3.1.

### Changed

- **`Database::batch` is gone.** `batch_atomic` replaces it and has no default
  implementation, so every `Database` must provide it — the point being that a
  batch is all-or-nothing by contract rather than by hope. (#126)
- **Structs that could be built from a literal no longer can**, having gained
  public fields: `ModuleContext` (`unprotected_writes_accepted`,
  `personal_data`), `Ports` (`realtime`, `tenants`), `HarnessConfig`
  (`harness_secret_revoked`, `harness_venture`), `Action` (`policy`) and
  `Notification` (`icon`, `url`, `ttl`, `badge`, `silent`, `loc`).
- **`Message` and `SqlMigration` are `#[non_exhaustive]`**, as are the `Kid`
  and `SignerError` enums — so literals and exhaustive matches on them need a
  rest pattern. (#255)
- **`Port` gained `Realtime`**, which shifted the discriminants of
  `HttpClient` (9 → 10), `Clock` (10 → 11), `IdGen` (11 → 12) and `Defer`
  (12 → 13). Code casting a `Port` with `as isize` gets a different number.
- **`PushError::Transient` changed shape**, and `SignerError`/`Kid` no longer
  have well-defined discriminants because they now carry data.
- **New variants on exhaustive enums**: `BlobError::TooLarge`,
  `HttpError::{ResponseTooLarge, DeadlineExceeded, BlockedDestination}`,
  `SignatureError::{WrongScope, RevokedKey}`.
- **`Kid` no longer derives `Copy`**, and **`HmacSigner` is no longer
  `UnwindSafe` or `RefUnwindSafe`**.

### Added

The public surface went from 227 items to 362. The larger pieces:

- **`Outbox`** — persist-before-defer delivery, so queued work survives the
  request that created it, with a `subject` column that keeps a queued row
  inside export and erasure. (#128, #266)
- **The personal-data catalogue** — `PersonalDataSet`, `PersonalDataCatalog`,
  `Disposition`, `CatalogEntry`: every module declares what it holds about a
  person, and a table erasure cannot reach is published as its own fact
  rather than as "not personal data". (#244, #272, #274, #291)
- **Tenancy** — `Tenant`, `TenantId`, `TenantConn` and tenant resolution. (#32)
- **Sidecar boundaries** — events cross inbound only, identity and contract
  per response rather than at cold start, and a sidecar's tables are visible
  to the collision check. (#61, #62, #66)
- **Boot-time reconciliation**, per module and per tenant. (#30)
- **`Realtime` and `Blob` ports**, and `Module::well_known` routing.

### Fixed

- A transport failure never reports the request URL. (#229)
- One `origin_of`, used by the CSP builder. (#215)
- One `Retry-After` parser, and APNs reads the date form. (#213, #214)
- A table omitted from `tables()` no longer escapes every personal-data
  check. (#272)

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
