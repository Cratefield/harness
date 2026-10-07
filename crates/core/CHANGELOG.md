# Changelog

All notable changes to `cratefield-core` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.2](https://github.com/Cratefield/harness/compare/cratefield-core-v0.8.1...cratefield-core-v0.8.2) - 2026-10-07

### Fixed

- close eight concurrency races across the pool cache, auth caches, realtime rooms, waitlist confirms and tracker adapters ([#823](https://github.com/Cratefield/harness/pull/823))

### Added

- **A provider-neutral billing lifecycle, in `billing`** (issue #593,
  ADR 0025). New pure types and functions — `LifecycleEvent` and its
  `LifecycleKind`, `Status`, `SubscriptionState`, `LifecyclePolicy`,
  `transition` and `gives_access` — that map a Stripe or RevenueCat
  webhook onto a state and answer whether it grants access, with no I/O
  and no vendor payload parsing (that stays in the adapters, issues #600
  and #601). Additive: no existing API changed and `HARNESS_API` is
  untouched.
- TextModel image inputs (issue [#628](https://github.com/Cratefield/harness/issues/628)): `Part` (`Text`/`Image`), `Turn::user_parts`, `Prompt::user_parts`, `Prompt::has_images`, `Prompt::check_images`, `Capability::Images`, `TextModelError::ImageLimit`, the `encode_image`/`encoded_image_len` helpers, and the `MAX_PROMPT_IMAGES`/`MAX_IMAGE_ENCODED_BYTES`/`MAX_PROMPT_IMAGE_ENCODED_BYTES` bounds. The router and `run_tool_loop` gate `Capability::Images` like `Capability::Tools`.
- `StatusOnly`, a request marker asking for the status line alone. An
  implementation that honours it returns no body and no body-describing
  headers, because there is no body to describe — cheaper than `HEAD`
  where the endpoint is already known and only liveness is wanted. It
  rides as a request extension exactly as `HttpPolicy` does and waives
  the body, not the ceilings; an implementation that does not read the
  extension answers the request like any other
  ([#714](https://github.com/Cratefield/harness/issues/714)).

## [0.8.1](https://github.com/Cratefield/harness/compare/cratefield-core-v0.8.0...cratefield-core-v0.8.1) - 2026-10-05

### Other

- Stripe customer portal sessions and subscription lookup ([#589](https://github.com/Cratefield/harness/pull/589)) ([#740](https://github.com/Cratefield/harness/pull/740))
- schema-validated structured output (complete_json / complete_as) ([#739](https://github.com/Cratefield/harness/pull/739))
- Venture CORS: accept browser-extension origins (chrome-extension, moz-extension, safari-web-extension) ([#737](https://github.com/Cratefield/harness/pull/737))
- Inbound mail: a verify-then-parse source in core, a Resend inbound adapter, and ADR 0028 for channels ([#563](https://github.com/Cratefield/harness/pull/563)) ([#734](https://github.com/Cratefield/harness/pull/734))

## [0.8.0](https://github.com/Cratefield/harness/compare/cratefield-core-v0.7.0...cratefield-core-v0.8.0) - 2026-10-04

### Added

- `TextModel` tool calling (`ToolSpec`, `tool_calls`, `run_tool_loop`) across the Anthropic and OpenAI-compatible adapters ([#665](https://github.com/Cratefield/harness/pull/665)) ([#705](https://github.com/Cratefield/harness/pull/705))

### Changed

- **Breaking** (found by cargo-semver-checks): `ports::text_model::Turn` is
  now `#[non_exhaustive]` and no longer derives `Eq`, so it is built with
  `Turn::user`, `Turn::assistant`, `Turn::assistant_tool_calls` or
  `Turn::tool_results` rather than a struct literal; `TextModelError` is now
  `#[non_exhaustive]`, so a `match` on it outside core needs a wildcard arm
  ([#705](https://github.com/Cratefield/harness/pull/705)).

## [0.7.0](https://github.com/Cratefield/harness/compare/cratefield-core-v0.6.0...cratefield-core-v0.7.0) - 2026-10-03

### Added

- *(core)* [**breaking**] add Destination::Colonizer { repo } and RoutingTracker::colonizer ([#676](https://github.com/Cratefield/harness/pull/676)) ([#687](https://github.com/Cratefield/harness/pull/687))
- *(core)* [**breaking**] name problem `type` URIs under the venture's own base ([#557](https://github.com/Cratefield/harness/pull/557)) ([#581](https://github.com/Cratefield/harness/pull/581))

### Other

- Blob port: presigned GET and PUT URLs for R2 through the S3 API (SigV4) ([#622](https://github.com/Cratefield/harness/pull/622)) ([#663](https://github.com/Cratefield/harness/pull/663))
- report metered usage to Stripe Billing Meters, idempotently ([#662](https://github.com/Cratefield/harness/pull/662))
- App JWTs, cached installation tokens, and a named GitHub webhook scheme ([#623](https://github.com/Cratefield/harness/pull/623)) ([#637](https://github.com/Cratefield/harness/pull/637))
- Webhook verification: Vercel (HMAC-SHA1) and GitLab (shared-token) schemes ([#636](https://github.com/Cratefield/harness/pull/636))
- Stream request and response bodies for routes a module declares ([#585](https://github.com/Cratefield/harness/pull/585)) ([#635](https://github.com/Cratefield/harness/pull/635))
- Usage metering: per-subject, per-period counters with an atomic check-and-increment ([#588](https://github.com/Cratefield/harness/pull/588)) ([#634](https://github.com/Cratefield/harness/pull/634))
- CustomHostnames port in core, with a Cloudflare for SaaS adapter ([#590](https://github.com/Cratefield/harness/pull/590)) ([#630](https://github.com/Cratefield/harness/pull/630))
- ADR 0025: provider-neutral billing lifecycle, entitlements and revenue ledger, fed by Stripe and RevenueCat ([#592](https://github.com/Cratefield/harness/pull/592)) ([#631](https://github.com/Cratefield/harness/pull/631))
- Route policy: let one module declare a signature verifier per webhook route ([#595](https://github.com/Cratefield/harness/pull/595)) ([#632](https://github.com/Cratefield/harness/pull/632))
- comment op, inbound status webhooks, Freshdesk destination and the Jira Cloud adapter (#559, part 1) ([#582](https://github.com/Cratefield/harness/pull/582))
- VectorIndex and Embedder ports, with Cloudflare Vectorize and exact in-process adapters ([#561](https://github.com/Cratefield/harness/pull/561)) ([#568](https://github.com/Cratefield/harness/pull/568))
- OpenAI-compatible adapter, cached-token usage on every completion, shared TextModel conformance suite ([#560](https://github.com/Cratefield/harness/pull/560)) ([#567](https://github.com/Cratefield/harness/pull/567))
- Production readiness fails when a module declares RateLimiter and none is mounted; a missing Workers limiter binding fails closed ([#562](https://github.com/Cratefield/harness/pull/562)) ([#569](https://github.com/Cratefield/harness/pull/569))

### Changed

- **Breaking — problem `type` URIs are named under the serving venture's
  own base.** `Problem::type_uri` now takes the venture's base as its
  argument, so the next release is 0.7.0 (a breaking change is a minor
  bump under 0.x): `type` is `<public_url>/problems/<slug>` — derived
  from the venture's `public_url`, overridable with the new
  `Venture::problem_base(..)` — and `about:blank` (RFC 9457 §4.2.1) for a
  venture with no public URL, instead of one hard-coded
  `https://factory0.ventures/problems/` base for every venture.
  `Problem::into_response` renders the context-free `about:blank` and
  stores the problem in the response extensions; the harness's outermost
  layer re-renders the body under the venture's base, so every path that
  serves a problem — module handlers, the tenant and readiness gates,
  rejections, 429s — names the venture it served for; the runtimes'
  pre-router refusals (native `421`, Worker `413` and unresolved-limiter
  `503`) name it through the new `Problem::into_response_with_base`. Clients must match
  on the slug — the part after `/problems/`, `auth/…` namespaces
  included — never on the full URI. The
  slug list is unchanged (docs/ERRORS.md). (#557)

A breaking change is pending here: `Destination` is an exhaustive enum and
gained `Freshdesk` and `Colonizer`, so a `match` over it no longer compiles
unchanged; the next release of core is therefore 0.7.0, not 0.6.1.

### Added

- **`Payments` carries a Merchant of Record (ADR 0027).** New optional
  methods, each with a default, so every existing adapter compiles
  unchanged and `HARNESS_API` stays 1:
  `verify_webhook_request(&HeaderMap, body)` for providers that sign over
  several headers (Standard Webhooks; the default reads
  `Stripe-Signature`); `create_portal_session` with
  `PortalSessionRequest`/`PortalSession` in issue #589's shape; and
  `get_dispute`, `list_disputes` and `close_dispute` with `Dispute`,
  `DisputeStatus`, `DisputePhase`, `DisputeListRequest` and `DisputePage`
  in issue #602's shape. `DisputeStatus::phase()` folds a provider status
  into `Open`/`Won`/`Lost`/`Closed`; `Dispute::event_key()` is the `Inbox`
  key for one transition. The defaults answer
  `PaymentsError::Unsupported`. (#690)
- **`Tracker::comment`** and **`TicketComment`**: add a note (optionally
  linking a URL) to an existing ticket, so a duplicate report links into the
  ticket it duplicates. The default impl refuses with
  `TrackerError::Rejected` naming the tracker, so existing adapters compile
  unchanged; `RoutingTracker` forwards it by destination. (#559)
- **Inbound status webhooks**: the `StatusWebhook` trait, `StatusUpdate`,
  `InboundStatusError` and `receive_status`, which verifies a delivery with
  core's `WebhookVerifier` before the adapter ever parses it. (#559)
- **`Destination::Freshdesk { domain }`** and `RoutingTracker::freshdesk`;
  no adapter ships for it yet. (#559)
- **`Destination::Colonizer { repo }`** and `RoutingTracker::colonizer`;
  no adapter ships for it yet. (#676)
- `TicketState` is now `Serialize`/`Deserialize` (snake case), so a state can
  cross the inbound webhook wire. (#559)

### Changed

- `Destination::Jira { site }` is documented as the bare hostname
  (`acme.atlassian.net`), not the hostname prefix: the new
  `cratefield-adapter-jira` refuses anything else, so the Basic credential
  cannot be sent to another host. (#559)

## [0.6.0] — 2026-09-28

A breaking release: `Port` is an exhaustive enum and gained `TextModel`,
`Tracker`, `Classifier` and `Auth` since 0.5.0, so a `match` over it no longer
compiles unchanged. Every published dependent is re-released against `^0.6` in
the same round, so the crates.io set resolves on one core again (#462, #464,
#558).

### Added

- **`webhook_signature`**: a generic HMAC-SHA256 webhook verifier
  (`WebhookVerifier`) with pluggable schemes (`Svix`, `StripeStyle`,
  `ProviderScheme`), plus `SignatureVerification` and a defaulted
  `Module::signature_verification()`, so a `RoutePolicy::Signature` route can
  be proved by a `webhook_signature` scheme instead of the `Payments` port;
  the boot gate then checks the module's secret key
  (`webhook_secret_readiness`) in place of the `Payments` leg. (#533)

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
