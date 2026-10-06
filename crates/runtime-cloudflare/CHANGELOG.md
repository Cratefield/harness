# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- The response body is read as a stream under the `HttpPolicy` cap, so an
  upstream that never declares a `content-length` is refused at the chunk
  that crosses the cap rather than buffered first. Reading stops there and
  drops the platform's handle on the fetch, so an endless body costs one
  chunk past the cap instead of the isolate's memory. The platform offers
  no stream at all for a null-body status (204/205/304, or the reply to a
  `HEAD`), which is read as an empty body rather than a failed send, so
  the cap does not cost those replies the buffered read used to answer
  ([#714](https://github.com/Cratefield/harness/issues/714)).
- Redirects are answered, not taken: the transport request asks for
  `redirect: "manual"`, so no upstream can move the exchange to another
  host or down to `http` after the destination was vetted
  ([#714](https://github.com/Cratefield/harness/issues/714)).

### Added

- `StatusOnly` request marker honoured: a request carrying it is answered
  from the status line alone, its body never read, and its
  body-describing headers (`Content-Length`, `Content-Encoding`,
  `Transfer-Encoding`) dropped, so a liveness probe of a large resource
  does not fail on a length it never asked for
  ([#714](https://github.com/Cratefield/harness/issues/714)).

## [0.4.0](https://github.com/Cratefield/harness/compare/cratefield-runtime-cloudflare-v0.3.0...cratefield-runtime-cloudflare-v0.4.0) - 2026-10-04

### Changed

- **Breaking:** requires `cratefield-core` 0.8 (was 0.7), and so a minor rather than a patch bump: a venture still on core 0.7 does not pick this release up through a caret requirement and end up with two copies of core ([#712](https://github.com/Cratefield/harness/issues/712)).

### Other

- updated the following local packages: cratefield-core

## [0.3.0](https://github.com/Cratefield/harness/compare/cratefield-runtime-cloudflare-v0.2.0...cratefield-runtime-cloudflare-v0.3.0) - 2026-10-03

### Added

- *(core)* [**breaking**] name problem `type` URIs under the venture's own base ([#557](https://github.com/Cratefield/harness/pull/557)) ([#581](https://github.com/Cratefield/harness/pull/581))

### Other

- Blob port: presigned GET and PUT URLs for R2 through the S3 API (SigV4) ([#622](https://github.com/Cratefield/harness/pull/622)) ([#663](https://github.com/Cratefield/harness/pull/663))
- Stream request and response bodies for routes a module declares ([#585](https://github.com/Cratefield/harness/pull/585)) ([#635](https://github.com/Cratefield/harness/pull/635))
- CustomHostnames port in core, with a Cloudflare for SaaS adapter ([#590](https://github.com/Cratefield/harness/pull/590)) ([#630](https://github.com/Cratefield/harness/pull/630))
- VectorIndex and Embedder ports, with Cloudflare Vectorize and exact in-process adapters ([#561](https://github.com/Cratefield/harness/pull/561)) ([#568](https://github.com/Cratefield/harness/pull/568))
- Production readiness fails when a module declares RateLimiter and none is mounted; a missing Workers limiter binding fails closed ([#562](https://github.com/Cratefield/harness/pull/562)) ([#569](https://github.com/Cratefield/harness/pull/569))
