# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Speech` port conformance (issue [#861](https://github.com/Cratefield/harness/issues/861)): `speech_conformance` and `speech_conformance_not_configured`, with the shared fixture constants, behind the `port-conformance` feature.

## [0.5.1](https://github.com/Cratefield/harness/compare/cratefield-testing-v0.5.0...cratefield-testing-v0.5.1) - 2026-10-06

### Other

- Actor port: per-key serialized state with transactional storage and alarms, on Durable Objects ([#583](https://github.com/Cratefield/harness/pull/583)) ([#743](https://github.com/Cratefield/harness/pull/743))
- image inputs (Part::Image) for the Anthropic and OpenAI-compatible adapters ([#745](https://github.com/Cratefield/harness/pull/745))
- Blob port: streamed reads and writes, multipart uploads and listing for objects above MAX_BLOB_BYTES ([#586](https://github.com/Cratefield/harness/pull/586)) ([#741](https://github.com/Cratefield/harness/pull/741))

### Added

- TextModel image inputs (issue [#628](https://github.com/Cratefield/harness/issues/628)): the `text_model_image_bounds_conformance` port suite, and a `FakeTextModel` that answers image prompts and refuses an over-limit one before recording it.

## [0.5.0](https://github.com/Cratefield/harness/compare/cratefield-testing-v0.4.0...cratefield-testing-v0.5.0) - 2026-10-04

### Changed

- **Breaking:** requires `cratefield-core` 0.8 (was 0.7), and so a minor rather than a patch bump: a venture still on core 0.7 does not pick this release up through a caret requirement and end up with two copies of core ([#712](https://github.com/Cratefield/harness/issues/712)).

### Other

- tool calling (ToolSpec, tool_calls, run_tool_loop) across the Anthropic and OpenAI-compatible adapters ([#665](https://github.com/Cratefield/harness/pull/665)) ([#705](https://github.com/Cratefield/harness/pull/705))

## [0.4.0](https://github.com/Cratefield/harness/compare/cratefield-testing-v0.3.0...cratefield-testing-v0.4.0) - 2026-10-03

### Added

- *(testing)* signed-delivery helpers and Owlpost/Colonizer HTTP fakes ([#666](https://github.com/Cratefield/harness/pull/666)) ([#686](https://github.com/Cratefield/harness/pull/686))
- *(core)* [**breaking**] name problem `type` URIs under the venture's own base ([#557](https://github.com/Cratefield/harness/pull/557)) ([#581](https://github.com/Cratefield/harness/pull/581))

### Other

- Blob port: presigned GET and PUT URLs for R2 through the S3 API (SigV4) ([#622](https://github.com/Cratefield/harness/pull/622)) ([#663](https://github.com/Cratefield/harness/pull/663))
- Stream request and response bodies for routes a module declares ([#585](https://github.com/Cratefield/harness/pull/585)) ([#635](https://github.com/Cratefield/harness/pull/635))
- Usage metering: per-subject, per-period counters with an atomic check-and-increment ([#588](https://github.com/Cratefield/harness/pull/588)) ([#634](https://github.com/Cratefield/harness/pull/634))
- CustomHostnames port in core, with a Cloudflare for SaaS adapter ([#590](https://github.com/Cratefield/harness/pull/590)) ([#630](https://github.com/Cratefield/harness/pull/630))
- comment op, inbound status webhooks, Freshdesk destination and the Jira Cloud adapter (#559, part 1) ([#582](https://github.com/Cratefield/harness/pull/582))
- VectorIndex and Embedder ports, with Cloudflare Vectorize and exact in-process adapters ([#561](https://github.com/Cratefield/harness/pull/561)) ([#568](https://github.com/Cratefield/harness/pull/568))
- OpenAI-compatible adapter, cached-token usage on every completion, shared TextModel conformance suite ([#560](https://github.com/Cratefield/harness/pull/560)) ([#567](https://github.com/Cratefield/harness/pull/567))
