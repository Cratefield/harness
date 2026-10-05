# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1](https://github.com/Cratefield/harness/compare/cratefield-adapter-openai-compatible-v0.2.0...cratefield-adapter-openai-compatible-v0.2.1) - 2026-10-05

### Other

- schema-validated structured output (complete_json / complete_as) ([#739](https://github.com/Cratefield/harness/pull/739))

## [0.2.0](https://github.com/Cratefield/harness/compare/cratefield-adapter-openai-compatible-v0.1.0...cratefield-adapter-openai-compatible-v0.2.0) - 2026-10-04

### Changed

- **Breaking:** requires `cratefield-core` 0.8 (was 0.7), and so a minor rather than a patch bump: a venture still on core 0.7 does not pick this release up through a caret requirement and end up with two copies of core ([#712](https://github.com/Cratefield/harness/issues/712)).

### Other

- tool calling (ToolSpec, tool_calls, run_tool_loop) across the Anthropic and OpenAI-compatible adapters ([#665](https://github.com/Cratefield/harness/pull/665)) ([#705](https://github.com/Cratefield/harness/pull/705))

## [0.1.0](https://github.com/Cratefield/harness/releases/tag/cratefield-adapter-openai-compatible-v0.1.0) - 2026-10-03

### Other

- OpenAI-compatible adapter, cached-token usage on every completion, shared TextModel conformance suite ([#560](https://github.com/Cratefield/harness/pull/560)) ([#567](https://github.com/Cratefield/harness/pull/567))
