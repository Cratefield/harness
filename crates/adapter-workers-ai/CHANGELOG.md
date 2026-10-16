# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.2](https://github.com/Cratefield/harness/compare/cratefield-adapter-workers-ai-v0.3.1...cratefield-adapter-workers-ai-v0.3.2) - 2026-10-16

### Other

- updated the following local packages: cratefield-core

## [0.3.1](https://github.com/Cratefield/harness/compare/cratefield-adapter-workers-ai-v0.3.0...cratefield-adapter-workers-ai-v0.3.1) - 2026-10-15

### Added

- *(core)* Speech port — transcription and streamed synthesis, with Workers AI and OpenAI-compatible adapters ([#861](https://github.com/Cratefield/harness/pull/861)) ([#868](https://github.com/Cratefield/harness/pull/868))

### Added

- `Speech` over the Workers AI binding (issue [#861](https://github.com/Cratefield/harness/issues/861)): `WorkersAiSpeech` transcribes with Deepgram Nova-3 (the default) or Whisper and synthesizes with Deepgram Aura, behind a `SpeechRunner` seam (`SpeechBinding` in production). Its default audio ceiling is lowered to `WORKERS_AI_MAX_AUDIO_BYTES`, because the binding takes the clip as a JSON number array.

## [0.3.0](https://github.com/Cratefield/harness/compare/cratefield-adapter-workers-ai-v0.2.1...cratefield-adapter-workers-ai-v0.3.0) - 2026-10-04

### Changed

- **Breaking:** requires `cratefield-core` 0.8 (was 0.7), and so a minor rather than a patch bump: a venture still on core 0.7 does not pick this release up through a caret requirement and end up with two copies of core ([#712](https://github.com/Cratefield/harness/issues/712)).

### Other

- updated the following local packages: cratefield-core

## [0.2.1](https://github.com/Cratefield/harness/compare/cratefield-adapter-workers-ai-v0.2.0...cratefield-adapter-workers-ai-v0.2.1) - 2026-10-03

### Other

- updated the following local packages: cratefield-core
