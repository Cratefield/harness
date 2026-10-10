# ADR 0029: Speech is its own port, limits checked before the network

Status: accepted, 2026-10-09. Issue #861. Extends ADR 0002 (ports and
adapters) with the `Speech` port; ADR 0028 recorded speech as shape
only — this one ships it.

## Context

A module that takes a voicemail, a support call or a spoken reminder
needs two things the harness has no home for: audio in, answered as
text, and text, answered as audio. Both are vendor-shaped surfaces —
Whisper's multipart form, Deepgram's models and voices, OpenAI's
`/audio/*` wire — and `TextModel` is completions by design (embeddings
live on `Embedder`, streaming stays out), so bolting audio onto it
would change the call shape every adapter and module already agrees
on.

## Decision

**A `Speech` port of its own**: `transcribe` and `synthesize` — the
port's two directions — plus `voices(language)` and the two facts a
caller shapes its ask from, `capabilities()` and `limits()`. A module
holds `Arc<dyn Speech>` and asks by capability, never by vendor, the
way `TextModel` names a tier. There is no outcome enum: audio either
came back or it did not, so an unwired port answers
`SpeechError::NotConfigured`, and `NotConfiguredSpeech` is the
standing placeholder.

**Limits are local, before any network call.** Every adapter runs
`check_transcribe` / `check_synthesize` at the top of the call, so an
over-limit ask is refused with `SpeechError::LimitExceeded` — naming
the ceiling and both sizes — without being paid for, the same rule
`Prompt::check_images` enforces on the text model. The defaults are
OpenAI's documented caps (25 MiB, ten minutes, 4 096 characters), so
an adapter wired to that provider is honest without configuration; a
caller that knows better declares the clip's length, and otherwise a
WAV's own header is read — pure arithmetic, no codec dependency. One
default is an adapter's own: the Workers AI binding takes the clip as
a JSON number array (~32 encoded bytes per audio byte, copied again
into a JavaScript array), so `WorkersAiSpeech` lowers `max_audio_bytes`
to 1 MiB — at the port's 25 MiB a clip would outrun a 128 MB isolate
before `LimitExceeded` could answer.

**Usage rides back in the provider's billing units.** `SpeechUsage` is
`audio_millis` and `characters` — milliseconds transcribed, characters
synthesised — so a spend cap meters what the provider bills without
the harness holding a price list.

**Synthesis streams through `ResponseStream`.** A provider that
streams starts yielding audio before the clip is finished; the port's
shape is the stream, and `SpeechCapabilities::streaming_output` says
whether a given adapter can honour it.

**Adapters are modules of existing crates, not new crates.**
`cratefield-adapter-workers-ai` adds the binding transport — Deepgram
nova-3 (or `@cf/openai/whisper*`) for STT, Deepgram aura-2-en and
aura-1 for TTS, streamed chunk by chunk off the binding's byte
stream — and `cratefield-adapter-openai-compatible` adds the audio
wire: multipart `/audio/transcriptions` with `verbose_json` word
timings, and `/audio/speech`, the base URL a builder argument, so a
Regolo-hosted Whisper differs from OpenAI by one call. The Workers AI
adapter is deliberately not a facade feature, for the same reason as
the classifier's third adapter: it depends on the `worker` crate, so
a Workers venture depends on it directly and a native venture never
pulls `worker` through `cratefield`. `speech_conformance`, in the
testing crate, pins the contract against both adapters from recorded
fixtures.

**No `Port::Speech` variant yet.** The `Ports` wiring — `requires()`,
composition failure, the `/__ready` answer — is deferred to a
follow-up so this change does not collide with concurrent work in
`ports/mod.rs`; until it lands, a venture wires the port by hand.

## Consequences

- OpenAI-compatible synthesis is buffered: `HttpClient::send` reads
  the whole body, so the answer leaves as one chunk and the adapter
  reports `streaming_output: false`, honestly. A streaming client
  (issue #859) raises the flag without a port change; the binding
  adapter streams today.
- Both families refuse identically before the network, and an
  over-limit refusal never reaches either provider.
- Voices are a provider fact, not a local allowlist: the Workers AI
  adapter synthesizes any non-empty speaker id (strict mode opt-in),
  because a local list would refuse ids the provider accepts as it
  adds speakers.
- The `Port::Speech` follow-up must add the variant, the `Port::ALL`
  entry and the readiness answer in one change, or composition and
  the wire disagree.

## References

- Issue #861; `crates/core/src/ports/speech.rs`,
  `crates/testing/src/speech.rs`, and the `speech` modules of
  `crates/adapter-workers-ai` and `crates/adapter-openai-compatible`;
  ADR 0002, ADR 0022 (an adapter stays out of the facade when it
  needs the `worker` crate), ADR 0028 (speech recorded as shape
  only).
- OpenAI audio API limits (the defaults behind `SpeechLimits`);
  Cloudflare Workers AI model catalogue (`@cf/deepgram/nova-3`,
  `@cf/openai/whisper*`, `@cf/deepgram/aura-2-en`, `aura-1`).
