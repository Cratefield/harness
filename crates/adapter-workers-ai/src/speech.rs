//! The [`Speech`] port over the Cloudflare Workers AI binding (issue #861):
//! Deepgram's Nova for speech-to-text and Aura for text-to-speech, reached
//! through `env.AI.run(...)` — no API key, billed to the venture's
//! Cloudflare account, exactly the transport the `Classifier` half uses.
//!
//! The binding cannot be constructed off wasm, so the call goes through
//! the narrow [`SpeechRunner`] seam and is testable natively with a fake.
//! The audio answer is a `worker::ByteStream`, which is `!Send`; a Workers
//! isolate is single-threaded, so `SendAudioStream` re-marks the boxed
//! stream `Send`, and TTS streams through [`ResponseStream`] unbuffered.
//!
//! The Aura voices are English-only while the transcription models are
//! multilingual, so `capabilities().languages` (`en`) is enforced by
//! [`check_synthesize`] on synthesis only and a transcription
//! `language_hint` rides to the provider. A speaker id the provider does
//! not know rides too — [`WorkersAiSpeech::with_strict_voices`] turns a
//! local refusal on for ventures that want one.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures_core::Stream;
use serde_json::Value;
use worker::send::{IntoSendFuture, SendWrapper};

use crate::{BINDING_MARKERS, TRANSIENT_MARKERS};
use cratefield_core::{
    AudioFormat, BoxStream, ResponseStream, Speech, SpeechCapabilities, SpeechError, SpeechLimits,
    SpeechUsage, StreamError, Synthesis, SynthesizeRequest, TranscribeRequest, Transcript, Voice,
    WordTiming, check_synthesize, check_transcribe, primary_subtag, scrub_text, wav_duration,
};

/// The speech seam, the sibling of [`AiRunner`](crate::AiRunner): one call
/// to the binding, a JSON document in and a JSON document or an audio byte
/// stream out. The error type is [`SpeechError`] itself, so a fake can
/// exercise every mapping.
#[async_trait]
pub trait SpeechRunner: Send + Sync {
    /// Runs one model call whose answer is a JSON document.
    ///
    /// # Errors
    /// Whatever `map_worker_error` makes of the binding's failure.
    async fn run_json(&self, model: &str, input: Value) -> Result<Value, SpeechError>;

    /// Runs one model call whose answer is a `Send` stream of audio
    /// bytes, the shape [`ResponseStream`] can hold.
    ///
    /// # Errors
    /// Whatever `map_worker_error` makes of the binding's failure.
    async fn run_audio(
        &self,
        model: &str,
        input: Value,
    ) -> Result<BoxStream<'static, Result<Bytes, StreamError>>, SpeechError>;
}

/// The real runner: the `env.AI` binding. No `unsafe` is needed to hold
/// the JS handle in a `Send + Sync` struct — `wasm-bindgen` declares
/// `JsValue` `Send + Sync`; only the call futures are `!Send`, which
/// `worker`'s `send` module fixes at the call site. Off wasm there is no
/// `Env` — hence the seam.
pub struct SpeechBinding(worker::Ai);

#[async_trait]
impl SpeechRunner for SpeechBinding {
    async fn run_json(&self, model: &str, input: Value) -> Result<Value, SpeechError> {
        self.0
            .run::<Value, Value>(model, input)
            .into_send()
            .await
            .map_err(|err| map_worker_error(&err))
    }

    async fn run_audio(
        &self,
        model: &str,
        input: Value,
    ) -> Result<BoxStream<'static, Result<Bytes, StreamError>>, SpeechError> {
        let stream = self
            .0
            .run_bytes(model, input)
            .into_send()
            .await
            .map_err(|err| map_worker_error(&err))?;
        let boxed: Box<dyn Stream<Item = Result<Vec<u8>, worker::Error>>> = Box::new(stream);
        Ok(Box::pin(SendAudioStream(SendWrapper::new(Pin::from(
            boxed,
        )))))
    }
}

/// The boxed worker audio stream `SendAudioStream` holds.
type BoxedByteStream = Pin<Box<dyn Stream<Item = Result<Vec<u8>, worker::Error>>>>;

/// A `worker::ByteStream` is `!Send`, but a Workers isolate is
/// single-threaded, which is what `worker::send::SendWrapper` is for:
/// boxing and wrapping gives [`SpeechRunner::run_audio`] the `Send +
/// 'static` stream it needs, with chunks as `Bytes` and a mid-stream
/// failure as a scrubbed [`StreamError::Transport`].
struct SendAudioStream(SendWrapper<BoxedByteStream>);

impl Stream for SendAudioStream {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // `Pin<Box<_>>` is `Unpin`, so the whole newtype is and `get_mut`
        // is sound; the boxed stream stays pinned.
        match self.get_mut().0.0.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => Poll::Ready(Some(Ok(Bytes::from(chunk)))),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(StreamError::Transport(
                scrub_text(&err.to_string()),
            )))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Maps a `worker::Error` onto the [`SpeechError`] vocabulary, the same
/// documented heuristic the `Classifier` half applies: binding absent is
/// [`SpeechError::NotConfigured`], throttling and overload are
/// [`SpeechError::Transient`] (no `Retry-After` is invented), everything
/// else [`SpeechError::Provider`] — an unknown shape must not masquerade
/// as retryable.
fn map_worker_error(err: &worker::Error) -> SpeechError {
    // The one structured variant the crate already names as a rate limit.
    if matches!(err, worker::Error::RateLimitExceeded(_)) {
        return SpeechError::Transient { retry_after: None };
    }
    let lowered = err.to_string().to_ascii_lowercase();
    if BINDING_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        return SpeechError::NotConfigured;
    }
    if TRANSIENT_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        return SpeechError::Transient { retry_after: None };
    }
    SpeechError::Provider(err.to_string())
}

/// The speech-to-text model a [`WorkersAiSpeech`] transcribes with.
/// `Nova3` is Deepgram's multilingual Nova-3 (words with confidence, no
/// clip length); the Whisper models are `OpenAI`'s (`Whisper` without
/// confidence, `WhisperLargeV3Turbo` with language and duration).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum TranscriptionModel {
    /// `@cf/deepgram/nova-3` — the default.
    #[default]
    Nova3,
    /// `@cf/openai/whisper`.
    Whisper,
    /// `@cf/openai/whisper-large-v3-turbo`.
    WhisperLargeV3Turbo,
}

impl TranscriptionModel {
    /// The model id the binding runs.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Nova3 => "@cf/deepgram/nova-3",
            Self::Whisper => "@cf/openai/whisper",
            Self::WhisperLargeV3Turbo => "@cf/openai/whisper-large-v3-turbo",
        }
    }
}

/// The Aura-2 English voices, in the model schema's order (`luna` the
/// documented default speaker).
#[rustfmt::skip]
const AURA_2_VOICES: [&str; 40] = [
    "amalthea", "andromeda", "apollo",  "arcas",    "aries",   "asteria", "athena", "atlas",
    "aurora",   "callista",  "cora",    "cordelia", "delia",   "draco",   "electra", "harmonia",
    "helena",   "hera",      "hermes",  "hyperion", "iris",    "janus",   "juno",    "jupiter",
    "luna",     "mars",      "minerva", "neptune",  "odysseus", "ophelia", "orion",  "orpheus",
    "pandora",  "phoebe",    "pluto",   "saturn",   "thalia",  "theia",   "vesta",   "zeus",
];

/// The older Aura-1 voices, in the model schema's order.
const AURA_1_VOICES: [&str; 12] = [
    "angus", "asteria", "arcas", "athena", "helios", "hera", "luna", "orion", "orpheus", "perseus",
    "stella", "zeus",
];

/// The text-to-speech model a [`WorkersAiSpeech`] voices with: Deepgram's
/// Aura, English-only on both generations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum SpeechModel {
    /// `@cf/deepgram/aura-2-en` — the current generation, 40 voices.
    #[default]
    Aura2En,
    /// `@cf/deepgram/aura-1` — the older generation, 12 voices.
    Aura1,
}

impl SpeechModel {
    /// The model id the binding runs.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Aura2En => "@cf/deepgram/aura-2-en",
            Self::Aura1 => "@cf/deepgram/aura-1",
        }
    }

    /// The voices Deepgram documents for the model, in document order.
    #[must_use]
    pub const fn voices(self) -> &'static [&'static str] {
        match self {
            Self::Aura2En => &AURA_2_VOICES,
            Self::Aura1 => &AURA_1_VOICES,
        }
    }
}

/// The most audio one transcription may carry when no
/// [`WorkersAiSpeech::with_limits`] override says otherwise: 1 MiB, well
/// under the port's 25 MiB default. The binding takes the clip as a JSON
/// number array — roughly 32 `serde_json::Value` bytes per audio byte
/// before `serde_wasm_bindgen` copies it into a JavaScript array again —
/// so a 25 MiB clip would ask a 128 MB Workers isolate for ~800 MB twice
/// over and be killed mid-request instead of refused with a typed
/// [`SpeechError::LimitExceeded`]. The other limits stay at the port
/// defaults.
pub const WORKERS_AI_MAX_AUDIO_BYTES: u64 = 1024 * 1024;

/// `Speech` over the Cloudflare Workers AI binding. The runner is a type
/// parameter so tests can substitute the binding; venture code writes
/// `WorkersAiSpeech::from_env(..)` and never names the parameter.
pub struct WorkersAiSpeech<R: SpeechRunner = SpeechBinding> {
    runner: R,
    transcription_model: TranscriptionModel,
    speech_model: SpeechModel,
    limits: SpeechLimits,
    strict_voices: bool,
}

impl WorkersAiSpeech<SpeechBinding> {
    /// The adapter over the venture's `env.AI` binding; a missing or
    /// wrong-typed binding yields `None` — the runtime does not provide
    /// the port — never a panic.
    pub fn from_env(env: &worker::Env, binding: &str) -> Option<Self> {
        let ai = env.ai(binding).ok()?;
        Some(Self::with_runner(SpeechBinding(ai)))
    }
}

impl<R: SpeechRunner> WorkersAiSpeech<R> {
    /// Any [`SpeechRunner`] stands in for the binding, so the whole port
    /// runs in a native `cargo test`.
    pub fn with_runner(runner: R) -> Self {
        Self {
            runner,
            transcription_model: TranscriptionModel::default(),
            speech_model: SpeechModel::default(),
            limits: SpeechLimits {
                max_audio_bytes: WORKERS_AI_MAX_AUDIO_BYTES,
                ..SpeechLimits::default()
            },
            strict_voices: false,
        }
    }

    /// Transcribes with `model` instead of the default Nova-3.
    #[must_use]
    pub fn with_transcription_model(mut self, model: TranscriptionModel) -> Self {
        self.transcription_model = model;
        self
    }

    /// Voices with `model` instead of the default Aura-2 English.
    #[must_use]
    pub fn with_speech_model(mut self, model: SpeechModel) -> Self {
        self.speech_model = model;
        self
    }

    /// Enforces `limits` instead of the adapter defaults (the byte cap
    /// being [`WORKERS_AI_MAX_AUDIO_BYTES`], the rest the port's).
    #[must_use]
    pub fn with_limits(mut self, limits: SpeechLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Refuses a speaker id outside the model's documented voices with
    /// [`SpeechError::InvalidInput`] before the call. Off by default: the
    /// provider owns the speaker namespace.
    #[must_use]
    pub fn with_strict_voices(mut self) -> Self {
        self.strict_voices = true;
        self
    }
}

#[async_trait]
impl<R: SpeechRunner> Speech for WorkersAiSpeech<R> {
    fn capabilities(&self) -> SpeechCapabilities {
        SpeechCapabilities {
            streaming_output: true,
            word_timings: true,
            // Synthesis-only: the Aura voices are English-only and
            // `check_synthesize` enforces this list, so a French voice-over
            // is refused before the binding is called; transcription stays
            // ungated, the models being multilingual.
            languages: vec!["en".to_owned()],
            // Every encoding the Aura schema documents, mapped onto the
            // wire by `encoding_for`.
            formats: vec![
                AudioFormat::Mp3,
                AudioFormat::Opus,
                AudioFormat::Flac,
                AudioFormat::Aac,
                AudioFormat::Wav,
                AudioFormat::Pcm,
            ],
        }
    }

    fn limits(&self) -> SpeechLimits {
        self.limits
    }

    async fn transcribe(&self, request: &TranscribeRequest) -> Result<Transcript, SpeechError> {
        // Limits first: an over-ceiling ask is refused before the binding
        // is called, the same as every adapter of this port.
        check_transcribe(request, &self.limits)?;

        let output = self
            .runner
            .run_json(
                self.transcription_model.id(),
                transcribe_input(self.transcription_model, request),
            )
            .await?;
        let parsed = parse_transcript(self.transcription_model, &output)?;
        // The provider's own duration (turbo's `transcription_info`) is the
        // honest bill; else what the request carried (declared, or the WAV
        // header); else where the last word ends.
        let millis = parsed
            .provider_millis
            .or_else(|| known_duration_millis(request))
            .or_else(|| {
                parsed
                    .words
                    .last()
                    .map(|word| u64::try_from(word.end.as_millis()).unwrap_or(u64::MAX))
            })
            .unwrap_or(0);
        tracing::debug!(
            provider = "workers-ai",
            outcome = "transcribed",
            "speech outcome"
        );
        let mut transcript = Transcript::new(parsed.text)
            .with_words(parsed.words)
            .with_usage(SpeechUsage::transcribed(millis));
        if let Some(language) = parsed.language {
            transcript = transcript.with_language(language);
        }
        Ok(transcript)
    }

    async fn synthesize(&self, request: &SynthesizeRequest) -> Result<Synthesis, SpeechError> {
        // Limits and advertised shape first — refused before the binding.
        check_synthesize(request, &self.limits, &self.capabilities())?;
        if request.voice.is_empty() {
            return Err(SpeechError::InvalidInput(
                "the voice id is empty".to_owned(),
            ));
        }
        if self.strict_voices
            && !self
                .speech_model
                .voices()
                .iter()
                .any(|voice| voice.eq_ignore_ascii_case(&request.voice))
        {
            return Err(SpeechError::InvalidInput(format!(
                "voice {:?} is not one of {}'s voices",
                request.voice,
                self.speech_model.id()
            )));
        }

        let Some((encoding, container)) = encoding_for(request.format) else {
            // `capabilities().formats` already refused anything not listed;
            // a future variant of the `#[non_exhaustive]` enum lands here
            // until this adapter learns its Deepgram encoding.
            return Err(SpeechError::UnsupportedFormat(
                request.format.mime().to_owned(),
            ));
        };

        let mut input = serde_json::json!({
            "text": request.text,
            "speaker": request.voice,
            "encoding": encoding,
        });
        if let Some(container) = container {
            input["container"] = Value::String(container.to_owned());
        }

        let audio = self.runner.run_audio(self.speech_model.id(), input).await?;
        tracing::debug!(
            provider = "workers-ai",
            outcome = "synthesised",
            "speech outcome"
        );
        Ok(Synthesis::new(
            request.format,
            SpeechUsage::synthesised(
                u64::try_from(request.text.chars().count()).unwrap_or(u64::MAX),
            ),
            ResponseStream::new(audio),
        ))
    }

    async fn voices(&self, language: Option<&str>) -> Result<Vec<Voice>, SpeechError> {
        // No network: this is the model schema's documented speaker enum.
        // A `fr-FR` ask filters to empty by primary subtag, the way
        // `SpeechCapabilities::supports_language` matches.
        if language.is_some_and(|asked| !primary_subtag(asked).eq_ignore_ascii_case("en")) {
            return Ok(Vec::new());
        }
        Ok(self
            .speech_model
            .voices()
            .iter()
            .map(|id| Voice::new(*id, title_case(id), vec!["en".to_owned()]))
            .collect())
    }
}

/// The display name for a voice id: `luna` becomes `Luna`.
fn title_case(id: &str) -> String {
    let mut chars = id.chars();
    match chars.next() {
        Some(first) => format!("{}{}", first.to_ascii_uppercase(), chars.as_str()),
        None => String::new(),
    }
}

/// Maps an [`AudioFormat`] onto the Aura `(encoding, container)` pair;
/// the advertised formats are exactly the Aura schema's encodings. `None`
/// — a future `#[non_exhaustive]` variant — the caller refuses as
/// [`SpeechError::UnsupportedFormat`].
const fn encoding_for(format: AudioFormat) -> Option<(&'static str, Option<&'static str>)> {
    match format {
        AudioFormat::Mp3 => Some(("mp3", None)),
        AudioFormat::Opus => Some(("opus", Some("ogg"))),
        AudioFormat::Flac => Some(("flac", None)),
        AudioFormat::Aac => Some(("aac", None)),
        AudioFormat::Wav => Some(("linear16", Some("wav"))),
        AudioFormat::Pcm => Some(("linear16", None)),
        _ => None,
    }
}

/// Builds the model's transcription request document: the clip as a
/// plain byte array (the binding's documented shape, no base64), the
/// content type and language hint where the schema carries them.
fn transcribe_input(model: TranscriptionModel, request: &TranscribeRequest) -> Value {
    let bytes = request.audio.to_vec();
    match model {
        TranscriptionModel::Nova3 => {
            let mut input = serde_json::json!({
                "audio": { "body": bytes, "contentType": request.mime },
                // Deepgram's transcript shaping, on for both: the port's
                // `Transcript` already assumes punctuated, formatted text.
                "punctuate": true,
                "smart_format": true,
            });
            if let Some(language) = &request.language_hint {
                input["language"] = Value::String(language.clone());
            }
            input
        }
        TranscriptionModel::Whisper => serde_json::json!({ "audio": bytes }),
        TranscriptionModel::WhisperLargeV3Turbo => {
            let mut input = serde_json::json!({ "audio": bytes, "task": "transcribe" });
            if let Some(language) = &request.language_hint {
                input["language"] = Value::String(language.clone());
            }
            input
        }
    }
}

/// The clip length the request carries: the declared duration, or the
/// RIFF header for WAV — the same derivation [`check_transcribe`] uses.
fn known_duration_millis(request: &TranscribeRequest) -> Option<u64> {
    request
        .duration
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .or_else(|| {
            if AudioFormat::from_mime(&request.mime) == Some(AudioFormat::Wav) {
                wav_duration(&request.audio)
                    .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            } else {
                None
            }
        })
}

/// One parsed provider transcript: words lifted from provider seconds
/// into [`Duration`]s, plus what the provider said about length and
/// language (turbo's `transcription_info`; the others report neither).
struct ParsedTranscript {
    text: String,
    language: Option<String>,
    words: Vec<WordTiming>,
    provider_millis: Option<u64>,
}

/// Parses the model's answer document into a [`ParsedTranscript`]; a body
/// without the documented shape is [`SpeechError::Provider`] with a fixed
/// message, never the raw body.
fn parse_transcript(
    model: TranscriptionModel,
    output: &Value,
) -> Result<ParsedTranscript, SpeechError> {
    let malformed = || {
        SpeechError::Provider(format!(
            "the {} response did not carry its documented transcript shape",
            model.id()
        ))
    };
    match model {
        TranscriptionModel::Nova3 => {
            let alternative = output
                .get("results")
                .and_then(|results| results.get("channels"))
                .and_then(Value::as_array)
                .and_then(|channels| channels.first())
                .and_then(|channel| channel.get("alternatives"))
                .and_then(Value::as_array)
                .and_then(|alternatives| alternatives.first())
                .ok_or_else(malformed)?;
            Ok(ParsedTranscript {
                text: alternative
                    .get("transcript")
                    .and_then(Value::as_str)
                    .ok_or_else(malformed)?
                    .to_owned(),
                language: None,
                words: words_array(alternative.get("words")),
                provider_millis: None,
            })
        }
        TranscriptionModel::Whisper => Ok(ParsedTranscript {
            text: output
                .get("text")
                .and_then(Value::as_str)
                .ok_or_else(malformed)?
                .to_owned(),
            language: None,
            words: words_array(output.get("words")),
            provider_millis: None,
        }),
        TranscriptionModel::WhisperLargeV3Turbo => {
            let info = output.get("transcription_info");
            let mut words = Vec::new();
            if let Some(segments) = output.get("segments").and_then(Value::as_array) {
                for segment in segments {
                    words.extend(words_array(segment.get("words")));
                }
            }
            Ok(ParsedTranscript {
                text: output
                    .get("text")
                    .and_then(Value::as_str)
                    .ok_or_else(malformed)?
                    .to_owned(),
                language: info
                    .and_then(|info| info.get("language"))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                provider_millis: info
                    .and_then(|info| info.get("duration"))
                    .and_then(secs_millis),
                words,
            })
        }
    }
}

/// The words of one provider entry list; a missing key is empty and a
/// malformed entry is skipped rather than invented.
fn words_array(value: Option<&Value>) -> Vec<WordTiming> {
    value
        .and_then(Value::as_array)
        .map(|entries| entries.iter().filter_map(word_timing).collect())
        .unwrap_or_default()
}

/// One spoken word off a provider entry, with `confidence` where the
/// model reports one (Nova-3 does, Whisper does not).
fn word_timing(entry: &Value) -> Option<WordTiming> {
    let start = secs_millis(entry.get("start")?)?;
    let end = secs_millis(entry.get("end")?)?;
    let mut timing = WordTiming::new(
        entry.get("word")?.as_str()?,
        Duration::from_millis(start),
        Duration::from_millis(end),
    );
    if let Some(confidence) = entry.get("confidence").and_then(Value::as_f64) {
        // The provider reports confidence as f64, the port carries f32 —
        // the narrowing loses precision the port never promised.
        #[allow(clippy::cast_possible_truncation)]
        let confidence = confidence as f32;
        timing.confidence = Some(confidence);
    }
    Some(timing)
}

/// Milliseconds for a JSON seconds value (`0.12` becomes `120`);
/// not-a-number, negative or out of range is `None`.
fn secs_millis(value: &Value) -> Option<u64> {
    let duration = Duration::try_from_secs_f64(value.as_f64()?).ok()?;
    u64::try_from(duration.as_millis()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_binding_error_mapping_lands_on_the_speech_vocabulary() {
        // Binding absent or unusable: `NotConfigured`.
        for text in [
            "Binding cannot be cast to the type Ai from Object",
            "Env does not contain binding `AI`",
            "Ai is not defined",
        ] {
            let mapped = map_worker_error(&worker::Error::JsError(text.to_owned()));
            assert!(
                matches!(mapped, SpeechError::NotConfigured),
                "{text}: {mapped:?}"
            );
        }
        // Throttling and overload: `Transient`, with no invented duration.
        for text in ["rate limit exceeded", "model is overloaded"] {
            let mapped = map_worker_error(&worker::Error::JsError(text.to_owned()));
            assert!(
                matches!(mapped, SpeechError::Transient { retry_after: None }),
                "{text}: {mapped:?}"
            );
        }
        let structured =
            map_worker_error(&worker::Error::RateLimitExceeded("daily cap".to_owned()));
        assert!(matches!(
            structured,
            SpeechError::Transient { retry_after: None }
        ));
        // The model refusing the input, and every shape the heuristic does
        // not know: `Provider` — never an invented retryable moment.
        for text in [
            "invalid input: expected an object",
            "model @cf/deepgram/nova-3 not found",
            "workerd hiccup",
        ] {
            let mapped = map_worker_error(&worker::Error::JsError(text.to_owned()));
            assert!(matches!(mapped, SpeechError::Provider(_)), "{text}");
        }
    }

    #[test]
    fn every_advertised_format_maps_to_its_deepgram_encoding_and_seconds_lift() {
        for (format, encoding, container) in [
            (AudioFormat::Mp3, "mp3", None),
            (AudioFormat::Opus, "opus", Some("ogg")),
            (AudioFormat::Flac, "flac", None),
            (AudioFormat::Aac, "aac", None),
            (AudioFormat::Wav, "linear16", Some("wav")),
            (AudioFormat::Pcm, "linear16", None),
        ] {
            assert_eq!(
                encoding_for(format),
                Some((encoding, container)),
                "{}",
                format.name()
            );
        }
        // Seconds lift to milliseconds; junk falls back to `None`.
        assert_eq!(secs_millis(&serde_json::json!(0.12)), Some(120));
        assert_eq!(secs_millis(&serde_json::json!(1.5)), Some(1_500));
        assert_eq!(secs_millis(&serde_json::json!(0)), Some(0));
        for junk in [
            serde_json::json!("fast"),
            serde_json::json!(-1.0),
            serde_json::json!(f64::NAN),
        ] {
            assert_eq!(secs_millis(&junk), None, "{junk}");
        }
    }
}
