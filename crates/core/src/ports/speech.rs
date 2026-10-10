//! The `Speech` port (issue #861): vendor-neutral speech-to-text and
//! text-to-speech, asked for by capability, never by vendor — the way
//! [`TextModel`](crate::TextModel) is for completions. A module holds
//! `Arc<dyn Speech>` and never learns which provider spoke.
//!
//! **Limits are checked locally, before any network call.** Every
//! implementation MUST run [`check_transcribe`] / [`check_synthesize`] on
//! the request first, so an over-limit ask is refused with
//! [`SpeechError::LimitExceeded`] without being paid for; the defaults
//! ([`SpeechLimits::default()`]) are `OpenAI`'s documented speech caps.
//! There is no outcome enum: the unwired answer is
//! [`SpeechError::NotConfigured`] — an error the caller matches, never a
//! silently empty transcript. [`NotConfiguredSpeech`] is the placeholder.

use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use thiserror::Error;

use crate::stream::ResponseStream;

/// The most audio one transcribe request may carry: 25 MiB.
pub const DEFAULT_MAX_AUDIO_BYTES: u64 = 25 * 1024 * 1024;

/// The longest clip one transcribe request may claim: ten minutes.
pub const DEFAULT_MAX_AUDIO_SECONDS: u32 = 600;

/// The most text one synthesize request may carry: 4 096 characters.
pub const DEFAULT_MAX_SYNTHESIS_CHARS: u32 = 4096;

/// An audio container/codec a [`Speech`] adapter speaks;
/// `#[non_exhaustive]` so the next provider-native format does not break
/// every `match`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AudioFormat {
    Mp3,
    Wav,
    Opus,
    Flac,
    Aac,
    Pcm,
}

impl AudioFormat {
    /// The canonical MIME type on the wire.
    #[must_use]
    pub const fn mime(self) -> &'static str {
        match self {
            AudioFormat::Mp3 => "audio/mpeg",
            AudioFormat::Wav => "audio/wav",
            AudioFormat::Opus => "audio/opus",
            AudioFormat::Flac => "audio/flac",
            AudioFormat::Aac => "audio/aac",
            AudioFormat::Pcm => "audio/pcm",
        }
    }

    /// The short name used in logs and errors.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            AudioFormat::Mp3 => "mp3",
            AudioFormat::Wav => "wav",
            AudioFormat::Opus => "opus",
            AudioFormat::Flac => "flac",
            AudioFormat::Aac => "aac",
            AudioFormat::Pcm => "pcm",
        }
    }

    /// Resolves a MIME type to a format, aliases included (`audio/x-wav`,
    /// `audio/ogg`, …); unknown types answer `None`.
    #[must_use]
    pub fn from_mime(mime: &str) -> Option<Self> {
        let mime = mime.split(';').next()?.trim().to_ascii_lowercase();
        match mime.as_str() {
            "audio/mpeg" | "audio/mp3" => Some(AudioFormat::Mp3),
            "audio/wav" | "audio/x-wav" | "audio/wave" | "audio/vnd.wave" => Some(AudioFormat::Wav),
            "audio/opus" | "audio/ogg" | "audio/webm" => Some(AudioFormat::Opus),
            "audio/flac" | "audio/x-flac" => Some(AudioFormat::Flac),
            "audio/aac" | "audio/mp4" => Some(AudioFormat::Aac),
            "audio/pcm" | "audio/l16" => Some(AudioFormat::Pcm),
            _ => None,
        }
    }
}

impl std::fmt::Display for AudioFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// The primary subtag of a BCP-47 tag: `en` from `en-US`.
#[must_use]
pub fn primary_subtag(tag: &str) -> &str {
    tag.split('-').next().unwrap_or(tag)
}

/// What a [`Speech`] adapter can do, asked before any call. An empty
/// `languages` serves anything; `formats` is the opposite of a wildcard —
/// an adapter that advertises none may be asked for none.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpeechCapabilities {
    pub streaming_output: bool,
    pub word_timings: bool,
    pub languages: Vec<String>,
    pub formats: Vec<AudioFormat>,
}

impl SpeechCapabilities {
    /// Whether `language` is served: always on an empty list, else a
    /// case-insensitive primary-subtag match (`en` serves `en-US`).
    #[must_use]
    pub fn supports_language(&self, language: &str) -> bool {
        if self.languages.is_empty() {
            return true;
        }
        self.languages
            .iter()
            .any(|tag| primary_subtag(tag).eq_ignore_ascii_case(primary_subtag(language)))
    }

    /// Whether `format` is among the advertised TTS output formats.
    #[must_use]
    pub fn supports_format(&self, format: AudioFormat) -> bool {
        self.formats.contains(&format)
    }
}

/// The local ceilings a [`Speech`] adapter enforces before any network
/// call, read off `Speech::limits`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpeechLimits {
    pub max_audio_bytes: u64,
    pub max_audio_seconds: u32,
    pub max_synthesis_chars: u32,
}

impl Default for SpeechLimits {
    fn default() -> Self {
        Self {
            max_audio_bytes: DEFAULT_MAX_AUDIO_BYTES,
            max_audio_seconds: DEFAULT_MAX_AUDIO_SECONDS,
            max_synthesis_chars: DEFAULT_MAX_SYNTHESIS_CHARS,
        }
    }
}

/// One text-to-speech request, built with [`SynthesizeRequest::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynthesizeRequest {
    pub text: String,
    pub voice: String,
    /// A BCP-47 tag steering pronunciation, when the caller knows it.
    pub language: Option<String>,
    pub format: AudioFormat,
}

impl SynthesizeRequest {
    #[must_use]
    pub fn new(text: impl Into<String>, voice: impl Into<String>, format: AudioFormat) -> Self {
        Self {
            text: text.into(),
            voice: voice.into(),
            language: None,
            format,
        }
    }

    #[must_use]
    pub fn with_language(mut self, language: impl Into<String>) -> Self {
        self.language = Some(language.into());
        self
    }
}

/// One speech-to-text request, built with [`TranscribeRequest::new`].
#[derive(Debug, Clone, PartialEq)]
pub struct TranscribeRequest {
    pub audio: Bytes,
    pub mime: String,
    /// A BCP-47 tag hinting the spoken language, when the caller knows it.
    pub language_hint: Option<String>,
    /// The clip's length, caller-declared. When absent and `mime` is WAV,
    /// [`check_transcribe`] derives it from the RIFF header; when still
    /// unknown, only [`SpeechLimits::max_audio_bytes`] applies.
    pub duration: Option<Duration>,
}

impl TranscribeRequest {
    #[must_use]
    pub fn new(audio: Bytes, mime: impl Into<String>) -> Self {
        Self {
            audio,
            mime: mime.into(),
            language_hint: None,
            duration: None,
        }
    }

    #[must_use]
    pub fn with_language_hint(mut self, language_hint: impl Into<String>) -> Self {
        self.language_hint = Some(language_hint.into());
        self
    }

    #[must_use]
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = Some(duration);
        self
    }
}

/// One spoken word in a transcript, with where it starts and ends.
#[derive(Debug, Clone, PartialEq)]
pub struct WordTiming {
    pub word: String,
    pub start: Duration,
    pub end: Duration,
    pub confidence: Option<f32>,
}

impl WordTiming {
    #[must_use]
    pub fn new(word: impl Into<String>, start: Duration, end: Duration) -> Self {
        Self {
            word: word.into(),
            start,
            end,
            confidence: None,
        }
    }
}

/// What one speech call cost, in the provider's own billing units:
/// milliseconds transcribed, characters synthesised.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SpeechUsage {
    pub audio_millis: u64,
    pub characters: u64,
}

impl SpeechUsage {
    #[must_use]
    pub const fn transcribed(audio_millis: u64) -> Self {
        Self {
            audio_millis,
            characters: 0,
        }
    }

    #[must_use]
    pub const fn synthesised(characters: u64) -> Self {
        Self {
            audio_millis: 0,
            characters,
        }
    }
}

/// One completed transcription.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Transcript {
    pub text: String,
    /// The language the provider detected (or echoed from the hint).
    pub language: Option<String>,
    pub words: Vec<WordTiming>,
    pub usage: SpeechUsage,
}

impl Transcript {
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn with_language(mut self, language: impl Into<String>) -> Self {
        self.language = Some(language.into());
        self
    }

    #[must_use]
    pub fn with_words(mut self, words: Vec<WordTiming>) -> Self {
        self.words = words;
        self
    }

    #[must_use]
    pub const fn with_usage(mut self, usage: SpeechUsage) -> Self {
        self.usage = usage;
        self
    }
}

/// One completed synthesis: the audio as a stream that can start reaching
/// the caller before the provider has finished. `Debug` shows the shape,
/// never the bytes.
#[derive(Clone)]
pub struct Synthesis {
    pub format: AudioFormat,
    pub usage: SpeechUsage,
    pub audio: ResponseStream,
}

impl Synthesis {
    #[must_use]
    pub const fn new(format: AudioFormat, usage: SpeechUsage, audio: ResponseStream) -> Self {
        Self {
            format,
            usage,
            audio,
        }
    }
}

impl std::fmt::Debug for Synthesis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Synthesis")
            .field("format", &self.format)
            .field("usage", &self.usage)
            .finish_non_exhaustive()
    }
}

/// One voice a provider can synthesize with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Voice {
    pub id: String,
    pub name: String,
    /// The BCP-47 tags this voice speaks.
    pub languages: Vec<String>,
}

impl Voice {
    #[must_use]
    pub fn new(id: impl Into<String>, name: impl Into<String>, languages: Vec<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            languages,
        }
    }
}

/// Which [`SpeechLimits`] ceiling a request crossed; `AudioSeconds`
/// compares milliseconds, so a sub-second clip is not rounded into
/// compliance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpeechLimit {
    AudioBytes,
    AudioSeconds,
    SynthesisChars,
}

impl SpeechLimit {
    /// The name used in errors and logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            SpeechLimit::AudioBytes => "audio bytes",
            SpeechLimit::AudioSeconds => "audio seconds",
            SpeechLimit::SynthesisChars => "synthesis characters",
        }
    }
}

/// Speech failures. [`LimitExceeded`](Self::LimitExceeded) is the typed
/// **local** refusal, carrying only numbers, safe in a log line as-is; the
/// variants carrying provider or caller text are scrubbed in `Display` the
/// way [`TextModelError`](crate::TextModelError)'s are (issue #235), while
/// `Debug` still shows the raw string for tests.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SpeechError {
    /// No speech provider is wired; nothing is wrong with the request.
    #[error("no speech provider is wired")]
    NotConfigured,
    /// A local ceiling was crossed and the provider was never called.
    #[error("over the {} ceiling: {actual} > {max}", limit.name())]
    LimitExceeded {
        limit: SpeechLimit,
        actual: u64,
        max: u64,
    },
    /// Not among the adapter's advertised [`SpeechCapabilities::formats`].
    #[error("unsupported audio format: {}", scrub(.0))]
    UnsupportedFormat(String),
    /// Not among the adapter's advertised [`SpeechCapabilities::languages`].
    #[error("unsupported language: {}", scrub(.0))]
    UnsupportedLanguage(String),
    /// The request was malformed before any provider saw it.
    #[error("speech request rejected: {}", scrub(.0))]
    InvalidInput(String),
    /// Retryable (a `5xx`, a `429`, a transport error); wait out
    /// `retry_after` when the provider named one.
    #[error("speech call failed, retryable")]
    Transient { retry_after: Option<Duration> },
    /// The provider refused the request or the call failed.
    #[error("speech provider failed: {}", scrub(.0))]
    Provider(String),
}

/// The `Display` scrub for the variants carrying provider or caller text.
fn scrub(value: &str) -> String {
    crate::logging::scrub_text(value)
}

impl SpeechError {
    /// The provider-named back-off, where there was one.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            SpeechError::Transient { retry_after } => *retry_after,
            _ => None,
        }
    }
}

/// The length of a RIFF/WAVE clip from its header: the `data` chunk's
/// declared size over the `fmt ` byte rate, rounded up to the millisecond.
/// A short, truncated or non-WAV payload answers `None`, never panics.
#[must_use]
pub fn wav_duration(audio: &[u8]) -> Option<Duration> {
    if audio.len() < 12 || &audio[0..4] != b"RIFF" || &audio[8..12] != b"WAVE" {
        return None;
    }
    let (mut byte_rate, mut data_len) = (0u32, None);
    let mut pos = 12usize;
    while pos + 8 <= audio.len() {
        let id = audio.get(pos..pos + 4)?;
        let size = usize::try_from(u32::from_le_bytes(
            audio.get(pos + 4..pos + 8)?.try_into().ok()?,
        ))
        .ok()?;
        match id {
            b"fmt " if size >= 16 => {
                byte_rate = u32::from_le_bytes(audio.get(pos + 16..pos + 20)?.try_into().ok()?);
            }
            b"data" => {
                data_len = Some(size);
                break;
            }
            _ => {}
        }
        // RIFF pads every odd-sized chunk to even: honour the pad byte,
        // or the next chunk header would be read one byte early.
        pos = pos.checked_add(size.checked_add(8)?.checked_add(size & 1)?)?;
    }
    // Ceiling to the millisecond: a clip never under-reports its length.
    let rate = u64::from(byte_rate);
    if rate == 0 {
        return None;
    }
    let len = u64::try_from(data_len?).ok()?;
    Some(Duration::from_millis(
        len.saturating_mul(1_000).div_ceil(rate),
    ))
}

/// Refuses a transcribe request crossing a local ceiling, **before** any
/// network call: empty audio is [`SpeechError::InvalidInput`], and so is a
/// mime that is empty or carries ASCII control characters (adapters paste
/// the mime into headers and multipart part lines, so a CR/LF must never
/// reach one); the payload over [`SpeechLimits::max_audio_bytes`] or the
/// clip over [`SpeechLimits::max_audio_seconds`] (declared, or derived
/// from the WAV header) is [`SpeechError::LimitExceeded`].
///
/// # Errors
/// The refusals named above.
pub fn check_transcribe(
    request: &TranscribeRequest,
    limits: &SpeechLimits,
) -> Result<(), SpeechError> {
    if request.audio.is_empty() {
        return Err(SpeechError::InvalidInput(
            "the audio payload is empty".to_owned(),
        ));
    }
    if request.mime.is_empty() || request.mime.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(SpeechError::InvalidInput(
            "the audio media type is empty or carries control characters".to_owned(),
        ));
    }
    let bytes = u64::try_from(request.audio.len()).unwrap_or(u64::MAX);
    if bytes > limits.max_audio_bytes {
        return Err(SpeechError::LimitExceeded {
            limit: SpeechLimit::AudioBytes,
            actual: bytes,
            max: limits.max_audio_bytes,
        });
    }
    let millis = match request.duration {
        Some(duration) => Some(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)),
        None if AudioFormat::from_mime(&request.mime) == Some(AudioFormat::Wav) => {
            wav_duration(&request.audio)
                .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        }
        None => None,
    };
    if let Some(actual) = millis {
        let max = u64::from(limits.max_audio_seconds) * 1_000;
        if actual > max {
            return Err(SpeechError::LimitExceeded {
                limit: SpeechLimit::AudioSeconds,
                actual,
                max,
            });
        }
    }
    Ok(())
}

/// Refuses a synthesize request crossing a local ceiling or the adapter's
/// own advertised capabilities, **before** any network call: empty text is
/// [`SpeechError::InvalidInput`], text over
/// [`SpeechLimits::max_synthesis_chars`] is [`SpeechError::LimitExceeded`],
/// and a format or language outside [`SpeechCapabilities::formats`] /
/// [`SpeechCapabilities::languages`] is `UnsupportedFormat` /
/// `UnsupportedLanguage`.
///
/// # Errors
/// The refusals named above; the first refusal wins.
pub fn check_synthesize(
    request: &SynthesizeRequest,
    limits: &SpeechLimits,
    capabilities: &SpeechCapabilities,
) -> Result<(), SpeechError> {
    if request.text.is_empty() {
        return Err(SpeechError::InvalidInput("the text is empty".to_owned()));
    }
    let chars = u64::try_from(request.text.chars().count()).unwrap_or(u64::MAX);
    if chars > u64::from(limits.max_synthesis_chars) {
        return Err(SpeechError::LimitExceeded {
            limit: SpeechLimit::SynthesisChars,
            actual: chars,
            max: u64::from(limits.max_synthesis_chars),
        });
    }
    if !capabilities.supports_format(request.format) {
        return Err(SpeechError::UnsupportedFormat(
            request.format.mime().to_owned(),
        ));
    }
    if let Some(language) = &request.language
        && !capabilities.supports_language(language)
    {
        return Err(SpeechError::UnsupportedLanguage(language.clone()));
    }
    Ok(())
}

/// Speaks for a venture: speech-to-text and text-to-speech over whichever
/// provider it wired. Every adapter MUST run the `check_*` functions at
/// the top of `transcribe` / `synthesize`, before any network call, so a
/// refusal costs nothing and every adapter refuses identically.
#[async_trait]
pub trait Speech: Send + Sync {
    /// Transcribes `request`'s audio.
    ///
    /// # Errors
    /// [`SpeechError::NotConfigured`] unwired; the refusal and failure
    /// variants otherwise.
    async fn transcribe(&self, request: &TranscribeRequest) -> Result<Transcript, SpeechError>;

    /// Synthesizes `request`'s text to audio; a streaming provider's
    /// [`Synthesis::audio`] starts yielding before the clip is complete.
    ///
    /// # Errors
    /// As `transcribe`, with `UnsupportedFormat` for `UnsupportedLanguage`.
    async fn synthesize(&self, request: &SynthesizeRequest) -> Result<Synthesis, SpeechError>;

    /// The voices the provider offers, filtered to `language` (a BCP-47
    /// tag) when given.
    ///
    /// # Errors
    /// As `transcribe`.
    async fn voices(&self, language: Option<&str>) -> Result<Vec<Voice>, SpeechError>;

    /// What this adapter can do, so a caller shapes its ask before
    /// calling.
    fn capabilities(&self) -> SpeechCapabilities;

    /// The local ceilings this adapter enforces;
    /// [`SpeechLimits::default()`] when it has none of its own.
    fn limits(&self) -> SpeechLimits {
        SpeechLimits::default()
    }
}

/// The standing placeholder when a venture wires no speech provider:
/// every call answers [`SpeechError::NotConfigured`], the way
/// [`NoopDefer`](crate::NoopDefer) drops deferred work.
#[derive(Debug, Clone, Copy, Default)]
pub struct NotConfiguredSpeech;

#[async_trait]
impl Speech for NotConfiguredSpeech {
    async fn transcribe(&self, _request: &TranscribeRequest) -> Result<Transcript, SpeechError> {
        Err(SpeechError::NotConfigured)
    }

    async fn synthesize(&self, _request: &SynthesizeRequest) -> Result<Synthesis, SpeechError> {
        Err(SpeechError::NotConfigured)
    }

    async fn voices(&self, _language: Option<&str>) -> Result<Vec<Voice>, SpeechError> {
        Err(SpeechError::NotConfigured)
    }

    fn capabilities(&self) -> SpeechCapabilities {
        SpeechCapabilities::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_core::Stream as _;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// A minimal 8-bit mono 8 kHz RIFF/WAVE clip with `byte_rate` as its
    /// fmt byte rate and `data` as its payload.
    fn wav(byte_rate: u32, data: &[u8]) -> Bytes {
        let data_len = u32::try_from(data.len()).expect("a test clip fits in u32");
        let mut out = Vec::with_capacity(44 + data.len());
        out.extend_from_slice(b"RIFF");
        out.extend_from_slice(&(36 + data_len).to_le_bytes());
        out.extend_from_slice(b"WAVEfmt ");
        out.extend_from_slice(&16u32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes()); // PCM
        out.extend_from_slice(&1u16.to_le_bytes()); // mono
        out.extend_from_slice(&8_000u32.to_le_bytes()); // sample rate
        out.extend_from_slice(&byte_rate.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes()); // block align
        out.extend_from_slice(&8u16.to_le_bytes()); // bits per sample
        out.extend_from_slice(b"data");
        out.extend_from_slice(&data_len.to_le_bytes());
        out.extend_from_slice(data);
        Bytes::from(out)
    }

    /// The same clip with one odd-sized `LIST` chunk — 3 bytes of payload
    /// plus its RIFF pad byte — ahead of `fmt `, as real writers emit.
    fn wav_with_odd_chunk(byte_rate: u32, data: &[u8]) -> Bytes {
        let data_len = u32::try_from(data.len()).expect("a test clip fits in u32");
        let mut out = Vec::with_capacity(56 + data.len());
        out.extend_from_slice(b"RIFF");
        out.extend_from_slice(&(36 + 12 + data_len).to_le_bytes());
        out.extend_from_slice(b"WAVE");
        out.extend_from_slice(b"LIST");
        out.extend_from_slice(&3u32.to_le_bytes());
        out.extend_from_slice(b"abc");
        out.extend_from_slice(&[0u8]); // the pad byte
        out.extend_from_slice(b"fmt ");
        out.extend_from_slice(&16u32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes()); // PCM
        out.extend_from_slice(&1u16.to_le_bytes()); // mono
        out.extend_from_slice(&8_000u32.to_le_bytes()); // sample rate
        out.extend_from_slice(&byte_rate.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes()); // block align
        out.extend_from_slice(&8u16.to_le_bytes()); // bits per sample
        out.extend_from_slice(b"data");
        out.extend_from_slice(&data_len.to_le_bytes());
        out.extend_from_slice(data);
        Bytes::from(out)
    }

    fn limits() -> SpeechLimits {
        SpeechLimits {
            max_audio_bytes: 100,
            max_audio_seconds: 10,
            max_synthesis_chars: 20,
        }
    }

    fn capabilities() -> SpeechCapabilities {
        SpeechCapabilities {
            streaming_output: true,
            word_timings: true,
            languages: vec!["en-US".to_owned()],
            formats: vec![AudioFormat::Mp3, AudioFormat::Wav],
        }
    }

    #[test]
    fn formats_round_trip_through_mime_and_name() {
        for format in [
            AudioFormat::Mp3,
            AudioFormat::Wav,
            AudioFormat::Opus,
            AudioFormat::Flac,
            AudioFormat::Aac,
            AudioFormat::Pcm,
        ] {
            assert_eq!(AudioFormat::from_mime(format.mime()), Some(format));
            assert_eq!(format.to_string(), format.name());
        }
        // The aliases providers and browsers actually send; parameters and
        // case are ignored, junk does not parse.
        for (mime, expected) in [
            ("audio/mp3", Some(AudioFormat::Mp3)),
            ("audio/x-wav", Some(AudioFormat::Wav)),
            ("audio/ogg", Some(AudioFormat::Opus)),
            ("audio/webm", Some(AudioFormat::Opus)),
            ("audio/x-flac", Some(AudioFormat::Flac)),
            ("audio/mp4", Some(AudioFormat::Aac)),
            ("Audio/WAV; codec=1", Some(AudioFormat::Wav)),
            ("video/mp4", None),
        ] {
            assert_eq!(AudioFormat::from_mime(mime), expected, "{mime}");
        }
    }

    #[test]
    fn wav_duration_reads_the_header_and_never_panics_on_garbage() {
        // 12 000 bytes at 8 000 bytes/second: 1.5 seconds.
        assert_eq!(
            wav_duration(&wav(8_000, &vec![0u8; 12_000])),
            Some(Duration::from_millis(1_500))
        );
        // Not WAV, truncated, and an absurd chunk size: all None.
        assert_eq!(wav_duration(b"OggS whatever"), None);
        assert_eq!(wav_duration(b"RIFF".as_slice()), None);
        assert_eq!(wav_duration(&wav(0, b"no rate")), None);
        let mut truncated = wav(8_000, b"payload").to_vec();
        truncated.truncate(30);
        assert_eq!(wav_duration(&truncated), None);
        // An odd-sized chunk with its RIFF pad byte is walked past, and
        // `data` after it still reads: 12 000 bytes at 8 000 B/s, 1.5 s.
        assert_eq!(
            wav_duration(&wav_with_odd_chunk(8_000, &vec![0u8; 12_000])),
            Some(Duration::from_millis(1_500))
        );
    }

    #[test]
    fn transcribe_refuses_each_limit_before_the_network() {
        let limits = limits();
        let empty = TranscribeRequest::new(Bytes::new(), "audio/wav");
        assert_eq!(
            check_transcribe(&empty, &limits),
            Err(SpeechError::InvalidInput(
                "the audio payload is empty".to_owned()
            ))
        );

        let over = TranscribeRequest::new(Bytes::from(vec![0u8; 101]), "audio/wav");
        assert_eq!(
            check_transcribe(&over, &limits),
            Err(SpeechError::LimitExceeded {
                limit: SpeechLimit::AudioBytes,
                actual: 101,
                max: 100,
            })
        );

        // A mime that is empty, or carries ASCII control characters (a
        // CR/LF riding into a header or a multipart part line), is
        // malformed before any adapter formats it.
        let unnamed = TranscribeRequest::new(Bytes::from(vec![0u8; 4]), "");
        assert_eq!(
            check_transcribe(&unnamed, &limits),
            Err(SpeechError::InvalidInput(
                "the audio media type is empty or carries control characters".to_owned()
            ))
        );
        let injected = TranscribeRequest::new(Bytes::from(vec![0u8; 4]), "audio/wav\r\nx: y");
        assert_eq!(
            check_transcribe(&injected, &limits),
            Err(SpeechError::InvalidInput(
                "the audio media type is empty or carries control characters".to_owned()
            ))
        );

        // A declared duration over the seconds ceiling.
        let long = TranscribeRequest::new(Bytes::from(vec![0u8; 4]), "audio/wav")
            .with_duration(Duration::from_secs(11));
        assert_eq!(
            check_transcribe(&long, &limits),
            Err(SpeechError::LimitExceeded {
                limit: SpeechLimit::AudioSeconds,
                actual: 11_000,
                max: 10_000,
            })
        );

        // The same refusal derived from the WAV header when nothing is
        // declared: 48 data bytes at 4 bytes/second is 12 s, under the
        // byte cap.
        let derived = TranscribeRequest::new(wav(100, &[0u8; 4]), "audio/wav"); // 40 ms
        assert_eq!(check_transcribe(&derived, &limits), Ok(()));
        let derived_over = TranscribeRequest::new(wav(4, &[0u8; 48]), "audio/wav");
        assert!(matches!(
            check_transcribe(&derived_over, &limits),
            Err(SpeechError::LimitExceeded {
                limit: SpeechLimit::AudioSeconds,
                ..
            })
        ));

        // Unknown length: only the byte ceiling applies.
        let unknown = TranscribeRequest::new(Bytes::from(vec![0u8; 4]), "audio/mpeg");
        assert_eq!(check_transcribe(&unknown, &limits), Ok(()));
    }

    #[test]
    fn synthesize_refuses_each_limit_and_unsupported_ask_before_the_network() {
        let limits = limits();
        let capabilities = capabilities();
        let request = SynthesizeRequest::new("hello world", "narrator", AudioFormat::Mp3);
        assert_eq!(check_synthesize(&request, &limits, &capabilities), Ok(()));

        let empty = SynthesizeRequest::new("", "narrator", AudioFormat::Mp3);
        assert_eq!(
            check_synthesize(&empty, &limits, &capabilities),
            Err(SpeechError::InvalidInput("the text is empty".to_owned()))
        );

        let long = SynthesizeRequest::new("x".repeat(21), "narrator", AudioFormat::Mp3);
        assert_eq!(
            check_synthesize(&long, &limits, &capabilities),
            Err(SpeechError::LimitExceeded {
                limit: SpeechLimit::SynthesisChars,
                actual: 21,
                max: 20,
            })
        );

        let format = SynthesizeRequest::new("hi", "narrator", AudioFormat::Opus);
        assert_eq!(
            check_synthesize(&format, &limits, &capabilities),
            Err(SpeechError::UnsupportedFormat("audio/opus".to_owned()))
        );

        let language =
            SynthesizeRequest::new("hi", "narrator", AudioFormat::Mp3).with_language("fr-FR");
        assert_eq!(
            check_synthesize(&language, &limits, &capabilities),
            Err(SpeechError::UnsupportedLanguage("fr-FR".to_owned()))
        );
        // Primary-subtag matching: `en` is served by an `en-US` capability.
        let english =
            SynthesizeRequest::new("hi", "narrator", AudioFormat::Mp3).with_language("en");
        assert_eq!(check_synthesize(&english, &limits, &capabilities), Ok(()));
    }

    #[test]
    fn provider_text_is_scrubbed_in_display_but_not_debug() {
        let error =
            SpeechError::Provider("400 for https://api.example.test?token=secret".to_owned());
        let text = error.to_string();
        assert!(!text.contains("secret"), "{text}");
        assert!(format!("{error:?}").contains("secret"));
        assert_eq!(SpeechError::NotConfigured.retry_after(), None);
        let throttled = SpeechError::Transient {
            retry_after: Some(Duration::from_secs(30)),
        };
        assert_eq!(throttled.retry_after(), Some(Duration::from_secs(30)));
    }

    /// A synthesis whose stream yields `head`, then waits on a oneshot
    /// gate before yielding `tail` and ending — a provider that has not
    /// finished while the caller already has its first bytes.
    struct Gated {
        head: Option<Result<Vec<u8>, String>>,
        gate: futures_channel::oneshot::Receiver<()>,
        tail: bool,
    }

    impl futures_core::Stream for Gated {
        type Item = Result<Vec<u8>, String>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.get_mut();
            if let Some(chunk) = this.head.take() {
                return Poll::Ready(Some(chunk));
            }
            if this.tail {
                return Poll::Ready(None);
            }
            match Pin::new(&mut this.gate).poll(cx) {
                Poll::Ready(_) => {
                    this.tail = true;
                    Poll::Ready(Some(Ok(b"tail".to_vec())))
                }
                Poll::Pending => Poll::Pending,
            }
        }
    }

    // Test-only one-shot plumbing, not request state; `std::sync::Mutex` is
    // disallowed workspace-wide (ADR 0007), so the alias carries the allow.
    #[allow(clippy::disallowed_types)]
    type GateSlot = std::sync::Mutex<Option<futures_channel::oneshot::Receiver<()>>>;

    /// The mock [`Speech`] whose `synthesize` hands back the gated stream,
    /// so the proof below runs through the port itself.
    struct GatedSpeech {
        gate: GateSlot,
    }

    #[async_trait]
    impl Speech for GatedSpeech {
        async fn transcribe(&self, _r: &TranscribeRequest) -> Result<Transcript, SpeechError> {
            Err(SpeechError::NotConfigured)
        }

        async fn synthesize(&self, _r: &SynthesizeRequest) -> Result<Synthesis, SpeechError> {
            let gate = self
                .gate
                .lock()
                .expect("gate lock uncontended")
                .take()
                .expect("gate receiver available");
            Ok(Synthesis::new(
                AudioFormat::Mp3,
                SpeechUsage::synthesised(8),
                ResponseStream::new(Gated {
                    head: Some(Ok(b"head".to_vec())),
                    gate,
                    tail: false,
                }),
            ))
        }

        async fn voices(&self, _l: Option<&str>) -> Result<Vec<Voice>, SpeechError> {
            Err(SpeechError::NotConfigured)
        }

        fn capabilities(&self) -> SpeechCapabilities {
            SpeechCapabilities {
                streaming_output: true,
                word_timings: false,
                languages: vec!["en".to_owned()],
                formats: vec![AudioFormat::Mp3],
            }
        }
    }

    #[test]
    fn synthesis_streams_before_the_provider_finishes() {
        let (sender, receiver) = futures_channel::oneshot::channel();
        let speech = GatedSpeech {
            gate: GateSlot::new(Some(receiver)),
        };
        let request = SynthesizeRequest::new("say this", "narrator", AudioFormat::Mp3);
        let synthesis = pollster::block_on(speech.synthesize(&request)).expect("synthesizes");
        let mut stream = synthesis
            .audio
            .take()
            .expect("an unpolled synthesis yields its source");

        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        // The first chunk arrives while the gate is still shut: the caller
        // has audio before the synthesis has completed.
        match Pin::new(&mut stream).poll_next(&mut cx) {
            Poll::Ready(Some(Ok(chunk))) => assert_eq!(&chunk[..], b"head"),
            other => panic!("expected the first chunk before completion, got {other:?}"),
        }
        assert!(
            matches!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Pending),
            "the second chunk must not arrive before the gate opens"
        );
        sender.send(()).expect("the gate opens");
        match Pin::new(&mut stream).poll_next(&mut cx) {
            Poll::Ready(Some(Ok(chunk))) => assert_eq!(&chunk[..], b"tail"),
            other => panic!("expected the tail chunk after the gate opened, got {other:?}"),
        }
        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(None)
        ));
    }
}
