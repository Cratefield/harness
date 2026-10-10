//! The `Speech` port (issue #861) over the `OpenAI`-compatible audio
//! wire: `POST {base_url}/audio/transcriptions` carries speech-to-text in
//! the Whisper shape `OpenAI` defined, and `POST {base_url}/audio/speech`
//! carries text-to-speech — so `OpenAI` itself and a Whisper host like
//! `https://api.regolo.ai/v1` differ by one builder call.
//!
//! **Degraded mode** matches the text model: with no API key every call
//! answers [`SpeechError::NotConfigured`] without a network call.
//! **Limits are checked locally** through [`check_transcribe`] /
//! [`check_synthesize`] at the top of each call — an over-limit ask is
//! refused, never paid for. The transcribe answer asks for `verbose_json`
//! with word timings, so a transcript carries its [`WordTiming`]s when the
//! model reports them. Synthesis does **not** stream today: the
//! [`HttpClient`] port buffers responses, so
//! [`SpeechCapabilities::streaming_output`] is `false` accordingly (a
//! streaming client, issue #859, can raise the flag).

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{
    AudioFormat, HttpClient, HttpError, HttpPolicy, MAX_RESPONSE_BYTES, MAX_RESPONSE_TIMEOUT,
    ResponseStream, Speech, SpeechCapabilities, SpeechError, SpeechLimits, SpeechUsage, Synthesis,
    SynthesizeRequest, TranscribeRequest, Transcript, Voice, WordTiming, check_synthesize,
    check_transcribe, primary_subtag, wav_duration,
};
use http::header::{AUTHORIZATION, CONTENT_TYPE, RETRY_AFTER};
use http::{Request, Response, StatusCode};
use serde_json::json;

/// The transcription model [`OpenAiCompatibleSpeech`] sends unless
/// overridden: `OpenAI`'s Whisper endpoint.
pub const DEFAULT_TRANSCRIPTION_MODEL: &str = "whisper-1";

/// The synthesis model [`OpenAiCompatibleSpeech`] sends unless overridden.
pub const DEFAULT_SPEECH_MODEL: &str = "tts-1";

/// The multipart boundary of the transcriptions form: long and fixed. The
/// form carries only name/value fields and provider-supplied audio, and
/// these bytes appearing inside a clip is not a practical risk.
const BOUNDARY: &str = "cratefield-speech-audio-form-boundary";

/// `OpenAI`'s stock TTS voices, the default `voices` advertises. Each one
/// speaks every language its model reads, so the [`Voice::languages`]
/// lists are empty — the port's multilingual mark.
const DEFAULT_VOICE_IDS: [&str; 9] = [
    "alloy", "ash", "coral", "echo", "fable", "onyx", "nova", "sage", "shimmer",
];

/// The `OpenAI`-compatible [`Speech`] over `POST {base_url}/audio/…`,
/// alongside the text model's `/chat/completions`.
pub struct OpenAiCompatibleSpeech {
    http: Arc<dyn HttpClient>,
    api_key: Option<String>,
    base_url: String,
    transcription_model: String,
    speech_model: String,
    voices: Vec<Voice>,
    limits: SpeechLimits,
}

impl OpenAiCompatibleSpeech {
    /// `api_key: None` => every call is [`SpeechError::NotConfigured`]
    /// (no network). A server that checks no key still gets the header:
    /// pass a placeholder rather than wiring degraded mode by accident.
    pub fn new(http: Arc<dyn HttpClient>, api_key: Option<String>) -> Self {
        Self {
            http,
            api_key,
            base_url: crate::DEFAULT_ENDPOINT.to_owned(),
            transcription_model: DEFAULT_TRANSCRIPTION_MODEL.to_owned(),
            speech_model: DEFAULT_SPEECH_MODEL.to_owned(),
            voices: DEFAULT_VOICE_IDS
                .iter()
                .map(|id| Voice::new(*id, *id, Vec::new()))
                .collect(),
            limits: SpeechLimits::default(),
        }
    }

    /// Points the adapter at a different audio server; a trailing slash on
    /// the base is harmless.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Sends a different transcription model than the default.
    #[must_use]
    pub fn with_transcription_model(mut self, model: impl Into<String>) -> Self {
        self.transcription_model = model.into();
        self
    }

    /// Sends a different synthesis model than the default.
    #[must_use]
    pub fn with_speech_model(mut self, model: impl Into<String>) -> Self {
        self.speech_model = model.into();
        self
    }

    /// Advertises a deployment's own voice list instead of `OpenAI`'s
    /// stock nine; an empty [`Voice::languages`] is the multilingual mark.
    #[must_use]
    pub fn with_voices(mut self, voices: impl IntoIterator<Item = Voice>) -> Self {
        self.voices = voices.into_iter().collect();
        self
    }

    /// Enforces ceilings other than the port defaults (already `OpenAI`'s
    /// documented speech caps): tighten only.
    #[must_use]
    pub fn with_limits(mut self, limits: SpeechLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Reads `OPENAI_API_KEY` and `OPENAI_BASE_URL` — the same variables
    /// the text model reads. On Workers the venture should read the
    /// secrets from its `Env` and use [`OpenAiCompatibleSpeech::new`].
    pub fn from_env(http: Arc<dyn HttpClient>) -> Self {
        Self::new(http, std::env::var("OPENAI_API_KEY").ok()).with_base_url(
            std::env::var("OPENAI_BASE_URL").unwrap_or_else(|_| crate::DEFAULT_ENDPOINT.to_owned()),
        )
    }

    /// The audio-endpoint URL for the configured base.
    fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.base_url.trim_end_matches('/'))
    }

    /// The key, or the port's degraded answer: no key means no provider,
    /// without a network call.
    fn key(&self) -> Result<&str, SpeechError> {
        let Some(api_key) = self.api_key.as_deref() else {
            tracing::info!(
                provider = "openai-compatible",
                outcome = "not_configured",
                "speech outcome"
            );
            return Err(SpeechError::NotConfigured);
        };
        Ok(api_key)
    }

    /// Posts `body` to `path` under the configured base, authenticated
    /// with the bearer key and bounded by the port's response caps; every
    /// non-2xx becomes a [`SpeechError`] here, so both callers share the
    /// one mapping.
    async fn post(
        &self,
        path: &str,
        content_type: &str,
        api_key: &str,
        body: Vec<u8>,
    ) -> Result<Response<Bytes>, SpeechError> {
        let mut request = Request::builder()
            .method(http::Method::POST)
            .uri(self.endpoint(path))
            .header(CONTENT_TYPE, content_type)
            .header(AUTHORIZATION, format!("Bearer {api_key}"))
            .body(Bytes::from(body))
            .map_err(|error| SpeechError::Provider(error.to_string()))?;
        // The port's 30 s ceiling for the call's tail, the port's body cap.
        request.extensions_mut().insert(HttpPolicy {
            timeout: MAX_RESPONSE_TIMEOUT,
            max_response_bytes: MAX_RESPONSE_BYTES,
        });
        let response = self
            .http
            .send(request)
            .await
            .map_err(|error| Self::transport(&error))?;
        if !response.status().is_success() {
            let retry_after = retry_after_secs(response.headers());
            let text = String::from_utf8_lossy(response.body()).to_string();
            let error = Self::map_status(response.status(), &text, retry_after);
            tracing::warn!(
                provider = "openai-compatible",
                code = response.status().as_u16(),
                outcome = "failed",
                error = %error,
                "speech outcome"
            );
            return Err(error);
        }
        Ok(response)
    }

    /// Status → port error, the one place the provider's taxonomy meets
    /// ours. The error envelope is parsed for its message; the raw body
    /// is the fallback, so a proxy's HTML error page still logs.
    fn map_status(status: StatusCode, body: &str, retry_after: Option<Duration>) -> SpeechError {
        let detail = crate::provider_message(body);
        match status {
            // "Later" in the seconds form, and a server on its side: both
            // retryable.
            StatusCode::TOO_MANY_REQUESTS => SpeechError::Transient { retry_after },
            status if status.is_server_error() => SpeechError::Transient { retry_after: None },
            // Every 4xx is the request's or the configuration's fault; none
            // is worth a retry unchanged.
            status if status.is_client_error() => SpeechError::Provider(detail),
            // Redirects and anything unmodelled: the call did not complete.
            _ => SpeechError::Provider(format!("unexpected status {status}: {detail}")),
        }
    }

    /// A transport-level failure is the port's retryable bucket; a spent
    /// outbound budget names its own back-off (issue #765), which rides
    /// through.
    fn transport(error: &HttpError) -> SpeechError {
        let retry_after = match error {
            HttpError::BudgetExhausted { retry_after, .. } => Some(*retry_after),
            _ => None,
        };
        SpeechError::Transient { retry_after }
    }
}

/// The seconds form of `Retry-After`; the HTTP-date form (issue #278)
/// reads as unstated rather than wrongly immediate — a 429 is
/// [`SpeechError::Transient`] either way.
fn retry_after_secs(headers: &http::HeaderMap) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    value.parse::<u64>().ok().map(Duration::from_secs)
}

/// Seconds-on-the-wire to a `Duration`; a non-finite, negative or
/// out-of-range reading is `None`, which drops the word rather than
/// inventing a zero timestamp for it — the binding adapter's parse does
/// the same.
fn secs(value: f64) -> Option<Duration> {
    Duration::try_from_secs_f64(value).ok()
}

/// Appends one `name`/`value` field of the multipart form.
fn push_field(form: &mut Vec<u8>, name: &str, value: &str) {
    form.extend_from_slice(
        format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n")
            .as_bytes(),
    );
    form.extend_from_slice(value.as_bytes());
    form.extend_from_slice(b"\r\n");
}

/// Builds the `multipart/form-data` body the transcriptions endpoint
/// takes: the audio as a `file` part with filename and media type, then
/// the model, the language hint's primary subtag, and the `verbose_json`
/// answer shape with word timings. Returns `Content-Type` and body.
fn transcription_form(request: &TranscribeRequest, model: &str) -> (String, Vec<u8>) {
    let mut form = Vec::with_capacity(request.audio.len() + 256);
    // A part filename by media type — `audio.wav`, `audio.mp3`, … — and
    // the caller's own type with a bare name when unknown.
    let (filename, media_type) = match AudioFormat::from_mime(&request.mime) {
        Some(format) => (format!("audio.{format}"), format.mime().to_owned()),
        None => ("audio".to_owned(), request.mime.clone()),
    };
    form.extend_from_slice(
        format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; \
             filename=\"{filename}\"\r\nContent-Type: {media_type}\r\n\r\n"
        )
        .as_bytes(),
    );
    form.extend_from_slice(&request.audio);
    form.extend_from_slice(b"\r\n");
    push_field(&mut form, "model", model);
    if let Some(tag) = request.language_hint.as_deref() {
        push_field(&mut form, "language", primary_subtag(tag));
    }
    push_field(&mut form, "response_format", "verbose_json");
    push_field(&mut form, "timestamp_granularities[]", "word");
    form.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={BOUNDARY}"), form)
}

/// The `verbose_json` transcription answer, in the shape `OpenAI`'s
/// Whisper endpoint documents; segments ride along on the wire, the port
/// reads only the words.
#[derive(serde::Deserialize)]
struct TranscriptionResponse {
    #[serde(default)]
    text: String,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    duration: Option<f64>,
    #[serde(default)]
    words: Vec<WireWord>,
}

/// One word of the answer, seconds on the wire.
#[derive(serde::Deserialize)]
struct WireWord {
    #[serde(default)]
    word: String,
    #[serde(default)]
    start: f64,
    #[serde(default)]
    end: f64,
}

/// The whole buffered body as one chunk: what `HttpClient::send` gives a
/// synthesis, wrapped so it can cross the port's stream boundary. Written
/// out because the crate has no `futures-util` and needs nothing more.
struct OneChunk {
    body: Option<Bytes>,
}

impl futures_core::Stream for OneChunk {
    type Item = Result<Bytes, std::convert::Infallible>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.get_mut().body.take().map(Ok))
    }
}

#[async_trait]
impl Speech for OpenAiCompatibleSpeech {
    async fn transcribe(&self, request: &TranscribeRequest) -> Result<Transcript, SpeechError> {
        // The bounds hold before the wire; the key check follows, the text
        // model's order.
        check_transcribe(request, &self.limits())?;
        let api_key = self.key()?;

        let (content_type, form) = transcription_form(request, &self.transcription_model);
        let response = self
            .post("/audio/transcriptions", &content_type, api_key, form)
            .await?;
        let text = String::from_utf8_lossy(response.body()).to_string();
        // A 2xx body that does not parse is not a refusal: nothing about
        // the request was wrong, the answer just never arrived in usable
        // form — the retryable bucket, the same line the text model draws.
        let parsed: TranscriptionResponse = serde_json::from_str(&text).map_err(|error| {
            tracing::warn!(
                provider = "openai-compatible",
                outcome = "unparsable",
                model = %self.transcription_model,
                detail = %error,
                "speech outcome"
            );
            SpeechError::Transient { retry_after: None }
        })?;

        // The length the provider reported wins; the caller-declared or
        // header-derived length answers when it said nothing; a clip with
        // no knowable length bills zero rather than guessing.
        let audio_millis = parsed
            .duration
            .and_then(|value| Duration::try_from_secs_f64(value).ok())
            .or(request.duration)
            .or_else(|| wav_duration(&request.audio))
            .map_or(0, |duration| {
                u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
            });
        // The detected language is a name (`english`), not a tag; the hint
        // this adapter sent is the tag the wire carries.
        let language = request
            .language_hint
            .as_deref()
            .map(primary_subtag)
            .map(str::to_owned)
            .or(parsed.language);
        let words: Vec<WordTiming> = parsed
            .words
            .iter()
            .filter_map(|word| {
                Some(WordTiming::new(
                    word.word.clone(),
                    secs(word.start)?,
                    secs(word.end)?,
                ))
            })
            .collect();
        tracing::info!(
            provider = "openai-compatible",
            code = response.status().as_u16(),
            outcome = "completed",
            model = %self.transcription_model,
            words = words.len(),
            "speech outcome"
        );
        Ok(Transcript {
            language,
            ..Transcript::new(parsed.text)
                .with_words(words)
                .with_usage(SpeechUsage::transcribed(audio_millis))
        })
    }

    async fn synthesize(&self, request: &SynthesizeRequest) -> Result<Synthesis, SpeechError> {
        // The bounds, then the deployment's own advertised formats: both
        // checked locally, before any request.
        check_synthesize(request, &self.limits(), &self.capabilities())?;
        let api_key = self.key()?;

        let payload = json!({
            "model": self.speech_model,
            "input": request.text,
            "voice": request.voice,
            "response_format": request.format.name(),
        });
        let body = serde_json::to_vec(&payload).map_err(|error| {
            SpeechError::Provider(format!("the synthesis request did not serialise: {error}"))
        })?;
        let response = self
            .post("/audio/speech", "application/json", api_key, body)
            .await?;
        let characters = u64::try_from(request.text.chars().count()).unwrap_or(u64::MAX);
        tracing::info!(
            provider = "openai-compatible",
            code = response.status().as_u16(),
            outcome = "completed",
            model = %self.speech_model,
            characters,
            "speech outcome"
        );
        Ok(Synthesis::new(
            request.format,
            SpeechUsage::synthesised(characters),
            // `HttpClient::send` buffers: the whole clip arrives as one
            // chunk, which is why `capabilities()` reports no streaming.
            ResponseStream::new(OneChunk {
                body: Some(response.into_body()),
            }),
        ))
    }

    async fn voices(&self, language: Option<&str>) -> Result<Vec<Voice>, SpeechError> {
        // Degraded mode matches the text model: no key, no provider.
        self.key()?;
        let voices = match language {
            None => self.voices.clone(),
            Some(language) => self
                .voices
                .iter()
                .filter(|voice| serves(voice, language))
                .cloned()
                .collect(),
        };
        Ok(voices)
    }

    fn capabilities(&self) -> SpeechCapabilities {
        SpeechCapabilities {
            streaming_output: false,
            // The transcriptions call asks for word timings by default.
            word_timings: true,
            // Whisper auto-detects and the TTS voices are multilingual.
            languages: Vec::new(),
            formats: vec![
                AudioFormat::Mp3,
                AudioFormat::Opus,
                AudioFormat::Aac,
                AudioFormat::Flac,
                AudioFormat::Wav,
                AudioFormat::Pcm,
            ],
        }
    }

    fn limits(&self) -> SpeechLimits {
        self.limits
    }
}

/// Whether `voice` speaks `language`: an empty [`Voice::languages`] is the
/// multilingual mark, otherwise a primary-subtag match.
fn serves(voice: &Voice, language: &str) -> bool {
    voice.languages.is_empty()
        || voice
            .languages
            .iter()
            .any(|tag| primary_subtag(tag).eq_ignore_ascii_case(primary_subtag(language)))
}
