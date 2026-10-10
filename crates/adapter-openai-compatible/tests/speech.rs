//! The `Speech` conformance suite (issue #861) run against the
//! `OpenAiCompatibleSpeech` adapter, plus the wire shapes: the
//! transcription request's multipart fields, the synthesis request's JSON,
//! the bearer key and content types, the 429/401 mapping and a
//! non-`OpenAI` base URL.

// Test-side recording fixture, not request state — the same category
// and allowance as the fakes in `cratefield-testing` (ADR 0007 policy).
#![allow(clippy::disallowed_types)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_adapter_openai_compatible::OpenAiCompatibleSpeech;
use cratefield_core::{AudioFormat, HttpClient, HttpError, Speech, SpeechError, SynthesizeRequest};
use cratefield_testing::{
    FakeHttpClient, SPEECH_CONFORMANCE_AUDIO_BYTES, SPEECH_CONFORMANCE_SYNTH_TEXT,
    SPEECH_CONFORMANCE_TRANSCRIPT_TEXT, speech_conformance, speech_conformance_not_configured,
    speech_conformance_transcribe_request,
};
use http::{HeaderMap, HeaderName, Request, Response, StatusCode};

// Obvious dummy key, never real.
const DUMMY_KEY: &str = "sk-openai-dummy-key-000000000000";

/// The one transcription answer the suite needs, in the vendor's
/// `verbose_json` shape.
const TRANSCRIPTION_RESPONSE: &str = include_str!("fixtures/speech-transcription-response.json");

fn ok(
    status: StatusCode,
    content_type: &'static str,
    body: &'static [u8],
) -> Result<Response<Bytes>, HttpError> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, content_type)
        .body(Bytes::from_static(body))
        .map_err(|err| HttpError::Transport(err.to_string()))
}

fn transcription_response() -> Result<Response<Bytes>, HttpError> {
    ok(
        StatusCode::OK,
        "application/json",
        TRANSCRIPTION_RESPONSE.as_bytes(),
    )
}

/// The one synthesis answer: the canonical audio, byte for byte.
fn synthesis_response() -> Result<Response<Bytes>, HttpError> {
    ok(StatusCode::OK, "audio/mpeg", SPEECH_CONFORMANCE_AUDIO_BYTES)
}

fn unauthorized() -> Result<Response<Bytes>, HttpError> {
    ok(
        StatusCode::UNAUTHORIZED,
        "application/json",
        br#"{"error":{"message":"invalid api key"}}"#,
    )
}

/// A 429 carrying `Retry-After` in its seconds form.
fn rate_limited() -> Result<Response<Bytes>, HttpError> {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::RETRY_AFTER, "30")
        .body(Bytes::from_static(
            br#"{"error":{"message":"rate limit exceeded"}}"#,
        ))
        .map_err(|err| HttpError::Transport(err.to_string()))
}

/// An adapter over a transport scripted with `responses`. The transport is
/// a `RecordingHeaders`, so a test can also read the requests' headers,
/// which `FakeHttpClient` does not keep.
fn scripted(
    responses: Vec<Result<Response<Bytes>, HttpError>>,
) -> (Arc<RecordingHeaders>, OpenAiCompatibleSpeech) {
    let http = Arc::new(RecordingHeaders {
        inner: FakeHttpClient::scripted(responses),
        headers: Mutex::new(Vec::new()),
    });
    let speech = OpenAiCompatibleSpeech::new(http.clone(), Some(DUMMY_KEY.to_owned()));
    (http, speech)
}

fn header_of(http: &RecordingHeaders, index: usize, name: &HeaderName) -> String {
    http.headers.lock().expect("recording lock")[index]
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

/// Records the requests' headers and delegates the scripting.
struct RecordingHeaders {
    inner: FakeHttpClient,
    headers: Mutex<Vec<HeaderMap>>,
}

#[async_trait]
impl HttpClient for RecordingHeaders {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        self.headers
            .lock()
            .expect("recording lock")
            .push(request.headers().clone());
        self.inner.send(request).await
    }
}

#[test]
fn the_shared_speech_conformance_suite_passes_over_the_openai_compatible_speech_adapter() {
    let (http, speech) = scripted(vec![transcription_response(), synthesis_response()]);
    pollster::block_on(speech_conformance(&speech, &|| http.inner.captured().len()));
    // The suite scripted exactly two wire calls, and no over-limit ask
    // added a third.
    assert_eq!(http.inner.captured().len(), 2);
}

#[test]
fn an_absent_key_answers_not_configured() {
    let speech = OpenAiCompatibleSpeech::new(Arc::new(FakeHttpClient::scripted(vec![])), None);
    pollster::block_on(speech_conformance_not_configured(&speech));
}

#[test]
fn transcribe_posts_multipart_with_the_model_language_and_audio() {
    let (http, speech) = scripted(vec![transcription_response()]);
    let transcript =
        pollster::block_on(speech.transcribe(&speech_conformance_transcribe_request()))
            .expect("the canonical clip transcribes");
    assert_eq!(transcript.text, SPEECH_CONFORMANCE_TRANSCRIPT_TEXT);

    let (method, uri, body) = &http.inner.captured()[0];
    assert_eq!(method, "POST");
    assert_eq!(uri, "https://api.openai.com/v1/audio/transcriptions");
    // The wire fields: model, the hint's primary subtag, the answer shape
    // and its word timings, and the audio itself with filename and type.
    assert!(
        body.contains("name=\"model\"\r\n\r\nwhisper-1\r\n"),
        "{body}"
    );
    assert!(body.contains("name=\"language\"\r\n\r\nen\r\n"), "{body}");
    assert!(body.contains("verbose_json"), "{body}");
    assert!(body.contains("timestamp_granularities[]"), "{body}");
    assert!(body.contains("filename=\"audio.wav\""), "{body}");
    assert!(body.contains("Content-Type: audio/wav"), "{body}");
    assert!(body.contains("RIFF"), "{body}");
    // The bearer key, and the multipart content type, on the request.
    assert_eq!(
        header_of(&http, 0, &http::header::AUTHORIZATION),
        format!("Bearer {DUMMY_KEY}")
    );
    assert!(
        header_of(&http, 0, &http::header::CONTENT_TYPE)
            .starts_with("multipart/form-data; boundary=")
    );

    // The same wire at another base URL and model: a Regolo-style host.
    let http = Arc::new(FakeHttpClient::scripted(vec![transcription_response()]));
    let speech = OpenAiCompatibleSpeech::new(http.clone(), Some(DUMMY_KEY.to_owned()))
        .with_base_url("https://api.regolo.ai/v1")
        .with_transcription_model("whisper-large-v3");
    pollster::block_on(speech.transcribe(&speech_conformance_transcribe_request()))
        .expect("transcribes");
    let (method, uri, body) = &http.captured()[0];
    assert_eq!(method, "POST");
    assert_eq!(uri, "https://api.regolo.ai/v1/audio/transcriptions");
    assert!(body.contains("whisper-large-v3"), "{body}");
}

#[test]
fn synthesize_posts_json_to_the_speech_endpoint() {
    let (http, speech) = scripted(vec![synthesis_response()]);
    let synthesis = pollster::block_on(speech.synthesize(&SynthesizeRequest::new(
        SPEECH_CONFORMANCE_SYNTH_TEXT,
        "alloy",
        AudioFormat::Mp3,
    )))
    .expect("the canonical text synthesizes");
    assert_eq!(synthesis.format, AudioFormat::Mp3);
    assert_eq!(synthesis.usage.audio_millis, 0);

    let (method, uri, body) = &http.inner.captured()[0];
    assert_eq!(method, "POST");
    assert_eq!(uri, "https://api.openai.com/v1/audio/speech");
    let sent: serde_json::Value = serde_json::from_str(body).expect("a json body");
    assert_eq!(sent["model"], "tts-1");
    assert_eq!(sent["input"], SPEECH_CONFORMANCE_SYNTH_TEXT);
    assert_eq!(sent["voice"], "alloy");
    assert_eq!(sent["response_format"], "mp3");
    // The bearer key, and the JSON content type, on this request too.
    assert_eq!(
        header_of(&http, 0, &http::header::AUTHORIZATION),
        format!("Bearer {DUMMY_KEY}")
    );
    assert_eq!(
        header_of(&http, 0, &http::header::CONTENT_TYPE),
        "application/json"
    );
}

#[test]
fn a_429_maps_to_transient_with_its_delay_and_a_bad_key_does_not() {
    let (_, speech) = scripted(vec![rate_limited()]);
    let error = pollster::block_on(speech.transcribe(&speech_conformance_transcribe_request()))
        .expect_err("the 429 refuses");
    assert_eq!(error.retry_after(), Some(Duration::from_secs(30)));

    let (_, speech) = scripted(vec![unauthorized()]);
    let error = pollster::block_on(speech.transcribe(&speech_conformance_transcribe_request()))
        .expect_err("the 401 refuses");
    assert_eq!(error, SpeechError::Provider("invalid api key".to_owned()));
}
