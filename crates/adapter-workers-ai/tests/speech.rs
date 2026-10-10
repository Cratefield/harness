//! The `Speech` adapter's behaviour against a fake `SpeechRunner`: the
//! binding cannot be constructed off wasm, but every line around the call —
//! limit checks, request building, transcript parsing, voice listing,
//! refusals, streaming — is exercised here, natively, over the recorded
//! fixtures in `tests/fixtures/`.

#![allow(clippy::disallowed_types)]

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures_core::Stream;
use serde_json::Value;

use cratefield_adapter_workers_ai::{
    SpeechModel, SpeechRunner, TranscriptionModel, WORKERS_AI_MAX_AUDIO_BYTES, WorkersAiSpeech,
};
use cratefield_core::{
    AudioFormat, BoxStream, Speech, SpeechError, SpeechLimits, StreamError, SynthesizeRequest,
    TranscribeRequest,
};
use cratefield_testing::{
    SPEECH_CONFORMANCE_AUDIO_BYTES, SPEECH_CONFORMANCE_AUDIO_MILLIS, SPEECH_CONFORMANCE_SYNTH_TEXT,
    SPEECH_CONFORMANCE_TRANSCRIPT_TEXT, speech_conformance, speech_conformance_transcribe_request,
};

// --- The fake binding ------------------------------------------------------

/// A stream over fixed chunks — the minimal stand-in for the binding's
/// audio stream, written out so the tests need no `futures-util`.
struct Chunks(std::vec::IntoIter<Result<Bytes, StreamError>>);

impl Stream for Chunks {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.get_mut().0.next())
    }
}

/// A chunk stream that yields `head` at once, then waits on a oneshot gate
/// before yielding `tail` and ending — a binding that has not finished
/// while the caller already has its first bytes.
struct Gated {
    head: Option<Result<Bytes, StreamError>>,
    gate: futures_channel::oneshot::Receiver<()>,
    tail: bool,
}

impl Stream for Gated {
    type Item = Result<Bytes, StreamError>;

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
                Poll::Ready(Some(Ok(Bytes::from_static(b"tail"))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// A stand-in binding: records every call (model + input), answers
/// `run_json` from a programmed queue, and builds each `run_audio` stream
/// from a factory so every synthesis gets a fresh one. Cheaply cloneable so
/// a test keeps a handle to the calls after the fake has been handed to the
/// adapter.
#[derive(Clone)]
struct FakeRunner {
    inner: Arc<Inner>,
}

struct Inner {
    state: Mutex<FakeState>,
    audio: Box<dyn Fn() -> BoxStream<'static, Result<Bytes, StreamError>> + Send + Sync>,
}

struct FakeState {
    calls: Vec<(String, Value)>,
    responses: std::collections::VecDeque<Result<Value, SpeechError>>,
}

impl FakeRunner {
    /// A programmed JSON answer, twice over (the suite's call and the
    /// shape check's repeat parse), with canonical audio.
    fn answering(response: Value) -> Self {
        Self::with_audio(
            vec![Ok(response.clone()), Ok(response)],
            Self::canonical_audio,
        )
    }

    fn with_audio(
        responses: Vec<Result<Value, SpeechError>>,
        audio: impl Fn() -> BoxStream<'static, Result<Bytes, StreamError>> + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(FakeState {
                    calls: Vec::new(),
                    responses: responses.into(),
                }),
                audio: Box::new(audio),
            }),
        }
    }

    /// The conformance suite's scripted bytes, split in two so the stream
    /// is real streaming.
    fn canonical_audio() -> BoxStream<'static, Result<Bytes, StreamError>> {
        let bytes = SPEECH_CONFORMANCE_AUDIO_BYTES;
        let split = bytes.len() / 2;
        Box::pin(Chunks(
            vec![
                Ok(Bytes::from(bytes[..split].to_vec())),
                Ok(Bytes::from(bytes[split..].to_vec())),
            ]
            .into_iter(),
        ))
    }

    /// The gated runner for the streaming acceptance test, plus the sender
    /// that opens its second chunk.
    fn gated() -> (Self, futures_channel::oneshot::Sender<()>) {
        let (sender, receiver) = futures_channel::oneshot::channel();
        let slot: Mutex<Option<futures_channel::oneshot::Receiver<()>>> =
            Mutex::new(Some(receiver));
        let runner = Self::with_audio(Vec::new(), move || {
            let gate = slot.lock().expect("gate lock").take().expect("gate once");
            Box::pin(Gated {
                head: Some(Ok(Bytes::from_static(b"head"))),
                gate,
                tail: false,
            })
        });
        (runner, sender)
    }

    fn calls(&self) -> Vec<(String, Value)> {
        self.inner.state.lock().expect("fake lock").calls.clone()
    }
}

#[async_trait]
impl SpeechRunner for FakeRunner {
    async fn run_json(&self, model: &str, input: Value) -> Result<Value, SpeechError> {
        let mut state = self.inner.state.lock().expect("fake lock");
        state.calls.push((model.to_owned(), input));
        state
            .responses
            .pop_front()
            .expect("every call is programmed a response")
    }

    async fn run_audio(
        &self,
        model: &str,
        input: Value,
    ) -> Result<BoxStream<'static, Result<Bytes, StreamError>>, SpeechError> {
        let mut state = self.inner.state.lock().expect("fake lock");
        state.calls.push((model.to_owned(), input));
        Ok((self.inner.audio)())
    }
}

// --- The fixtures ----------------------------------------------------------

fn nova3_response() -> Value {
    serde_json::from_str(include_str!("fixtures/nova-3-response.json")).expect("fixture parses")
}

fn whisper_response() -> Value {
    serde_json::from_str(include_str!("fixtures/whisper-response.json")).expect("fixture parses")
}

fn turbo_response() -> Value {
    serde_json::from_str(include_str!("fixtures/turbo-response.json")).expect("fixture parses")
}

// --- The suite -------------------------------------------------------------

#[test]
fn the_conformance_suite_passes_over_nova_3_and_the_shape_holds() {
    let runner = FakeRunner::answering(nova3_response());
    let speech = WorkersAiSpeech::with_runner(runner.clone());
    pollster::block_on(speech_conformance(&speech, &|| runner.calls().len()));
    assert_eq!(
        runner.calls().len(),
        2,
        "one transcribe and one synthesize; voices is the schema, not a call"
    );

    // calls[0] is the suite's transcribe: nova-3's documented document,
    // the clip as a plain byte array, the hint where nova-3 takes one.
    let (model, input) = &runner.calls()[0];
    assert_eq!(model, "@cf/deepgram/nova-3");
    let request = speech_conformance_transcribe_request();
    let body = input["audio"]["body"].as_array().expect("byte array");
    assert_eq!(body.len(), request.audio.len());
    assert_eq!(
        (
            body.first().and_then(Value::as_u64),
            body.last().and_then(Value::as_u64)
        ),
        (
            Some(u64::from(request.audio[0])),
            Some(u64::from(request.audio[request.audio.len() - 1])),
        ),
        "the clip rides as a plain byte array, first to last"
    );
    assert_eq!(input["audio"]["contentType"], "audio/wav");
    assert_eq!(input["language"], "en");
    assert_eq!(input["punctuate"], true);
    assert_eq!(input["smart_format"], true);

    // And the parse, once more: nova-3's words carry confidence.
    let transcript =
        pollster::block_on(speech.transcribe(&speech_conformance_transcribe_request()))
            .expect("transcribes");
    let first = &transcript.words[0];
    assert_eq!(first.word, "the");
    assert_eq!(first.start, Duration::from_millis(0));
    assert_eq!(first.end, Duration::from_millis(120));
    let confidence = first.confidence.expect("nova-3 words carry confidence");
    assert!((confidence - 0.98).abs() < 1.0e-6, "{confidence}");
}

#[test]
fn the_conformance_suite_passes_over_whisper_and_the_shape_holds() {
    let runner = FakeRunner::answering(whisper_response());
    let speech = WorkersAiSpeech::with_runner(runner.clone())
        .with_transcription_model(TranscriptionModel::Whisper);
    pollster::block_on(speech_conformance(&speech, &|| runner.calls().len()));
    assert_eq!(runner.calls().len(), 2);

    // The base Whisper schema: bare audio, no language field.
    let (model, input) = &runner.calls()[0];
    assert_eq!(model, "@cf/openai/whisper");
    assert!(input["audio"].is_array());
    assert!(input.get("language").is_none());
    assert!(input.get("contentType").is_none());

    // And the parse: no language, no confidence.
    let transcript =
        pollster::block_on(speech.transcribe(&speech_conformance_transcribe_request()))
            .expect("transcribes");
    assert_eq!(transcript.language, None);
    assert!(
        transcript
            .words
            .iter()
            .all(|word| word.confidence.is_none())
    );
}

#[test]
fn turbo_prefers_the_provider_duration_and_reports_the_language() {
    let runner = FakeRunner::answering(turbo_response());
    let speech = WorkersAiSpeech::with_runner(runner.clone())
        .with_transcription_model(TranscriptionModel::WhisperLargeV3Turbo);
    // Not WAV and nothing declared, so the only length on offer is the
    // provider's own `transcription_info.duration`.
    let request =
        TranscribeRequest::new(Bytes::from(vec![7u8; 16]), "audio/mpeg").with_language_hint("en");
    let transcript = pollster::block_on(speech.transcribe(&request)).expect("transcribes");

    assert_eq!(transcript.text, SPEECH_CONFORMANCE_TRANSCRIPT_TEXT);
    assert_eq!(
        transcript.usage.audio_millis, SPEECH_CONFORMANCE_AUDIO_MILLIS,
        "the provider's duration bills, not the last word's end"
    );
    assert_eq!(transcript.language.as_deref(), Some("en"));
    assert_eq!(transcript.words.len(), 4);

    let input = &runner.calls()[0].1;
    assert_eq!(input["task"], "transcribe");
    assert_eq!(input["language"], "en");
}

// --- Request shapes and voices ---------------------------------------------

#[test]
fn aura_receives_speaker_and_encoding_and_bills_characters() {
    let runner = FakeRunner::answering(nova3_response());
    let speech = WorkersAiSpeech::with_runner(runner.clone());
    let request = SynthesizeRequest::new(SPEECH_CONFORMANCE_SYNTH_TEXT, "luna", AudioFormat::Mp3);
    let synthesis = pollster::block_on(speech.synthesize(&request)).expect("synthesizes");
    assert_eq!(synthesis.format, AudioFormat::Mp3);
    assert_eq!(synthesis.usage.audio_millis, 0);
    assert_eq!(
        synthesis.usage.characters,
        u64::try_from(SPEECH_CONFORMANCE_SYNTH_TEXT.chars().count()).expect("a short text")
    );

    let (model, input) = &runner.calls()[0];
    assert_eq!(model, "@cf/deepgram/aura-2-en");
    assert_eq!(input["speaker"], "luna");
    assert_eq!(input["encoding"], "mp3");
    assert!(input.get("container").is_none(), "mp3 needs no container");
}

#[test]
fn voices_are_the_local_schema_filtered_by_primary_subtag() {
    for (model, expected) in [(SpeechModel::Aura2En, 40), (SpeechModel::Aura1, 12)] {
        let runner = FakeRunner::answering(nova3_response());
        let speech = WorkersAiSpeech::with_runner(runner.clone()).with_speech_model(model);
        let every = pollster::block_on(speech.voices(None)).expect("voices");
        assert_eq!(every.len(), expected, "{}", model.id());
        assert!(
            every
                .iter()
                .all(|voice| voice.languages == vec!["en".to_owned()])
        );
        assert_eq!(
            pollster::block_on(speech.voices(Some("en-GB")))
                .expect("voices")
                .len(),
            expected,
            "primary subtags match"
        );
        assert!(
            pollster::block_on(speech.voices(Some("fr-FR")))
                .expect("voices")
                .is_empty()
        );
        assert_eq!(
            runner.calls().len(),
            0,
            "the list is the schema, never a call"
        );
    }
    let aura2 = WorkersAiSpeech::with_runner(FakeRunner::answering(nova3_response()));
    let every = pollster::block_on(aura2.voices(None)).expect("voices");
    assert!(every.iter().any(|voice| voice.id == "luna"));
}

// --- Local refusals ---------------------------------------------------------

#[test]
fn the_speaker_namespace_belongs_to_the_provider_unless_strict_voices() {
    // The port's own conformance suite synthesizes with the arbitrary id
    // `conformance`, so the default forwards it: the provider owns the
    // speaker namespace.
    let runner = FakeRunner::answering(nova3_response());
    let speech = WorkersAiSpeech::with_runner(runner.clone());
    let request = SynthesizeRequest::new("hi", "conformance", AudioFormat::Mp3);
    pollster::block_on(speech.synthesize(&request)).expect("synthesizes");
    assert_eq!(runner.calls()[0].1["speaker"], "conformance");

    // With strict voices the typo is refused locally, a documented voice
    // by any case still rides.
    let strict = WorkersAiSpeech::with_runner(runner.clone()).with_strict_voices();
    let outcome = pollster::block_on(strict.synthesize(&SynthesizeRequest::new(
        "hi",
        "narrator",
        AudioFormat::Mp3,
    )));
    assert!(
        matches!(outcome, Err(SpeechError::InvalidInput(_))),
        "{outcome:?}"
    );
    pollster::block_on(strict.synthesize(&SynthesizeRequest::new("hi", "Luna", AudioFormat::Mp3)))
        .expect("a documented voice synthesizes");
    assert_eq!(runner.calls().len(), 2);
    assert_eq!(runner.calls()[1].1["speaker"], "Luna");
}

#[test]
fn malformed_and_over_limit_asks_are_refused_before_the_binding() {
    let runner = FakeRunner::answering(nova3_response());
    let speech = WorkersAiSpeech::with_runner(runner.clone()).with_limits(SpeechLimits {
        max_audio_bytes: 100,
        max_audio_seconds: 10,
        max_synthesis_chars: 20,
    });

    // An empty voice id is malformed, whatever the provider would do.
    let outcome =
        pollster::block_on(speech.synthesize(&SynthesizeRequest::new("hi", "", AudioFormat::Mp3)));
    assert!(
        matches!(outcome, Err(SpeechError::InvalidInput(_))),
        "{outcome:?}"
    );

    // capabilities().languages is the synthesis side: the Aura voices are
    // English-only, so a French voice-over never reaches the binding.
    let french = SynthesizeRequest::new("bonjour", "luna", AudioFormat::Mp3).with_language("fr-FR");
    assert_eq!(
        pollster::block_on(speech.synthesize(&french)).err(),
        Some(SpeechError::UnsupportedLanguage("fr-FR".to_owned()))
    );

    // Either ceiling.
    let over_bytes = TranscribeRequest::new(Bytes::from(vec![0u8; 101]), "audio/wav");
    assert!(matches!(
        pollster::block_on(speech.transcribe(&over_bytes)),
        Err(SpeechError::LimitExceeded {
            limit: cratefield_core::SpeechLimit::AudioBytes,
            ..
        })
    ));
    let over_chars = SynthesizeRequest::new("x".repeat(21), "luna", AudioFormat::Mp3);
    assert!(matches!(
        pollster::block_on(speech.synthesize(&over_chars)),
        Err(SpeechError::LimitExceeded {
            limit: cratefield_core::SpeechLimit::SynthesisChars,
            ..
        })
    ));
    assert_eq!(runner.calls().len(), 0, "no refusal reached the binding");
}

#[test]
fn the_default_byte_ceiling_refuses_a_clip_over_one_mib_before_the_binding() {
    // The adapter's own default is well under the port's 25 MiB: the clip
    // rides to the binding as a JSON number array, so 25 MiB of audio
    // would outrun a 128 MB isolate before `LimitExceeded` could answer.
    let runner = FakeRunner::answering(nova3_response());
    let speech = WorkersAiSpeech::with_runner(runner.clone());
    assert_eq!(speech.limits().max_audio_bytes, WORKERS_AI_MAX_AUDIO_BYTES);

    // Just over that default — but under the port default — is refused
    // locally, typed, and the binding sees nothing.
    let clip = vec![0u8; usize::try_from(WORKERS_AI_MAX_AUDIO_BYTES + 1).expect("1 MiB fits")];
    let outcome = pollster::block_on(
        speech.transcribe(&TranscribeRequest::new(Bytes::from(clip), "audio/mpeg")),
    );
    assert!(
        matches!(
            outcome,
            Err(SpeechError::LimitExceeded {
                limit: cratefield_core::SpeechLimit::AudioBytes,
                ..
            })
        ),
        "{outcome:?}"
    );
    assert_eq!(runner.calls().len(), 0, "no refusal reached the binding");
}

// --- Streaming -------------------------------------------------------------

#[test]
fn synthesis_streams_before_the_provider_has_finished() {
    let (runner, sender) = FakeRunner::gated();
    let speech = WorkersAiSpeech::with_runner(runner);
    let request = SynthesizeRequest::new(SPEECH_CONFORMANCE_SYNTH_TEXT, "luna", AudioFormat::Mp3);
    let synthesis = pollster::block_on(speech.synthesize(&request)).expect("synthesizes");
    let mut stream = synthesis
        .audio
        .take()
        .expect("a fresh synthesis still owns its stream");

    let mut cx = Context::from_waker(std::task::Waker::noop());
    // The first chunk arrives while the gate is still shut: the caller has
    // audio before the binding has finished the clip.
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
