//! The [`Speech`] port contract (issue #861): the canonical values every
//! adapter's recorded fixture is built from, and the assertions every
//! adapter runs against itself. Needs nothing beyond `cratefield-core`.

use std::pin::Pin;
use std::time::Duration;

use bytes::Bytes;
use futures_core::Stream as _;

use cratefield_core::{
    AudioFormat, Speech, SpeechCapabilities, SpeechError, SpeechLimit, Synthesis,
    SynthesizeRequest, TranscribeRequest, Transcript,
};

/// The canonical transcript the suite expects, verbatim: four words,
/// short and fixed, so an adapter test scripts its transport to answer
/// exactly this in its vendor's wire shape.
pub const SPEECH_CONFORMANCE_TRANSCRIPT_TEXT: &str = "the quick brown fox";

/// The canonical length of the transcribed audio, in milliseconds — what
/// the canonical WAV clip works out to, and what the scripted transcript
/// must report as `SpeechUsage::audio_millis`.
pub const SPEECH_CONFORMANCE_AUDIO_MILLIS: u64 = 1_500;

/// The canonical word timings as `(word, start_ms, end_ms)`: the four
/// words of [`SPEECH_CONFORMANCE_TRANSCRIPT_TEXT`], the first starting at
/// zero.
pub const SPEECH_CONFORMANCE_WORD_TIMINGS: [(&str, u64, u64); 4] = [
    ("the", 0, 120),
    ("quick", 120, 380),
    ("brown", 380, 640),
    ("fox", 640, 900),
];

/// The canonical text the suite synthesizes.
pub const SPEECH_CONFORMANCE_SYNTH_TEXT: &str = "cratefield speech conformance";

/// The canonical audio the scripted synthesis returns, byte for byte: a
/// short mp3-shaped stand-in the suite asserts is carried through
/// unharmed, not that it decodes.
pub const SPEECH_CONFORMANCE_AUDIO_BYTES: &[u8] = b"cratefield-conformance-fake-mp3-audio";

/// A small valid WAV clip (8 000 bytes/second, 12 000 data bytes —
/// exactly [`SPEECH_CONFORMANCE_AUDIO_MILLIS`]) with no declared duration,
/// so the length derives from the RIFF header. The request a fixture
/// scripts against: `audio/wav`, language hint `en`.
#[must_use]
pub fn speech_conformance_transcribe_request() -> TranscribeRequest {
    // The same 8-bit mono 8 kHz header the port's own tests build.
    let mut audio = Vec::with_capacity(44 + 12_000);
    audio.extend_from_slice(b"RIFF");
    audio.extend_from_slice(&u32::to_le_bytes(36 + 12_000));
    audio.extend_from_slice(b"WAVEfmt ");
    audio.extend_from_slice(&u32::to_le_bytes(16));
    audio.extend_from_slice(&u16::to_le_bytes(1)); // PCM
    audio.extend_from_slice(&u16::to_le_bytes(1)); // mono
    audio.extend_from_slice(&u32::to_le_bytes(8_000)); // sample rate
    audio.extend_from_slice(&u32::to_le_bytes(8_000)); // byte rate
    audio.extend_from_slice(&u16::to_le_bytes(1)); // block align
    audio.extend_from_slice(&u16::to_le_bytes(8)); // bits per sample
    audio.extend_from_slice(b"data");
    audio.extend_from_slice(&u32::to_le_bytes(12_000));
    audio.resize(44 + 12_000, 0);
    TranscribeRequest::new(Bytes::from(audio), "audio/wav").with_language_hint("en")
}

/// Asserts the [`Speech`] trait contract against an adapter whose
/// transport is scripted to answer the canonical fixture: the
/// [`speech_conformance_transcribe_request`] clip with
/// [`SPEECH_CONFORMANCE_TRANSCRIPT_TEXT`] (usage
/// [`SPEECH_CONFORMANCE_AUDIO_MILLIS`]), a synthesis of
/// [`SPEECH_CONFORMANCE_SYNTH_TEXT`] in `Mp3` streaming out
/// [`SPEECH_CONFORMANCE_AUDIO_BYTES`] byte for byte, and a non-empty
/// voice list.
///
/// The suite makes **exactly one** transcribe, one synthesize and one
/// voices call — script those three responses and no other. `calls` reads
/// the transport's call count (for the kit's `FakeHttpClient`,
/// `|| http.captured().len()`); after the three scripted calls it must
/// never move again, because every over-limit ask below has to be refused
/// **before the network** — that is the rule the suite exists to prove.
///
/// # Panics
///
/// Panics with the failing rule named when the contract is violated.
pub async fn speech_conformance(speech: &dyn Speech, calls: &dyn Fn() -> usize) {
    assert_transcription(speech).await;
    assert_synthesis(speech).await;

    // Rule 3: a voice list a caller can offer a user.
    let voices = speech.voices(None).await.unwrap_or_else(|error| {
        panic!("the scripted voice listing failed — script one non-empty answer: {error:?}")
    });
    assert!(
        !voices.is_empty(),
        "rule 3 (voices(None) is non-empty — a caller offers the user a voice)"
    );

    // Rule 4: the over-limit asks are refused locally (see the helper).
    assert_over_limit_refused_locally(speech, calls).await;
}

/// Rule 1: the canonical clip comes back as the canonical transcript.
async fn assert_transcription(speech: &dyn Speech) {
    let transcript = speech
        .transcribe(&speech_conformance_transcribe_request())
        .await
        .unwrap_or_else(|error| {
            panic!(
                "the scripted transcription failed — script the transport to answer \
                 speech_conformance_transcribe_request() with \
                 SPEECH_CONFORMANCE_TRANSCRIPT_TEXT and SPEECH_CONFORMANCE_AUDIO_MILLIS: \
                 {error:?}"
            )
        });
    assert_eq!(
        transcript.text, SPEECH_CONFORMANCE_TRANSCRIPT_TEXT,
        "rule 1 (the text is the scripted transcript, verbatim): got {:?}",
        transcript.text
    );
    assert_eq!(
        transcript.usage.audio_millis, SPEECH_CONFORMANCE_AUDIO_MILLIS,
        "rule 1 (every transcript reports the audio it billed, in milliseconds)"
    );
    assert_eq!(
        transcript.usage.characters, 0,
        "rule 1 (a transcription bills milliseconds, not characters)"
    );
    assert_word_timings(&transcript, &speech.capabilities());
}

/// Rule 2: the canonical synthesis streams the canonical bytes back, in
/// the format that was asked for, billing the text's characters.
async fn assert_synthesis(speech: &dyn Speech) {
    let capabilities = speech.capabilities();
    assert!(
        capabilities.supports_format(AudioFormat::Mp3),
        "the fixture synthesizes Mp3 — advertise it in capabilities().formats"
    );
    let request = SynthesizeRequest::new(
        SPEECH_CONFORMANCE_SYNTH_TEXT,
        "conformance",
        AudioFormat::Mp3,
    );
    let synthesis = speech.synthesize(&request).await.unwrap_or_else(|error| {
        panic!(
            "the scripted synthesis failed — script the transport to voice \
                 SPEECH_CONFORMANCE_SYNTH_TEXT as SPEECH_CONFORMANCE_AUDIO_BYTES: {error:?}"
        )
    });
    assert_eq!(
        synthesis.format,
        AudioFormat::Mp3,
        "rule 2 (the synthesis names the format that was asked for)"
    );
    assert_eq!(
        synthesis.usage.characters,
        u64::try_from(SPEECH_CONFORMANCE_SYNTH_TEXT.chars().count())
            .expect("a conformance text fits in u64"),
        "rule 2 (every synthesis reports the characters it billed)"
    );
    assert_eq!(
        synthesis.usage.audio_millis, 0,
        "rule 2 (a synthesis bills characters, not milliseconds)"
    );
    let body = collect(synthesis).await;
    assert_eq!(
        &body[..],
        SPEECH_CONFORMANCE_AUDIO_BYTES,
        "rule 2 (the streamed audio is the scripted bytes, unharmed)"
    );
}

/// Rule 4: each over-limit ask is refused with the matching
/// [`SpeechLimit`], and `calls` never moves again — the refusals
/// provably happened before the network.
async fn assert_over_limit_refused_locally(speech: &dyn Speech, calls: &dyn Fn() -> usize) {
    let limits = speech.limits();
    let scripted_calls = calls();

    let over_bytes = TranscribeRequest::new(
        Bytes::from(vec![
            0u8;
            usize::try_from(limits.max_audio_bytes + 1)
                .expect("the audio byte cap fits in usize")
        ]),
        "audio/wav",
    );
    assert_limit_refused(
        speech.transcribe(&over_bytes).await.map(drop),
        SpeechLimit::AudioBytes,
        limits.max_audio_bytes + 1,
        limits.max_audio_bytes,
        calls,
        scripted_calls,
    );

    let over_seconds = TranscribeRequest::new(small_audio(), "audio/wav")
        .with_duration(Duration::from_secs(u64::from(limits.max_audio_seconds) + 1));
    assert_limit_refused(
        speech.transcribe(&over_seconds).await.map(drop),
        SpeechLimit::AudioSeconds,
        (u64::from(limits.max_audio_seconds) + 1) * 1_000,
        u64::from(limits.max_audio_seconds) * 1_000,
        calls,
        scripted_calls,
    );

    let over_chars = SynthesizeRequest::new(
        "x".repeat(
            usize::try_from(u64::from(limits.max_synthesis_chars) + 1)
                .expect("the synthesis char cap fits in usize"),
        ),
        "conformance",
        AudioFormat::Mp3,
    );
    assert_limit_refused(
        speech.synthesize(&over_chars).await.map(drop),
        SpeechLimit::SynthesisChars,
        u64::from(limits.max_synthesis_chars) + 1,
        u64::from(limits.max_synthesis_chars),
        calls,
        scripted_calls,
    );
}

/// Asserts an adapter with no key behind it answers
/// [`SpeechError::NotConfigured`] on every operation — the unwired port
/// is an error the caller matches.
///
/// # Panics
/// If an operation succeeds or fails as anything but `NotConfigured`.
pub async fn speech_conformance_not_configured(speech: &dyn Speech) {
    let transcript = speech
        .transcribe(&speech_conformance_transcribe_request())
        .await
        .err();
    assert_eq!(
        transcript,
        Some(SpeechError::NotConfigured),
        "an adapter with no key answers NotConfigured"
    );
    let synthesis = speech
        .synthesize(&SynthesizeRequest::new(
            SPEECH_CONFORMANCE_SYNTH_TEXT,
            "conformance",
            AudioFormat::Mp3,
        ))
        .await
        .err();
    assert_eq!(synthesis, Some(SpeechError::NotConfigured));
    let voices = speech.voices(None).await.err();
    assert_eq!(voices, Some(SpeechError::NotConfigured));
}

/// Asserts the transcript's word timings: empty is allowed (a provider
/// that reports no timing), anything else is the canonical four words in
/// order, monotonic, at millisecond precision.
fn assert_word_timings(transcript: &Transcript, capabilities: &SpeechCapabilities) {
    if transcript.words.is_empty() {
        return;
    }
    assert!(
        capabilities.word_timings,
        "rule 1 (words are only reported by an adapter advertising word_timings)"
    );
    assert_eq!(
        transcript.words.len(),
        SPEECH_CONFORMANCE_WORD_TIMINGS.len(),
        "rule 1 (a timed transcript carries the canonical four words)"
    );
    let mut previous_end = 0u128;
    for (timing, (word, start_ms, end_ms)) in
        transcript.words.iter().zip(SPEECH_CONFORMANCE_WORD_TIMINGS)
    {
        assert_eq!(timing.word, word, "rule 1 (the words come back in order)");
        assert_eq!(
            timing.start.as_millis(),
            u128::from(start_ms),
            "rule 1 (word timings are at millisecond precision)"
        );
        assert_eq!(timing.end.as_millis(), u128::from(end_ms));
        assert!(
            timing.start <= timing.end && previous_end <= timing.start.as_millis(),
            "rule 1 (timings are monotonic: start <= end, no overlap)"
        );
        previous_end = timing.end.as_millis();
    }
}

/// Asserts a `LimitExceeded` answer names the right ceiling with the right
/// sizes, and that the transport was not called again.
fn assert_limit_refused(
    result: Result<(), SpeechError>,
    limit: SpeechLimit,
    actual: u64,
    max: u64,
    calls: &dyn Fn() -> usize,
    scripted_calls: usize,
) {
    assert_eq!(
        result.err(),
        Some(SpeechError::LimitExceeded { limit, actual, max }),
        "rule 4 (the over-limit ask is refused with its own ceiling)"
    );
    assert_eq!(
        calls(),
        scripted_calls,
        "rule 4 (the refusal happened before the network: the transport saw nothing)"
    );
}

/// Drains a synthesis to bytes: whoever consumes a [`Synthesis`] polls the
/// taken stream to the end, so the suite does exactly that.
async fn collect(synthesis: Synthesis) -> Vec<u8> {
    let mut source = synthesis
        .audio
        .take()
        .expect("a fresh synthesis still owns its stream");
    let mut body = Vec::new();
    loop {
        match std::future::poll_fn(|cx| Pin::new(&mut source).poll_next(cx)).await {
            Some(Ok(chunk)) => body.extend_from_slice(&chunk),
            Some(Err(error)) => panic!("the scripted audio stream failed mid-body: {error}"),
            None => return body,
        }
    }
}

/// A small clip under every cap, for the over-seconds ask.
fn small_audio() -> Bytes {
    Bytes::from(vec![0u8; 64])
}

#[cfg(all(test, feature = "harness"))]
mod tests {
    use super::*;
    use cratefield_core::NotConfiguredSpeech;

    /// The suite runs for real against both adapters' test suites; here it
    /// is enough to prove the unwired-port helper holds over the port's
    /// own placeholder.
    #[pollster::test]
    async fn the_unwired_port_answers_not_configured() {
        speech_conformance_not_configured(&NotConfiguredSpeech).await;
    }
}
