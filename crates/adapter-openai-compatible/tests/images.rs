//! Image-input acceptance tests for the `OpenAiCompatible` adapter (issue
//! #628): a parts-bearing turn serialises as the `content` array of text and
//! `image_url` parts (recorded in `tests/fixtures/image-request.json`); image
//! input is opt-in; a deployment without vision refuses an image prompt
//! before any request; and an over-limit prompt is refused with `ImageLimit`
//! also before any request.

// Test-side recording fixture, not request state — the same category and
// allowance as the fakes in `cratefield-testing` (ADR 0007 policy).
#![allow(clippy::disallowed_types)]

use bytes::Bytes;
use cratefield_adapter_openai_compatible::OpenAiCompatible;
use cratefield_core::{
    Capability, HttpError, ImageLimit, ImageMediaType, MAX_IMAGE_ENCODED_BYTES, ModelTier, Part,
    Prompt, TextModel, TextModelError,
};
use cratefield_testing::{FakeHttpClient, FixedClock};
use http::Response;
use serde_json::Value;
use std::sync::Arc;

// Obvious dummy key, never real.
const DUMMY_KEY: &str = "sk-openai-dummy-key-000000000000";

/// The exact request body a one-text-part, two-image prompt produces, as
/// recorded when the fixture was taken.
const IMAGE_REQUEST: &str = include_str!("fixtures/image-request.json");

/// A plain text answer, so a recorded request reaches a well-formed 200.
const PLAIN_RESPONSE: &str = r#"{
    "model": "gpt-4o-2024-08-06",
    "choices": [{"message": {"role": "assistant", "content": "Two images."}, "finish_reason": "stop"}],
    "usage": {"prompt_tokens": 5, "completion_tokens": 2}
}"#;

fn ok(body: &str) -> Result<Response<Bytes>, HttpError> {
    Response::builder()
        .status(200)
        .body(Bytes::from(body.to_owned()))
        .map_err(|err| HttpError::Transport(err.to_string()))
}

/// The adapter over `http`, without image input (the default).
fn default_adapter(http: &FakeHttpClient) -> OpenAiCompatible {
    OpenAiCompatible::new(
        Arc::new(http.clone()),
        Arc::new(FixedClock(
            time::OffsetDateTime::from_unix_timestamp(0).expect("valid timestamp"),
        )),
        Some(DUMMY_KEY.to_owned()),
        "gpt-4o-2024-08-06",
    )
}

/// The adapter over `http` with image input opted in.
fn adapter(http: &FakeHttpClient) -> OpenAiCompatible {
    default_adapter(http).with_images()
}

/// The prompt the recorded fixture was taken from: one user turn of one text
/// part and two images — a PNG and a JPEG — in order.
fn image_prompt() -> Prompt {
    Prompt::new(ModelTier::Fast)
        .user_parts([
            Part::text("What is in these two images?"),
            // Signature bytes only: a real PNG and JPEG, kept tiny.
            Part::image(ImageMediaType::Png, vec![0x89, 0x50, 0x4e, 0x47]),
            Part::image(ImageMediaType::Jpeg, vec![0xff, 0xd8, 0xff, 0xe0]),
        ])
        .max_tokens(256)
}

/// The raw byte length whose standard base64 encoding is exactly `encoded`
/// (a multiple of four) — the shape that sits one group over a ceiling.
fn raw_len_for_encoded(encoded: usize) -> usize {
    (encoded / 4) * 3
}

#[pollster::test]
async fn the_request_body_matches_the_recorded_image_fixture() {
    let http = FakeHttpClient::scripted(vec![ok(PLAIN_RESPONSE)]);
    adapter(&http)
        .complete(&image_prompt())
        .await
        .expect("completes");

    let captured = http.captured();
    assert_eq!(captured.len(), 1, "one request reaches the wire");
    let sent: Value = serde_json::from_str(&captured[0].2).expect("request is JSON");
    let expected: Value = serde_json::from_str(IMAGE_REQUEST).expect("fixture is JSON");
    assert_eq!(
        sent, expected,
        "the request body is the recorded fixture exactly"
    );
}

#[pollster::test]
async fn image_input_is_opt_in_and_without_it_an_image_prompt_is_unsupported() {
    let http = FakeHttpClient::scripted(vec![]);
    let without = default_adapter(&http);
    // Off by default: the wire speaks images but a model behind it may not.
    assert!(!without.supports(ModelTier::Fast, Capability::Images));
    // Tools stay on, unaffected.
    assert!(without.supports(ModelTier::Fast, Capability::Tools));

    let err = without.complete(&image_prompt()).await.unwrap_err();
    assert_eq!(err, TextModelError::Unsupported(Capability::Images));
    assert!(
        http.captured().is_empty(),
        "no request for a prompt the adapter cannot carry"
    );

    // The opt-in flips the image capability.
    assert!(
        default_adapter(&http)
            .with_images()
            .supports(ModelTier::Strong, Capability::Images)
    );
}

#[pollster::test]
async fn text_only_messages_still_serialise_content_as_a_plain_string() {
    // The regression the untagged content enum exists for: a prompt with no
    // parts keeps the exact string content every earlier test and fixture
    // records, even on an adapter that carries images.
    let http = FakeHttpClient::scripted(vec![ok(PLAIN_RESPONSE)]);
    adapter(&http)
        .complete(&Prompt::new(ModelTier::Fast).user("Say hello"))
        .await
        .expect("completes");

    let sent: Value = serde_json::from_str(&http.captured()[0].2).expect("request is JSON");
    assert_eq!(sent["messages"][0]["content"], "Say hello");
}

#[pollster::test]
async fn an_oversized_image_is_refused_with_zero_requests() {
    let over = MAX_IMAGE_ENCODED_BYTES + 4;
    let over_raw = raw_len_for_encoded(over);
    let http = FakeHttpClient::scripted(vec![]);
    let prompt = Prompt::new(ModelTier::Fast).user_parts([
        Part::text("a caption"),
        Part::image(ImageMediaType::Png, vec![0u8; over_raw]),
    ]);

    let err = adapter(&http).complete(&prompt).await.unwrap_err();
    assert_eq!(
        err,
        TextModelError::ImageLimit(ImageLimit::ImageTooLarge {
            index: 0,
            encoded_bytes: over,
        })
    );
    assert!(
        http.captured().is_empty(),
        "an over-limit image is refused before any request"
    );
}
