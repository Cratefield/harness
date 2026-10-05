//! Image input over the `Anthropic` adapter (issue #628): the content-block
//! request a `Turn::user_parts` produces — checked against the recorded
//! fixture — the `Capability::Images` report, and an over-limit image
//! refused before any request.

// Test-side recording fixture, not request state — the same category and
// allowance as the fakes in `cratefield-testing` (ADR 0007 policy).
#![allow(clippy::disallowed_types)]

use bytes::Bytes;
use cratefield_adapter_anthropic::Anthropic;
use cratefield_core::{
    Capability, HttpError, ImageLimit, ImageMediaType, MAX_IMAGE_ENCODED_BYTES, ModelTier, Part,
    Prompt, TextModel, TextModelError,
};
use cratefield_testing::{FakeHttpClient, FixedClock};
use http::Response;
use std::sync::Arc;

/// The first eight bytes of a PNG: the file's magic number, which is all a
/// request-shape test needs to stand in for an image.
const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
/// A JPEG's opening bytes: the SOI marker and the first APP0 marker byte.
const JPEG_SIGNATURE: [u8; 4] = [0xFF, 0xD8, 0xFF, 0xE0];

/// A minimal well-formed text answer, enough for `complete` to succeed.
const TEXT_BODY: &str = r#"{
    "id": "msg_text",
    "type": "message",
    "role": "assistant",
    "model": "claude-opus-5",
    "content": [{"type": "text", "text": "ok"}],
    "stop_reason": "end_turn",
    "usage": {"input_tokens": 1, "output_tokens": 1}
}"#;

fn ok(body: &str) -> Result<Response<Bytes>, HttpError> {
    Response::builder()
        .status(200)
        .body(Bytes::from(body.to_owned()))
        .map_err(|err| HttpError::Transport(err.to_string()))
}

/// The adapter over a fake the test keeps a handle on, so it can read the
/// recorded requests back (`FakeHttpClient::captured`).
fn adapter(http: Arc<FakeHttpClient>) -> Anthropic {
    Anthropic::new(
        http,
        Arc::new(FixedClock(
            time::OffsetDateTime::from_unix_timestamp(0).expect("valid timestamp"),
        )),
        // An obvious dummy key, never real.
        Some("sk-ant-dummy-key-000000000000".to_owned()),
        "claude-opus-5",
    )
}

/// The exact prompt the recorded fixture was captured from: one user turn,
/// one text part and two images, in order.
fn image_prompt() -> Prompt {
    Prompt::new(ModelTier::Fast)
        .user_parts([
            Part::text("What is in these images?"),
            Part::image(ImageMediaType::Png, PNG_SIGNATURE),
            Part::image(ImageMediaType::Jpeg, JPEG_SIGNATURE),
        ])
        .max_tokens(256)
}

#[pollster::test]
async fn image_parts_serialise_as_an_ordered_content_block_array() {
    // The recorded request: a parts-bearing turn is the content-block array
    // the Messages API needs, each part translated in order — text as a
    // `text` block, an image as an inline base64 `image` block. Asserted
    // against the checked-in fixture, as JSON values so key order is not
    // part of the contract.
    let http = Arc::new(FakeHttpClient::scripted(vec![ok(TEXT_BODY)]));
    let model = adapter(Arc::clone(&http));

    model.complete(&image_prompt()).await.expect("completes");

    let recorded = http.captured();
    let sent: serde_json::Value = serde_json::from_str(&recorded[0].2).expect("json");
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/image-request.json")).expect("fixture json");
    assert_eq!(sent, expected, "{sent}");
}

#[test]
fn the_adapter_reports_the_images_capability() {
    let model = adapter(Arc::new(FakeHttpClient::scripted(vec![])));
    assert!(model.supports(ModelTier::Fast, Capability::Images));
    // The tools capability the adapter already reported is untouched.
    assert!(model.supports(ModelTier::Fast, Capability::Tools));
}

#[pollster::test]
async fn an_image_over_the_per_image_bound_is_refused_before_any_request() {
    // `MAX_IMAGE_ENCODED_BYTES` raw bytes encode to more than that ceiling,
    // so the prompt crosses the per-image bound. (The too-many and
    // total-too-large bounds are proven by the conformance suite.)
    let http = Arc::new(FakeHttpClient::scripted(vec![ok(TEXT_BODY)]));
    let model = adapter(Arc::clone(&http));
    let prompt = Prompt::new(ModelTier::Fast).user_parts([Part::image(
        ImageMediaType::Png,
        vec![0u8; MAX_IMAGE_ENCODED_BYTES],
    )]);

    let err = model.complete(&prompt).await.unwrap_err();
    assert!(
        matches!(
            err,
            TextModelError::ImageLimit(ImageLimit::ImageTooLarge { index: 0, .. })
        ),
        "got {err}"
    );
    assert!(
        http.captured().is_empty(),
        "an over-limit image is refused before any request"
    );
}
