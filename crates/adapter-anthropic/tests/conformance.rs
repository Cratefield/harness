//! The wasm dependency boundary and the shared `TextModel` conformance
//! suite (issue #560) run against the `Anthropic` adapter. The suite's
//! transport is scripted with one well-formed Messages response for
//! `text_model_conformance_prompt` — canonical reply, canonical counts,
//! and the cache read that makes the `cached_input_tokens` half of the
//! contract hold.

use bytes::Bytes;
use cratefield_adapter_anthropic::Anthropic;
use cratefield_core::HttpClient;
use cratefield_testing::{
    FakeHttpClient, FixedClock, TEXT_MODEL_CONFORMANCE_CACHED_INPUT_TOKENS,
    TEXT_MODEL_CONFORMANCE_INPUT_TOKENS, TEXT_MODEL_CONFORMANCE_OUTPUT_TOKENS,
    TEXT_MODEL_CONFORMANCE_REPLY, assert_wasm_safe_deps, text_model_conformance,
    text_model_image_bounds_conformance,
};
use http::Response;
use std::sync::Arc;

/// The one Messages response the suite's single completion needs, in the
/// vendor's wire shape: the canonical reply, the canonical counts, and a
/// cache read so `cached_input_tokens` is reported.
fn conformance_response() -> Result<Response<Bytes>, cratefield_core::HttpError> {
    let body = serde_json::json!({
        "id": "msg_conformance",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-5",
        "content": [{"type": "text", "text": TEXT_MODEL_CONFORMANCE_REPLY}],
        "stop_reason": "end_turn",
        "usage": {
            // The Messages wire splits the prompt: `input_tokens` is the
            // uncached remainder, the cache read arrives separately, and
            // the adapter sums them into the port's one total — so the
            // script sends the canonical total minus its cached subset.
            "input_tokens": TEXT_MODEL_CONFORMANCE_INPUT_TOKENS
                - TEXT_MODEL_CONFORMANCE_CACHED_INPUT_TOKENS,
            "output_tokens": TEXT_MODEL_CONFORMANCE_OUTPUT_TOKENS,
            "cache_read_input_tokens": TEXT_MODEL_CONFORMANCE_CACHED_INPUT_TOKENS
        }
    })
    .to_string();
    Response::builder()
        .status(http::StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Bytes::from(body))
        .map_err(|err| cratefield_core::HttpError::Transport(err.to_string()))
}

fn adapter() -> Anthropic {
    let http: Arc<dyn HttpClient> =
        Arc::new(FakeHttpClient::scripted(vec![conformance_response()]));
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

#[test]
fn anthropic_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}

#[test]
fn the_shared_text_model_conformance_suite_passes_over_the_anthropic_adapter() {
    pollster::block_on(text_model_conformance(&adapter()));
}

#[test]
fn the_image_bounds_are_refused_before_any_network_call() {
    // A transport with nothing scripted: a pass proves each over-limit
    // prompt was refused locally, and the emptiness check proves no request
    // was made at all.
    let http = Arc::new(FakeHttpClient::scripted(vec![]));
    let transport: Arc<dyn HttpClient> = http.clone();
    let model = Anthropic::new(
        transport,
        Arc::new(FixedClock(
            time::OffsetDateTime::from_unix_timestamp(0).expect("valid timestamp"),
        )),
        // An obvious dummy key, never real — present so the bounds, not a
        // missing key, are what the adapter answers with.
        Some("sk-ant-dummy-key-000000000000".to_owned()),
        "claude-opus-5",
    );
    pollster::block_on(text_model_image_bounds_conformance(&model));
    assert!(
        http.captured().is_empty(),
        "no request for an over-limit prompt"
    );
}
