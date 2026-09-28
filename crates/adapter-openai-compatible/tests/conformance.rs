//! The shared `TextModel` conformance suite (issue #560) run against the
//! `OpenAiCompatible` adapter, plus the wasm dependency boundary. The
//! suite's transport is scripted with one well-formed chat-completions
//! response for `text_model_conformance_prompt` — canonical reply,
//! canonical counts, and the cached-token details that make the
//! `cached_input_tokens` half of the contract hold.

use bytes::Bytes;
use cratefield_adapter_openai_compatible::OpenAiCompatible;
use cratefield_core::HttpClient;
use cratefield_testing::{
    FakeHttpClient, FixedClock, TEXT_MODEL_CONFORMANCE_CACHED_INPUT_TOKENS,
    TEXT_MODEL_CONFORMANCE_INPUT_TOKENS, TEXT_MODEL_CONFORMANCE_OUTPUT_TOKENS,
    TEXT_MODEL_CONFORMANCE_REPLY, assert_wasm_safe_deps, text_model_conformance,
    text_model_conformance_not_configured,
};
use http::Response;
use std::sync::Arc;

/// The one chat-completions response the suite's single completion needs,
/// in the vendor's wire shape: the canonical reply, the canonical counts,
/// and a cache read so `cached_input_tokens` is reported.
fn conformance_response() -> Result<Response<Bytes>, cratefield_core::HttpError> {
    let body = serde_json::json!({
        "id": "chatcmpl_conformance",
        "object": "chat.completion",
        "model": "conformance-model",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": TEXT_MODEL_CONFORMANCE_REPLY},
                "finish_reason": "stop"
            }
        ],
        "usage": {
            "prompt_tokens": TEXT_MODEL_CONFORMANCE_INPUT_TOKENS,
            "completion_tokens": TEXT_MODEL_CONFORMANCE_OUTPUT_TOKENS,
            "prompt_tokens_details": {"cached_tokens": TEXT_MODEL_CONFORMANCE_CACHED_INPUT_TOKENS}
        }
    })
    .to_string();
    Response::builder()
        .status(http::StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Bytes::from(body))
        .map_err(|err| cratefield_core::HttpError::Transport(err.to_string()))
}

fn adapter() -> OpenAiCompatible {
    let http: Arc<dyn HttpClient> =
        Arc::new(FakeHttpClient::scripted(vec![conformance_response()]));
    OpenAiCompatible::new(
        http,
        Arc::new(FixedClock(
            time::OffsetDateTime::from_unix_timestamp(0).expect("valid timestamp"),
        )),
        // An obvious dummy key, never real.
        Some("sk-openai-dummy-key-000000000000".to_owned()),
        "gpt-4o-mini",
    )
}

#[test]
fn openai_compatible_deps_are_wasm_safe() {
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}

#[test]
fn the_shared_text_model_conformance_suite_passes_over_the_openai_compatible_adapter() {
    pollster::block_on(text_model_conformance(&adapter()));
}

#[test]
fn an_absent_key_answers_not_configured() {
    let http: Arc<dyn HttpClient> = Arc::new(FakeHttpClient::scripted(vec![]));
    let unconfigured = OpenAiCompatible::new(
        http,
        Arc::new(FixedClock(
            time::OffsetDateTime::from_unix_timestamp(0).expect("valid timestamp"),
        )),
        None,
        "gpt-4o-mini",
    );
    pollster::block_on(text_model_conformance_not_configured(&unconfigured));
}
