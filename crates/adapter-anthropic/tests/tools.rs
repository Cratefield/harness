//! Tool use over the `Anthropic` adapter (issue #665): the two-step round
//! trip driven by `run_tool_loop` against the recorded Messages fixtures,
//! the `tool_choice` mapping, the `json_schema` + `tools` refusal, and the
//! unchanged request body of a tool-free prompt.

// Test-side recording fixture, not request state — the same category and
// allowance as the fakes in `cratefield-testing` (ADR 0007 policy).
#![allow(clippy::disallowed_types)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_adapter_anthropic::Anthropic;
use cratefield_core::{
    Capability, HttpError, ModelTier, Prompt, TextModel, TextModelError, ToolBudget, ToolCall,
    ToolChoice, ToolExecutor, ToolResult, ToolSpec, Turn, run_tool_loop,
};
use cratefield_testing::{FakeHttpClient, FixedClock};
use http::Response;
use std::sync::Arc;
use std::sync::Mutex;

/// Anthropic's documented `get_weather` round trip, in the docs' response
/// shape: the first answer's `stop_reason` is `tool_use` and its content
/// carries a text block and a `tool_use` block; the second is the final
/// answer once the `tool_result` went back.
/// <https://platform.claude.com/docs/en/agents-and-tools/tool-use/overview>
const TOOL_USE_RESPONSE: &str = include_str!("fixtures/tool-use-response-1.json");
const TOOL_USE_FINAL_RESPONSE: &str = include_str!("fixtures/tool-use-response-2.json");

const FINAL_ANSWER: &str =
    "The current weather in San Francisco is 15 degrees Celsius with partly cloudy skies.";
const TOOL_USE_ID: &str = "toolu_01A09q90qw90lq917835lq9";
const WEATHER: &str = "15 degrees Celsius, partly cloudy";

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

/// The docs' `get_weather` tool, exactly as the example declares it.
fn weather_tool() -> ToolSpec {
    ToolSpec::new(
        "get_weather",
        "Get the current weather for a given location.",
        serde_json::json!({
            "type": "object",
            "properties": {
                "location": {
                    "type": "string",
                    "description": "City and state, e.g. San Francisco, CA"
                }
            },
            "required": ["location"]
        }),
    )
}

/// Records every call it is handed and answers with the docs' canned
/// weather, the way a real tool handler would.
#[derive(Default)]
struct RecordingExecutor {
    calls: Mutex<Vec<ToolCall>>,
}

impl RecordingExecutor {
    fn calls(&self) -> Vec<ToolCall> {
        self.calls.lock().expect("executor lock").clone()
    }
}

#[async_trait]
impl ToolExecutor for RecordingExecutor {
    async fn execute(&self, call: &ToolCall) -> Result<String, String> {
        self.calls.lock().expect("executor lock").push(call.clone());
        Ok(WEATHER.to_owned())
    }
}

#[pollster::test]
async fn a_two_step_tool_call_round_trips_through_the_recorded_fixtures() {
    let http = Arc::new(FakeHttpClient::scripted(vec![
        ok(TOOL_USE_RESPONSE),
        ok(TOOL_USE_FINAL_RESPONSE),
    ]));
    let model = adapter(Arc::clone(&http));
    let executor = RecordingExecutor::default();

    let prompt = Prompt::new(ModelTier::Fast)
        .user("What's the weather in San Francisco?")
        .max_tokens(1024)
        .tool(weather_tool())
        .tool_choice(ToolChoice::Auto);

    let outcome = run_tool_loop(&model, prompt, &executor, ToolBudget::steps(4))
        .await
        .expect("the loop answers");

    // The final completion is the second fixture's answer, with no calls.
    assert_eq!(outcome.completion.text, FINAL_ANSWER);
    assert_eq!(outcome.completion.model, "claude-opus-5");
    assert!(outcome.completion.tool_calls.is_empty());

    // The executor saw the parsed arguments, exactly once.
    let calls = executor.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].id, TOOL_USE_ID);
    assert_eq!(calls[0].name, "get_weather");
    assert_eq!(
        calls[0].arguments,
        serde_json::json!({ "location": "San Francisco, CA" })
    );

    // The transcript: the opening user turn, the assistant turn quoting the
    // call, and the user turn carrying its result.
    assert_eq!(
        outcome.messages,
        vec![
            Turn::user("What's the weather in San Francisco?"),
            Turn::assistant_tool_calls(
                "I'll check the current weather in San Francisco.",
                vec![ToolCall::new(
                    TOOL_USE_ID,
                    "get_weather",
                    serde_json::json!({ "location": "San Francisco, CA" }),
                )],
            ),
            Turn::tool_results(vec![ToolResult::ok(TOOL_USE_ID, WEATHER)]),
        ]
    );

    // Both calls' usage is summed.
    assert_eq!(outcome.steps.len(), 2);
    assert_eq!(outcome.input_tokens(), 603 + 710);
    assert_eq!(outcome.output_tokens(), 74 + 28);

    // The two recorded request bodies, in order.
    let recorded = http.captured();
    assert_eq!(recorded.len(), 2);

    // Request 1: the tool offer and the caller's choice.
    let first: serde_json::Value = serde_json::from_str(&recorded[0].2).expect("json");
    assert_eq!(first["tools"][0]["name"], "get_weather");
    assert_eq!(
        first["tools"][0]["description"],
        "Get the current weather for a given location."
    );
    assert_eq!(first["tools"][0]["input_schema"]["required"][0], "location");
    assert_eq!(first["tool_choice"], serde_json::json!({ "type": "auto" }));
    assert_eq!(
        first["messages"][0]["content"],
        "What's the weather in San Francisco?"
    );

    // Request 2: the assistant's `tool_use` block (same id) then the user's
    // `tool_result` block with the matching `tool_use_id`, in that order.
    let second: serde_json::Value = serde_json::from_str(&recorded[1].2).expect("json");
    assert_eq!(second["messages"][1]["role"], "assistant");
    assert_eq!(second["messages"][1]["content"][0]["type"], "text");
    assert_eq!(
        second["messages"][1]["content"][0]["text"],
        "I'll check the current weather in San Francisco."
    );
    assert_eq!(second["messages"][1]["content"][1]["type"], "tool_use");
    assert_eq!(second["messages"][1]["content"][1]["id"], TOOL_USE_ID);
    assert_eq!(second["messages"][1]["content"][1]["name"], "get_weather");
    assert_eq!(
        second["messages"][1]["content"][1]["input"],
        serde_json::json!({ "location": "San Francisco, CA" })
    );
    assert_eq!(second["messages"][2]["role"], "user");
    assert_eq!(second["messages"][2]["content"][0]["type"], "tool_result");
    assert_eq!(
        second["messages"][2]["content"][0]["tool_use_id"],
        TOOL_USE_ID
    );
    assert_eq!(second["messages"][2]["content"][0]["content"], WEATHER);
    assert!(
        second["messages"][2]["content"][0]
            .get("is_error")
            .is_none(),
        "a successful result omits is_error: {}",
        second["messages"][2]["content"][0]
    );
}

#[pollster::test]
async fn every_tool_choice_variant_maps_onto_the_wire() {
    // One canned answer per call — each `complete` consumes one scripted
    // response — and only the request body is under test.
    let http = Arc::new(FakeHttpClient::scripted(vec![
        ok(TEXT_BODY),
        ok(TEXT_BODY),
        ok(TEXT_BODY),
        ok(TEXT_BODY),
    ]));
    let model = adapter(Arc::clone(&http));

    let choices = [
        (ToolChoice::Auto, serde_json::json!({ "type": "auto" })),
        (ToolChoice::None, serde_json::json!({ "type": "none" })),
        (ToolChoice::Required, serde_json::json!({ "type": "any" })),
        (
            ToolChoice::Tool("get_weather".to_owned()),
            serde_json::json!({ "type": "tool", "name": "get_weather" }),
        ),
    ];
    for (choice, expected) in choices {
        let prompt = Prompt::new(ModelTier::Fast)
            .user("What's the weather in San Francisco?")
            .tool(weather_tool())
            .tool_choice(choice);
        model.complete(&prompt).await.expect("completes");

        let recorded = http.captured();
        let body: serde_json::Value =
            serde_json::from_str(&recorded.last().expect("a request").2).expect("json");
        assert_eq!(body["tool_choice"], expected, "{body}");
    }
}

#[pollster::test]
async fn tools_without_a_choice_send_tools_but_omit_tool_choice() {
    // `Prompt::tool_choice` unset leaves the choice to the provider's own
    // default: the tools travel, the steering field does not.
    let http = Arc::new(FakeHttpClient::scripted(vec![ok(TEXT_BODY)]));
    let model = adapter(Arc::clone(&http));

    let prompt = Prompt::new(ModelTier::Fast)
        .user("What's the weather in San Francisco?")
        .tool(weather_tool());
    model.complete(&prompt).await.expect("completes");

    let recorded = http.captured();
    let body: serde_json::Value = serde_json::from_str(&recorded[0].2).expect("json");
    assert_eq!(body["tools"][0]["name"], "get_weather");
    assert!(body.get("tool_choice").is_none(), "{body}");
}

#[pollster::test]
async fn a_tool_free_prompt_sends_no_tools_and_no_tool_choice() {
    // The request a caller sent before tools existed is unchanged.
    let http = Arc::new(FakeHttpClient::scripted(vec![ok(TEXT_BODY)]));
    let model = adapter(Arc::clone(&http));

    let completion = model
        .complete(&Prompt::new(ModelTier::Fast).user("Say hello"))
        .await
        .expect("completes");
    assert_eq!(completion.text, "ok");

    let recorded = http.captured();
    let body: serde_json::Value = serde_json::from_str(&recorded[0].2).expect("json");
    assert!(body.get("tools").is_none(), "{body}");
    assert!(body.get("tool_choice").is_none(), "{body}");
    assert_eq!(body["messages"][0]["content"], "Say hello");
}

#[pollster::test]
async fn json_schema_and_tools_together_are_refused_before_any_request() {
    let http = Arc::new(FakeHttpClient::scripted(vec![ok(TOOL_USE_FINAL_RESPONSE)]));
    let model = adapter(Arc::clone(&http));

    let prompt = Prompt::new(ModelTier::Fast)
        .user("hi")
        .json_schema(serde_json::json!({ "type": "object" }))
        .tool(weather_tool());
    let err = model.complete(&prompt).await.unwrap_err();
    match err {
        TextModelError::Rejected(detail) => {
            assert!(detail.contains("json_schema"), "{detail}");
            assert!(detail.contains("tools"), "{detail}");
        }
        other => panic!("wrong error: {other}"),
    }
    assert!(http.captured().is_empty(), "no request was made");
}

#[pollster::test]
async fn a_tool_only_answer_reports_the_call_with_empty_text() {
    // The model answered with no prose at all, only a call: an empty
    // completion text is not an error.
    let body = r#"{
        "id": "msg_tool_only",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-5",
        "content": [
            {"type": "tool_use", "id": "toolu_01", "name": "get_weather", "input": {"location": "Oslo"}}
        ],
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 9, "output_tokens": 4}
    }"#;
    let http = Arc::new(FakeHttpClient::scripted(vec![ok(body)]));
    let model = adapter(Arc::clone(&http));

    let completion = model
        .complete(&Prompt::new(ModelTier::Fast).user("hi").tool(weather_tool()))
        .await
        .expect("completes");

    assert_eq!(completion.text, "");
    assert_eq!(completion.tool_calls.len(), 1);
    assert_eq!(completion.tool_calls[0].id, "toolu_01");
    assert_eq!(completion.tool_calls[0].name, "get_weather");
    assert_eq!(
        completion.tool_calls[0].arguments,
        serde_json::json!({ "location": "Oslo" })
    );
}

#[pollster::test]
async fn a_tool_call_truncated_at_max_tokens_is_rejected() {
    // `max_tokens` cut the call off mid-arguments; a partial `input` must
    // never reach an executor.
    let body = r#"{
        "id": "msg_truncated_tool",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-5",
        "content": [
            {"type": "tool_use", "id": "toolu_01", "name": "get_weather", "input": {"location": "San Fra"}}
        ],
        "stop_reason": "max_tokens",
        "usage": {"input_tokens": 9, "output_tokens": 4}
    }"#;
    let http = Arc::new(FakeHttpClient::scripted(vec![ok(body)]));
    let model = adapter(Arc::clone(&http));

    let err = model
        .complete(&Prompt::new(ModelTier::Fast).user("hi").tool(weather_tool()))
        .await
        .unwrap_err();
    match err {
        TextModelError::Rejected(detail) => {
            assert!(detail.contains("max_tokens"), "{detail}");
            assert!(detail.contains("truncated"), "{detail}");
        }
        other => panic!("wrong error: {other}"),
    }
}

#[test]
fn the_adapter_reports_the_tools_capability() {
    let model = adapter(Arc::new(FakeHttpClient::scripted(vec![])));
    assert!(model.supports(ModelTier::Fast, Capability::Tools));
}
