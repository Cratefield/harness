//! Tool-calling acceptance tests for the `OpenAiCompatible` adapter (issue
//! #665): the request carries the prompt's tools and `tool_choice`, the
//! answer's `tool_calls` parse back with their arguments as JSON, a
//! two-step conversation replays an assistant call and its result, and an
//! adapter whose deployment turned tools off refuses a tools-bearing prompt
//! before any request. The two chat-completions bodies of the round trip
//! are modelled on the vendor docs' function-calling example, recorded in
//! `tests/fixtures/`.

// Test-side recording fixture, not request state — the same category and
// allowance as the fakes in `cratefield-testing` (ADR 0007 policy).
#![allow(clippy::disallowed_types)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_adapter_openai_compatible::OpenAiCompatible;
use cratefield_core::{
    Capability, HttpError, ModelTier, Prompt, TextModel, TextModelError, ToolBudget, ToolCall,
    ToolChoice, ToolExecutor, ToolResult, ToolSpec, Turn, run_tool_loop,
};
use cratefield_testing::{FakeHttpClient, FixedClock};
use http::Response;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

// Obvious dummy key, never real.
const DUMMY_KEY: &str = "sk-openai-dummy-key-000000000000";

/// The vendor docs' function-calling example, in its full shape: first the
/// `get_weather` call (`content: null`, `finish_reason: "tool_calls"`,
/// arguments as a JSON string), then the final text answer. Both carry the
/// docs' complete `usage` block.
const TOOL_CALL_RESPONSE: &str = include_str!("fixtures/tool-call-response.json");
const TOOL_CALL_FINAL_RESPONSE: &str = include_str!("fixtures/tool-call-final-response.json");

/// A plain text answer, for the request-shape tests that need no tool call.
const PLAIN_RESPONSE: &str = r#"{
    "model": "gpt-4o-2024-08-06",
    "choices": [{"message": {"role": "assistant", "content": "Sunny."}, "finish_reason": "stop"}],
    "usage": {"prompt_tokens": 5, "completion_tokens": 2}
}"#;

fn ok(body: &str) -> Result<Response<Bytes>, HttpError> {
    Response::builder()
        .status(200)
        .body(Bytes::from(body.to_owned()))
        .map_err(|err| HttpError::Transport(err.to_string()))
}

fn adapter(http: FakeHttpClient) -> OpenAiCompatible {
    OpenAiCompatible::new(
        Arc::new(http),
        Arc::new(FixedClock(
            time::OffsetDateTime::from_unix_timestamp(0).expect("valid timestamp"),
        )),
        Some(DUMMY_KEY.to_owned()),
        "gpt-4o-2024-08-06",
    )
}

/// The docs' `get_weather` tool: the schema the loop validates a call's
/// arguments against, and the name the wire carries.
fn weather_tool() -> ToolSpec {
    ToolSpec::new(
        "get_weather",
        "Get the current weather in a given location",
        json!({
            "type": "object",
            "properties": {
                "location": {"type": "string", "description": "The city and state"}
            },
            "required": ["location"]
        }),
    )
}

fn weather_prompt() -> Prompt {
    Prompt::new(ModelTier::Fast)
        .user("What is the weather like in Boston?")
        .tool(weather_tool())
        .tool_choice(ToolChoice::Auto)
}

/// Records every call it runs and answers one fixed result — the executor
/// half of the loop, scripted so a test can assert what reached it.
struct RecordingExecutor {
    calls: Mutex<Vec<ToolCall>>,
    answer: String,
}

impl RecordingExecutor {
    fn new(answer: impl Into<String>) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            answer: answer.into(),
        }
    }

    fn calls(&self) -> Vec<ToolCall> {
        self.calls.lock().expect("executor lock").clone()
    }
}

#[async_trait]
impl ToolExecutor for RecordingExecutor {
    async fn execute(&self, call: &ToolCall) -> Result<String, String> {
        self.calls.lock().expect("executor lock").push(call.clone());
        Ok(self.answer.clone())
    }
}

#[pollster::test]
async fn a_two_step_tool_call_round_trips_through_the_recorded_fixtures() {
    let http = FakeHttpClient::scripted(vec![ok(TOOL_CALL_RESPONSE), ok(TOOL_CALL_FINAL_RESPONSE)]);
    let model = adapter(http.clone());
    let executor = RecordingExecutor::new("72F and sunny");

    let outcome = run_tool_loop(&model, weather_prompt(), &executor, ToolBudget::steps(4))
        .await
        .expect("the loop finishes");

    // The final completion is the second fixture's text, with no call left.
    assert_eq!(
        outcome.completion.text,
        "The weather in Boston is 72F and sunny."
    );
    assert!(outcome.completion.tool_calls.is_empty());

    // The executor ran the parsed call — the arguments are an object, not
    // the raw JSON string the wire carried.
    let calls = executor.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].id, "call_abc123");
    assert_eq!(calls[0].name, "get_weather");
    assert_eq!(calls[0].arguments, json!({"location": "Boston, MA"}));

    // The transcript: the prompt's user turn, the assistant call, the
    // results.
    assert_eq!(outcome.messages.len(), 3);
    assert_eq!(
        outcome.messages[0],
        Turn::user("What is the weather like in Boston?")
    );
    assert_eq!(
        outcome.messages[2].tool_results,
        vec![ToolResult::ok("call_abc123", "72F and sunny")]
    );

    // Usage is summed across both steps, from the fixtures' own counts.
    assert_eq!(outcome.input_tokens(), 82 + 102);
    assert_eq!(outcome.output_tokens(), 17 + 15);
    assert_eq!(outcome.steps[0].tool_calls, 1);
    assert_eq!(outcome.steps[1].tool_calls, 0);

    // Two requests reached the wire.
    let captured = http.captured();
    assert_eq!(captured.len(), 2);

    // Request 1 offered the tool and left the choice to the model.
    let first: Value = serde_json::from_str(&captured[0].2).expect("request 1 is JSON");
    assert_eq!(first["tools"][0]["type"], "function");
    assert_eq!(first["tools"][0]["function"]["name"], "get_weather");
    assert_eq!(
        first["tools"][0]["function"]["parameters"]["type"],
        "object"
    );
    assert_eq!(first["tool_choice"], "auto");
    assert_eq!(first["messages"][0]["role"], "user");

    // Request 2 quotes the assistant's call and answers it: the same id, the
    // arguments as a JSON string, then the `role: "tool"` message with the
    // matching `tool_call_id`.
    let second: Value = serde_json::from_str(&captured[1].2).expect("request 2 is JSON");
    assert_eq!(second["messages"][0]["role"], "user");
    assert_eq!(second["messages"][1]["role"], "assistant");
    assert_eq!(
        second["messages"][1]["content"],
        Value::Null,
        "a call-only assistant turn carries null content"
    );
    assert_eq!(second["messages"][1]["tool_calls"][0]["id"], "call_abc123");
    assert_eq!(second["messages"][1]["tool_calls"][0]["type"], "function");
    assert_eq!(
        second["messages"][1]["tool_calls"][0]["function"]["name"],
        "get_weather"
    );
    assert_eq!(
        second["messages"][1]["tool_calls"][0]["function"]["arguments"],
        json!({"location": "Boston, MA"}).to_string()
    );
    assert_eq!(second["messages"][2]["role"], "tool");
    assert_eq!(second["messages"][2]["tool_call_id"], "call_abc123");
    assert_eq!(second["messages"][2]["content"], "72F and sunny");
}

#[pollster::test]
async fn tool_choice_maps_to_every_wire_variant() {
    let cases = [
        (ToolChoice::Auto, json!("auto")),
        (ToolChoice::None, json!("none")),
        (ToolChoice::Required, json!("required")),
        (
            ToolChoice::Tool("get_weather".to_owned()),
            json!({"type": "function", "function": {"name": "get_weather"}}),
        ),
    ];
    for (choice, expected) in cases {
        let http = FakeHttpClient::scripted(vec![ok(PLAIN_RESPONSE)]);
        let prompt = Prompt::new(ModelTier::Fast)
            .user("hi")
            .tool(weather_tool())
            .tool_choice(choice.clone());
        adapter(http.clone())
            .complete(&prompt)
            .await
            .expect("completes");

        let captured = http.captured();
        let sent: Value = serde_json::from_str(&captured[0].2).expect("request is JSON");
        assert_eq!(sent["tool_choice"], expected, "choice {choice:?}");
        assert_eq!(sent["tools"][0]["function"]["name"], "get_weather");
    }
}

#[pollster::test]
async fn tools_disabled_refuses_a_tools_bearing_prompt_before_any_request() {
    let http = FakeHttpClient::scripted(vec![]);
    let model = adapter(http.clone()).without_tools();

    assert!(!model.supports(ModelTier::Fast, Capability::Tools));
    let err = model.complete(&weather_prompt()).await.unwrap_err();
    assert_eq!(err, TextModelError::Unsupported(Capability::Tools));
    assert!(
        http.captured().is_empty(),
        "no request is made for a prompt the adapter cannot carry"
    );
}

#[pollster::test]
async fn tools_are_supported_by_default_and_reach_the_wire() {
    let http = FakeHttpClient::scripted(vec![ok(PLAIN_RESPONSE)]);
    let model = adapter(http.clone());
    assert!(model.supports(ModelTier::Strong, Capability::Tools));

    model.complete(&weather_prompt()).await.expect("completes");
    let captured = http.captured();
    let sent: Value = serde_json::from_str(&captured[0].2).expect("request is JSON");
    assert_eq!(sent["tools"][0]["function"]["name"], "get_weather");
}

#[pollster::test]
async fn a_tool_free_prompt_sends_no_tools_and_no_tool_choice() {
    let http = FakeHttpClient::scripted(vec![ok(PLAIN_RESPONSE)]);
    adapter(http.clone())
        .complete(&Prompt::new(ModelTier::Fast).user("Say hello"))
        .await
        .expect("completes");

    let captured = http.captured();
    let sent: Value = serde_json::from_str(&captured[0].2).expect("request is JSON");
    assert!(sent.get("tools").is_none(), "{sent}");
    assert!(sent.get("tool_choice").is_none(), "{sent}");
    assert_eq!(sent["messages"][0]["content"], "Say hello");
}

#[pollster::test]
async fn unparsable_tool_call_arguments_are_kept_as_a_raw_string() {
    // The model's arguments string is a truncated JSON object. Keeping it as
    // the raw string lets `run_tool_loop`'s schema validation refuse the
    // call and feed the error back, rather than the whole answer failing to
    // parse.
    let body = r#"{
        "model": "gpt-4o-2024-08-06",
        "choices": [{
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_bad",
                    "type": "function",
                    "function": {"name": "get_weather", "arguments": "{\"location\":"}
                }]
            },
            "finish_reason": "tool_calls"
        }],
        "usage": {"prompt_tokens": 10, "completion_tokens": 3}
    }"#;
    let http = FakeHttpClient::scripted(vec![ok(body)]);
    let completion = adapter(http)
        .complete(&weather_prompt())
        .await
        .expect("completes");

    assert_eq!(completion.text, "", "a call-only answer has no text");
    assert_eq!(completion.tool_calls.len(), 1);
    assert_eq!(
        completion.tool_calls[0].arguments,
        Value::String("{\"location\":".to_owned())
    );
}

#[pollster::test]
async fn a_replayed_raw_arguments_string_is_emitted_verbatim() {
    // A `Value::String` is arguments the adapter kept because they did not
    // parse. Replaying it must emit that text as the wire's arguments
    // string exactly as it arrived — re-serialising the value would
    // double-encode it into a quoted JSON string.
    let raw = "{\"location\":".to_owned();
    let http = FakeHttpClient::scripted(vec![ok(PLAIN_RESPONSE)]);
    let prompt = Prompt::new(ModelTier::Fast)
        .user("go")
        .turn(Turn::assistant_tool_calls(
            "",
            vec![ToolCall::new(
                "call_bad",
                "get_weather",
                Value::String(raw.clone()),
            )],
        ))
        .turn(Turn::tool_results(vec![ToolResult::error(
            "call_bad",
            "arguments must be a JSON object",
        )]));
    adapter(http.clone())
        .complete(&prompt)
        .await
        .expect("completes");

    let captured = http.captured();
    let sent: Value = serde_json::from_str(&captured[0].2).expect("request is JSON");
    assert_eq!(
        sent["messages"][1]["tool_calls"][0]["function"]["arguments"],
        Value::String(raw),
        "the raw arguments text is replayed verbatim, not double-encoded"
    );
}

#[pollster::test]
async fn a_tool_call_truncated_at_max_tokens_is_rejected() {
    // `finish_reason: "length"` cut the arguments off mid-string: the call
    // must not reach an executor, so the whole response is `Rejected`.
    let body = r#"{
        "model": "gpt-4o-2024-08-06",
        "choices": [{
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_cut",
                    "type": "function",
                    "function": {"name": "get_weather", "arguments": "{\"location\": \"Bos"}
                }]
            },
            "finish_reason": "length"
        }],
        "usage": {"prompt_tokens": 10, "completion_tokens": 8}
    }"#;
    let http = FakeHttpClient::scripted(vec![ok(body)]);
    let err = adapter(http).complete(&weather_prompt()).await.unwrap_err();
    assert!(
        matches!(&err, TextModelError::Rejected(detail) if detail.contains("truncated")),
        "got {err}"
    );
}

#[pollster::test]
async fn a_failed_tool_result_is_prefixed_on_the_wire() {
    // The wire has no `is_error` field on a tool message, so a failed result
    // is prefixed with `Error: ` for the model to read; a successful one is
    // sent as-is. One `role: "tool"` message per result, in order.
    let http = FakeHttpClient::scripted(vec![ok(PLAIN_RESPONSE)]);
    let prompt = Prompt::new(ModelTier::Fast)
        .user("go")
        .turn(Turn::assistant_tool_calls(
            "",
            vec![
                ToolCall::new("call_1", "get_weather", json!({"location": "Boston, MA"})),
                ToolCall::new("call_2", "get_weather", json!({"location": "Boston, MA"})),
            ],
        ))
        .turn(Turn::tool_results(vec![
            ToolResult::error("call_1", "the service is down"),
            ToolResult::ok("call_2", "72F and sunny"),
        ]));
    adapter(http.clone())
        .complete(&prompt)
        .await
        .expect("completes");

    let captured = http.captured();
    let sent: Value = serde_json::from_str(&captured[0].2).expect("request is JSON");
    let messages = sent["messages"].as_array().expect("messages array");
    // user, assistant(call), tool(error), tool(ok).
    assert_eq!(messages.len(), 4);
    assert_eq!(messages[2]["role"], "tool");
    assert_eq!(messages[2]["tool_call_id"], "call_1");
    assert_eq!(messages[2]["content"], "Error: the service is down");
    assert_eq!(messages[3]["role"], "tool");
    assert_eq!(messages[3]["tool_call_id"], "call_2");
    assert_eq!(messages[3]["content"], "72F and sunny");
}
