//! The UI message stream fixtures (issue #860): the exact bytes the
//! Rust encoder writes for four scripted runs, committed under
//! `tests/fixtures/ui-message-stream/v1` so the Node test in
//! `packages/ui-message-contract` can replay the same files through the
//! Vercel AI SDK's own parser and prove the two language halves agree.
//!
//! Run with `UPDATE_UI_MESSAGE_FIXTURES=1` to rewrite the files from the
//! current encoder output — after a deliberate protocol change only; the
//! committed bytes are a cross-language contract, so a diff here reviews
//! like an API change.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use cratefield_core::sse::ui_message::{
    UiFinishReason, UiMessageChunk, UiMessageEncoder, text_stream_chunks,
};
use cratefield_core::{
    BoxStream, Capability, FinishReason, ModelTier, Prompt, TextDelta, TextModel, TextModelError,
    ToolBudget, ToolCall, ToolExecutor, ToolSpec, run_tool_loop_stream,
};
use futures_util::StreamExt as _;
use serde_json::{Value, json};

/// The fixtures live one directory per protocol version, so a future v2
/// lands beside v1 instead of rewriting it.
fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ui-message-stream/v1")
}

/// The environment variable that turns the assertion into a rewrite.
const UPDATE: &str = "UPDATE_UI_MESSAGE_FIXTURES";

/// The chunks as the bytes [`cratefield_core::sse::ui_message_response`]
/// writes: one SSE event per chunk, then the `[DONE]` marker.
fn wire_bytes(chunks: &[UiMessageChunk]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for chunk in chunks {
        bytes.extend_from_slice(&chunk.to_sse_event().encode());
    }
    bytes.extend_from_slice(b"data: [DONE]\n\n");
    bytes
}

/// The chunk type tags in order — the stream's shape, readable at a
/// glance and asserted below so a regression names the wrong chunk
/// instead of only failing a byte diff.
fn kinds(chunks: &[UiMessageChunk]) -> Vec<String> {
    chunks
        .iter()
        .map(|chunk| {
            let wire = serde_json::to_value(chunk).expect("a chunk serialises");
            wire["type"]
                .as_str()
                .expect("every chunk is typed")
                .to_owned()
        })
        .collect()
}

/// Drives a chunk stream to its end and gathers every chunk.
fn collect(mut chunks: BoxStream<'static, UiMessageChunk>) -> Vec<UiMessageChunk> {
    pollster::block_on(async {
        let mut chunks_out = Vec::new();
        while let Some(chunk) = chunks.next().await {
            chunks_out.push(chunk);
        }
        chunks_out
    })
}

/// The text-and-reasoning script: reasoning first, then answer text in
/// two deltas (one part, two grows), usage the UI stream carries
/// nothing for, and the closing `Finish`. Run through
/// [`text_stream_chunks`] — the adapter a plain completion route uses —
/// with no message id, so the fixture shows the omitted `messageId`.
fn text_and_reasoning_chunks() -> Vec<UiMessageChunk> {
    let deltas: BoxStream<'static, Result<TextDelta, TextModelError>> =
        Box::pin(futures_util::stream::iter(vec![
            Ok(TextDelta::Reasoning(
                "The user asks about Munich.".to_owned(),
            )),
            Ok(TextDelta::Reasoning("A sentence will do.".to_owned())),
            Ok(TextDelta::Text("Munich sits on the Isar".to_owned())),
            Ok(TextDelta::Text(", in Bavaria.".to_owned())),
            Ok(TextDelta::Usage {
                input_tokens: 12,
                output_tokens: 9,
                cached_input_tokens: None,
            }),
            Ok(TextDelta::Finish {
                reason: FinishReason::Stop,
                model: "fake".to_owned(),
            }),
        ]));
    collect(text_stream_chunks(deltas))
}

/// A model whose streams replay a scripted delta list per call, in
/// order — the same scripting `tool_loop_stream.rs` tests by. Step one
/// asks for the tool, step two answers.
struct ScriptedModel {
    script: Vec<Vec<Result<TextDelta, TextModelError>>>,
    calls: AtomicUsize,
}

#[async_trait]
impl TextModel for ScriptedModel {
    async fn complete(
        &self,
        _prompt: &Prompt,
    ) -> Result<cratefield_core::Completion, TextModelError> {
        Err(TextModelError::NotConfigured)
    }

    fn stream<'a>(
        &'a self,
        _prompt: &'a Prompt,
    ) -> BoxStream<'a, Result<TextDelta, TextModelError>> {
        let index = self
            .calls
            .fetch_add(1, Ordering::SeqCst)
            .min(self.script.len() - 1);
        Box::pin(futures_util::stream::iter(self.script[index].clone()))
    }

    fn supports(&self, _tier: ModelTier, capability: Capability) -> bool {
        capability == Capability::Tools
    }
}

/// The executor behind the tool-loop case: answers JSON, so the fixture
/// shows the output riding as an object rather than a string.
struct WeatherExecutor;

#[async_trait]
impl ToolExecutor for WeatherExecutor {
    async fn execute(&self, _call: &ToolCall) -> Result<String, String> {
        Ok(json!({ "temp_c": 21, "sky": "clear" }).to_string())
    }
}

/// A tool taking one required string argument.
fn lookup_tool() -> ToolSpec {
    ToolSpec::new(
        "lookup",
        "Look up a query.",
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["q"],
            "properties": { "q": { "type": "string" } },
        }),
    )
}

/// The deltas of a streamed call that asks for `name` with `arguments`,
/// the arguments arriving in two chunks so the fixture shows streamed
/// `tool-input-delta`s rather than one buffered announcement.
fn asks_for(name: &str, arguments: Value) -> Vec<Result<TextDelta, TextModelError>> {
    let call = ToolCall::new("call-1", name, arguments);
    let full = call.arguments.to_string();
    let (head, tail) = full.split_at(full.len() / 2);
    vec![
        Ok(TextDelta::Text("thinking ".to_owned())),
        Ok(TextDelta::ToolCallStarted {
            index: 0,
            id: call.id.clone(),
            name: call.name.clone(),
        }),
        Ok(TextDelta::ToolCallArguments {
            index: 0,
            chunk: head.to_owned(),
        }),
        Ok(TextDelta::ToolCallArguments {
            index: 0,
            chunk: tail.to_owned(),
        }),
        Ok(TextDelta::ToolCallFinished { index: 0, call }),
        Ok(TextDelta::Usage {
            input_tokens: 10,
            output_tokens: 5,
            cached_input_tokens: None,
        }),
        Ok(TextDelta::Finish {
            reason: FinishReason::ToolUse,
            model: "fake".to_owned(),
        }),
    ]
}

/// The deltas of a streamed call that answers `text` and stops.
fn answers(text: &str) -> Vec<Result<TextDelta, TextModelError>> {
    vec![
        Ok(TextDelta::Text(text.to_owned())),
        Ok(TextDelta::Usage {
            input_tokens: 20,
            output_tokens: 7,
            cached_input_tokens: None,
        }),
        Ok(TextDelta::Finish {
            reason: FinishReason::Stop,
            model: "fake".to_owned(),
        }),
    ]
}

/// The tool-loop case, end to end: the real [`run_tool_loop_stream`] over
/// a two-step script — a tool call with streamed arguments and a JSON
/// result, then the plain answer — folded through an encoder that names
/// the message, the way a chat route would.
fn tool_loop_chunks() -> Vec<UiMessageChunk> {
    let model = Arc::new(ScriptedModel {
        script: vec![
            asks_for("lookup", json!({ "q": "munich" })),
            answers("It is 21 and clear in Munich."),
        ],
        calls: AtomicUsize::new(0),
    });
    let events = pollster::block_on(async {
        let mut stream = run_tool_loop_stream(
            &*model,
            Prompt::new(ModelTier::Fast)
                .user("weather in munich")
                .tool(lookup_tool()),
            &WeatherExecutor,
            ToolBudget::steps(4),
        );
        let mut events = Vec::new();
        while let Some(event) = stream.next().await {
            events.push(event.expect("the scripted loop succeeds"));
        }
        events
    });
    let mut encoder = UiMessageEncoder::with_message_id("msg-tool-loop");
    let mut chunks = Vec::new();
    for event in &events {
        chunks.extend(encoder.tool_loop_event(event));
    }
    chunks
}

/// The error case: the answer dies mid-stream, and the adapter puts the
/// fixed masked sentence on the wire — the provider's own words stay in
/// the log.
fn error_mid_stream_chunks() -> Vec<UiMessageChunk> {
    let deltas: BoxStream<'static, Result<TextDelta, TextModelError>> =
        Box::pin(futures_util::stream::iter(vec![
            Ok(TextDelta::Text("Half an answer".to_owned())),
            Err(TextModelError::Transport(
                "provider words that must not reach the client".to_owned(),
            )),
        ]));
    collect(text_stream_chunks(deltas))
}

/// The custom case, hand-built: the chunks a caller pushes directly —
/// a source, a `data-weather` part, a tool call failing — without an
/// encoder folding anything. Shows the optional fields present and
/// absent, the `data-*` type tag, and a tool error that names a call the
/// stream announced first, which the AI SDK's parser requires.
fn custom_parts_chunks() -> Vec<UiMessageChunk> {
    vec![
        UiMessageChunk::Start {
            message_id: Some("msg-custom".to_owned()),
            message_metadata: None,
        },
        UiMessageChunk::StartStep,
        UiMessageChunk::SourceUrl {
            source_id: "src-1".to_owned(),
            url: "https://example.com/munich".to_owned(),
            title: Some("Munich travel guide".to_owned()),
        },
        UiMessageChunk::Data {
            name: "weather".to_owned(),
            id: Some("w1".to_owned()),
            data: json!({ "temp_c": 21 }),
            transient: None,
        },
        UiMessageChunk::TextStart {
            id: "text-0".to_owned(),
        },
        UiMessageChunk::TextDelta {
            id: "text-0".to_owned(),
            delta: "Munich sits on the Isar.".to_owned(),
        },
        UiMessageChunk::TextEnd {
            id: "text-0".to_owned(),
        },
        // A tool error names a call the stream has announced: the AI
        // SDK's parser drops an output for a call it has never seen.
        UiMessageChunk::ToolInputStart {
            tool_call_id: "call-1".to_owned(),
            tool_name: "forecast".to_owned(),
        },
        UiMessageChunk::ToolInputAvailable {
            tool_call_id: "call-1".to_owned(),
            tool_name: "forecast".to_owned(),
            input: json!({ "city": "munich" }),
        },
        UiMessageChunk::ToolOutputError {
            tool_call_id: "call-1".to_owned(),
            error_text: "the forecast service timed out".to_owned(),
        },
        UiMessageChunk::FinishStep,
        UiMessageChunk::Finish {
            finish_reason: Some(UiFinishReason::Other),
            message_metadata: None,
        },
    ]
}

/// Every fixture case with the one-line reason it exists — the table the
/// README documents and the Node contract test walks.
fn cases() -> Vec<(&'static str, Vec<UiMessageChunk>)> {
    vec![
        ("text-and-reasoning", text_and_reasoning_chunks()),
        ("tool-loop", tool_loop_chunks()),
        ("error-mid-stream", error_mid_stream_chunks()),
        ("custom-parts", custom_parts_chunks()),
    ]
}

#[test]
fn the_encoder_writes_the_committed_fixture_bytes() {
    for (name, chunks) in cases() {
        let bytes = wire_bytes(&chunks);
        let path = fixture_dir().join(format!("{name}.sse"));
        if std::env::var(UPDATE).is_ok_and(|value| value == "1") {
            fs::create_dir_all(fixture_dir()).expect("the fixture directory");
            fs::write(&path, &bytes).expect("the fixture write");
            continue;
        }
        let committed =
            fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        assert_eq!(
            bytes, committed,
            "{name} drifted from its fixture; rerun with {UPDATE}=1 only if the \
             protocol change is deliberate"
        );
    }
}

#[test]
fn each_fixture_has_the_shape_its_name_promises() {
    let cases = cases();
    let (text, tool_loop, error, custom) = (&cases[0], &cases[1], &cases[2], &cases[3]);
    assert_eq!(
        kinds(&text.1),
        vec![
            "start",
            "start-step",
            "reasoning-start",
            "reasoning-delta",
            "reasoning-delta",
            "reasoning-end",
            "text-start",
            "text-delta",
            "text-delta",
            "text-end",
            "finish-step",
            "finish",
        ],
        "both pairs of deltas grow one open part each"
    );
    assert_eq!(
        kinds(&tool_loop.1),
        vec![
            "start",
            "start-step",
            "text-start",
            "text-delta",
            "text-end",
            "tool-input-start",
            "tool-input-delta",
            "tool-input-delta",
            "tool-input-available",
            "finish-step",
            "tool-output-available",
            "start-step",
            "text-start",
            "text-delta",
            "text-end",
            "finish-step",
            "finish",
        ],
        "the tool output lands after the step that called it closed; the \
         second step reopens; the final finish carries the last reason"
    );
    assert_eq!(
        kinds(&error.1),
        vec![
            "start",
            "start-step",
            "text-start",
            "text-delta",
            "text-end",
            "error",
        ],
        "the open part closes, the failure masks to the fixed sentence, \
         and the message ends without a finish-step"
    );
    assert_eq!(
        kinds(&custom.1),
        vec![
            "start",
            "start-step",
            "source-url",
            "data-weather",
            "text-start",
            "text-delta",
            "text-end",
            "tool-input-start",
            "tool-input-available",
            "tool-output-error",
            "finish-step",
            "finish",
        ],
        "the hand-built stream rides as it was built; the tool error names a call the stream announced first"
    );
}
