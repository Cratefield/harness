//! `run_tool_loop_stream` end to end (issue #859), over a model whose
//! streams are scripted delta by delta and a recording executor, against
//! `run_tool_loop` on the same script: same event shape, same outcome,
//! same errors.
#![expect(
    clippy::disallowed_types,
    reason = "the stubs record their calls, as the fakes in cratefield-testing do"
)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cratefield_core::{
    BoxStream, Capability, Completion, CompletionBuilder, FinishReason, ModelTier, Prompt,
    TextDelta, TextModel, TextModelError, ToolBudget, ToolCall, ToolExecutor, ToolLoopError,
    ToolLoopEvent, ToolResult, ToolSpec, run_tool_loop, run_tool_loop_stream,
};
use futures_util::StreamExt as _;
use serde_json::{Value, json};

/// A [`TextModel`] whose `stream` yields a scripted list of deltas per
/// model call, in order, and whose `complete` folds the same script entry
/// into the completion it would have produced — so the buffered loop and
/// the streamed loop see identical steps and their outcomes and errors
/// compare like for like. Every prompt a stream is opened with is
/// recorded. Once the script is spent the last entry repeats, the same
/// rule the buffered loop's tests script by.
struct DeltaModel {
    script: Mutex<VecDeque<Vec<Result<TextDelta, TextModelError>>>>,
    last: Mutex<Option<Vec<Result<TextDelta, TextModelError>>>>,
    prompts: Mutex<Vec<Prompt>>,
    /// Whether a model stream is open right now: set when one starts,
    /// cleared by the guard the stream owns when it is dropped.
    open: Arc<AtomicBool>,
    /// Yield the script and then never answer again — the model stopped
    /// talking mid-stream, the state only a dropped consumer cancels.
    hold: bool,
    supports_tools: bool,
}

impl DeltaModel {
    fn new(script: Vec<Vec<Result<TextDelta, TextModelError>>>) -> Arc<Self> {
        Self::scripted(script, true, false)
    }

    /// The same scripted model, reporting no tools capability.
    fn without_tools(script: Vec<Vec<Result<TextDelta, TextModelError>>>) -> Arc<Self> {
        Self::scripted(script, false, false)
    }

    /// A model that stops answering once its script is spent: its stream
    /// stays open forever.
    fn holding(script: Vec<Vec<Result<TextDelta, TextModelError>>>) -> Arc<Self> {
        Self::scripted(script, true, true)
    }

    fn scripted(
        script: Vec<Vec<Result<TextDelta, TextModelError>>>,
        supports_tools: bool,
        hold: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            script: Mutex::new(script.into()),
            last: Mutex::new(None),
            prompts: Mutex::new(Vec::new()),
            open: Arc::new(AtomicBool::new(false)),
            hold,
            supports_tools,
        })
    }

    fn next_entry(&self) -> Vec<Result<TextDelta, TextModelError>> {
        let next = self.script.lock().expect("script lock").pop_front();
        match next {
            Some(entry) => {
                *self.last.lock().expect("script lock") = Some(entry.clone());
                entry
            }
            None => self
                .last
                .lock()
                .expect("script lock")
                .clone()
                .expect("the script answered at least once"),
        }
    }

    fn prompts(&self) -> Vec<Prompt> {
        self.prompts.lock().expect("prompt lock").clone()
    }

    fn streams_started(&self) -> usize {
        self.prompts().len()
    }

    /// Whether the in-flight model stream, if there was one, has been
    /// dropped.
    fn stream_dropped(&self) -> bool {
        !self.open.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl TextModel for DeltaModel {
    async fn complete(&self, _prompt: &Prompt) -> Result<Completion, TextModelError> {
        // The buffered half answers by folding the very deltas the stream
        // would have yielded, so both loops see identical completions.
        let mut builder = CompletionBuilder::default();
        for delta in self.next_entry() {
            match delta {
                Ok(delta) => builder.push(&delta),
                Err(error) => return Err(error),
            }
        }
        Ok(builder.finish())
    }

    fn stream<'a>(
        &'a self,
        prompt: &'a Prompt,
    ) -> BoxStream<'a, Result<TextDelta, TextModelError>> {
        self.prompts
            .lock()
            .expect("prompt lock")
            .push(prompt.clone());
        self.open.store(true, Ordering::SeqCst);
        let entry = self.next_entry();
        if self.hold {
            // The script yields, then the model never answers again. The
            // guard travels inside the stream, so dropping the stream —
            // and only dropping it — clears the flag.
            let guard = StreamGuard {
                open: Arc::clone(&self.open),
            };
            Box::pin(futures_util::stream::iter(entry).chain(Held { _guard: guard }))
        } else {
            Box::pin(futures_util::stream::iter(entry))
        }
    }

    fn supports(&self, _tier: ModelTier, capability: Capability) -> bool {
        self.supports_tools && capability == Capability::Tools
    }
}

/// Marks a model stream open while it lives. It travels inside the stream
/// it guards, so the flag clears exactly when the stream is dropped —
/// which is the cancellation the loop's consumer triggers.
struct StreamGuard {
    open: Arc<AtomicBool>,
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.open.store(false, Ordering::SeqCst);
    }
}

/// The held tail of a stalled model stream: never yields, and owns the
/// [`StreamGuard`] so dropping the stream clears the open flag.
struct Held {
    _guard: StreamGuard,
}

impl futures_core::Stream for Held {
    type Item = Result<TextDelta, TextModelError>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::task::Poll::Pending
    }
}

/// A [`ToolExecutor`] that records the calls it ran and answers success.
struct RecordingExecutor {
    calls: Mutex<Vec<ToolCall>>,
}

impl RecordingExecutor {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
        })
    }

    fn call_count(&self) -> usize {
        self.calls.lock().expect("executor lock").len()
    }
}

#[async_trait]
impl ToolExecutor for RecordingExecutor {
    async fn execute(&self, call: &ToolCall) -> Result<String, String> {
        self.calls.lock().expect("executor lock").push(call.clone());
        Ok(format!("ran {}", call.name))
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

/// The deltas one streamed call yields when it asks for `name` with
/// `arguments`, reporting `input` and `output` tokens. The arguments
/// arrive in two chunks on purpose, so the assertions see the loop
/// forwarding deltas as they arrive rather than one buffered answer.
fn asks_for(
    name: &str,
    arguments: Value,
    input: u64,
    output: u64,
) -> Vec<Result<TextDelta, TextModelError>> {
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
            input_tokens: input,
            output_tokens: output,
            cached_input_tokens: None,
        }),
        Ok(TextDelta::Finish {
            reason: FinishReason::ToolUse,
            model: "fake".to_owned(),
        }),
    ]
}

/// The deltas one streamed call yields when it answers `text` and stops.
fn answers(text: &str, input: u64, output: u64) -> Vec<Result<TextDelta, TextModelError>> {
    vec![
        Ok(TextDelta::Text(text.to_owned())),
        Ok(TextDelta::Usage {
            input_tokens: input,
            output_tokens: output,
            cached_input_tokens: None,
        }),
        Ok(TextDelta::Finish {
            reason: FinishReason::Stop,
            model: "fake".to_owned(),
        }),
    ]
}

/// Drives a streamed loop to its end and gathers every item.
fn collect(
    mut stream: BoxStream<'_, Result<ToolLoopEvent, ToolLoopError>>,
) -> Vec<Result<ToolLoopEvent, ToolLoopError>> {
    pollster::block_on(async {
        let mut events = Vec::new();
        while let Some(event) = stream.next().await {
            events.push(event);
        }
        events
    })
}

/// A one-word summary of an event, so a whole stream's shape asserts in
/// one `Vec` equality.
fn shape(event: &Result<ToolLoopEvent, ToolLoopError>) -> String {
    match event {
        Ok(ToolLoopEvent::Delta { step, delta }) => format!(
            "delta {step} {}",
            match delta {
                TextDelta::Text(_) => "text",
                TextDelta::Reasoning(_) => "reasoning",
                TextDelta::ToolCallStarted { .. } => "started",
                TextDelta::ToolCallArguments { .. } => "args",
                TextDelta::ToolCallFinished { .. } => "finished",
                TextDelta::Usage { .. } => "usage",
                TextDelta::Finish { .. } => "finish",
                _ => "other",
            }
        ),
        Ok(ToolLoopEvent::ToolResult { step, .. }) => format!("result {step}"),
        Ok(ToolLoopEvent::StepFinished { step, .. }) => format!("step {step}"),
        Ok(ToolLoopEvent::Done(_)) => "done".to_owned(),
        Ok(_) => "other".to_owned(),
        Err(_) => "error".to_owned(),
    }
}

#[test]
fn a_two_step_stream_yields_the_events_the_buffered_loop_summarises() {
    let script = vec![
        asks_for("lookup", json!({ "q": "x" }), 10, 5),
        answers("the answer", 20, 7),
    ];
    let model = DeltaModel::new(script.clone());
    let executor = RecordingExecutor::new();
    let prompt = Prompt::new(ModelTier::Fast)
        .user("find x")
        .tool(lookup_tool());

    let mut events = collect(run_tool_loop_stream(
        &*model,
        prompt.clone(),
        &*executor,
        ToolBudget::steps(4),
    ));

    // Deltas live as they arrived, tagged with the step; each step closes
    // with its usage; the executed call and its result sit between the two
    // steps; the outcome comes last.
    assert_eq!(
        events.iter().map(shape).collect::<Vec<_>>(),
        vec![
            "delta 0 text",
            "delta 0 started",
            "delta 0 args",
            "delta 0 args",
            "delta 0 finished",
            "delta 0 usage",
            "delta 0 finish",
            "step 0",
            "result 0",
            "delta 1 text",
            "delta 1 usage",
            "delta 1 finish",
            "step 1",
            "done",
        ],
    );

    let Some(Ok(ToolLoopEvent::Done(outcome))) = events.pop() else {
        panic!("the stream ended without a Done");
    };
    // The executed call and its result sit between the two steps' usage
    // reports, where the shape above puts them.
    let Some(Ok(ToolLoopEvent::ToolResult { call, result, .. })) = events.get(8).cloned() else {
        panic!("no tool result between the two steps");
    };
    assert_eq!(call.id, "call-1");
    assert_eq!(result, ToolResult::ok("call-1", "ran lookup"));
    assert_eq!(
        executor.call_count(),
        1,
        "the streamed loop ran the one call"
    );

    // The outcome is the one the buffered loop returns for the same
    // script, over a fresh model running the identical steps.
    let buffered_model = DeltaModel::new(script);
    let buffered = pollster::block_on(run_tool_loop(
        &*buffered_model,
        Prompt::new(ModelTier::Fast)
            .user("find x")
            .tool(lookup_tool()),
        &*executor,
        ToolBudget::steps(4),
    ))
    .expect("the buffered loop answers the same script");
    assert_eq!(outcome, buffered);
    assert_eq!(outcome.completion.text, "the answer");
    assert_eq!(outcome.steps.len(), 2);

    // The second stream saw the tool result fed back.
    let prompts = model.prompts();
    assert_eq!(prompts.len(), 2);
    assert_eq!(prompts[1].messages.len(), 3);
    assert_eq!(
        prompts[1].messages[2].tool_results,
        vec![ToolResult::ok("call-1", "ran lookup")]
    );
}

#[test]
fn budget_exhaustion_ends_the_stream_with_the_buffered_error() {
    // The model never stops asking for tools: the second step's cumulative
    // total (40) crosses the ceiling (25), so the stream ends there with
    // the same error the buffered loop returns, and the over-budget
    // step's tools never run.
    let script = || {
        vec![
            asks_for("lookup", json!({ "q": "x" }), 10, 10),
            asks_for("lookup", json!({ "q": "x" }), 10, 10),
        ]
    };
    let model = DeltaModel::new(script());
    let executor = RecordingExecutor::new();
    let prompt = Prompt::new(ModelTier::Fast).user("x").tool(lookup_tool());
    let budget = ToolBudget::steps(4).max_total_tokens(25);

    let mut events = collect(run_tool_loop_stream(
        &*model,
        prompt.clone(),
        &*executor,
        budget.clone(),
    ));

    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Ok(ToolLoopEvent::Done(_)))),
        "an exhausted loop never produces an outcome"
    );
    let Some(Err(error)) = events.pop() else {
        panic!("the stream did not end with the budget error");
    };
    assert_eq!(
        events.last().map(shape),
        Some("step 1".to_owned()),
        "the over-budget step still reports its usage before the error"
    );
    assert_eq!(executor.call_count(), 1, "only the first step's calls ran");

    let buffered = pollster::block_on(run_tool_loop(
        &*DeltaModel::new(script()),
        Prompt::new(ModelTier::Fast).user("x").tool(lookup_tool()),
        &*executor,
        budget,
    ))
    .unwrap_err();
    assert_eq!(error, buffered);
    match error {
        ToolLoopError::TokenBudgetExhausted { used, steps } => {
            assert_eq!(used, 40);
            assert_eq!(steps.len(), 2);
        }
        other => panic!("expected a token-budget error, got {other:?}"),
    }
}

#[test]
fn a_model_error_mid_stream_ends_the_loop_with_the_buffered_error() {
    let script = || {
        vec![vec![
            Ok(TextDelta::Text("partial".to_owned())),
            Err(TextModelError::Transport("boom".to_owned())),
        ]]
    };
    let model = DeltaModel::new(script());
    let executor = RecordingExecutor::new();
    let prompt = Prompt::new(ModelTier::Fast).user("x").tool(lookup_tool());

    let mut events = collect(run_tool_loop_stream(
        &*model,
        prompt.clone(),
        &*executor,
        ToolBudget::steps(4),
    ));

    // The deltas before the failure were forwarded; the failure itself is
    // the loop's last item, and nothing ran after it.
    assert_eq!(
        events.iter().map(shape).collect::<Vec<_>>(),
        vec!["delta 0 text", "error"],
    );
    assert_eq!(
        events[1],
        Err(ToolLoopError::Model(TextModelError::Transport(
            "boom".to_owned()
        ))),
    );
    assert_eq!(executor.call_count(), 0);
    assert_eq!(
        model.streams_started(),
        1,
        "the loop stopped at the failed step"
    );

    // The buffered loop, over the same script, fails with the same error:
    // its `complete` folds the identical deltas.
    let buffered = pollster::block_on(run_tool_loop(
        &*DeltaModel::new(script()),
        Prompt::new(ModelTier::Fast).user("x").tool(lookup_tool()),
        &*executor,
        ToolBudget::steps(4),
    ))
    .unwrap_err();
    assert_eq!(events.pop().unwrap().unwrap_err(), buffered);
}

#[test]
fn dropping_the_stream_cancels_the_in_flight_step() {
    // The first delta arrives, then the model never answers again: the
    // stream is mid-step when the consumer drops it. Dropping must drop
    // the model's stream with it — the cancellation contract
    // `TextModel::stream` carries — run no tool, and make no further
    // model call.
    let model = DeltaModel::holding(vec![asks_for("lookup", json!({ "q": "x" }), 10, 5)]);
    let executor = RecordingExecutor::new();
    let prompt = Prompt::new(ModelTier::Fast).user("x").tool(lookup_tool());

    let mut stream = run_tool_loop_stream(&*model, prompt, &*executor, ToolBudget::steps(4));
    let first = pollster::block_on(stream.next()).expect("the first delta arrives");
    assert!(matches!(
        first,
        Ok(ToolLoopEvent::Delta {
            step: 0,
            delta: TextDelta::Text(_)
        })
    ));

    drop(stream);

    assert!(
        model.stream_dropped(),
        "the in-flight model stream was dropped"
    );
    assert_eq!(model.streams_started(), 1, "no further model call was made");
    assert_eq!(
        executor.call_count(),
        0,
        "no tool ran for a dropped consumer"
    );
}

#[test]
fn the_gates_refuse_a_stream_before_the_model_is_called() {
    let script = || vec![answers("unused", 1, 1)];
    let model = DeltaModel::without_tools(script());
    let executor = RecordingExecutor::new();
    let prompt = Prompt::new(ModelTier::Fast).user("x").tool(lookup_tool());

    let mut stream =
        run_tool_loop_stream(&*model, prompt.clone(), &*executor, ToolBudget::steps(2));
    let first = pollster::block_on(stream.next()).expect("the refusal is the first item");
    assert_eq!(
        first.unwrap_err(),
        ToolLoopError::Model(TextModelError::Unsupported(Capability::Tools)),
    );
    assert!(
        pollster::block_on(stream.next()).is_none(),
        "the refusal ends the stream"
    );
    assert_eq!(model.streams_started(), 0, "no stream was opened");
    assert_eq!(executor.call_count(), 0);

    // The buffered loop refuses the same prompt with the same error.
    let buffered = pollster::block_on(run_tool_loop(
        &*DeltaModel::without_tools(script()),
        Prompt::new(ModelTier::Fast).user("x").tool(lookup_tool()),
        &*executor,
        ToolBudget::steps(2),
    ))
    .unwrap_err();
    assert_eq!(
        buffered,
        ToolLoopError::Model(TextModelError::Unsupported(Capability::Tools)),
    );
}
