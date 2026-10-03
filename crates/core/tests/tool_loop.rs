//! `run_tool_loop` end to end (issue #665), over a scripted model and a
//! recording executor.
#![expect(
    clippy::disallowed_types,
    reason = "the stubs record their calls, as the fakes in cratefield-testing do"
)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cratefield_core::{
    Capability, Completion, ModelTier, Prompt, Role, RoutingTextModel, TextModel, TextModelError,
    ToolBudget, ToolCall, ToolExecutor, ToolLoopError, ToolLoopOutcome, ToolResult, ToolSpec, Turn,
    run_tool_loop,
};
use serde_json::{Value, json};

/// A [`TextModel`] that answers from a script in order and, once the script
/// is spent, repeats its last answer — so a test can script a fixed number
/// of steps or a model that never stops asking for tools. Every prompt it
/// is asked is recorded.
struct ScriptedModel {
    script: Mutex<VecDeque<Completion>>,
    last: Mutex<Option<Completion>>,
    prompts: Mutex<Vec<Prompt>>,
    supports_tools: bool,
}

impl ScriptedModel {
    fn new(script: Vec<Completion>) -> Arc<Self> {
        Self::scripted(script, true)
    }

    /// The same scripted model, reporting no tools capability.
    fn without_tools(script: Vec<Completion>) -> Arc<Self> {
        Self::scripted(script, false)
    }

    fn scripted(script: Vec<Completion>, supports_tools: bool) -> Arc<Self> {
        Arc::new(Self {
            script: Mutex::new(script.into()),
            last: Mutex::new(None),
            prompts: Mutex::new(Vec::new()),
            supports_tools,
        })
    }

    fn calls(&self) -> usize {
        self.prompts.lock().expect("script lock").len()
    }

    fn prompts(&self) -> Vec<Prompt> {
        self.prompts.lock().expect("script lock").clone()
    }
}

#[async_trait]
impl TextModel for ScriptedModel {
    async fn complete(&self, prompt: &Prompt) -> Result<Completion, TextModelError> {
        self.prompts
            .lock()
            .expect("script lock")
            .push(prompt.clone());
        let next = self.script.lock().expect("script lock").pop_front();
        let completion = match next {
            Some(completion) => {
                *self.last.lock().expect("script lock") = Some(completion.clone());
                completion
            }
            None => self
                .last
                .lock()
                .expect("script lock")
                .clone()
                .expect("the script answered at least once"),
        };
        Ok(completion)
    }

    fn supports(&self, _tier: ModelTier, capability: Capability) -> bool {
        self.supports_tools && capability == Capability::Tools
    }
}

/// A [`ToolExecutor`] that records the calls it ran and answers success,
/// or a fixed error where a test wants a tool-level failure.
struct RecordingExecutor {
    calls: Mutex<Vec<ToolCall>>,
    fail: Option<String>,
}

impl RecordingExecutor {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            fail: None,
        })
    }

    fn failing(message: &str) -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            fail: Some(message.to_owned()),
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
        match &self.fail {
            Some(message) => Err(message.clone()),
            None => Ok(format!("ran {}", call.name)),
        }
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

/// A completion that asks for `name` with `arguments`, reporting `input` and
/// `output` tokens.
fn asks_for(name: &str, arguments: Value, input: u64, output: u64) -> Completion {
    Completion::new("", "fake")
        .usage(input, output)
        .tool_calls(vec![ToolCall::new("call-1", name, arguments)])
}

fn run(
    model: &Arc<ScriptedModel>,
    prompt: Prompt,
    executor: &Arc<RecordingExecutor>,
    budget: ToolBudget,
) -> Result<ToolLoopOutcome, ToolLoopError> {
    pollster::block_on(run_tool_loop(&**model, prompt, &**executor, budget))
}

#[test]
fn a_two_step_loop_runs_the_tool_and_returns_the_final_answer() {
    let model = ScriptedModel::new(vec![
        asks_for("lookup", json!({ "q": "x" }), 10, 5),
        Completion::new("the answer", "fake").usage(20, 7),
    ]);
    let executor = RecordingExecutor::new();
    let prompt = Prompt::new(ModelTier::Fast)
        .user("find x")
        .tool(lookup_tool());

    let outcome = run(&model, prompt, &executor, ToolBudget::steps(4)).unwrap();

    assert_eq!(outcome.completion.text, "the answer");
    assert_eq!(outcome.steps.len(), 2);
    assert_eq!(outcome.steps[0].tool_calls, 1);
    assert_eq!(outcome.steps[1].tool_calls, 0);
    assert_eq!(outcome.input_tokens(), 30);
    assert_eq!(outcome.output_tokens(), 12);
    assert_eq!(executor.call_count(), 1);

    // The transcript is the prompt's own turn, then the assistant's
    // requested call and the user turn carrying its result.
    assert_eq!(outcome.messages.len(), 3);
    assert_eq!(outcome.messages[0], Turn::user("find x"));
    assert_eq!(outcome.messages[1].role, Role::Assistant);
    assert_eq!(outcome.messages[1].tool_calls.len(), 1);
    assert_eq!(outcome.messages[2].role, Role::User);
    assert_eq!(
        outcome.messages[2].tool_results,
        vec![ToolResult::ok("call-1", "ran lookup")]
    );

    // The second call actually saw the tool result fed back.
    let prompts = model.prompts();
    assert_eq!(prompts.len(), 2);
    assert!(prompts[1].messages.len() > prompts[0].messages.len());
    assert_eq!(prompts[1].messages[2].tool_results.len(), 1);
}

#[test]
fn the_step_budget_stops_a_model_that_never_stops_asking() {
    // One scripted completion, repeated forever: the model always wants a
    // tool, so only the budget ends the loop.
    let model = ScriptedModel::new(vec![asks_for("lookup", json!({ "q": "x" }), 1, 1)]);
    let executor = RecordingExecutor::new();
    let prompt = Prompt::new(ModelTier::Fast)
        .user("find x")
        .tool(lookup_tool());

    let error = run(&model, prompt, &executor, ToolBudget::steps(2)).unwrap_err();

    match error {
        ToolLoopError::StepBudgetExhausted { steps } => {
            assert_eq!(steps.len(), 2, "exactly the budgeted calls");
        }
        other => panic!("expected a step-budget error, got {other:?}"),
    }
    assert_eq!(model.calls(), 2);
}

#[test]
fn arguments_that_fail_the_schema_never_reach_the_executor() {
    let model = ScriptedModel::new(vec![
        // `q` must be a string; the model sent a number.
        asks_for("lookup", json!({ "q": 5 }), 3, 3),
        Completion::new("recovered", "fake").usage(4, 4),
    ]);
    let executor = RecordingExecutor::new();
    let prompt = Prompt::new(ModelTier::Fast)
        .user("find x")
        .tool(lookup_tool());

    let outcome = run(&model, prompt, &executor, ToolBudget::steps(4)).unwrap();

    assert_eq!(executor.call_count(), 0, "an invalid call is not executed");
    assert_eq!(outcome.completion.text, "recovered");
    let result = &outcome.messages[2].tool_results[0];
    assert!(result.is_error, "the model is shown the violation");
    assert_eq!(result.tool_call_id, "call-1");
}

#[test]
fn non_object_arguments_never_reach_the_executor() {
    // A schema with no top-level `type` — `{"properties", "required"}` —
    // asserts nothing about a non-object, so the loop must refuse the
    // arguments before the schema is consulted: the raw string an adapter
    // keeps for unparsable arguments can never reach an executor.
    let tool = ToolSpec::new(
        "lookup",
        "Look up a query.",
        json!({
            "properties": { "q": { "type": "string" } },
            "required": ["q"],
        }),
    );
    let model = ScriptedModel::new(vec![
        asks_for("lookup", Value::String("oops".to_owned()), 3, 3),
        Completion::new("recovered", "fake").usage(4, 4),
    ]);
    let executor = RecordingExecutor::new();
    let prompt = Prompt::new(ModelTier::Fast).user("find x").tool(tool);

    let outcome = run(&model, prompt, &executor, ToolBudget::steps(4)).unwrap();

    assert_eq!(
        executor.call_count(),
        0,
        "a non-object call is not executed"
    );
    assert_eq!(outcome.completion.text, "recovered");
    let result = &outcome.messages[2].tool_results[0];
    assert!(result.is_error, "the model is shown the violation");
    assert_eq!(result.tool_call_id, "call-1");
}

#[test]
fn an_unknown_tool_name_becomes_an_error_result() {
    let model = ScriptedModel::new(vec![
        asks_for("missing", json!({}), 1, 1),
        Completion::new("ok", "fake").usage(1, 1),
    ]);
    let executor = RecordingExecutor::new();
    let prompt = Prompt::new(ModelTier::Fast).user("x").tool(lookup_tool());

    let outcome = run(&model, prompt, &executor, ToolBudget::steps(4)).unwrap();

    assert_eq!(executor.call_count(), 0);
    assert!(outcome.messages[2].tool_results[0].is_error);
}

#[test]
fn a_tool_level_failure_is_fed_back_and_the_loop_continues() {
    let model = ScriptedModel::new(vec![
        asks_for("lookup", json!({ "q": "x" }), 1, 1),
        Completion::new("recovered", "fake").usage(1, 1),
    ]);
    let executor = RecordingExecutor::failing("tool exploded");
    let prompt = Prompt::new(ModelTier::Fast).user("x").tool(lookup_tool());

    let outcome = run(&model, prompt, &executor, ToolBudget::steps(4)).unwrap();

    assert_eq!(executor.call_count(), 1, "the executor was asked to run it");
    assert_eq!(outcome.completion.text, "recovered");
    let result = &outcome.messages[2].tool_results[0];
    assert!(result.is_error);
    assert_eq!(result.content, "tool exploded");
}

#[test]
fn a_schema_keyword_this_validator_cannot_honour_fails_before_any_call() {
    let tool = ToolSpec::new("t", "d", json!({ "type": "object", "pattern": "^a$" }));
    let model = ScriptedModel::new(vec![Completion::new("unused", "fake")]);
    let executor = RecordingExecutor::new();
    let prompt = Prompt::new(ModelTier::Fast).user("x").tool(tool);

    let error = run(&model, prompt, &executor, ToolBudget::steps(4)).unwrap_err();

    match error {
        ToolLoopError::InvalidToolSchema { tool, reason } => {
            assert_eq!(tool, "t");
            assert!(reason.contains("pattern"), "{reason}");
        }
        other => panic!("expected an invalid-schema error, got {other:?}"),
    }
    assert_eq!(model.calls(), 0, "the schema is checked before any call");
    assert_eq!(executor.call_count(), 0);
}

#[test]
fn a_model_without_tool_support_is_refused_before_any_call() {
    let model = ScriptedModel::without_tools(vec![Completion::new("unused", "fake")]);
    let executor = RecordingExecutor::new();
    let prompt = Prompt::new(ModelTier::Fast).user("x").tool(lookup_tool());

    let error = run(&model, prompt, &executor, ToolBudget::steps(4)).unwrap_err();

    assert_eq!(
        error,
        ToolLoopError::Model(TextModelError::Unsupported(Capability::Tools))
    );
    assert_eq!(model.calls(), 0);
    assert_eq!(executor.call_count(), 0);
}

#[test]
fn the_token_budget_stops_a_loop_still_asking_for_tools() {
    // The model never stops asking: the second step's cumulative total (40)
    // crosses the ceiling (25), so the loop ends there and the second
    // step's calls are never run.
    let model = ScriptedModel::new(vec![asks_for("lookup", json!({ "q": "x" }), 10, 10)]);
    let executor = RecordingExecutor::new();
    let prompt = Prompt::new(ModelTier::Fast).user("x").tool(lookup_tool());

    let error = run(
        &model,
        prompt,
        &executor,
        ToolBudget::steps(4).max_total_tokens(25),
    )
    .unwrap_err();

    match error {
        ToolLoopError::TokenBudgetExhausted { used, steps } => {
            assert_eq!(used, 40);
            assert_eq!(steps.len(), 2);
        }
        other => panic!("expected a token-budget error, got {other:?}"),
    }
    assert_eq!(
        executor.call_count(),
        1,
        "only the first step's calls ran; the over-budget step's did not"
    );
}

#[test]
fn an_answer_with_no_tool_calls_is_returned_even_over_the_token_budget() {
    // The final answer pushed the total past the ceiling, but it has
    // already been paid for and asked for no tool: returning it spends the
    // tokens on a usable answer rather than discarding it for nothing.
    let model = ScriptedModel::new(vec![
        asks_for("lookup", json!({ "q": "x" }), 10, 10),
        Completion::new("the answer", "fake").usage(10, 20),
    ]);
    let executor = RecordingExecutor::new();
    let prompt = Prompt::new(ModelTier::Fast).user("x").tool(lookup_tool());

    let outcome = run(
        &model,
        prompt,
        &executor,
        ToolBudget::steps(4).max_total_tokens(25),
    )
    .unwrap();

    assert_eq!(outcome.completion.text, "the answer");
    assert_eq!(outcome.steps.len(), 2);
    assert!(
        outcome.input_tokens() + outcome.output_tokens() > 25,
        "the final answer cost more than the budget, and is still returned"
    );
    assert_eq!(executor.call_count(), 1);
}

#[test]
fn a_zero_step_budget_makes_no_model_call() {
    // A budget of N means at most N calls; N = 0 means none, not one, so
    // the loop fails before it reaches the model or the executor.
    let model = ScriptedModel::new(vec![Completion::new("unused", "fake")]);
    let executor = RecordingExecutor::new();
    let prompt = Prompt::new(ModelTier::Fast).user("x").tool(lookup_tool());

    let error = run(&model, prompt, &executor, ToolBudget::steps(0)).unwrap_err();

    match error {
        ToolLoopError::StepBudgetExhausted { steps } => {
            assert!(steps.is_empty(), "no call was made, so no step is recorded");
        }
        other => panic!("expected a step-budget error, got {other:?}"),
    }
    assert_eq!(model.calls(), 0, "a zero budget makes no model call");
    assert_eq!(executor.call_count(), 0);
}

#[test]
fn a_router_only_lets_a_prompt_reach_a_tier_that_carries_tools() {
    // Fast can carry tools, Strong cannot. The Fast prompt reaches its own
    // model; the Strong prompt is refused with Unsupported and the Strong
    // model is never called.
    let fast = ScriptedModel::new(vec![Completion::new("fast answer", "fake")]);
    let strong = ScriptedModel::without_tools(vec![Completion::new("unused", "fake")]);
    let router = RoutingTextModel::new()
        .fast(fast.clone())
        .strong(strong.clone());
    let executor = RecordingExecutor::new();

    assert!(router.supports(ModelTier::Fast, Capability::Tools));
    assert!(!router.supports(ModelTier::Strong, Capability::Tools));

    let outcome = pollster::block_on(run_tool_loop(
        &router,
        Prompt::new(ModelTier::Fast).user("x").tool(lookup_tool()),
        &*executor,
        ToolBudget::steps(2),
    ))
    .expect("the fast tier carries tools");
    assert_eq!(outcome.completion.text, "fast answer");
    assert_eq!(fast.calls(), 1);

    let error = pollster::block_on(run_tool_loop(
        &router,
        Prompt::new(ModelTier::Strong).user("x").tool(lookup_tool()),
        &*executor,
        ToolBudget::steps(2),
    ))
    .unwrap_err();
    assert_eq!(
        error,
        ToolLoopError::Model(TextModelError::Unsupported(Capability::Tools))
    );
    assert_eq!(strong.calls(), 0, "the strong model is never called");
}

#[test]
fn a_prompt_without_tools_is_one_plain_call() {
    let model = ScriptedModel::new(vec![Completion::new("direct", "fake").usage(1, 1)]);
    let executor = RecordingExecutor::new();

    let outcome = run(
        &model,
        Prompt::new(ModelTier::Fast).user("hi"),
        &executor,
        ToolBudget::steps(4),
    )
    .unwrap();

    assert_eq!(outcome.completion.text, "direct");
    assert_eq!(outcome.steps.len(), 1);
    assert_eq!(model.calls(), 1);
    assert_eq!(outcome.messages.len(), 1);
    assert_eq!(executor.call_count(), 0);
}
