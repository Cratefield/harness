//! `FakeTextModel` and a module that declares the `TextModel` port
//! (issue #429).

use std::sync::Arc;
use std::time::Duration;

use cratefield_core::{
    Completion, Config, ConfigError, Migrations, Module, ModuleContext, Port, TextModel,
};
use cratefield_testing::{FakeTextModel, TestHarness, TextModelMode, conformance, request};

/// A module that drafts through the `TextModel` port — the smallest shape
/// that declares it and really uses it: the route asks the fast tier for a
/// line and answers with whatever came back (or the error's scrubbed
/// `Display`, which is what a module that degrades does).
pub struct Drafter;

impl Module for Drafter {
    fn name(&self) -> &'static str {
        "drafter"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::TextModel]
    }

    fn migrations(&self) -> Migrations {
        Migrations::default()
    }

    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let text_model = ctx.ports.text_model.expect("drafter requires TextModel");
        axum::Router::new().route(
            "/draft",
            axum::routing::get(move || {
                let text_model = Arc::clone(&text_model);
                async move {
                    let prompt = cratefield_core::Prompt::new(cratefield_core::ModelTier::Fast)
                        .user("Draft a line");
                    cratefield_core::Json(match text_model.complete(&prompt).await {
                        Ok(completion) => serde_json::json!({ "draft": completion.text }),
                        Err(error) => serde_json::json!({ "error": error.to_string() }),
                    })
                }
            }),
        )
    }
}

#[test]
fn a_module_that_requires_the_text_model_port_conforms() {
    // The port is additive to HARNESS_API = 1, so a module declaring it
    // passes the same eight checks every other module passes — including
    // check 4, which is only true when `full_fake_ports` fakes the port.
    conformance(Box::new(Drafter));
}

#[test]
fn the_harness_fakes_the_port_a_module_declares() {
    // `TestHarness::new` fakes every port; this is the text model leg of
    // that promise, exercised through the module's own route rather than
    // asserted on the struct.
    let kit = TestHarness::new(vec![Box::new(Drafter)]);
    let response = pollster::block_on(request(
        &kit.router,
        http::Method::GET,
        "/v1/drafter/draft",
        None,
    ));
    assert_eq!(
        response.status,
        http::StatusCode::OK,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    assert_eq!(response.json()["draft"], "fake completion");
}

// ---------------------------------------------------------------------------
// FakeTextModel

#[test]
fn answers_a_scripted_reply_with_a_deterministic_model_and_usage() {
    let model = FakeTextModel::new(TextModelMode::Reply("The room starts at ten.".to_owned()));
    let prompt = cratefield_core::Prompt::new(cratefield_core::ModelTier::Fast).user("When?");

    let completion = pollster::block_on(model.complete(&prompt)).unwrap();
    assert_eq!(completion.text, "The room starts at ten.");
    assert_eq!(
        completion.model, "fake-fast",
        "model names the tier, not a vendor"
    );
    assert_eq!(completion.json, None);
    assert!(completion.input_tokens > 0);
    assert!(completion.output_tokens > 0);
    // Deterministic: the same prompt and text answer the same counts.
    let again = pollster::block_on(model.complete(&prompt)).unwrap();
    assert_eq!(
        (again.input_tokens, again.output_tokens),
        (completion.input_tokens, completion.output_tokens)
    );
}

#[test]
fn a_transient_mode_carries_the_provider_back_off() {
    let model = FakeTextModel::new(TextModelMode::Transient {
        retry_after: Some(Duration::from_secs(30)),
    });
    let prompt = cratefield_core::Prompt::new(cratefield_core::ModelTier::Strong).user("Judge");

    let error = pollster::block_on(model.complete(&prompt)).unwrap_err();
    assert_eq!(
        error,
        cratefield_core::TextModelError::Transient {
            retry_after: Some(Duration::from_secs(30))
        }
    );
    assert_eq!(error.retry_after(), Some(Duration::from_secs(30)));
    // A retry that then gets an answer is recorded; the failed attempt is not.
    model.set_mode(TextModelMode::Reply("the verdict".to_owned()));
    let completion = pollster::block_on(model.complete(&prompt)).unwrap();
    assert_eq!(completion.text, "the verdict");
    assert_eq!(
        model.prompts().len(),
        1,
        "only the successful completion is recorded"
    );
}

#[test]
fn a_rejected_mode_carries_the_provider_text() {
    let model = FakeTextModel::new(TextModelMode::Rejected(
        "provider 422: content policy".to_owned(),
    ));
    let prompt = cratefield_core::Prompt::new(cratefield_core::ModelTier::Fast).user("Draft");

    let error = pollster::block_on(model.complete(&prompt)).unwrap_err();
    assert_eq!(
        error,
        cratefield_core::TextModelError::Rejected("provider 422: content policy".to_owned())
    );
    assert_eq!(error.retry_after(), None, "a refusal is not a back-off");
    assert!(model.prompts().is_empty(), "a failure is not recorded");
}

#[test]
fn the_exact_error_mode_answers_with_that_error() {
    let error = cratefield_core::TextModelError::Transport("isolate out of memory".to_owned());
    let model = FakeTextModel::new(TextModelMode::Error(error.clone()));
    let prompt = cratefield_core::Prompt::new(cratefield_core::ModelTier::Strong).user("Judge");

    assert_eq!(
        pollster::block_on(model.complete(&prompt)).unwrap_err(),
        error
    );
}

#[test]
fn the_not_configured_mode_reports_an_unwired_tier() {
    let model = FakeTextModel::new(TextModelMode::NotConfigured);
    let prompt = cratefield_core::Prompt::new(cratefield_core::ModelTier::Fast).user("Draft");

    assert_eq!(
        pollster::block_on(model.complete(&prompt)).unwrap_err(),
        cratefield_core::TextModelError::NotConfigured
    );
    assert!(model.prompts().is_empty());
}

#[test]
fn an_exact_completion_mode_answers_with_that_completion() {
    let completion = Completion::new("the answer", "vendor-of-the-day").usage(7, 9);
    let model = FakeTextModel::new(TextModelMode::Complete(completion.clone()));
    let prompt = cratefield_core::Prompt::new(cratefield_core::ModelTier::Strong).user("Judge");

    assert_eq!(
        pollster::block_on(model.complete(&prompt)).unwrap(),
        completion
    );
    assert_eq!(model.last().unwrap(), prompt);
}

/// The point of the per-tier modes: one test wires Fast to a reply and
/// Strong to a failure, and a module can be seen treating the two tiers
/// differently without either vendor being named.
#[test]
fn one_failing_tier_among_answering_ones() {
    let model = FakeTextModel::default();
    model.set_mode_for(
        cratefield_core::ModelTier::Strong,
        TextModelMode::Transient { retry_after: None },
    );
    assert_eq!(
        model.mode_for(cratefield_core::ModelTier::Strong),
        TextModelMode::Transient { retry_after: None }
    );
    assert_eq!(
        model.mode_for(cratefield_core::ModelTier::Fast),
        TextModelMode::Reply("fake completion".to_owned()),
        "the global mode still answers the other tier"
    );

    let strong = cratefield_core::Prompt::new(cratefield_core::ModelTier::Strong).user("Judge");
    assert!(pollster::block_on(model.complete(&strong)).is_err());
    let fast = cratefield_core::Prompt::new(cratefield_core::ModelTier::Fast).user("Draft");
    assert!(pollster::block_on(model.complete(&fast)).is_ok());

    // The override wins over a moved global mode, and clears back onto it.
    model.set_mode(TextModelMode::NotConfigured);
    assert_eq!(
        model.mode_for(cratefield_core::ModelTier::Strong),
        TextModelMode::Transient { retry_after: None }
    );
    model.clear_mode_for(cratefield_core::ModelTier::Strong);
    assert_eq!(
        model.mode_for(cratefield_core::ModelTier::Strong),
        TextModelMode::NotConfigured
    );
}

#[test]
fn a_scripted_prompt_is_recorded_with_its_tier() {
    let model = FakeTextModel::default();
    let strong = cratefield_core::Prompt::new(cratefield_core::ModelTier::Strong)
        .system("Judge fairly")
        .user("A draft");
    let fast = cratefield_core::Prompt::new(cratefield_core::ModelTier::Fast).user("A note");

    pollster::block_on(model.complete(&strong)).unwrap();
    pollster::block_on(model.complete(&fast)).unwrap();

    let prompts = model.prompts();
    assert_eq!(prompts.len(), 2);
    assert_eq!(prompts[0], strong);
    assert_eq!(prompts[1], fast);
    assert_eq!(model.last().unwrap(), fast);
    assert_eq!(prompts[0].tier, cratefield_core::ModelTier::Strong);
}
