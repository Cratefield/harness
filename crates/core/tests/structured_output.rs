//! `TextModelExt` end to end (issue #580) over a scripted model, and the
//! guaranteed error that never carries the model's output.
#![expect(
    clippy::disallowed_types,
    reason = "the stub records its calls, as the fakes in cratefield-testing do"
)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use cratefield_core::{Completion, ModelTier, Prompt, TextModel, TextModelError, TextModelExt};
use schemars::{JsonSchema, Schema};
use serde::Deserialize;
use serde_json::{Value, json};

/// A [`TextModel`] that answers from a script in order, recording every
/// prompt it is asked so a test can count calls and read the repair retry.
struct ScriptedModel {
    script: Mutex<VecDeque<Result<Completion, TextModelError>>>,
    prompts: Mutex<Vec<Prompt>>,
}

impl ScriptedModel {
    fn new(script: Vec<Result<Completion, TextModelError>>) -> Arc<Self> {
        Arc::new(Self {
            script: Mutex::new(script.into()),
            prompts: Mutex::new(Vec::new()),
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
        self.script
            .lock()
            .expect("script lock")
            .pop_front()
            .expect("the script has an answer for every call")
    }
}

/// An answer in the script, wrapped `Ok` where the script is built.
fn said(text: &str) -> Completion {
    Completion::new(text, "vendor")
}

/// An answer that carries native structured output.
fn said_json(json: Value) -> Completion {
    Completion::new("", "vendor").json(json)
}

/// A schema built from a literal, for the focused cases.
fn schema(value: Value) -> Schema {
    Schema::try_from(value).expect("a valid JSON Schema")
}

/// The object schema the focused cases share: one required number.
fn price_schema() -> Schema {
    schema(json!({
        "type": "object",
        "properties": { "price": { "type": "number" } },
        "required": ["price"],
        "additionalProperties": false,
    }))
}

fn prompt() -> Prompt {
    Prompt::new(ModelTier::Fast).user("Extract the price.")
}

#[test]
fn the_extension_reaches_a_dyn_text_model() {
    // The blanket impl is for `M: TextModel + ?Sized`, so a `dyn TextModel`
    // — what a module holds as `Arc<dyn TextModel>` — gets `complete_json`
    // too, and an adapter cannot opt out of the validation.
    let scripted = ScriptedModel::new(vec![Ok(said_json(json!({ "price": 7 })))]);
    let model: Arc<dyn TextModel> = scripted.clone();
    let value = pollster::block_on(model.complete_json(prompt(), &price_schema())).unwrap();
    assert_eq!(value, json!({ "price": 7 }));
    assert_eq!(scripted.calls(), 1);
}

// -----------------------------------------------------------------
// The happy paths

#[test]
fn a_native_structured_answer_comes_back_after_one_call() {
    let model = ScriptedModel::new(vec![Ok(said_json(json!({ "price": 120.5 })))]);
    let value = pollster::block_on(model.complete_json(prompt(), &price_schema())).unwrap();
    assert_eq!(value, json!({ "price": 120.5 }));
    assert_eq!(model.calls(), 1, "a conforming answer needs no repair");
    // The prompt the model was asked carried the schema, so an adapter can
    // request provider-native structured output.
    assert!(model.prompts()[0].json_schema.is_some());
}

#[test]
fn a_fenced_json_reply_is_accepted_as_the_fallback() {
    // A provider without native structured output answers in text; the
    // markdown fence a real model wraps it in is stripped.
    let model = ScriptedModel::new(vec![Ok(said("```json\n{\"price\": 99}\n```"))]);
    let value = pollster::block_on(model.complete_json(prompt(), &price_schema())).unwrap();
    assert_eq!(value, json!({ "price": 99 }));
    assert_eq!(model.calls(), 1);
}

// -----------------------------------------------------------------
// The repair retry

#[test]
fn an_unparseable_reply_is_retried_once_and_the_retry_names_the_failure() {
    let model = ScriptedModel::new(vec![
        Ok(said("I am afraid I cannot do that")),
        Ok(said("{\"price\": 42}")),
    ]);
    let value = pollster::block_on(model.complete_json(prompt(), &price_schema())).unwrap();
    assert_eq!(value, json!({ "price": 42 }));
    assert_eq!(model.calls(), 2, "exactly one repair retry");

    // The retry quotes the first reply back and names the failure, then
    // asks for only JSON.
    let retry = &model.prompts()[1].messages;
    assert_eq!(
        retry.len(),
        3,
        "the reply and the repair instruction were appended"
    );
    assert_eq!(retry[1].content, "I am afraid I cannot do that");
    assert!(
        retry[2].content.contains("not valid JSON"),
        "{}",
        retry[2].content
    );
}

#[test]
fn a_still_bad_answer_is_a_violation_that_never_carries_the_output() {
    // The message names the path and reason, never the model's value.
    let secret = "SECRET-customer-note-xyz";
    let model = ScriptedModel::new(vec![Ok(said(secret)), Ok(said(secret))]);
    let error = pollster::block_on(model.complete_json(prompt(), &price_schema())).unwrap_err();
    match &error {
        TextModelError::SchemaViolation(reason) => {
            assert!(
                !reason.contains(secret),
                "must not echo the output: {reason}"
            );
        }
        other => panic!("expected a schema violation, got {other:?}"),
    }
    assert!(!error.to_string().contains(secret));
    assert_eq!(model.calls(), 2, "one repair retry, then stop");

    // A number below the schema's `minimum` is reported by the bound, not
    // the value: 42 must not appear.
    let minimum_schema = schema(json!({
        "type": "object",
        "properties": { "price": { "type": "number", "minimum": 100 } },
    }));
    let model = ScriptedModel::new(vec![
        Ok(said_json(json!({ "price": 42 }))),
        Ok(said_json(json!({ "price": 42 }))),
    ]);
    let error = pollster::block_on(model.complete_json(prompt(), &minimum_schema)).unwrap_err();
    match &error {
        TextModelError::SchemaViolation(reason) => {
            assert!(reason.contains("minimum"), "{reason}");
            assert!(!reason.contains("42"), "must not echo the value: {reason}");
        }
        other => panic!("expected a schema violation, got {other:?}"),
    }
    assert!(!error.to_string().contains("42"));
}

#[test]
fn a_nonconforming_answer_is_a_violation_after_the_repair_retry() {
    // Wrong types, extra keys (`additionalProperties: false`) and missing
    // required fields all take one repair retry, then fail; the message
    // names the schema path.
    for (answer, needle) in [
        (json!({ "price": "cheap" }), "price"),
        (json!({ "price": 1.0, "sneaky": true }), "sneaky"),
        (json!({}), "price"),
    ] {
        let model = ScriptedModel::new(vec![
            Ok(said_json(answer.clone())),
            Ok(said_json(answer.clone())),
        ]);
        let error = pollster::block_on(model.complete_json(prompt(), &price_schema())).unwrap_err();
        assert_eq!(model.calls(), 2, "one repair retry for {answer}");
        match error {
            TextModelError::SchemaViolation(reason) => {
                assert!(reason.contains(needle), "{answer}: {reason}");
            }
            other => panic!("expected a schema violation for {answer}, got {other:?}"),
        }
    }
}

// -----------------------------------------------------------------
// Refusals that never reach the model

#[test]
fn a_schema_the_validator_cannot_honour_is_refused_before_the_model_is_called() {
    // An unsupported keyword, and a root that is not an object: both are
    // the caller's mistake, and the model must never be asked.
    for (bad, needle) in [
        (
            schema(json!({
                "type": "object",
                "properties": { "price": { "type": "string", "pattern": "^[0-9]" } },
            })),
            "pattern",
        ),
        (
            schema(json!({
                "type": "array",
                "items": { "type": "number" },
            })),
            "root type",
        ),
    ] {
        // An empty script: the model panics if it is asked at all.
        let model = ScriptedModel::new(Vec::new());
        let error = pollster::block_on(model.complete_json(prompt(), &bad)).unwrap_err();
        match error {
            TextModelError::InvalidSchema(reason) => assert!(reason.contains(needle), "{reason}"),
            other => panic!("expected an invalid-schema error, got {other:?}"),
        }
        assert_eq!(
            model.calls(),
            0,
            "a caller's schema bug is not the model's to pay for"
        );
    }
}

#[test]
fn a_transient_failure_propagates_without_a_repair_retry() {
    let model = ScriptedModel::new(vec![Err(TextModelError::Transient {
        retry_after: Some(Duration::from_secs(7)),
    })]);
    let error = pollster::block_on(model.complete_json(prompt(), &price_schema())).unwrap_err();
    assert_eq!(
        error,
        TextModelError::Transient {
            retry_after: Some(Duration::from_secs(7))
        }
    );
    assert_eq!(
        model.calls(),
        1,
        "a failed call is not repaired, it is reported"
    );
}

// -----------------------------------------------------------------
// complete_as: the typed form, over a generated schema

/// The docs example: a quote extracted from a hotel's emailed reply. The
/// schema `complete_as` generates from this is the one `complete_json`
/// checks, so the test also proves a real `schemars` struct — an optional
/// number, a nested-free object, a list, and `deny_unknown_fields` — is
/// within the supported subset.
#[derive(Debug, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
struct Quote {
    price: f64,
    currency: String,
    check_in: String,
    check_out: String,
    room: String,
    conditions: Vec<String>,
    valid_until: Option<String>,
}

#[test]
fn complete_as_deserializes_into_the_requested_type() {
    let model = ScriptedModel::new(vec![Ok(said_json(json!({
        "price": 142.5,
        "currency": "EUR",
        "check_in": "2026-07-04",
        "check_out": "2026-07-11",
        "room": "double, sea view",
        "conditions": ["free cancellation until 48h before"],
        "valid_until": null,
    })))]);
    let quote: Quote = pollster::block_on(model.complete_as(prompt())).unwrap();
    assert_eq!(
        quote,
        Quote {
            price: 142.5,
            currency: "EUR".to_owned(),
            check_in: "2026-07-04".to_owned(),
            check_out: "2026-07-11".to_owned(),
            room: "double, sea view".to_owned(),
            conditions: vec!["free cancellation until 48h before".to_owned()],
            valid_until: None,
        }
    );
    assert_eq!(
        model.calls(),
        1,
        "the generated schema is within the supported subset"
    );
}
