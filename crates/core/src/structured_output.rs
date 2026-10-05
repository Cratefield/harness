//! JSON-Schema-constrained output for the [`TextModel`] port (issue #580):
//! ask for a value that conforms to a schema, and get either a conforming
//! value or an error — never a half-parsed one.
//!
//! [`Prompt::json_schema`] is already a *request*; what was missing was the
//! guarantee. [`TextModelExt`] is that guarantee, blanket-implemented so an
//! adapter cannot skip it: it checks the schema before the call, asks for it,
//! validates the answer (native [`Completion::json`] or text parsed as JSON)
//! and allows one repair retry. The validator is the tool loop's narrow,
//! fail-closed subset. See the trait and its methods for the full contract.

use async_trait::async_trait;
use schemars::{JsonSchema, Schema};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::ports::{Completion, Prompt, TextModel, TextModelError, Turn};
use crate::surface::schema_for;
use crate::tool_loop::{validate_instance, validate_schema};

/// Structured output on any [`TextModel`] (issue #580). Blanket-implemented
/// for every `TextModel`, so an adapter cannot override — and cannot skip —
/// the schema check, the validation, or the repair retry; import the trait
/// to call the methods.
#[async_trait]
pub trait TextModelExt: TextModel {
    /// Completes `prompt` and returns a value that conforms to `schema`.
    ///
    /// The schema is checked on the supported subset before the first call,
    /// the prompt's [`Prompt::json_schema`] is set to it, and the answer —
    /// native structured output, or text parsed as JSON — is validated
    /// against it. On failure the model gets one repair retry; a second
    /// failure is [`TextModelError::SchemaViolation`].
    ///
    /// # Errors
    ///
    /// - [`TextModelError::InvalidSchema`] if `schema` uses a keyword the
    ///   validator does not implement; the model is never called.
    /// - [`TextModelError::SchemaViolation`] if the answer still does not
    ///   conform after the repair retry. The message names the failed
    ///   path and reason only, never the model's output.
    /// - Whatever `complete` itself returned, unchanged: `NotConfigured`,
    ///   `Rejected`, `Transient`, `Transport`, `Unsupported`.
    async fn complete_json(&self, prompt: Prompt, schema: &Schema)
    -> Result<Value, TextModelError>;

    /// Completes `prompt` and deserializes the conforming value into `T`,
    /// using `T`'s own schema ([`schema_for`]) as the constraint — the
    /// typed form of [`TextModelExt::complete_json`].
    ///
    /// # Errors
    ///
    /// The same as [`TextModelExt::complete_json`], plus
    /// [`TextModelError::SchemaViolation`] if the conforming value does not
    /// deserialize into `T` (a shape the schema generator and the
    /// deserializer disagree on).
    async fn complete_as<T>(&self, prompt: Prompt) -> Result<T, TextModelError>
    where
        T: JsonSchema + DeserializeOwned + Send;
}

#[async_trait]
impl<M: TextModel + ?Sized> TextModelExt for M {
    async fn complete_json(
        &self,
        mut prompt: Prompt,
        schema: &Schema,
    ) -> Result<Value, TextModelError> {
        let schema = schema.as_value().clone();
        // Fail closed before the model is asked: an unsupported keyword, or a
        // root that is not an object, is the caller's mistake.
        validate_schema(&schema).map_err(TextModelError::InvalidSchema)?;
        // Both native paths require an object root: Anthropic's forced tool
        // takes an object `input_schema`, OpenAI's strict `response_format`
        // an object. A non-object root has no provider that could honour it.
        if schema.get("type").and_then(Value::as_str) != Some("object") {
            return Err(TextModelError::InvalidSchema(
                "the schema's root type must be \"object\"".to_owned(),
            ));
        }
        prompt.json_schema = Some(schema.clone());

        let completion = self.complete(&prompt).await?;
        match checked(&schema, &completion) {
            Ok(value) => Ok(value),
            Err(reason) => {
                // One repair retry: show the model what it said and what was
                // wrong with it, and ask once more for only the JSON.
                prompt.messages.push(Turn::assistant(said(&completion)));
                prompt
                    .messages
                    .push(Turn::user(repair_instruction(&reason)));
                let retry = self.complete(&prompt).await?;
                checked(&schema, &retry).map_err(TextModelError::SchemaViolation)
            }
        }
    }

    async fn complete_as<T>(&self, prompt: Prompt) -> Result<T, TextModelError>
    where
        T: JsonSchema + DeserializeOwned + Send,
    {
        let schema = schema_for::<T>();
        let value = self.complete_json(prompt, &schema).await?;
        serde_json::from_value(value).map_err(|_| {
            // The serde error quotes the offending value, which may be the
            // personal data the schema was there to structure; the schema
            // already checked the shape, so name the failure without it.
            TextModelError::SchemaViolation(
                "the validated value did not deserialize into the requested type".to_owned(),
            )
        })
    }
}

/// The candidate value from `completion`, or the reason it is unusable:
/// [`Completion::json`] when the provider honoured the schema request, else
/// [`Completion::text`] parsed as JSON with any markdown fence stripped.
fn checked(schema: &Value, completion: &Completion) -> Result<Value, String> {
    let candidate = match &completion.json {
        Some(json) => json.clone(),
        None => serde_json::from_str(strip_code_fence(&completion.text))
            .map_err(|_| "the reply was not valid JSON".to_owned())?,
    };
    validate_instance(schema, &candidate)?;
    Ok(candidate)
}

/// What the model said, for quoting back as the assistant turn of a repair:
/// its text, its parsed JSON when a native provider put nothing in the text,
/// or a placeholder — an empty assistant turn is refused by some providers.
fn said(completion: &Completion) -> String {
    if !completion.text.is_empty() {
        return completion.text.clone();
    }
    match &completion.json {
        Some(json) => json.to_string(),
        None => "(empty reply)".to_owned(),
    }
}

/// The user turn a repair asks for: the failure, and the one thing to do
/// about it.
fn repair_instruction(reason: &str) -> String {
    format!(
        "That reply did not conform to the required JSON schema ({reason}). \
         Reply with only a JSON value that conforms to the schema, and nothing else."
    )
}

/// Strips one wrapping markdown code fence, tolerating the language tag
/// (`json`), a bare fence, and plain whitespace-only padding — the shape a
/// model without native structured output wraps its JSON in.
fn strip_code_fence(text: &str) -> &str {
    let trimmed = text.trim();
    let Some(after_open) = trimmed.strip_prefix("```") else {
        return trimmed;
    };
    let body = match after_open.split_once('\n') {
        Some((_, body)) => body,
        None => after_open,
    };
    match body.rfind("```") {
        Some(end) => body[..end].trim(),
        None => body.trim(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fenced_reply_is_unwrapped() {
        assert_eq!(strip_code_fence("```json\n{\"a\": 1}\n```"), "{\"a\": 1}");
        assert_eq!(strip_code_fence("```\n{\"a\": 1}\n```"), "{\"a\": 1}");
        assert_eq!(strip_code_fence("  {\"a\": 1}  "), "{\"a\": 1}");
        assert_eq!(strip_code_fence("```json\n{\"a\": 1}"), "{\"a\": 1}");
    }

    #[test]
    fn a_repair_names_the_reason_and_asks_for_only_json() {
        let instruction = repair_instruction("the answer is not valid JSON");
        assert!(instruction.contains("the answer is not valid JSON"));
        assert!(instruction.contains("only a JSON value"));
    }
}
