//! Mail rendering and sending for `email-signup`. The built-in templates
//! here are the module's fallback when the venture registered no
//! override; issue #12 replaces them with askama templates with the same
//! ids and data types.

use factory0_core::{
    MailError, Message, ModuleConfig, ModuleContext, Rendered, SendOutcome, Template,
    TemplateError, TemplateRegistry,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

pub(crate) const TEMPLATE_CONFIRM: &str = "email-signup/confirm";
pub(crate) const TEMPLATE_WELCOME: &str = "email-signup/welcome";

/// Typed data for `email-signup/confirm`; askama templates in ventures
/// deserialize the same shape, so overrides are type-checked at compile
/// time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmMailData {
    pub venture: String,
    pub email: String,
    pub confirm_url: String,
    pub unsubscribe_url: String,
}

/// Typed data for `email-signup/welcome`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelcomeMailData {
    pub venture: String,
    pub email: String,
    pub unsubscribe_url: String,
}

pub(crate) fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

fn mail_error(template: &str, id: &str) -> TemplateError {
    TemplateError::RenderFailed {
        id: id.to_string(),
        reason: format!("data does not fit the {template} template"),
    }
}

struct BuiltInConfirm;

impl Template for BuiltInConfirm {
    fn render(&self, data: &Value, _locale: &str) -> Result<Rendered, TemplateError> {
        let data: ConfirmMailData = serde_json::from_value(data.clone())
            .map_err(|_| mail_error("confirm", TEMPLATE_CONFIRM))?;
        Ok(Rendered {
            subject: format!("Confirm your email for {}", data.venture),
            html: format!(
                "<p>Welcome to {venture}.</p>\n<p>Confirm your email address:</p>\n\
                 <p><a href=\"{confirm}\">{confirm}</a></p>\n\
                 <p>Or unsubscribe: <a href=\"{unsub}\">{unsub}</a></p>\n",
                venture = escape_html(&data.venture),
                confirm = escape_html(&data.confirm_url),
                unsub = escape_html(&data.unsubscribe_url),
            ),
            text: format!(
                "Welcome to {venture}!\n\nConfirm your email address:\n{confirm}\n\n\
                 Or unsubscribe:\n{unsub}\n",
                venture = data.venture,
                confirm = data.confirm_url,
                unsub = data.unsubscribe_url,
            ),
        })
    }
}

struct BuiltInWelcome;

impl Template for BuiltInWelcome {
    fn render(&self, data: &Value, _locale: &str) -> Result<Rendered, TemplateError> {
        let data: WelcomeMailData = serde_json::from_value(data.clone())
            .map_err(|_| mail_error("welcome", TEMPLATE_WELCOME))?;
        Ok(Rendered {
            subject: format!("Welcome to {}", data.venture),
            html: format!(
                "<p>You are on the {venture} list. Welcome!</p>\n\
                 <p>Unsubscribe any time: <a href=\"{unsub}\">{unsub}</a></p>\n",
                venture = escape_html(&data.venture),
                unsub = escape_html(&data.unsubscribe_url),
            ),
            text: format!(
                "You are on the {venture} list. Welcome!\n\nUnsubscribe any time:\n{unsub}\n",
                venture = data.venture,
                unsub = data.unsubscribe_url,
            ),
        })
    }
}

/// The module's default templates, for `Harness::builder().templates(..)`.
/// Ventures register them first and their overrides second.
pub fn default_templates() -> Vec<(String, Box<dyn Template>)> {
    vec![
        (TEMPLATE_CONFIRM.to_string(), Box::new(BuiltInConfirm)),
        (TEMPLATE_WELCOME.to_string(), Box::new(BuiltInWelcome)),
    ]
}

/// Renders through the venture's registry, falling back to the built-in
/// template when the registry misses (the conformance kit registers
/// nothing).
pub(crate) fn render(
    registry: &TemplateRegistry,
    id: &str,
    data: &Value,
    locale: &str,
) -> Result<Rendered, TemplateError> {
    match registry.render(id, data, locale) {
        Ok(rendered) => Ok(rendered),
        Err(TemplateError::UnknownTemplate { .. }) => match id {
            TEMPLATE_CONFIRM => BuiltInConfirm.render(data, locale),
            TEMPLATE_WELCOME => BuiltInWelcome.render(data, locale),
            other => Err(TemplateError::UnknownTemplate {
                id: other.to_string(),
                locale: locale.to_string(),
            }),
        },
        Err(other) => Err(other),
    }
}

pub(crate) struct OutgoingMail {
    pub to: String,
    pub template_id: &'static str,
    pub data: Value,
    pub locale: String,
    pub idempotency_key: String,
}

/// Renders and sends one mail. The recipient is never logged; the
/// idempotency key and outcome are (architecture section 11, #14).
pub(crate) async fn send(
    ctx: &ModuleContext,
    mail: &OutgoingMail,
) -> Result<SendOutcome, MailError> {
    let rendered =
        render(&ctx.templates, mail.template_id, &mail.data, &mail.locale).map_err(|err| {
            MailError::Invalid {
                detail: err.to_string(),
            }
        })?;
    let cfg = ModuleConfig::new("email-signup", &*ctx.config);
    let from = cfg.get_str("FROM", &format!("no-reply@send.{}", ctx.venture.domain));
    let message = Message {
        to: mail.to.clone(),
        from,
        reply_to: cfg.get_opt("REPLY_TO"),
        subject: rendered.subject,
        html: rendered.html,
        text: rendered.text,
        idempotency_key: Some(mail.idempotency_key.clone()),
        tags: vec!["email-signup".to_string()],
    };
    let Some(mailer) = ctx.ports.mailer.clone() else {
        return Ok(SendOutcome::NotConfigured);
    };
    let outcome = mailer.send(message).await;
    match &outcome {
        Ok(result) => tracing::info!(
            template = mail.template_id,
            outcome = match result {
                SendOutcome::Sent { .. } => "sent",
                SendOutcome::NotConfigured => "not_configured",
            },
            idempotency_key = %mail.idempotency_key,
            "signup mail dispatch",
        ),
        Err(err) => tracing::error!(
            template = mail.template_id,
            error = %err,
            idempotency_key = %mail.idempotency_key,
            "signup mail failed",
        ),
    }
    outcome
}

/// Convenience for deferred sends (welcome mail): render, send, log —
/// errors never fail the deferred task.
pub(crate) fn spawn_deferred(
    ctx: Arc<ModuleContext>,
    mail: OutgoingMail,
) -> factory0_core::BoxFuture<'static, ()> {
    Box::pin(async move {
        if let Err(err) = send(&ctx, &mail).await {
            tracing::error!(error = %err, template = mail.template_id, "deferred signup mail failed");
        }
    })
}
