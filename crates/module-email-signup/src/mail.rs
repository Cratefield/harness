//! Mail rendering and sending for `email-signup`. The default templates
//! are askama templates compiled into the crate (issue #12), exported via
//! [`default_templates`] and used directly as the fallback when the
//! venture registered no override.
//!
//! Locale: `en` is shipped; ventures register overrides under
//! `email-signup/confirm@<locale>` (e.g. `@nl`, `@is`) and the registry
//! resolves them per request locale.

use askama::Template as _;
use cratefield_core::{
    Brand, MailError, Message, ModuleConfig, ModuleContext, Rendered, SendOutcome, Template,
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
    #[serde(default)]
    pub brand: Brand,
}

/// Typed data for `email-signup/welcome`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelcomeMailData {
    pub venture: String,
    pub email: String,
    pub unsubscribe_url: String,
    #[serde(default)]
    pub brand: Brand,
}

fn parse_failed(id: &str) -> TemplateError {
    TemplateError::RenderFailed {
        id: id.to_owned(),
        reason: "data does not fit the template".to_owned(),
    }
}

fn askama_failed(id: &str, err: &askama::Error) -> TemplateError {
    TemplateError::RenderFailed {
        id: id.to_owned(),
        reason: err.to_string(),
    }
}

#[derive(askama::Template)]
#[template(path = "email_confirm.html")]
struct ConfirmHtml<'a> {
    data: &'a ConfirmMailData,
}

#[derive(askama::Template)]
#[template(path = "email_confirm.txt")]
struct ConfirmText<'a> {
    data: &'a ConfirmMailData,
}

#[derive(askama::Template)]
#[template(path = "email_welcome.html")]
struct WelcomeHtml<'a> {
    data: &'a WelcomeMailData,
}

#[derive(askama::Template)]
#[template(path = "email_welcome.txt")]
struct WelcomeText<'a> {
    data: &'a WelcomeMailData,
}

struct ConfirmTemplate;

impl Template for ConfirmTemplate {
    fn render(&self, data: &Value, _locale: &str) -> Result<Rendered, TemplateError> {
        let data: ConfirmMailData =
            serde_json::from_value(data.clone()).map_err(|_| parse_failed(TEMPLATE_CONFIRM))?;
        Ok(Rendered {
            subject: format!("Confirm your email for {}", data.venture),
            html: ConfirmHtml { data: &data }
                .render()
                .map_err(|err| askama_failed(TEMPLATE_CONFIRM, &err))?,
            text: ConfirmText { data: &data }
                .render()
                .map_err(|err| askama_failed(TEMPLATE_CONFIRM, &err))?,
        })
    }
}

struct WelcomeTemplate;

impl Template for WelcomeTemplate {
    fn render(&self, data: &Value, _locale: &str) -> Result<Rendered, TemplateError> {
        let data: WelcomeMailData =
            serde_json::from_value(data.clone()).map_err(|_| parse_failed(TEMPLATE_WELCOME))?;
        Ok(Rendered {
            subject: format!("Welcome to {}", data.venture),
            html: WelcomeHtml { data: &data }
                .render()
                .map_err(|err| askama_failed(TEMPLATE_WELCOME, &err))?,
            text: WelcomeText { data: &data }
                .render()
                .map_err(|err| askama_failed(TEMPLATE_WELCOME, &err))?,
        })
    }
}

/// The module's default askama templates, for
/// `Harness::builder().templates(..)`. Ventures register them first and
/// their overrides second.
pub fn default_templates() -> Vec<(String, Box<dyn Template>)> {
    vec![
        (TEMPLATE_CONFIRM.to_owned(), Box::new(ConfirmTemplate)),
        (TEMPLATE_WELCOME.to_owned(), Box::new(WelcomeTemplate)),
    ]
}

/// Renders through the venture's registry, falling back to the compiled
/// defaults when the registry misses (the conformance kit registers
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
            TEMPLATE_CONFIRM => ConfirmTemplate.render(data, locale),
            TEMPLATE_WELCOME => WelcomeTemplate.render(data, locale),
            other => Err(TemplateError::UnknownTemplate {
                id: other.to_owned(),
                locale: locale.to_owned(),
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
        tags: vec!["email-signup".to_owned()],
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
            idempotency = %mail.idempotency_key,
            "signup mail dispatch",
        ),
        Err(err) => tracing::error!(
            template = mail.template_id,
            error = %err,
            idempotency = %mail.idempotency_key,
            "signup mail failed",
        ),
    }
    outcome
}

/// Deferred send (the welcome mail): errors are logged, never surfaced.
pub(crate) fn spawn_deferred(
    ctx: Arc<ModuleContext>,
    mail: OutgoingMail,
) -> cratefield_core::BoxFuture<'static, ()> {
    Box::pin(async move {
        if let Err(err) = send(&ctx, &mail).await {
            tracing::error!(
                error = %err,
                template = mail.template_id,
                "deferred signup mail failed"
            );
        }
    })
}
