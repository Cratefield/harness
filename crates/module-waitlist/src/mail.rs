//! Mail rendering and sending for `waitlist`. Built-in fallback
//! templates with the same ids and data types issue #12's askama
//! templates use.

use factory0_core::{
    MailError, Message, ModuleConfig, ModuleContext, Rendered, SendOutcome, Template,
    TemplateError, TemplateRegistry,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

pub(crate) const TEMPLATE_CONFIRM: &str = "waitlist/confirm";
pub(crate) const TEMPLATE_CONFIRMED: &str = "waitlist/confirmed";

/// Typed data for `waitlist/confirm`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmMailData {
    pub venture: String,
    pub product: String,
    pub email: String,
    pub confirm_url: String,
}

/// Typed data for `waitlist/confirmed` (the "you're in" mail).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmedMailData {
    pub venture: String,
    pub product: String,
    pub email: String,
    pub position: i64,
    pub status_url: String,
}

fn mail_error(id: &str) -> impl Fn() -> TemplateError + '_ {
    move || TemplateError::RenderFailed {
        id: id.to_string(),
        reason: "data does not fit the template".to_string(),
    }
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

struct BuiltInConfirm;

impl Template for BuiltInConfirm {
    fn render(&self, data: &Value, _locale: &str) -> Result<Rendered, TemplateError> {
        let data: ConfirmMailData =
            serde_json::from_value(data.clone()).map_err(|_| mail_error(TEMPLATE_CONFIRM)())?;
        Ok(Rendered {
            subject: format!("Confirm your spot on the {} waitlist", data.product),
            html: format!(
                "<p>{venture} is admitting {product} members in order.</p>\n\
                 <p>Confirm your address to hold your spot:</p>\n\
                 <p><a href=\"{confirm}\">{confirm}</a></p>\n",
                venture = escape_html(&data.venture),
                product = escape_html(&data.product),
                confirm = escape_html(&data.confirm_url),
            ),
            text: format!(
                "{venture} is admitting {product} members in order.\n\n\
                 Confirm your address to hold your spot:\n{confirm}\n",
                venture = data.venture,
                product = data.product,
                confirm = data.confirm_url,
            ),
        })
    }
}

struct BuiltInConfirmed;

impl Template for BuiltInConfirmed {
    fn render(&self, data: &Value, _locale: &str) -> Result<Rendered, TemplateError> {
        let data: ConfirmedMailData =
            serde_json::from_value(data.clone()).map_err(|_| mail_error(TEMPLATE_CONFIRMED)())?;
        Ok(Rendered {
            subject: format!(
                "You are #{position} on the {product} waitlist",
                position = data.position,
                product = data.product
            ),
            html: format!(
                "<p>You are #{position} on the {venture} {product} waitlist.</p>\n\
                 <p>Check your place any time: <a href=\"{status}\">{status}</a></p>\n",
                position = data.position,
                venture = escape_html(&data.venture),
                product = escape_html(&data.product),
                status = escape_html(&data.status_url),
            ),
            text: format!(
                "You are #{position} on the {venture} {product} waitlist.\n\n\
                 Check your place any time:\n{status}\n",
                position = data.position,
                venture = data.venture,
                product = data.product,
                status = data.status_url,
            ),
        })
    }
}

/// The module's default templates, for `Harness::builder().templates(..)`.
pub fn default_templates() -> Vec<(String, Box<dyn Template>)> {
    vec![
        (TEMPLATE_CONFIRM.to_string(), Box::new(BuiltInConfirm)),
        (TEMPLATE_CONFIRMED.to_string(), Box::new(BuiltInConfirmed)),
    ]
}

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
            TEMPLATE_CONFIRMED => BuiltInConfirmed.render(data, locale),
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
    let cfg = ModuleConfig::new("waitlist", &*ctx.config);
    let from = cfg.get_str("FROM", &format!("no-reply@send.{}", ctx.venture.domain));
    let message = Message {
        to: mail.to.clone(),
        from,
        reply_to: cfg.get_opt("REPLY_TO"),
        subject: rendered.subject,
        html: rendered.html,
        text: rendered.text,
        idempotency_key: Some(mail.idempotency_key.clone()),
        tags: vec!["waitlist".to_string()],
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
            "waitlist mail dispatch",
        ),
        Err(err) => tracing::error!(
            template = mail.template_id,
            error = %err,
            idempotency_key = %mail.idempotency_key,
            "waitlist mail failed",
        ),
    }
    outcome
}

/// Deferred send (the confirmed mail): errors are logged, never surfaced.
pub(crate) fn spawn_deferred(
    ctx: Arc<ModuleContext>,
    mail: OutgoingMail,
) -> factory0_core::BoxFuture<'static, ()> {
    Box::pin(async move {
        if let Err(err) = send(&ctx, &mail).await {
            tracing::error!(error = %err, template = mail.template_id, "deferred waitlist mail failed");
        }
    })
}
