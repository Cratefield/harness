//! Mail rendering and sending for `email-signup`. The default templates
//! render through `cratefield-mail-templates` in the venture's
//! [`MailTheme`] (issue #12), exported via [`default_templates`] (the theme
//! the module resolves from the venture and its `MAIL_THEME` config) and
//! [`themed_templates`] (a theme the venture composed), and used directly
//! as the fallback when the venture registered neither.
//!
//! Locale: `en` is shipped; ventures register overrides under
//! `email-signup/confirm@<locale>` (e.g. `@nl`, `@is`) and the registry
//! resolves them per request locale.

use cratefield_core::{
    Brand, MailError, Message, ModuleConfig, ModuleContext, Rendered, SendOutcome, Template,
    TemplateError, TemplateRegistry,
};
use cratefield_mail_templates::{self as mt, MailTheme};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

pub(crate) const TEMPLATE_CONFIRM: &str = "email-signup/confirm";
pub(crate) const TEMPLATE_WELCOME: &str = "email-signup/welcome";

/// Typed data for `email-signup/confirm`; templates in ventures
/// deserialize the same shape. The module also puts the resolved theme
/// under `theme` (see [`mt::attach_theme`]).
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

struct ConfirmTemplate {
    theme: Option<MailTheme>,
}

impl Template for ConfirmTemplate {
    fn render(&self, data: &Value, _locale: &str) -> Result<Rendered, TemplateError> {
        let theme = mt::theme_for_template(self.theme.as_ref(), data);
        let data: ConfirmMailData =
            serde_json::from_value(data.clone()).map_err(|_| parse_failed(TEMPLATE_CONFIRM))?;
        let venture = theme.name_or(&data.venture);
        Ok(mt::Message::new(
            format!("Confirm your email for {venture}"),
            "Confirm your email",
        )
        .preheader(format!(
            "Confirm your address to finish signing up for {venture}."
        ))
        .paragraph(format!(
            "Welcome to {venture}. Confirm your address to finish signing up."
        ))
        .button("Confirm email", &data.confirm_url)
        .fallback_link()
        .link_intro("If the button does not work, open this link:")
        .note(
            "If you did not sign up, ignore this email: nothing happens until the link \
                     is opened.",
        )
        .recipient(&data.email)
        .why(format!("this address was used to sign up for {venture}"))
        .footer_link("Unsubscribe", &data.unsubscribe_url)
        .render(&theme)
        .into())
    }
}

struct WelcomeTemplate {
    theme: Option<MailTheme>,
}

impl Template for WelcomeTemplate {
    fn render(&self, data: &Value, _locale: &str) -> Result<Rendered, TemplateError> {
        let theme = mt::theme_for_template(self.theme.as_ref(), data);
        let data: WelcomeMailData =
            serde_json::from_value(data.clone()).map_err(|_| parse_failed(TEMPLATE_WELCOME))?;
        let venture = theme.name_or(&data.venture);
        Ok(
            mt::Message::new(format!("Welcome to {venture}"), "You are on the list")
                .preheader(format!("Your email address is confirmed for {venture}."))
                .paragraph(format!(
                    "Welcome to {venture} \u{2014} your email address is confirmed."
                ))
                .recipient(&data.email)
                .why(format!("you signed up for {venture}"))
                .footer_link("Unsubscribe", &data.unsubscribe_url)
                .render(&theme)
                .into(),
        )
    }
}

/// The module's default templates, for `Harness::builder().templates(..)`.
/// Ventures register them first and their overrides second. They render
/// in the theme the module resolves for each mail (the venture's core
/// `Brand`, with the deployment's `MAIL_THEME` config on top); use
/// [`themed_templates`] to compose the venture's own theme.
pub fn default_templates() -> Vec<(String, Box<dyn Template>)> {
    templates(None)
}

/// The module's templates in `theme`, the venture's own style. The
/// deployment's `MAIL_THEME` config still applies on top.
pub fn themed_templates(theme: &MailTheme) -> Vec<(String, Box<dyn Template>)> {
    templates(Some(theme))
}

fn templates(theme: Option<&MailTheme>) -> Vec<(String, Box<dyn Template>)> {
    vec![
        (
            TEMPLATE_CONFIRM.to_owned(),
            Box::new(ConfirmTemplate {
                theme: theme.cloned(),
            }),
        ),
        (
            TEMPLATE_WELCOME.to_owned(),
            Box::new(WelcomeTemplate {
                theme: theme.cloned(),
            }),
        ),
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
            TEMPLATE_CONFIRM => ConfirmTemplate { theme: None }.render(data, locale),
            TEMPLATE_WELCOME => WelcomeTemplate { theme: None }.render(data, locale),
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
    let mut data = mail.data.clone();
    mt::attach_theme(&mut data, &ctx.venture, &*ctx.config);
    let rendered =
        render(&ctx.templates, mail.template_id, &data, &mail.locale).map_err(|err| {
            MailError::Invalid {
                detail: err.to_string(),
            }
        })?;
    let cfg = ModuleConfig::new("email-signup", &*ctx.config);
    let from = cfg.get_str("FROM", &format!("no-reply@send.{}", ctx.venture.domain));
    let mut message = Message::new(
        mail.to.clone(),
        from,
        rendered.subject,
        rendered.text,
        rendered.html,
    )
    .idempotency_key(mail.idempotency_key.clone())
    .tags(["email-signup"]);
    if let Some(reply_to) = cfg.get_opt("REPLY_TO") {
        message = message.reply_to(reply_to);
    }
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
