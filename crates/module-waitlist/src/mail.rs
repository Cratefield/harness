//! Mail rendering and sending for `waitlist`. The default templates render
//! through `cratefield-mail-templates` in the venture's [`MailTheme`]
//! (issue #12), exported via [`default_templates`] (the theme the module
//! resolves from the venture and its `MAIL_THEME` config) and
//! [`themed_templates`] (a theme the venture composed), and used directly
//! as the fallback when the venture registered neither. Locale: `en`
//! shipped; ventures register `waitlist/confirm@<locale>` overrides.

use cratefield_core::{
    Brand, MailError, Message, ModuleConfig, ModuleContext, Rendered, SendOutcome, Template,
    TemplateError, TemplateRegistry,
};
use cratefield_mail_templates::{self as mt, MailTheme};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

pub(crate) const TEMPLATE_CONFIRM: &str = "waitlist/confirm";
pub(crate) const TEMPLATE_CONFIRMED: &str = "waitlist/confirmed";

/// Typed data for `waitlist/confirm`. The module also puts the resolved
/// theme under `theme` (see [`mt::attach_theme`]), so a venture's own
/// override template can render in the same style.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmMailData {
    pub venture: String,
    pub product: String,
    pub email: String,
    pub confirm_url: String,
    #[serde(default)]
    pub brand: Brand,
}

/// Typed data for `waitlist/confirmed` (the "you're in" mail).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmedMailData {
    pub venture: String,
    pub product: String,
    pub email: String,
    pub position: i64,
    pub status_url: String,
    #[serde(default)]
    pub brand: Brand,
}

fn parse_failed(id: &str) -> TemplateError {
    TemplateError::RenderFailed {
        id: id.to_owned(),
        reason: "data does not fit the template".to_owned(),
    }
}

/// How the mails name the list: `(list, members, on)` — the list in the
/// subject, who is admitted, and the list in a sentence. A single-product
/// venture whose product slug is its own name reads "the `FindsYou`
/// waitlist", not "the `FindsYou` `findsyou` waitlist".
fn wording(venture: &str, product: &str) -> (String, String, String) {
    let squash = |s: &str| {
        s.chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|c| c.to_ascii_lowercase())
            .collect::<String>()
    };
    if squash(venture) == squash(product) {
        (venture.to_owned(), "members".to_owned(), venture.to_owned())
    } else {
        (
            product.to_owned(),
            format!("{product} members"),
            format!("{venture} {product}"),
        )
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
        let (list, members, on) = wording(venture, &data.product);
        Ok(mt::Message::new(
            format!("Confirm your spot on the {list} waitlist"),
            "Hold your spot",
        )
        .preheader(format!(
            "Confirm your address to hold your place on the {list} waitlist."
        ))
        .paragraph(format!(
            "{venture} is admitting {members} in join order. Confirm your address to hold \
             your place on the waitlist."
        ))
        .button("Confirm my spot", &data.confirm_url)
        .fallback_link()
        .link_intro("If the button does not work, open this link:")
        .note(
            "If you did not join this waitlist, ignore this email: nothing happens until the \
             link is opened.",
        )
        .recipient(&data.email)
        .why(format!("this address was entered on the {on} waitlist"))
        .render(&theme)
        .into())
    }
}

struct ConfirmedTemplate {
    theme: Option<MailTheme>,
}

impl Template for ConfirmedTemplate {
    fn render(&self, data: &Value, _locale: &str) -> Result<Rendered, TemplateError> {
        let theme = mt::theme_for_template(self.theme.as_ref(), data);
        let data: ConfirmedMailData =
            serde_json::from_value(data.clone()).map_err(|_| parse_failed(TEMPLATE_CONFIRMED))?;
        let venture = theme.name_or(&data.venture);
        let (list, _, on) = wording(venture, &data.product);
        let position = data.position;
        Ok(mt::Message::new(
            format!("You are #{position} on the {list} waitlist"),
            format!("You are #{position}"),
        )
        .preheader(format!(
            "Your spot is confirmed. You are number {position} in line."
        ))
        .paragraph(format!(
            "Your spot on the {on} waitlist is confirmed. You are number {position} in line."
        ))
        .button("Check my place", &data.status_url)
        .fallback_link()
        .link_intro("Check your place any time:")
        .recipient(&data.email)
        .why(format!("you confirmed your spot on the {on} waitlist"))
        .render(&theme)
        .into())
    }
}

/// The module's default templates, for `Harness::builder().templates(..)`.
/// They render in the theme the module resolves for each mail: the
/// venture's core `Brand`, with the deployment's `MAIL_THEME` config on
/// top. Use [`themed_templates`] to compose the venture's own theme.
pub fn default_templates() -> Vec<(String, Box<dyn Template>)> {
    templates(None)
}

/// The module's templates in `theme`, the venture's own style, for
/// `Harness::builder().templates(..)`. The deployment's `MAIL_THEME`
/// config still applies on top.
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
            TEMPLATE_CONFIRMED.to_owned(),
            Box::new(ConfirmedTemplate {
                theme: theme.cloned(),
            }),
        ),
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
            TEMPLATE_CONFIRM => ConfirmTemplate { theme: None }.render(data, locale),
            TEMPLATE_CONFIRMED => ConfirmedTemplate { theme: None }.render(data, locale),
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
    let cfg = ModuleConfig::new("waitlist", &*ctx.config);
    let from = cfg.get_str("FROM", &format!("no-reply@send.{}", ctx.venture.domain));
    let mut message = Message::new(
        mail.to.clone(),
        from,
        rendered.subject,
        rendered.text,
        rendered.html,
    )
    .idempotency_key(mail.idempotency_key.clone())
    .tags(["waitlist"]);
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
            "waitlist mail dispatch",
        ),
        Err(err) => tracing::error!(
            template = mail.template_id,
            error = %err,
            idempotency = %mail.idempotency_key,
            "waitlist mail failed",
        ),
    }
    outcome
}

/// Deferred send (the confirmed mail): errors are logged, never surfaced.
pub(crate) fn spawn_deferred(
    ctx: Arc<ModuleContext>,
    mail: OutgoingMail,
) -> cratefield_core::BoxFuture<'static, ()> {
    Box::pin(async move {
        if let Err(err) = send(&ctx, &mail).await {
            tracing::error!(
                error = %err,
                template = mail.template_id,
                "deferred waitlist mail failed"
            );
        }
    })
}
