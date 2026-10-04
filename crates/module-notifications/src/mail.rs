//! The notification email's body: rendered through the template registry
//! as `notifications/email`, in the venture's [`MailTheme`] via
//! `cratefield-mail-templates`, so a venture can restyle or reword it like
//! every other module's mail.
//!
//! The module decides everything that is not presentation — the subject
//! (the catalog's, the category's, or the title), the recipient's language
//! and direction, both unsubscribe links — and hands them to the template
//! as [`EmailMail`].

use cratefield_core::{Rendered, Template, TemplateError, TemplateRegistry};
use cratefield_mail_templates::{self as mt, Dir, MailTheme};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The registry id a venture overrides.
pub const TEMPLATE_EMAIL: &str = "notifications/email";

/// What the email template is given. Serialized through the registry, so
/// it is a wire format: adding a field is fine, renaming one breaks
/// overrides. The module also puts the resolved theme under `theme`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailMail {
    /// The venture's name.
    pub venture: String,
    /// The subject, already in the recipient's language.
    pub subject: String,
    /// The notification's title, its heading.
    pub title: String,
    /// The notification's body.
    pub body: String,
    /// Where the notification points, if anywhere.
    pub url: Option<String>,
    /// The BCP 47 tag the mail is in.
    pub lang: String,
    /// `ltr` or `rtl`.
    pub dir: String,
    /// Stops this category (the one-click link, or the settings page).
    pub unsubscribe: String,
    /// Stops every notification email.
    pub unsubscribe_all: String,
}

struct EmailTemplate {
    theme: Option<MailTheme>,
}

impl Template for EmailTemplate {
    fn render(&self, data: &Value, _locale: &str) -> Result<Rendered, TemplateError> {
        let theme = mt::theme_for_template(self.theme.as_ref(), data);
        let data: EmailMail =
            serde_json::from_value(data.clone()).map_err(|_| TemplateError::RenderFailed {
                id: TEMPLATE_EMAIL.to_owned(),
                reason: "the mail data is not the shape this template takes".to_owned(),
            })?;
        let mut message = mt::Message::new(&data.subject, &data.title)
            .preheader(&data.body)
            .lang(&data.lang)
            .dir(if data.dir == "rtl" {
                Dir::Rtl
            } else {
                Dir::Ltr
            })
            .paragraph(&data.body);
        if let Some(url) = &data.url {
            message = message.button("Open", url);
        }
        Ok(message
            .footer_link("Stop receiving these", &data.unsubscribe)
            .footer_link("stop all notification email", &data.unsubscribe_all)
            .render(&theme)
            .into())
    }
}

/// The module's default template, for `Harness::builder().templates(..)`.
/// It renders in the theme the module resolves for each mail (the
/// venture's core `Brand`, with the deployment's `MAIL_THEME` config on
/// top); use [`themed_templates`] to compose the venture's own theme.
#[must_use]
pub fn default_templates() -> Vec<(String, Box<dyn Template>)> {
    templates(None)
}

/// The module's template in `theme`, the venture's own style. The
/// deployment's `MAIL_THEME` config still applies on top.
#[must_use]
pub fn themed_templates(theme: &MailTheme) -> Vec<(String, Box<dyn Template>)> {
    templates(Some(theme))
}

fn templates(theme: Option<&MailTheme>) -> Vec<(String, Box<dyn Template>)> {
    vec![(
        TEMPLATE_EMAIL.to_owned(),
        Box::new(EmailTemplate {
            theme: theme.cloned(),
        }) as Box<dyn Template>,
    )]
}

/// Renders through the venture's registry, falling back to the compiled
/// default when the registry misses (the conformance kit registers
/// nothing).
pub(crate) fn render(
    registry: &TemplateRegistry,
    data: &Value,
    locale: &str,
) -> Result<Rendered, TemplateError> {
    match registry.render(TEMPLATE_EMAIL, data, locale) {
        Err(TemplateError::UnknownTemplate { .. }) => {
            EmailTemplate { theme: None }.render(data, locale)
        }
        other => other,
    }
}
