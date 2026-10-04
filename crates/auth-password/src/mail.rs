//! The three mails password accounts send (issues #19, #20).
//!
//! Rendered through the harness template registry so a venture can
//! override the wording, with the compiled default as the fallback — the
//! same shape `auth-magic-link` and `module-email-signup` use, and the
//! reason the conformance kit (which registers nothing) still works.
//!
//! Three ids rather than one: a verification mail, a "somebody tried to
//! register you" notice, and a password reset are three different
//! messages, and a venture that wants to reword one should not have to
//! reword the others.

use cratefield_core::{Config, Rendered, Template, TemplateError, TemplateRegistry, Venture};
use cratefield_mail_templates::{self as mt, MailTheme};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The registry ids a venture overrides, and the ids `emits`-style
/// conformance looks for.
pub const TEMPLATE_VERIFY: &str = "auth-password/verify";
pub const TEMPLATE_DUPLICATE: &str = "auth-password/duplicate";
pub const TEMPLATE_RESET: &str = "auth-password/reset";

/// What the verification template is given. Serialized through the
/// registry, so it is a wire format: adding a field is fine, renaming one
/// breaks overrides. Every mail's data also carries the resolved theme
/// under `theme` (see [`mt::attach_theme`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyMail {
    pub venture: String,
    /// The full confirm URL, token included.
    pub link: String,
    /// How long the link lasts, for the sentence that says so.
    pub hours: i64,
}

/// What the duplicate-registration template is given.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateMail {
    pub venture: String,
    /// A link to the reset-request page, or empty when the deployment
    /// has no hosted page to point at.
    pub reset_link: String,
}

/// What the password-reset template is given.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetMail {
    pub venture: String,
    /// The full reset URL, token included.
    pub link: String,
    /// How long the link lasts, for the sentence that says so.
    pub minutes: i64,
}

#[derive(Debug, Clone, Copy)]
enum Kind {
    Verify,
    Duplicate,
    Reset,
}

/// One of the three default mails, in a composed theme or (`None`) the one
/// the module attached to the data.
pub(crate) struct PasswordTemplate {
    kind: Kind,
    theme: Option<MailTheme>,
}

pub(crate) const VERIFY_DEFAULT: PasswordTemplate = PasswordTemplate {
    kind: Kind::Verify,
    theme: None,
};
pub(crate) const DUPLICATE_DEFAULT: PasswordTemplate = PasswordTemplate {
    kind: Kind::Duplicate,
    theme: None,
};
pub(crate) const RESET_DEFAULT: PasswordTemplate = PasswordTemplate {
    kind: Kind::Reset,
    theme: None,
};

impl PasswordTemplate {
    fn id(&self) -> &'static str {
        match self.kind {
            Kind::Verify => TEMPLATE_VERIFY,
            Kind::Duplicate => TEMPLATE_DUPLICATE,
            Kind::Reset => TEMPLATE_RESET,
        }
    }
}

fn parse<T: serde::de::DeserializeOwned>(id: &str, data: &Value) -> Result<T, TemplateError> {
    serde_json::from_value(data.clone()).map_err(|_| parse_failed(id))
}

impl Template for PasswordTemplate {
    fn render(&self, data: &Value, _locale: &str) -> Result<Rendered, TemplateError> {
        let theme = mt::theme_for_template(self.theme.as_ref(), data);
        let id = self.id();
        let message = match self.kind {
            Kind::Verify => {
                let data: VerifyMail = parse(id, data)?;
                let venture = theme.name_or(&data.venture);
                let hours = data.hours;
                mt::Message::new(
                    format!("Confirm your address for {venture}"),
                    format!("Confirm your address for {venture}"),
                )
                .preheader(format!(
                    "This link works once and expires in {hours} hours. If you did not create \
                     an account, ignore this message."
                ))
                .paragraph(format!(
                    "Open this link to confirm this address. It works once and expires in \
                     {hours} hours."
                ))
                .button("Confirm this address", &data.link)
                .fallback_link()
                .link_intro("If the button does not work, copy this address into your browser:")
                .note(
                    "If you did not create an account, you can ignore this message. Nobody can \
                     use the link without opening it, and it will expire on its own.",
                )
                .why(format!(
                    "someone created a {venture} account with this address"
                ))
            }
            Kind::Duplicate => {
                let data: DuplicateMail = parse(id, data)?;
                let venture = theme.name_or(&data.venture);
                let lead = if data.reset_link.is_empty() {
                    "Somebody just tried to create an account with this email address, and it \
                     already has one. If that was you, sign in instead."
                        .to_owned()
                } else {
                    "Somebody just tried to create an account with this email address, and it \
                     already has one. If that was you, sign in instead \u{2014} or reset your \
                     password if you have forgotten it."
                        .to_owned()
                };
                let mut message = mt::Message::new(
                    format!("Somebody tried to create an account with {venture}"),
                    format!("You already have an account with {venture}"),
                )
                .preheader("Somebody tried to create an account with this address.")
                .paragraph(lead);
                if !data.reset_link.is_empty() {
                    message = message
                        .button("Reset your password", &data.reset_link)
                        .fallback_link()
                        .link_intro(
                            "If the button does not work, copy this address into your browser:",
                        );
                }
                message
                    .note(
                        "If it was not you, you can ignore this message. Nothing has changed on \
                         your account.",
                    )
                    .why(format!(
                        "someone tried to create a {venture} account with this address"
                    ))
            }
            Kind::Reset => {
                let data: ResetMail = parse(id, data)?;
                let venture = theme.name_or(&data.venture);
                let minutes = data.minutes;
                mt::Message::new(
                    format!("Reset your password for {venture}"),
                    format!("Reset your password for {venture}"),
                )
                .preheader(format!(
                    "This link works once and expires in {minutes} minutes. If you did not ask \
                     for it, ignore this message."
                ))
                .paragraph(format!(
                    "Open this link to choose a new password. It works once and expires in \
                     {minutes} minutes."
                ))
                .button("Choose a new password", &data.link)
                .fallback_link()
                .link_intro("If the button does not work, copy this address into your browser:")
                .note(
                    "If you did not ask to reset your password, you can ignore this message. \
                     Your password has not changed, and the link will expire on its own.",
                )
                .why(format!(
                    "someone asked to reset the {venture} password for this address"
                ))
            }
        };
        Ok(message.render(&theme).into())
    }
}

fn parse_failed(id: &str) -> TemplateError {
    TemplateError::RenderFailed {
        id: id.to_owned(),
        reason: "the mail data is not the shape this template takes".to_owned(),
    }
}

/// The module's default templates, for
/// `Harness::builder().templates(..)` — register these alongside
/// `auth-magic-link`'s so both modules' mail resolves. They render in the
/// theme the module resolves for each mail (the venture's core `Brand`,
/// with the deployment's `MAIL_THEME` config on top); use
/// [`themed_templates`] to compose the venture's own theme.
#[must_use]
pub fn default_templates() -> Vec<(String, Box<dyn Template>)> {
    templates(None)
}

/// The module's templates in `theme`, the venture's own style. The
/// deployment's `MAIL_THEME` config still applies on top.
#[must_use]
pub fn themed_templates(theme: &MailTheme) -> Vec<(String, Box<dyn Template>)> {
    templates(Some(theme))
}

fn templates(theme: Option<&MailTheme>) -> Vec<(String, Box<dyn Template>)> {
    [Kind::Verify, Kind::Duplicate, Kind::Reset]
        .into_iter()
        .map(|kind| {
            let template = PasswordTemplate {
                kind,
                theme: theme.cloned(),
            };
            (
                template.id().to_owned(),
                Box::new(template) as Box<dyn Template>,
            )
        })
        .collect()
}

/// Renders through the venture's registry, falling back to the compiled
/// default when the registry misses. The theme the venture and its config
/// resolve to rides along in the data.
///
/// # Errors
///
/// Whatever the template returns.
pub(crate) fn render<T: Serialize>(
    registry: &TemplateRegistry,
    id: &str,
    default: &dyn Template,
    data: &T,
    locale: &str,
    venture: &Venture,
    config: &dyn Config,
) -> Result<Rendered, TemplateError> {
    let mut value = serde_json::to_value(data).map_err(|err| TemplateError::RenderFailed {
        id: id.to_owned(),
        reason: err.to_string(),
    })?;
    mt::attach_theme(&mut value, venture, config);
    match registry.render(id, &value, locale) {
        Err(TemplateError::UnknownTemplate { .. }) => default.render(&value, locale),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::EmptyConfig;

    fn venture() -> Venture {
        Venture::new("Factory Zero", "factory0.ventures")
    }

    #[test]
    fn the_text_part_carries_the_raw_link() {
        // A mail client that shows only the text part must still be
        // usable, and a person copying the link out of it must get the
        // whole thing.
        let data = VerifyMail {
            venture: "Factory Zero".to_owned(),
            link: "https://auth.factory0.ventures/v1/auth-password/verify?token=abc".to_owned(),
            hours: 24,
        };
        let rendered = render(
            &TemplateRegistry::new(),
            TEMPLATE_VERIFY,
            &VERIFY_DEFAULT,
            &data,
            "en",
            &venture(),
            &EmptyConfig,
        )
        .expect("renders");
        assert!(rendered.text.contains(&data.link), "{}", rendered.text);
        assert!(rendered.subject.contains("Factory Zero"));
        assert!(rendered.text.contains("24 hours"));
        assert!(!rendered.text.contains('<'), "{}", rendered.text);
        // Once as the button, once as the copyable link.
        assert_eq!(
            rendered
                .html
                .matches(&format!("href=\"{}\"", data.link))
                .count(),
            2
        );
    }

    #[test]
    fn the_duplicate_mail_omits_the_reset_button_when_there_is_no_page() {
        let data = DuplicateMail {
            venture: "Factory Zero".to_owned(),
            reset_link: String::new(),
        };
        let rendered = render(
            &TemplateRegistry::new(),
            TEMPLATE_DUPLICATE,
            &DUPLICATE_DEFAULT,
            &data,
            "en",
            &venture(),
            &EmptyConfig,
        )
        .expect("renders");
        // No button and no link but the venture's own site in the footer.
        assert!(
            !rendered.text.contains("Reset your password"),
            "{}",
            rendered.text
        );
        assert!(
            !rendered.html.contains("class=\"cf-btn\""),
            "{}",
            rendered.html
        );
        assert!(!rendered.text.contains("/v1/"), "{}", rendered.text);
        assert!(rendered.text.contains("already has one"));
    }

    #[test]
    fn a_venture_override_wins_and_a_missing_one_falls_back() {
        struct Override;
        impl Template for Override {
            fn render(&self, _data: &Value, _locale: &str) -> Result<Rendered, TemplateError> {
                Ok(Rendered {
                    subject: "the venture's own subject".to_owned(),
                    html: "<p>theirs</p>".to_owned(),
                    text: "theirs".to_owned(),
                })
            }
        }

        let mut registry = TemplateRegistry::new();
        registry.register(TEMPLATE_RESET, Box::new(Override));
        let data = ResetMail {
            venture: "Factory Zero".to_owned(),
            link: "https://auth.example/v1/auth-password/reset?token=abc".to_owned(),
            minutes: 30,
        };
        let overridden = render(
            &registry,
            TEMPLATE_RESET,
            &RESET_DEFAULT,
            &data,
            "en",
            &venture(),
            &EmptyConfig,
        )
        .expect("renders");
        assert_eq!(overridden.subject, "the venture's own subject");

        // The other two ids are untouched and still fall back.
        let verify = render(
            &registry,
            TEMPLATE_VERIFY,
            &VERIFY_DEFAULT,
            &VerifyMail {
                venture: "Factory Zero".to_owned(),
                link: "https://auth.example/v1/auth-password/verify?token=abc".to_owned(),
                hours: 24,
            },
            "en",
            &venture(),
            &EmptyConfig,
        )
        .expect("falls back");
        assert!(verify.subject.contains("Factory Zero"));
    }

    #[test]
    fn nothing_from_the_link_can_break_out_of_the_html() {
        // The link is built by this service, not by a caller, but the
        // layout escapes it anyway and this asserts that it does.
        let hostile = ResetMail {
            venture: "Factory Zero".to_owned(),
            link: "https://auth.example/x?t=a\"><script>alert(1)</script>".to_owned(),
            minutes: 30,
        };
        let rendered = render(
            &TemplateRegistry::new(),
            TEMPLATE_RESET,
            &RESET_DEFAULT,
            &hostile,
            "en",
            &venture(),
            &EmptyConfig,
        )
        .expect("renders");
        assert!(
            !rendered.html.contains("<script>alert(1)"),
            "{}",
            rendered.html
        );
    }
}
