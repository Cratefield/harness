//! The sign-in mail (issue #21).
//!
//! Rendered through the harness template registry so a venture can
//! override the wording, with the compiled default as the fallback — the
//! same shape `module-email-signup` uses, and the reason the conformance
//! kit (which registers nothing) still works.

use cratefield_core::{Config, Rendered, Template, TemplateError, TemplateRegistry, Venture};
use cratefield_mail_templates::{self as mt, MailTheme};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The registry id a venture overrides.
pub const TEMPLATE_MAGIC_LINK: &str = "auth-magic-link/sign-in";

/// What the template is given. Serialized through the registry, so it is
/// a wire format: adding a field is fine, renaming one breaks overrides.
/// The module also puts the resolved theme under `theme` (see
/// [`mt::attach_theme`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicLinkMail {
    /// The venture's display name.
    pub venture: String,
    /// The full consume URL, token included.
    pub link: String,
    /// How long the link lasts, for the sentence that says so.
    pub minutes: i64,
}

struct MagicLinkTemplate {
    theme: Option<MailTheme>,
}

impl Template for MagicLinkTemplate {
    fn render(&self, data: &Value, _locale: &str) -> Result<Rendered, TemplateError> {
        let theme = mt::theme_for_template(self.theme.as_ref(), data);
        let data: MagicLinkMail =
            serde_json::from_value(data.clone()).map_err(|_| TemplateError::RenderFailed {
                id: TEMPLATE_MAGIC_LINK.to_owned(),
                reason: "the mail data is not the shape this template takes".to_owned(),
            })?;
        let venture = theme.name_or(&data.venture);
        let minutes = data.minutes;
        Ok(mt::Message::new(
            format!("Sign in to {venture}"),
            format!("Sign in to {venture}"),
        )
        .preheader(format!(
            "This link works once and expires in {minutes} minutes. If you did not ask \
                 for it, ignore this message."
        ))
        .paragraph(format!(
            "Open this link to sign in. It works once and expires in {minutes} minutes."
        ))
        .button("Sign in", &data.link)
        .fallback_link()
        .link_intro("If the button does not work, copy this address into your browser:")
        .note(
            "If you did not ask to sign in, you can ignore this message. Nobody can use \
                 the link without opening it, and it will expire on its own.",
        )
        .why(format!(
            "someone asked to sign in to {venture} with this address"
        ))
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
        TEMPLATE_MAGIC_LINK.to_owned(),
        Box::new(MagicLinkTemplate {
            theme: theme.cloned(),
        }) as Box<dyn Template>,
    )]
}

/// Renders through the venture's registry, falling back to the compiled
/// default when the registry misses. The theme the venture and its config
/// resolve to rides along in the data.
///
/// # Errors
///
/// Whatever the template returns.
pub(crate) fn render(
    registry: &TemplateRegistry,
    data: &MagicLinkMail,
    locale: &str,
    venture: &Venture,
    config: &dyn Config,
) -> Result<Rendered, TemplateError> {
    let mut value = serde_json::to_value(data).map_err(|err| TemplateError::RenderFailed {
        id: TEMPLATE_MAGIC_LINK.to_owned(),
        reason: err.to_string(),
    })?;
    mt::attach_theme(&mut value, venture, config);
    match registry.render(TEMPLATE_MAGIC_LINK, &value, locale) {
        Err(TemplateError::UnknownTemplate { .. }) => {
            MagicLinkTemplate { theme: None }.render(&value, locale)
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::EmptyConfig;

    fn venture() -> Venture {
        Venture::new("factory0", "factory0.ventures")
    }

    fn data() -> MagicLinkMail {
        MagicLinkMail {
            venture: "Factory Zero".to_owned(),
            link: "https://auth.factory0.ventures/v1/auth-magic-link/consume?token=abc123"
                .to_owned(),
            minutes: 15,
        }
    }

    #[test]
    fn the_text_part_carries_the_raw_link() {
        // The acceptance criterion, and it matters: a mail client that
        // shows only the text part must still be usable, and a person
        // copying the link out of it must get the whole thing.
        let rendered = MagicLinkTemplate { theme: None }
            .render(&serde_json::to_value(data()).expect("json"), "en")
            .expect("renders");
        assert!(rendered.text.contains(&data().link), "{}", rendered.text);
        assert!(rendered.subject.contains("Factory Zero"));
        assert!(rendered.text.contains("15 minutes"));
        // No HTML in the text part.
        assert!(!rendered.text.contains('<'), "{}", rendered.text);
    }

    #[test]
    fn the_html_part_carries_the_link_twice_and_says_it_expires() {
        let rendered = MagicLinkTemplate { theme: None }
            .render(&serde_json::to_value(data()).expect("json"), "en")
            .expect("renders");
        // Once as the button, once as the copyable link: a mail client
        // that strips the anchor still leaves the address as text.
        assert_eq!(
            rendered
                .html
                .matches(&format!("href=\"{}\"", data().link))
                .count(),
            2,
            "{}",
            rendered.html
        );
        assert!(rendered.html.contains(&format!(">{}</a>", data().link)));
        assert!(rendered.html.contains("expires in 15 minutes"));
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

        // Empty registry: the compiled default answers, which is what
        // makes the conformance kit work.
        let empty = TemplateRegistry::new();
        let fallback = render(&empty, &data(), "en", &venture(), &EmptyConfig).expect("falls back");
        // In the venture's theme, which names it as the venture does.
        assert_eq!(fallback.subject, "Sign in to factory0");

        let mut registry = TemplateRegistry::new();
        registry.register(TEMPLATE_MAGIC_LINK, Box::new(Override));
        let overridden =
            render(&registry, &data(), "en", &venture(), &EmptyConfig).expect("renders");
        assert_eq!(overridden.subject, "the venture's own subject");
    }

    #[test]
    fn nothing_from_the_link_can_break_out_of_the_html() {
        // The link is built by this service, not by a caller, but the
        // layout escapes it anyway and this asserts that it does: a future change
        // that let a `return_to` reach the link must not become an
        // injection into somebody's inbox.
        let hostile = MagicLinkMail {
            link: "https://auth.example/x?t=a\"><script>alert(1)</script>".to_owned(),
            ..data()
        };
        let rendered = MagicLinkTemplate { theme: None }
            .render(&serde_json::to_value(&hostile).expect("json"), "en")
            .expect("renders");
        assert!(
            !rendered.html.contains("<script>alert(1)"),
            "{}",
            rendered.html
        );
    }
}
