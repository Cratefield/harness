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

use askama::Template as _;
use cratefield_core::{Rendered, Template, TemplateError, TemplateRegistry};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The registry ids a venture overrides, and the ids `emits`-style
/// conformance looks for.
pub const TEMPLATE_VERIFY: &str = "auth-password/verify";
pub const TEMPLATE_DUPLICATE: &str = "auth-password/duplicate";
pub const TEMPLATE_RESET: &str = "auth-password/reset";

/// The value for one askama field, taken from the parsed data: a text
/// field is borrowed, a number is copied.
macro_rules! mail_value {
    (str, $data:ident, $field:ident) => {
        &$data.$field
    };
    (int, $data:ident, $field:ident) => {
        $data.$field
    };
}

/// The three defaults are one shape: parse the wire data, render the html
/// and text parts from the same fields, prefix the subject. Written once
/// here; each id keeps its own template structs, so a venture can still
/// override one and leave the others alone.
macro_rules! default_mail {
    (
        $id:expr, $data:ident, $prefix:literal, $default:ident, $html:ident, $text:ident,
        { $($field:ident: $kind:ident),* $(,)? }
    ) => {
        pub(crate) struct $default;

        impl Template for $default {
            fn render(&self, data: &Value, _locale: &str) -> Result<Rendered, TemplateError> {
                let data: $data =
                    serde_json::from_value(data.clone()).map_err(|_| parse_failed($id))?;
                Ok(Rendered {
                    subject: format!("{} {}", $prefix, data.venture),
                    html: $html { $($field: mail_value!($kind, data, $field)),* }
                        .render()
                        .map_err(|err| askama_failed($id, &err))?,
                    text: $text { $($field: mail_value!($kind, data, $field)),* }
                        .render()
                        .map_err(|err| askama_failed($id, &err))?,
                })
            }
        }
    };
}

// ---------------------------------------------------------------------------
// verify

/// What the verification template is given. Serialized through the
/// registry, so it is a wire format: adding a field is fine, renaming one
/// breaks overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyMail {
    pub venture: String,
    /// The full confirm URL, token included.
    pub link: String,
    /// How long the link lasts, for the sentence that says so.
    pub hours: i64,
}

#[derive(askama::Template)]
#[template(path = "verify.html")]
struct VerifyHtml<'a> {
    venture: &'a str,
    link: &'a str,
    hours: i64,
}

#[derive(askama::Template)]
#[template(path = "verify.txt")]
struct VerifyText<'a> {
    venture: &'a str,
    link: &'a str,
    hours: i64,
}

default_mail! {
    TEMPLATE_VERIFY, VerifyMail, "Confirm your address for", VerifyDefault, VerifyHtml, VerifyText,
    { venture: str, link: str, hours: int }
}

// ---------------------------------------------------------------------------
// duplicate

/// What the duplicate-registration template is given.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateMail {
    pub venture: String,
    /// A link to the reset-request page, or empty when the deployment
    /// has no hosted page to point at.
    pub reset_link: String,
}

#[derive(askama::Template)]
#[template(path = "duplicate.html")]
struct DuplicateHtml<'a> {
    venture: &'a str,
    reset_link: &'a str,
}

#[derive(askama::Template)]
#[template(path = "duplicate.txt")]
struct DuplicateText<'a> {
    venture: &'a str,
    reset_link: &'a str,
}

default_mail! {
    TEMPLATE_DUPLICATE, DuplicateMail, "Somebody tried to create an account with",
    DuplicateDefault, DuplicateHtml, DuplicateText,
    { venture: str, reset_link: str }
}

// ---------------------------------------------------------------------------
// reset

/// What the password-reset template is given.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetMail {
    pub venture: String,
    /// The full reset URL, token included.
    pub link: String,
    /// How long the link lasts, for the sentence that says so.
    pub minutes: i64,
}

#[derive(askama::Template)]
#[template(path = "reset.html")]
struct ResetHtml<'a> {
    venture: &'a str,
    link: &'a str,
    minutes: i64,
}

#[derive(askama::Template)]
#[template(path = "reset.txt")]
struct ResetText<'a> {
    venture: &'a str,
    link: &'a str,
    minutes: i64,
}

default_mail! {
    TEMPLATE_RESET, ResetMail, "Reset your password for", ResetDefault, ResetHtml, ResetText,
    { venture: str, link: str, minutes: int }
}

fn parse_failed(id: &str) -> TemplateError {
    TemplateError::RenderFailed {
        id: id.to_owned(),
        reason: "the mail data is not the shape this template takes".to_owned(),
    }
}

fn askama_failed(id: &str, err: &askama::Error) -> TemplateError {
    TemplateError::RenderFailed {
        id: id.to_owned(),
        reason: err.to_string(),
    }
}

/// The module's default templates, for
/// `Harness::builder().templates(..)` — register these alongside
/// `auth-magic-link`'s so both modules' mail resolves.
#[must_use]
pub fn default_templates() -> Vec<(String, Box<dyn Template>)> {
    vec![
        (
            TEMPLATE_VERIFY.to_owned(),
            Box::new(VerifyDefault) as Box<dyn Template>,
        ),
        (
            TEMPLATE_DUPLICATE.to_owned(),
            Box::new(DuplicateDefault) as Box<dyn Template>,
        ),
        (
            TEMPLATE_RESET.to_owned(),
            Box::new(ResetDefault) as Box<dyn Template>,
        ),
    ]
}

/// Renders through the venture's registry, falling back to the compiled
/// default when the registry misses.
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
) -> Result<Rendered, TemplateError> {
    let value = serde_json::to_value(data).map_err(|err| TemplateError::RenderFailed {
        id: id.to_owned(),
        reason: err.to_string(),
    })?;
    match registry.render(id, &value, locale) {
        Err(TemplateError::UnknownTemplate { .. }) => default.render(&value, locale),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            &VerifyDefault,
            &data,
            "en",
        )
        .expect("renders");
        assert!(rendered.text.contains(&data.link), "{}", rendered.text);
        assert!(rendered.subject.contains("Factory Zero"));
        assert!(rendered.text.contains("24 hours"));
        assert!(!rendered.text.contains('<'), "{}", rendered.text);
        // Once as the button, once as copyable text.
        assert_eq!(rendered.html.matches(&data.link).count(), 2);
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
            &DuplicateDefault,
            &data,
            "en",
        )
        .expect("renders");
        assert!(!rendered.text.contains("http"), "{}", rendered.text);
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
        let overridden =
            render(&registry, TEMPLATE_RESET, &ResetDefault, &data, "en").expect("renders");
        assert_eq!(overridden.subject, "the venture's own subject");

        // The other two ids are untouched and still fall back.
        let verify = render(
            &registry,
            TEMPLATE_VERIFY,
            &VerifyDefault,
            &VerifyMail {
                venture: "Factory Zero".to_owned(),
                link: "https://auth.example/v1/auth-password/verify?token=abc".to_owned(),
                hours: 24,
            },
            "en",
        )
        .expect("falls back");
        assert!(verify.subject.contains("Factory Zero"));
    }

    #[test]
    fn nothing_from_the_link_can_break_out_of_the_html() {
        // The link is built by this service, not by a caller, but askama
        // escapes it anyway and this asserts that it does.
        let hostile = ResetMail {
            venture: "Factory Zero".to_owned(),
            link: "https://auth.example/x?t=a\"><script>alert(1)</script>".to_owned(),
            minutes: 30,
        };
        let rendered = render(
            &TemplateRegistry::new(),
            TEMPLATE_RESET,
            &ResetDefault,
            &hostile,
            "en",
        )
        .expect("renders");
        assert!(
            !rendered.html.contains("<script>alert(1)"),
            "{}",
            rendered.html
        );
    }
}
