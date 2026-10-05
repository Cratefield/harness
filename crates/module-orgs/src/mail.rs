//! The invitation mail (issue #652).
//!
//! One mail: the organization's name, the role offered, a link, and — for a
//! venture that serves its own accept page — the token itself, so an invitee
//! is never stuck when the configured base is not where they expect to land.
//! It renders through the template registry as `orgs/invitation`, in the
//! venture's [`MailTheme`] via `cratefield-mail-templates`, so a venture can
//! restyle or reword it like every other module's mail. The organization's
//! name is typed by a person; the layout escapes it with everything else.

use cratefield_core::{
    MailError, Message, ModuleConfig, ModuleContext, Rendered, SendOutcome, Template,
    TemplateError, TemplateRegistry,
};
use cratefield_mail_templates::{self as mt, MailTheme};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::OrgsError;

/// One invitation to render and send. The raw `token` is here and nowhere
/// else: the row holds only its SHA-256, so this is the last moment it exists.
pub(crate) struct OutgoingInvitation<'a> {
    pub(crate) to: &'a str,
    pub(crate) org_name: &'a str,
    pub(crate) role: &'a str,
    pub(crate) accept_url: &'a str,
    pub(crate) token: &'a str,
    pub(crate) idempotency_key: &'a str,
    pub(crate) expires_in_days: i64,
}

/// Where the accept link points: `ORGS_ACCEPT_URL` when a venture serves its
/// own page, otherwise this module's own route under the API base — the
/// venture's `ORGS_API_BASE` when set, `https://api.<domain>` otherwise, the
/// same resolution `module-waitlist` and `module-email-signup` use. The token
/// is appended as a query pair, percent-encoded, so it survives the round trip
/// however the base was written.
pub(crate) fn accept_url(ctx: &ModuleContext, token: &str) -> String {
    let cfg = ModuleConfig::new(crate::MODULE_NAME, &*ctx.config);
    let base = cfg.get_opt("ACCEPT_URL").unwrap_or_else(|| {
        format!(
            "{}/v1/{}/invitations/accept",
            api_base(&cfg, ctx),
            crate::MODULE_NAME
        )
    });
    format!("{}?token={}", base, encode_uri_component(token))
}

/// The API origin, as the sibling modules resolve it.
fn api_base(cfg: &ModuleConfig<'_>, ctx: &ModuleContext) -> String {
    cfg.get_opt("API_BASE")
        .unwrap_or_else(|| format!("https://api.{}", ctx.venture.domain))
}

/// Percent-encodes one query-pair value, leaving the unreserved set alone. A
/// ULID is already unreserved, so this only matters for a venture that shipped
/// its own token shape.
fn encode_uri_component(value: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

/// The registry id a venture overrides.
pub const TEMPLATE_INVITATION: &str = "orgs/invitation";

/// What the invitation template is given. Serialized through the registry,
/// so it is a wire format: adding a field is fine, renaming one breaks
/// overrides. The module also puts the resolved theme under `theme`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitationMail {
    /// The venture's name.
    pub venture: String,
    /// The venture's domain, named beside it.
    pub domain: String,
    /// The invitee's address.
    pub email: String,
    /// The organization's name, as a person typed it.
    pub org: String,
    /// The role offered.
    pub role: String,
    /// The accept link, token included.
    pub accept_url: String,
    /// The raw token, for an accept page that asks for it.
    pub token: String,
    /// Days until the invitation expires.
    pub expires_in_days: i64,
}

struct InvitationTemplate {
    theme: Option<MailTheme>,
}

impl Template for InvitationTemplate {
    fn render(&self, data: &Value, _locale: &str) -> Result<Rendered, TemplateError> {
        let theme = mt::theme_for_template(self.theme.as_ref(), data);
        let data: InvitationMail =
            serde_json::from_value(data.clone()).map_err(|_| TemplateError::RenderFailed {
                id: TEMPLATE_INVITATION.to_owned(),
                reason: "the mail data is not the shape this template takes".to_owned(),
            })?;
        let venture = theme.name_or(&data.venture);
        let days = data.expires_in_days;
        let plural = if days == 1 { "day" } else { "days" };
        Ok(mt::Message::new(
            format!("You have been invited to join {}", data.org),
            "You have been invited",
        )
        .preheader(format!(
            "Join \u{201c}{}\u{201d} on {venture} as {}.",
            data.org, data.role
        ))
        .paragraph(format!(
            "You have been invited to join an organization on {venture} ({}).",
            data.domain
        ))
        .fact("Organization", &data.org)
        .fact("Role", &data.role)
        .button("Accept the invitation", &data.accept_url)
        .code(
            "If you would rather paste it, your invitation token is:",
            &data.token,
        )
        .note(format!("This invitation expires in {days} {plural}."))
        .note(
            "If you were not expecting this, ignore this email: nothing happens unless you \
             accept.",
        )
        .recipient(&data.email)
        .why(format!(
            "someone invited this address to an organization on {venture}"
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
        TEMPLATE_INVITATION.to_owned(),
        Box::new(InvitationTemplate {
            theme: theme.cloned(),
        }) as Box<dyn Template>,
    )]
}

/// Renders through the venture's registry, falling back to the compiled
/// default when the registry misses (the conformance kit registers
/// nothing).
fn render(registry: &TemplateRegistry, data: &Value) -> Result<Rendered, TemplateError> {
    match registry.render(TEMPLATE_INVITATION, data, "en") {
        Err(TemplateError::UnknownTemplate { .. }) => {
            InvitationTemplate { theme: None }.render(data, "en")
        }
        other => other,
    }
}

/// Renders and sends one invitation.
///
/// # Errors
///
/// [`OrgsError::MailNotConfigured`] when the deployment has no mailer or the
/// mailer reports no verified sending domain — the invitation endpoints are
/// what surface that as `503 mail-not-configured` — and [`OrgsError::Mail`]
/// when the provider refuses the message. Either way the caller drops the
/// invitation row: an invitation nobody can receive is not an invitation.
pub(crate) async fn send(
    ctx: &ModuleContext,
    mail: &OutgoingInvitation<'_>,
) -> Result<(), OrgsError> {
    let cfg = ModuleConfig::new(crate::MODULE_NAME, &*ctx.config);
    let from = cfg.get_str("FROM", &format!("no-reply@send.{}", ctx.venture.domain));

    let mut data = serde_json::to_value(InvitationMail {
        venture: ctx.venture.name.clone(),
        domain: ctx.venture.domain.clone(),
        email: mail.to.to_owned(),
        org: mail.org_name.to_owned(),
        role: mail.role.to_owned(),
        accept_url: mail.accept_url.to_owned(),
        token: mail.token.to_owned(),
        expires_in_days: mail.expires_in_days,
    })
    .map_err(|error| OrgsError::Mail(error.to_string()))?;
    mt::attach_theme(&mut data, &ctx.venture, &*ctx.config);
    let rendered =
        render(&ctx.templates, &data).map_err(|error| OrgsError::Mail(error.to_string()))?;

    let mut message = Message::new(
        mail.to,
        from,
        rendered.subject,
        rendered.text,
        rendered.html,
    )
    .idempotency_key(mail.idempotency_key)
    .tags([crate::MODULE_NAME, "invitation"]);
    if let Some(reply_to) = cfg.get_opt("REPLY_TO") {
        message = message.reply_to(reply_to);
    }

    let Some(mailer) = ctx.ports.mailer.clone() else {
        return Err(OrgsError::MailNotConfigured);
    };
    match mailer.send(message).await {
        Ok(SendOutcome::Sent { .. }) => {
            // The recipient is never logged; the idempotency key and the
            // outcome are (architecture section 11).
            tracing::info!(
                idempotency = %mail.idempotency_key,
                "org invitation dispatched"
            );
            Ok(())
        }
        Ok(SendOutcome::NotConfigured) => Err(OrgsError::MailNotConfigured),
        Err(error) => Err(OrgsError::Mail(mail_error(&error))),
    }
}

/// The provider's failure, reduced to a sentence safe to keep: `MailError`'s
/// own `Display` already scrubs the provider's text of credentials, and the
/// variant is what a caller needs to tell a retry from a misconfiguration.
fn mail_error(error: &MailError) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unreserved_set_survives_and_the_rest_is_encoded() {
        assert_eq!(encode_uri_component("01J8Z9ABCDEF"), "01J8Z9ABCDEF");
        assert_eq!(encode_uri_component("a b/c?d"), "a%20b%2Fc%3Fd");
    }

    #[test]
    fn markup_in_a_name_is_escaped_and_cannot_forge_a_text_line() {
        let data = serde_json::to_value(InvitationMail {
            venture: "acme".to_owned(),
            domain: "acme.test".to_owned(),
            email: "ada@example.com".to_owned(),
            org: "<script>alert('x')</script>\r\nBcc: x@evil.test".to_owned(),
            role: "admin".to_owned(),
            accept_url: "https://api.acme.test/v1/orgs/invitations/accept?token=t".to_owned(),
            token: "t".to_owned(),
            expires_in_days: 7,
        })
        .expect("json");
        let rendered = render(&TemplateRegistry::new(), &data).expect("renders");
        assert!(!rendered.html.contains("<script>"), "{}", rendered.html);
        assert!(rendered.html.contains("&lt;script&gt;alert(&#39;x&#39;)"));
        assert!(!rendered.text.contains("\nBcc:"), "{}", rendered.text);
        assert!(!rendered.subject.contains('\n'));
        assert!(rendered.text.contains("expires in 7 days"));
        assert!(rendered.text.contains("accept?token=t"));
    }
}
