//! The invitation mail (issue #652).
//!
//! One mail, rendered here rather than through a template registry, because a
//! venture has nothing to localize yet: it carries the organization's name, the
//! role offered, a link, and — for a venture that serves its own accept page —
//! the token itself, so an invitee is never stuck when the configured base is
//! not where they expect to land. The body is built from values this module
//! controls except the organization's name, which is escaped.

use cratefield_core::{MailError, Message, ModuleConfig, ModuleContext, SendOutcome};

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

/// Renders and sends one invitation.
///
/// # Errors
///
/// [`OrgsError::MailNotConfigured`] when the deployment has no mailer or the
/// mailer reports no verified sending domain — the `503 mail-not-configured`
/// the waitlist form degrades on — and [`OrgsError::Mail`] when the provider
/// refuses the message. Either way the caller drops the invitation row: an
/// invitation nobody can receive is not an invitation.
pub(crate) async fn send(
    ctx: &ModuleContext,
    mail: &OutgoingInvitation<'_>,
) -> Result<(), OrgsError> {
    let cfg = ModuleConfig::new(crate::MODULE_NAME, &*ctx.config);
    let from = cfg.get_str("FROM", &format!("no-reply@send.{}", ctx.venture.domain));

    let days = mail.expires_in_days;
    let subject = format!("You have been invited to join {}", mail.org_name);
    let inviter_line = format!("{} ({})", ctx.venture.name, ctx.venture.domain);
    let text = format!(
        "{inviter_line}\n\n\
         You have been invited to join \"{org}\" as {role}.\n\n\
         Accept the invitation:\n{url}\n\n\
         If you would rather paste it, your invitation token is:\n{token}\n\n\
         This invitation expires in {days} {plural}.\n",
        org = mail.org_name,
        role = mail.role,
        url = mail.accept_url,
        token = mail.token,
        days = days,
        plural = if days == 1 { "day" } else { "days" },
    );
    let html = format!(
        "<p>You have been invited to join <strong>{org}</strong> as {role}.</p>\
         <p><a href=\"{url}\">Accept the invitation</a></p>\
         <p>Or paste this token into the accept page: <code>{token}</code></p>\
         <p>This invitation expires in {days} {plural}.</p>",
        org = escape_html(mail.org_name),
        role = escape_html(mail.role),
        url = mail.accept_url,
        token = escape_html(mail.token),
        days = days,
        plural = if days == 1 { "day" } else { "days" },
    );

    let mut message = Message::new(mail.to, from, subject, text, html)
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

/// Escapes the five characters that would let a value leave an HTML text
/// node or an attribute. Only the organization's name and the role need it —
/// roles come from the venture's own configuration, but a name is typed by a
/// person, and this mail is rendered by a client that will honour markup.
fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unreserved_set_survives_and_the_rest_is_encoded() {
        assert_eq!(encode_uri_component("01J8Z9ABCDEF"), "01J8Z9ABCDEF");
        assert_eq!(encode_uri_component("a b/c?d"), "a%20b%2Fc%3Fd");
    }

    #[test]
    fn markup_in_a_name_does_not_escape_its_text_node() {
        assert_eq!(
            escape_html("<script>alert('x')</script>"),
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"
        );
    }
}
