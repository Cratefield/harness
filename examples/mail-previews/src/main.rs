//! Writes every harness module's mail, with sample values, in one venture's
//! theme: `<name>.html`, `<name>.txt` and an `index.html` linking them.
//!
//! ```text
//! cargo run -p cratefield-mail-previews -- [--theme theme.json] [--product slug] [out-dir]
//! ```
//!
//! `--theme` is a JSON [`MailTheme`] (any subset of its fields; the rest
//! default); without it the previews use [`MailTheme::cratefield`].
//! `--product` names the waitlist product (default: the brand name in lower
//! case). The out dir defaults to `target/email-previews`. Host-only
//! tooling: the modules themselves never touch `std::fs`.

use std::fmt::Write as _;
use std::path::PathBuf;

use cratefield_core::{Brand, Template};
use cratefield_mail_templates::{MailTheme, escape};
use serde_json::{Value, json};

struct Args {
    theme: MailTheme,
    product: Option<String>,
    out: PathBuf,
}

fn args() -> Args {
    let mut theme = MailTheme::cratefield();
    let mut product = None;
    let mut out = PathBuf::from("target/email-previews");
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--theme" => {
                let path = it.next().expect("--theme takes a path");
                let raw = std::fs::read_to_string(&path).expect("read the theme file");
                theme = MailTheme::from_json(&raw).expect("the theme file is a MailTheme");
            }
            "--product" => product = Some(it.next().expect("--product takes a slug")),
            "-h" | "--help" => {
                println!("usage: mail-previews [--theme theme.json] [--product slug] [out-dir]");
                std::process::exit(0);
            }
            other => out = PathBuf::from(other),
        }
    }
    Args {
        theme,
        product,
        out,
    }
}

fn find(templates: Vec<(String, Box<dyn Template>)>, id: &str) -> Box<dyn Template> {
    templates
        .into_iter()
        .find(|(template_id, _)| template_id == id)
        .unwrap_or_else(|| panic!("{id} is registered"))
        .1
}

#[allow(clippy::too_many_lines, reason = "one sample per mail, in a list")]
fn main() -> std::io::Result<()> {
    let Args {
        theme,
        product,
        out,
    } = args();
    std::fs::create_dir_all(&out)?;
    let venture = theme.brand_name.clone();
    let product = product.unwrap_or_else(|| venture.to_lowercase().replace(' ', ""));
    let host = theme
        .site_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .to_owned();
    let api = format!("https://api.{host}");
    let email = "ada@example.com";
    let token = "Jx3mQ9vT0cWb8nL2kPz7rY5sHd1fGa4eUo6iBq0tNcM";
    let brand = Brand::default();

    let samples: Vec<(&str, Box<dyn Template>, Value)> = vec![
        (
            "waitlist-confirm",
            find(
                cratefield_module_waitlist::themed_templates(&theme),
                "waitlist/confirm",
            ),
            json!({
                "venture": venture, "product": product, "email": email,
                "confirm_url": format!("{api}/v1/waitlist/confirm?token={token}"),
                "brand": brand,
            }),
        ),
        (
            "waitlist-confirmed",
            find(
                cratefield_module_waitlist::themed_templates(&theme),
                "waitlist/confirmed",
            ),
            json!({
                "venture": venture, "product": product, "email": email, "position": 42,
                "status_url": format!("{api}/v1/waitlist/status?token={token}"),
                "brand": brand,
            }),
        ),
        (
            "sign-in",
            find(
                cratefield_auth_magic_link::themed_templates(&theme),
                cratefield_auth_magic_link::TEMPLATE_MAGIC_LINK,
            ),
            json!({
                "venture": venture,
                "link": format!("{api}/v1/auth-magic-link/consume?token={token}"),
                "minutes": 15,
            }),
        ),
        (
            "email-signup-confirm",
            find(
                cratefield_module_email_signup::themed_templates(&theme),
                "email-signup/confirm",
            ),
            json!({
                "venture": venture, "email": email,
                "confirm_url": format!("{api}/v1/email-signup/confirm?token={token}"),
                "unsubscribe_url": format!("{api}/v1/email-signup/unsubscribe?token={token}"),
                "brand": brand,
            }),
        ),
        (
            "email-signup-welcome",
            find(
                cratefield_module_email_signup::themed_templates(&theme),
                "email-signup/welcome",
            ),
            json!({
                "venture": venture, "email": email,
                "unsubscribe_url": format!("{api}/v1/email-signup/unsubscribe?token={token}"),
                "brand": brand,
            }),
        ),
        (
            "password-verify",
            find(
                cratefield_auth_password::themed_templates(&theme),
                cratefield_auth_password::TEMPLATE_VERIFY,
            ),
            json!({
                "venture": venture,
                "link": format!("{api}/v1/auth-password/verify?token={token}"),
                "hours": 24,
            }),
        ),
        (
            "password-reset",
            find(
                cratefield_auth_password::themed_templates(&theme),
                cratefield_auth_password::TEMPLATE_RESET,
            ),
            json!({
                "venture": venture,
                "link": format!("{api}/v1/auth-password/reset?token={token}"),
                "minutes": 30,
            }),
        ),
        (
            "password-duplicate",
            find(
                cratefield_auth_password::themed_templates(&theme),
                cratefield_auth_password::TEMPLATE_DUPLICATE,
            ),
            json!({
                "venture": venture,
                "reset_link": format!("{api}/v1/auth-password/reset/request"),
            }),
        ),
        (
            "org-invitation",
            find(
                cratefield_module_orgs::themed_templates(&theme),
                cratefield_module_orgs::TEMPLATE_INVITATION,
            ),
            json!({
                "venture": venture, "domain": host, "email": email,
                "org": "Analytical Engines", "role": "admin",
                "accept_url": format!("{api}/v1/orgs/invitations/accept?token=01J9ZQ4M8K2D7X3B6N5R0T1V2W"),
                "token": "01J9ZQ4M8K2D7X3B6N5R0T1V2W", "expires_in_days": 7,
            }),
        ),
        (
            "notification",
            find(
                cratefield_module_notifications::themed_templates(&theme),
                cratefield_module_notifications::TEMPLATE_EMAIL,
            ),
            json!({
                "venture": venture, "subject": "Your export is ready",
                "title": "Your export is ready",
                "body": "The CSV of your March orders is ready to download.",
                "url": format!("{}/exports/42", theme.site_url),
                "lang": "en", "dir": "ltr",
                "unsubscribe": format!("{api}/v1/notifications/unsubscribe?token={token}"),
                "unsubscribe_all": format!("{api}/v1/notifications/unsubscribe?token=all-{token}"),
            }),
        ),
    ];

    let title = format!("{} emails", escape(&venture));
    let mut index = format!(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>{title}</title>\
         <body style=\"font-family:system-ui,sans-serif;margin:32px\"><h1>{title}</h1><ul>"
    );
    for (name, template, data) in samples {
        let rendered = template
            .render(&data, "en")
            .unwrap_or_else(|err| panic!("{name} renders: {err}"));
        std::fs::write(out.join(format!("{name}.html")), &rendered.html)?;
        std::fs::write(
            out.join(format!("{name}.txt")),
            format!("Subject: {}\n\n{}", rendered.subject, rendered.text),
        )?;
        let _ = write!(
            index,
            "<li><a href=\"{name}.html\">{name}</a> (<a href=\"{name}.txt\">text</a>): {}</li>",
            escape(&rendered.subject)
        );
        println!("{}", out.join(format!("{name}.html")).display());
    }
    index.push_str("</ul></body></html>");
    std::fs::write(out.join("index.html"), index)?;
    Ok(())
}
