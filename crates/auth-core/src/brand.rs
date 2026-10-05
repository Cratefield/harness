//! The instance's branding (issue #777).
//!
//! Auth runs as one instance per app, on the app's own domain, so every
//! page and mail this service renders speaks for that app and nothing else.
//! The values come from configuration (`wrangler.toml` vars on the Worker)
//! and are shared by every auth module: the chooser, the error and
//! sign-out pages, the mail subjects, and the passkey relying-party name.
//!
//! | Key | Meaning | When unset |
//! |---|---|---|
//! | `AUTH_BRAND_NAME` | Display name, e.g. `Alphahunt` | the venture's own name |
//! | `AUTH_BRAND_LOGO_URL` | Absolute `https` URL of a logo | no logo |
//! | `AUTH_BRAND_ACCENT` | `#rgb` or `#rrggbb` accent colour | [`DEFAULT_ACCENT`](crate::brand::DEFAULT_ACCENT) |
//! | `AUTH_BRAND_SUPPORT_EMAIL` | Where people write for help | no help link |
//! | `AUTH_BRAND_FOOTER` | Footer text | `<domain> · <name>` |
//! | `AUTH_BRAND_PRIVACY_URL` | Privacy policy, absolute `https` | no link |
//! | `AUTH_BRAND_TERMS_URL` | Terms of service, absolute `https` | no link |
//!
//! Every default is neutral: it is either absent or derived from the
//! venture the instance itself runs as. Nothing falls back to another
//! app's name or domain. [`Brand::problems`](crate::brand::Brand::problems) is what refuses a malformed
//! value at boot (`auth-core`'s `validate_config` calls it), and
//! [`Brand::from_config`](crate::brand::Brand::from_config) never lets one reach a page: a value that would
//! be refused is read as unset, so the accent colour that lands inside a
//! `<style>` block is always a validated hex colour.

use cratefield_core::{Config, Venture};

/// `AUTH_BRAND_NAME`: the display name pages and mail subjects use.
pub const NAME_KEY: &str = "AUTH_BRAND_NAME";
/// `AUTH_BRAND_LOGO_URL`: an absolute `https` image URL.
pub const LOGO_URL_KEY: &str = "AUTH_BRAND_LOGO_URL";
/// `AUTH_BRAND_ACCENT`: `#rgb` or `#rrggbb`.
pub const ACCENT_KEY: &str = "AUTH_BRAND_ACCENT";
/// `AUTH_BRAND_SUPPORT_EMAIL`: the help address.
pub const SUPPORT_EMAIL_KEY: &str = "AUTH_BRAND_SUPPORT_EMAIL";
/// `AUTH_BRAND_FOOTER`: the footer line.
pub const FOOTER_KEY: &str = "AUTH_BRAND_FOOTER";
/// `AUTH_BRAND_PRIVACY_URL`: the privacy policy.
pub const PRIVACY_URL_KEY: &str = "AUTH_BRAND_PRIVACY_URL";
/// `AUTH_BRAND_TERMS_URL`: the terms of service.
pub const TERMS_URL_KEY: &str = "AUTH_BRAND_TERMS_URL";

/// The accent colour when `AUTH_BRAND_ACCENT` is unset: a neutral blue
/// that belongs to no app.
pub const DEFAULT_ACCENT: &str = "#4f6bed";

/// The longest display name or footer accepted. Both are rendered on
/// every page and in mail subjects; anything longer is a mistake.
const MAX_TEXT: usize = 200;

/// The instance's branding, ready to render.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Brand {
    /// The display name.
    pub name: String,
    /// A logo, when configured.
    pub logo_url: Option<String>,
    /// A validated `#rgb`/`#rrggbb` colour, lower-cased.
    pub accent: String,
    /// The help address, when configured.
    pub support_email: Option<String>,
    /// The footer line.
    pub footer: String,
    /// The privacy policy, when configured.
    pub privacy_url: Option<String>,
    /// The terms of service, when configured.
    pub terms_url: Option<String>,
}

impl Brand {
    /// Reads the branding for `venture`. Never fails: a malformed value is
    /// read as unset (boot validation is what refuses it), so a page can
    /// always render.
    #[must_use]
    pub fn from_config(cfg: &dyn Config, venture: &Venture) -> Self {
        let name = get(cfg, NAME_KEY)
            .filter(|value| check_text(value).is_ok())
            .unwrap_or_else(|| venture.name.clone());
        let footer = get(cfg, FOOTER_KEY)
            .filter(|value| check_text(value).is_ok())
            .unwrap_or_else(|| {
                if venture.domain.is_empty() {
                    name.clone()
                } else {
                    format!("{} · {name}", venture.domain)
                }
            });
        Self {
            logo_url: get(cfg, LOGO_URL_KEY).filter(|value| check_url(value).is_ok()),
            accent: get(cfg, ACCENT_KEY)
                .and_then(|value| check_accent(&value).ok())
                .unwrap_or_else(|| DEFAULT_ACCENT.to_owned()),
            support_email: get(cfg, SUPPORT_EMAIL_KEY).filter(|value| check_email(value).is_ok()),
            privacy_url: get(cfg, PRIVACY_URL_KEY).filter(|value| check_url(value).is_ok()),
            terms_url: get(cfg, TERMS_URL_KEY).filter(|value| check_url(value).is_ok()),
            name,
            footer,
        }
    }

    /// The venture as a mail theme should see it (issue #777): this
    /// brand's display name, accent, logo and footer, so a sign-in mail
    /// reads like the pages around it. The venture's kebab-case `name` is
    /// a technical id, never what a person reads in a subject line.
    #[must_use]
    pub fn mail_venture(&self, venture: &Venture) -> Venture {
        let mut themed = venture.clone();
        themed.name.clone_from(&self.name);
        themed.brand.accent.clone_from(&self.accent);
        if self.logo_url.is_some() {
            themed.brand.logo_url.clone_from(&self.logo_url);
        }
        themed.brand.footer = Some(self.footer.clone());
        themed
    }

    /// Every malformed branding value, as `KEY: problem`. Unset values are
    /// not problems here; whether a key is *required* is the deployable
    /// instance's decision, not the library's.
    #[must_use]
    pub fn problems(cfg: &dyn Config) -> Vec<String> {
        let checks: [(&str, Check); 7] = [
            (NAME_KEY, check_text),
            (FOOTER_KEY, check_text),
            (LOGO_URL_KEY, check_url),
            (ACCENT_KEY, check_accent),
            (SUPPORT_EMAIL_KEY, check_email),
            (PRIVACY_URL_KEY, check_url),
            (TERMS_URL_KEY, check_url),
        ];
        checks
            .iter()
            .filter_map(|(key, check)| {
                let value = get(cfg, key)?;
                check(&value)
                    .err()
                    .map(|problem| format!("{key}: {problem}"))
            })
            .collect()
    }
}

/// A value check: the normalized value, or what is wrong with it.
type Check = fn(&str) -> Result<String, String>;

/// One variable, trimmed; blank reads as unset.
fn get(cfg: &dyn Config, key: &str) -> Option<String> {
    cfg.get(key)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// A line of text: bounded, with no control characters (a mail subject
/// carries it, and a CR/LF there is a header injection).
fn check_text(value: &str) -> Result<String, String> {
    if value.chars().any(char::is_control) {
        return Err("must not contain control characters".to_owned());
    }
    if value.chars().count() > MAX_TEXT {
        return Err(format!("must be at most {MAX_TEXT} characters"));
    }
    Ok(value.to_owned())
}

/// An absolute `https` URL (`http` only on loopback, for local work).
fn check_url(value: &str) -> Result<String, String> {
    let url =
        url::Url::parse(value).map_err(|err| format!("{value:?} is not an absolute URL: {err}"))?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    match url.scheme() {
        "https" => Ok(value.to_owned()),
        "http" if loopback => Ok(value.to_owned()),
        _ => Err(format!("{value:?} must use https")),
    }
}

/// `#rgb` or `#rrggbb`, nothing else: the value is written into a
/// `<style>` block, where HTML escaping is no defence.
fn check_accent(value: &str) -> Result<String, String> {
    let hex = value.strip_prefix('#').unwrap_or_default();
    if matches!(hex.len(), 3 | 6) && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(value.to_ascii_lowercase());
    }
    Err(format!("must be a #rgb or #rrggbb colour, got {value:?}"))
}

/// A bare `local@domain` address.
fn check_email(value: &str) -> Result<String, String> {
    let (local, domain) = value.split_once('@').unwrap_or(("", ""));
    if local.is_empty()
        || domain.is_empty()
        || domain.contains('@')
        || value.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(format!("{value:?} is not an email address"));
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::MapConfig;

    fn venture() -> Venture {
        Venture::new("acme", "auth.acme.example")
    }

    #[test]
    fn unset_branding_is_the_instance_s_own_name_and_nothing_else() {
        let brand = Brand::from_config(&MapConfig::default(), &venture());
        assert_eq!(brand.name, "acme");
        assert_eq!(brand.footer, "auth.acme.example · acme");
        assert_eq!(brand.accent, DEFAULT_ACCENT);
        assert_eq!(brand.logo_url, None);
        assert_eq!(brand.support_email, None);
        assert_eq!(brand.privacy_url, None);
        assert_eq!(brand.terms_url, None);
    }

    #[test]
    fn mail_sees_the_display_name_not_the_venture_id() {
        let cfg = MapConfig::from_pairs([(NAME_KEY, "Acme"), (ACCENT_KEY, "#123456")]);
        let brand = Brand::from_config(&cfg, &venture());
        let themed = brand.mail_venture(&venture());
        assert_eq!(themed.name, "Acme");
        assert_eq!(themed.brand.accent, "#123456");
        assert_eq!(themed.domain, "auth.acme.example");
    }

    #[test]
    fn configured_branding_is_read() {
        let cfg = MapConfig::from_pairs([
            (NAME_KEY, "Acme"),
            (LOGO_URL_KEY, "https://acme.example/logo.svg"),
            (ACCENT_KEY, "#FF8800"),
            (SUPPORT_EMAIL_KEY, "help@acme.example"),
            (FOOTER_KEY, "Acme Ltd"),
            (PRIVACY_URL_KEY, "https://acme.example/privacy"),
            (TERMS_URL_KEY, "https://acme.example/terms"),
        ]);
        let brand = Brand::from_config(&cfg, &venture());
        assert_eq!(brand.name, "Acme");
        assert_eq!(brand.accent, "#ff8800");
        assert_eq!(brand.footer, "Acme Ltd");
        assert_eq!(brand.support_email.as_deref(), Some("help@acme.example"));
        assert!(Brand::problems(&cfg).is_empty());
    }

    #[test]
    fn malformed_values_are_problems_and_never_rendered() {
        let cfg = MapConfig::from_pairs([
            (ACCENT_KEY, "red;}body{display:none"),
            (LOGO_URL_KEY, "javascript:alert(1)"),
            (PRIVACY_URL_KEY, "http://acme.example/privacy"),
            (SUPPORT_EMAIL_KEY, "not an address"),
            (NAME_KEY, "Acme\r\nBcc: x"),
        ]);
        let problems = Brand::problems(&cfg).join("\n");
        for key in [
            ACCENT_KEY,
            LOGO_URL_KEY,
            PRIVACY_URL_KEY,
            SUPPORT_EMAIL_KEY,
            NAME_KEY,
        ] {
            assert!(problems.contains(key), "{key} not refused: {problems}");
        }
        let brand = Brand::from_config(&cfg, &venture());
        assert_eq!(brand.accent, DEFAULT_ACCENT);
        assert_eq!(brand.logo_url, None);
        assert_eq!(brand.privacy_url, None);
        assert_eq!(brand.support_email, None);
        assert_eq!(brand.name, "acme");
    }
}
