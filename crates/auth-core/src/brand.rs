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
//! The page theme is opt-in on top of that (issue #840): an instance that
//! sets none of these keeps the neutral dark pages every instance had
//! before. Every value is validated the way the accent is, because each
//! one is written into the pages' `<style>` block.
//!
//! | Key | Meaning | When unset |
//! |---|---|---|
//! | `AUTH_BRAND_BACKGROUND` | `#rgb`/`#rrggbb` page background | the neutral near-black |
//! | `AUTH_BRAND_TEXT` | `#rgb`/`#rrggbb` text colour | the neutral off-white |
//! | `AUTH_BRAND_ACCENT_TEXT` | Label colour on accent-filled buttons | black or white, whichever reads on the accent |
//! | `AUTH_BRAND_DANGER` | Field errors and error notices | a soft red |
//! | `AUTH_BRAND_SCHEME` | `dark` or `light` (the browser's `color-scheme`) | from the background's lightness |
//! | `AUTH_BRAND_RADIUS` | Corner radius in pixels, `0` (square) to `32` | `10` |
//! | `AUTH_BRAND_FONT_BODY` | Body font stack | the system stack |
//! | `AUTH_BRAND_FONT_DISPLAY` | Heading font stack | the body stack |
//! | `AUTH_BRAND_FONT_MONO` | Label and code font stack | the system monospace stack |
//! | `AUTH_BRAND_FONT_CSS_URL` | An `https` stylesheet that loads those fonts | no web fonts |
//!
//! Surfaces, borders and muted text are mixed from the background and
//! text colours when either is set, so a two-colour brand needs no more
//! than those two keys.
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

/// `AUTH_BRAND_BACKGROUND`: the page background (issue #840).
pub const BACKGROUND_KEY: &str = "AUTH_BRAND_BACKGROUND";
/// `AUTH_BRAND_TEXT`: the text colour.
pub const TEXT_KEY: &str = "AUTH_BRAND_TEXT";
/// `AUTH_BRAND_ACCENT_TEXT`: the label colour on an accent-filled button.
pub const ACCENT_TEXT_KEY: &str = "AUTH_BRAND_ACCENT_TEXT";
/// `AUTH_BRAND_DANGER`: field errors and error notices.
pub const DANGER_KEY: &str = "AUTH_BRAND_DANGER";
/// `AUTH_BRAND_SCHEME`: `dark` or `light`.
pub const SCHEME_KEY: &str = "AUTH_BRAND_SCHEME";
/// `AUTH_BRAND_RADIUS`: corner radius in CSS pixels, `0`–`32`.
pub const RADIUS_KEY: &str = "AUTH_BRAND_RADIUS";
/// `AUTH_BRAND_FONT_BODY`: the body font stack.
pub const FONT_BODY_KEY: &str = "AUTH_BRAND_FONT_BODY";
/// `AUTH_BRAND_FONT_DISPLAY`: the heading font stack.
pub const FONT_DISPLAY_KEY: &str = "AUTH_BRAND_FONT_DISPLAY";
/// `AUTH_BRAND_FONT_MONO`: the label and code font stack.
pub const FONT_MONO_KEY: &str = "AUTH_BRAND_FONT_MONO";
/// `AUTH_BRAND_FONT_CSS_URL`: an `https` stylesheet that loads the fonts.
pub const FONT_CSS_URL_KEY: &str = "AUTH_BRAND_FONT_CSS_URL";

/// The accent colour when `AUTH_BRAND_ACCENT` is unset: a neutral blue
/// that belongs to no app.
pub const DEFAULT_ACCENT: &str = "#4f6bed";

/// The neutral page colours every instance had before the theme keys
/// existed (issue #840): an instance that sets none of them looks exactly
/// as it did.
const DEFAULT_BACKGROUND: &str = "#0a0a0b";
const DEFAULT_TEXT: &str = "#edebe6";
const DEFAULT_SURFACE: &str = "#17171a";
const DEFAULT_BORDER: &str = "#26262b";
const DEFAULT_MUTED: &str = "#9b978f";
const DEFAULT_DANGER: &str = "#ffb4a2";
const DEFAULT_RADIUS: u8 = 10;
const DEFAULT_FONT_BODY: &str = "system-ui, -apple-system, \"Segoe UI\", sans-serif";
const DEFAULT_FONT_MONO: &str = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";

/// The longest font stack accepted.
const MAX_FONT_STACK: usize = 300;
/// The largest corner radius accepted, in CSS pixels.
const MAX_RADIUS: u8 = 32;

/// The shared stylesheet every hosted page renders with, after the
/// variables [`Brand::stylesheet`] writes for it.
const HOSTED_CSS: &str = include_str!("../templates/hosted.css");

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
    /// The page colours, fonts and corners (issue #840).
    pub theme: PageTheme,
}

/// How the hosted pages look (issue #840): every value validated, so
/// [`Brand::stylesheet`] can write them into a `<style>` block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageTheme {
    /// `dark` or `light`.
    pub scheme: &'static str,
    /// The page background.
    pub background: String,
    /// Cards, inputs and secondary buttons.
    pub surface: String,
    /// Borders and rules.
    pub border: String,
    /// Body text.
    pub text: String,
    /// Secondary text.
    pub muted: String,
    /// The label colour on an accent-filled button.
    pub accent_text: String,
    /// Field errors and error notices.
    pub danger: String,
    /// Corner radius, CSS pixels.
    pub radius: u8,
    /// The body font stack.
    pub font_body: String,
    /// The heading font stack.
    pub font_display: String,
    /// The label and code font stack.
    pub font_mono: String,
    /// The stylesheet that loads the fonts, when configured.
    pub font_css_url: Option<String>,
}

impl PageTheme {
    /// The theme `cfg` asks for, with `accent` already resolved. A
    /// malformed value reads as unset, as everywhere in [`Brand`].
    fn from_config(cfg: &dyn Config, accent: &str) -> Self {
        let colour = |key: &str| get(cfg, key).and_then(|value| check_accent(&value).ok());
        let font = |key: &str| get(cfg, key).and_then(|value| check_font(&value).ok());
        let configured_bg = colour(BACKGROUND_KEY);
        let configured_text = colour(TEXT_KEY);
        let background = configured_bg
            .clone()
            .unwrap_or_else(|| DEFAULT_BACKGROUND.to_owned());
        let text = configured_text
            .clone()
            .unwrap_or_else(|| DEFAULT_TEXT.to_owned());
        // The neutral greys belong to the neutral background; once an
        // instance names its own colours, the in-between shades are mixed
        // from them so they cannot clash.
        let (surface, border, muted) = if configured_bg.is_none() && configured_text.is_none() {
            (
                DEFAULT_SURFACE.to_owned(),
                DEFAULT_BORDER.to_owned(),
                DEFAULT_MUTED.to_owned(),
            )
        } else {
            (
                mix(&background, &text, 0.07),
                mix(&background, &text, 0.18),
                mix(&background, &text, 0.62),
            )
        };
        let scheme = match get(cfg, SCHEME_KEY)
            .as_deref()
            .and_then(|v| check_scheme(v).ok())
        {
            Some(scheme) => scheme,
            None if luminance(&background) > 0.5 => "light",
            None => "dark",
        };
        let accent_text = colour(ACCENT_TEXT_KEY).unwrap_or_else(|| {
            if luminance(accent) > 0.45 {
                "#0a0a0b".to_owned()
            } else {
                "#ffffff".to_owned()
            }
        });
        let font_body = font(FONT_BODY_KEY).unwrap_or_else(|| DEFAULT_FONT_BODY.to_owned());
        Self {
            scheme,
            surface,
            border,
            muted,
            accent_text,
            danger: colour(DANGER_KEY).unwrap_or_else(|| DEFAULT_DANGER.to_owned()),
            radius: get(cfg, RADIUS_KEY)
                .and_then(|value| check_radius(&value).ok())
                .unwrap_or(DEFAULT_RADIUS),
            font_display: font(FONT_DISPLAY_KEY).unwrap_or_else(|| font_body.clone()),
            font_mono: font(FONT_MONO_KEY).unwrap_or_else(|| DEFAULT_FONT_MONO.to_owned()),
            font_body,
            font_css_url: get(cfg, FONT_CSS_URL_KEY).filter(|value| check_https(value).is_ok()),
            background,
            text,
        }
    }
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
        let accent = get(cfg, ACCENT_KEY)
            .and_then(|value| check_accent(&value).ok())
            .unwrap_or_else(|| DEFAULT_ACCENT.to_owned());
        Self {
            logo_url: get(cfg, LOGO_URL_KEY).filter(|value| check_url(value).is_ok()),
            theme: PageTheme::from_config(cfg, &accent),
            accent,
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

    /// The hosted pages' stylesheet: this brand's colours, fonts and
    /// corners as CSS custom properties, then the shared rules that use
    /// them. Safe to write into a `<style>` block as it is: every value
    /// in it passed the same checks [`Brand::problems`] applies, and the
    /// rest is a compiled-in constant.
    #[must_use]
    pub fn stylesheet(&self) -> String {
        let t = &self.theme;
        format!(
            ":root {{ color-scheme: {scheme}; --cf-bg: {bg}; --cf-surface: {surface}; \
--cf-border: {border}; --cf-text: {text}; --cf-muted: {muted}; --cf-accent: {accent}; \
--cf-accent-text: {accent_text}; --cf-danger: {danger}; --cf-radius: {radius}px; \
--cf-font-body: {body}; --cf-font-display: {display}; --cf-font-mono: {mono}; }}\n{HOSTED_CSS}",
            scheme = t.scheme,
            bg = t.background,
            surface = t.surface,
            border = t.border,
            text = t.text,
            muted = t.muted,
            accent = self.accent,
            accent_text = t.accent_text,
            danger = t.danger,
            radius = t.radius,
            body = t.font_body,
            display = t.font_display,
            mono = t.font_mono,
        )
    }

    /// Every malformed branding value, as `KEY: problem`. Unset values are
    /// not problems here; whether a key is *required* is the deployable
    /// instance's decision, not the library's.
    #[must_use]
    pub fn problems(cfg: &dyn Config) -> Vec<String> {
        let checks: [(&str, Check); 17] = [
            (NAME_KEY, check_text),
            (FOOTER_KEY, check_text),
            (LOGO_URL_KEY, check_url),
            (ACCENT_KEY, check_accent),
            (SUPPORT_EMAIL_KEY, check_email),
            (PRIVACY_URL_KEY, check_url),
            (TERMS_URL_KEY, check_url),
            (BACKGROUND_KEY, check_accent),
            (TEXT_KEY, check_accent),
            (ACCENT_TEXT_KEY, check_accent),
            (DANGER_KEY, check_accent),
            (SCHEME_KEY, |value| check_scheme(value).map(str::to_owned)),
            (RADIUS_KEY, |value| {
                check_radius(value).map(|r| r.to_string())
            }),
            (FONT_BODY_KEY, check_font),
            (FONT_DISPLAY_KEY, check_font),
            (FONT_MONO_KEY, check_font),
            (FONT_CSS_URL_KEY, check_https),
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

/// `dark` or `light`, the two values `color-scheme` takes here.
fn check_scheme(value: &str) -> Result<&'static str, String> {
    match value.to_ascii_lowercase().as_str() {
        "dark" => Ok("dark"),
        "light" => Ok("light"),
        _ => Err(format!("must be dark or light, got {value:?}")),
    }
}

/// A whole number of CSS pixels, `0` to [`MAX_RADIUS`].
fn check_radius(value: &str) -> Result<u8, String> {
    value
        .parse::<u8>()
        .ok()
        .filter(|radius| *radius <= MAX_RADIUS)
        .ok_or_else(|| {
            format!("must be a whole number of pixels from 0 to {MAX_RADIUS}, got {value:?}")
        })
}

/// A CSS font stack: family names, quotes, commas and spaces, nothing
/// that could end the declaration or the `<style>` block it sits in.
fn check_font(value: &str) -> Result<String, String> {
    if value.chars().count() > MAX_FONT_STACK {
        return Err(format!("must be at most {MAX_FONT_STACK} characters"));
    }
    let allowed = |c: char| {
        c.is_ascii_alphanumeric() || matches!(c, ' ' | ',' | '-' | '.' | '_' | '\'' | '"')
    };
    if !value.chars().all(allowed) {
        return Err(format!(
            "{value:?} is not a font stack (letters, digits, spaces, commas, hyphens, dots, \
             underscores and quotes only)"
        ));
    }
    if value.matches('"').count() % 2 == 1 || value.matches('\'').count() % 2 == 1 {
        return Err(format!("{value:?} has an unclosed quote"));
    }
    Ok(value.to_owned())
}

/// An absolute `https` URL — a stylesheet is code the page runs, so no
/// loopback `http` exception here.
fn check_https(value: &str) -> Result<String, String> {
    let url =
        url::Url::parse(value).map_err(|err| format!("{value:?} is not an absolute URL: {err}"))?;
    if url.scheme() == "https" {
        Ok(value.to_owned())
    } else {
        Err(format!("{value:?} must use https"))
    }
}

/// `#rgb` or `#rrggbb` as three channels, `0.0`–`1.0`. Only ever called
/// with a value [`check_accent`] passed; anything else reads as black.
fn channels(hex: &str) -> [f64; 3] {
    let digits = hex.trim_start_matches('#');
    let expanded: String = if digits.len() == 3 {
        digits.chars().flat_map(|c| [c, c]).collect()
    } else {
        digits.to_owned()
    };
    let channel = |i: usize| {
        expanded
            .get(i..i + 2)
            .and_then(|pair| u8::from_str_radix(pair, 16).ok())
            .map_or(0.0, |v| f64::from(v) / 255.0)
    };
    [channel(0), channel(2), channel(4)]
}

/// Relative luminance (WCAG 2), `0.0` black to `1.0` white.
fn luminance(hex: &str) -> f64 {
    let linear = |c: f64| {
        if c <= 0.039_28 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    let [r, g, b] = channels(hex);
    0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b)
}

/// `from` moved `amount` of the way to `to`, as `#rrggbb`.
fn mix(from: &str, to: &str, amount: f64) -> String {
    let (a, b) = (channels(from), channels(to));
    let blend = |i: usize| {
        let value = (a[i] + (b[i] - a[i]) * amount) * 255.0;
        // Clamped to a byte first, so the cast cannot truncate.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let byte = value.round().clamp(0.0, 255.0) as u8;
        byte
    };
    format!("#{:02x}{:02x}{:02x}", blend(0), blend(1), blend(2))
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
    fn an_unthemed_instance_keeps_the_neutral_pages() {
        let brand = Brand::from_config(&MapConfig::default(), &venture());
        let theme = &brand.theme;
        assert_eq!(theme.scheme, "dark");
        assert_eq!(theme.background, DEFAULT_BACKGROUND);
        assert_eq!(theme.surface, DEFAULT_SURFACE);
        assert_eq!(theme.border, DEFAULT_BORDER);
        assert_eq!(theme.radius, DEFAULT_RADIUS);
        assert_eq!(theme.font_css_url, None);
        // White reads on the neutral blue.
        assert_eq!(theme.accent_text, "#ffffff");
        let css = brand.stylesheet();
        assert!(css.contains("--cf-bg: #0a0a0b;"), "{css}");
        assert!(css.contains("--cf-radius: 10px;"), "{css}");
    }

    #[test]
    fn a_dark_brand_themes_every_surface() {
        // Alphahunt's own values (issue #840).
        let cfg = MapConfig::from_pairs([
            (ACCENT_KEY, "#D8FF3C"),
            (BACKGROUND_KEY, "#0C0C0D"),
            (TEXT_KEY, "#ECEAE4"),
            (DANGER_KEY, "#FF3B2F"),
            (RADIUS_KEY, "0"),
            (
                FONT_DISPLAY_KEY,
                "\"Archivo Black\", \"Arial Black\", sans-serif",
            ),
            (FONT_BODY_KEY, "Geist, system-ui, sans-serif"),
            (FONT_MONO_KEY, "'JetBrains Mono', ui-monospace, monospace"),
            (
                FONT_CSS_URL_KEY,
                "https://fonts.googleapis.com/css2?family=Archivo+Black&display=swap",
            ),
        ]);
        assert!(
            Brand::problems(&cfg).is_empty(),
            "{:?}",
            Brand::problems(&cfg)
        );
        let brand = Brand::from_config(&cfg, &venture());
        let theme = &brand.theme;
        assert_eq!(theme.scheme, "dark");
        assert_eq!(theme.background, "#0c0c0d");
        assert_eq!(theme.text, "#eceae4");
        assert_eq!(theme.danger, "#ff3b2f");
        assert_eq!(theme.radius, 0);
        // Dark text reads on the lime; the greys are mixed from the two.
        assert_eq!(theme.accent_text, "#0a0a0b");
        assert_ne!(theme.surface, DEFAULT_SURFACE);
        assert!(luminance(&theme.surface) > luminance(&theme.background));
        assert!(luminance(&theme.muted) < luminance(&theme.text));
        let css = brand.stylesheet();
        assert!(css.contains("--cf-accent: #d8ff3c;"), "{css}");
        assert!(
            css.contains("--cf-font-display: \"Archivo Black\""),
            "{css}"
        );
        assert!(css.contains("--cf-radius: 0px;"), "{css}");
    }

    #[test]
    fn a_light_background_picks_the_light_scheme_unless_told_otherwise() {
        let light = MapConfig::from_pairs([(BACKGROUND_KEY, "#ffffff"), (TEXT_KEY, "#111111")]);
        assert_eq!(Brand::from_config(&light, &venture()).theme.scheme, "light");
        let told = MapConfig::from_pairs([(BACKGROUND_KEY, "#ffffff"), (SCHEME_KEY, "dark")]);
        assert_eq!(Brand::from_config(&told, &venture()).theme.scheme, "dark");
    }

    #[test]
    fn nothing_from_a_theme_key_can_leave_the_style_block() {
        let cfg = MapConfig::from_pairs([
            (BACKGROUND_KEY, "red;}body{display:none"),
            (FONT_BODY_KEY, "x;}</style><script>alert(1)</script>"),
            (FONT_MONO_KEY, "\"unclosed"),
            (FONT_CSS_URL_KEY, "http://fonts.example/css"),
            (RADIUS_KEY, "99"),
            (SCHEME_KEY, "dim"),
        ]);
        let problems = Brand::problems(&cfg).join("\n");
        for key in [
            BACKGROUND_KEY,
            FONT_BODY_KEY,
            FONT_MONO_KEY,
            FONT_CSS_URL_KEY,
            RADIUS_KEY,
            SCHEME_KEY,
        ] {
            assert!(problems.contains(key), "{key} not refused: {problems}");
        }
        let brand = Brand::from_config(&cfg, &venture());
        let css = brand.stylesheet();
        assert!(!css.contains("</style"), "{css}");
        assert!(!css.contains("display:none"), "{css}");
        assert_eq!(brand.theme.background, DEFAULT_BACKGROUND);
        assert_eq!(brand.theme.radius, DEFAULT_RADIUS);
        assert_eq!(brand.theme.font_css_url, None);
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
