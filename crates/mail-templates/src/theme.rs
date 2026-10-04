//! [`MailTheme`]: what makes a mail look like the venture's website, and
//! where a module gets it from.

use cratefield_core::{Config, Venture};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The config key a deployment sets to adjust the theme without a rebuild:
/// a JSON object with any subset of [`MailTheme`]'s fields, merged over the
/// composed theme (nested `light`/`dark` objects merge field by field).
pub const THEME_CONFIG_KEY: &str = "MAIL_THEME";

/// The key under which a module puts the resolved theme into the data a
/// mail template receives, so a venture's own override template can use
/// it too.
pub const DATA_THEME: &str = "theme";

/// The key under which a module puts the raw [`THEME_CONFIG_KEY`] object,
/// so a template that carries a composed theme still applies the
/// deployment's adjustments on top of it.
pub const DATA_THEME_OVERRIDE: &str = "theme_override";

/// One colour scheme. Every value is a CSS hex colour (`#rgb`, `#rrggbb`
/// or `#rrggbbaa`); anything else is replaced by the neutral default when
/// the mail is rendered, so a theme from config can never inject CSS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Palette {
    /// The page behind the card.
    pub bg: String,
    /// The card.
    pub card: String,
    /// Card border and rules.
    pub border: String,
    /// Headings and strong text.
    pub ink: String,
    /// Body text.
    pub text: String,
    /// Notes, labels and the footer.
    pub muted: String,
    /// Links and the wordmark's accent.
    pub accent: String,
    /// The primary button.
    pub button: String,
    /// The primary button's label; must contrast with `button`.
    pub button_text: String,
    /// The background of code values (a token, a key prefix).
    pub code_bg: String,
}

macro_rules! setters {
    ($ty:ty { $($field:ident),* $(,)? }) => {
        impl $ty {
            $(
                #[doc = concat!("Sets `", stringify!($field), "`.")]
                #[must_use]
                pub fn $field(mut self, value: impl Into<String>) -> Self {
                    self.$field = value.into();
                    self
                }
            )*
        }
    };
}

setters!(Palette {
    bg,
    card,
    border,
    ink,
    text,
    muted,
    accent,
    button,
    button_text,
    code_bg
});

impl Palette {
    /// The neutral light scheme: zinc greys, an ink button.
    pub fn neutral_light() -> Self {
        Self {
            bg: "#F4F4F5".to_owned(),
            card: "#FFFFFF".to_owned(),
            border: "#E4E4E7".to_owned(),
            ink: "#18181B".to_owned(),
            text: "#3F3F46".to_owned(),
            muted: "#71717A".to_owned(),
            accent: "#18181B".to_owned(),
            button: "#18181B".to_owned(),
            button_text: "#FFFFFF".to_owned(),
            code_bg: "#F4F4F5".to_owned(),
        }
    }

    /// The neutral dark scheme.
    pub fn neutral_dark() -> Self {
        Self {
            bg: "#09090B".to_owned(),
            card: "#18181B".to_owned(),
            border: "#27272A".to_owned(),
            ink: "#FAFAFA".to_owned(),
            text: "#D4D4D8".to_owned(),
            muted: "#A1A1AA".to_owned(),
            accent: "#FAFAFA".to_owned(),
            button: "#FAFAFA".to_owned(),
            button_text: "#18181B".to_owned(),
            code_bg: "#09090B".to_owned(),
        }
    }

    /// Every colour replaced by `fallback`'s where it is not a hex colour.
    pub(crate) fn sanitized(&self, fallback: &Palette) -> Palette {
        let pick = |value: &str, default: &str| {
            if is_hex_colour(value) {
                value.to_owned()
            } else {
                default.to_owned()
            }
        };
        Palette {
            bg: pick(&self.bg, &fallback.bg),
            card: pick(&self.card, &fallback.card),
            border: pick(&self.border, &fallback.border),
            ink: pick(&self.ink, &fallback.ink),
            text: pick(&self.text, &fallback.text),
            muted: pick(&self.muted, &fallback.muted),
            accent: pick(&self.accent, &fallback.accent),
            button: pick(&self.button, &fallback.button),
            button_text: pick(&self.button_text, &fallback.button_text),
            code_bg: pick(&self.code_bg, &fallback.code_bg),
        }
    }
}

impl Default for Palette {
    fn default() -> Self {
        Self::neutral_light()
    }
}

/// How a venture's mail looks: its name and logo, its website's colours in
/// light and dark, its fonts and its footer.
///
/// Build one with [`MailTheme::new`] and the setters, or deserialize one:
/// every field has a default, so a partial JSON object is a theme.
///
/// ```
/// use cratefield_mail_templates::{MailTheme, Palette};
///
/// let theme = MailTheme::new("Owlpost", "https://owlpost.to")
///     .wordmark("owlpost.to")
///     .logo("https://owlpost.to/assets/email/logo-64.png", "Owlpost")
///     .light(Palette::neutral_light().accent("#F4B63F").button("#0E1526"))
///     .footer_line("Owlpost, Bali");
/// assert_eq!(theme.brand_name, "Owlpost");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct MailTheme {
    /// The venture's name as people write it (`FindsYou`): the logo's
    /// fallback alt text and the footer's sign-off.
    pub brand_name: String,
    /// The text beside the logo in the header; empty shows the logo alone
    /// (a logo that already spells the name). With neither, the header
    /// shows `brand_name`.
    pub wordmark: String,
    /// The website, `https://` and no trailing slash: the header links to
    /// it and the footer names it.
    pub site_url: String,
    /// A hosted PNG (never SVG: most clients drop it), shown at
    /// `logo_width`×`logo_height` CSS pixels; host it at twice that size.
    pub logo_url: Option<String>,
    /// The logo's alt text; empty means `brand_name`.
    pub logo_alt: String,
    /// Display width of the logo, CSS pixels.
    pub logo_width: u16,
    /// Display height of the logo, CSS pixels.
    pub logo_height: u16,
    /// A tile colour behind the logo (a mark designed to sit on a dark
    /// square); `None` for no tile.
    pub logo_bg: Option<String>,
    /// The light scheme, the one every client shows by default.
    pub light: Palette,
    /// The scheme for clients that honour `prefers-color-scheme: dark`.
    pub dark: Palette,
    /// The font stack. No web fonts load in mail: name the site's font
    /// first, for readers who have it installed, then a system stack.
    pub font: String,
    /// The monospace stack, for links and codes.
    pub mono: String,
    /// Card corner radius, CSS pixels.
    pub radius: u8,
    /// Button corner radius, CSS pixels.
    pub button_radius: u8,
    /// Lines at the foot of every mail: a postal address, a line about
    /// why people get mail from the venture.
    pub footer: Vec<String>,
    /// Where people write when something looks wrong; shown in the footer.
    pub contact: Option<String>,
}

setters!(MailTheme {
    brand_name,
    wordmark,
    site_url,
    logo_alt,
    font,
    mono
});

impl Default for MailTheme {
    fn default() -> Self {
        Self {
            brand_name: String::new(),
            wordmark: String::new(),
            site_url: String::new(),
            logo_url: None,
            logo_alt: String::new(),
            logo_width: 32,
            logo_height: 32,
            logo_bg: None,
            light: Palette::neutral_light(),
            dark: Palette::neutral_dark(),
            font: "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
                .to_owned(),
            mono: "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace".to_owned(),
            radius: 12,
            button_radius: 8,
            footer: Vec::new(),
            contact: None,
        }
    }
}

impl MailTheme {
    /// The neutral theme for a venture called `brand_name` at `site_url`.
    pub fn new(brand_name: impl Into<String>, site_url: impl Into<String>) -> Self {
        Self {
            brand_name: brand_name.into(),
            site_url: site_url.into(),
            ..Self::default()
        }
    }

    /// The logo and its alt text.
    #[must_use]
    pub fn logo(mut self, url: impl Into<String>, alt: impl Into<String>) -> Self {
        self.logo_url = Some(url.into());
        self.logo_alt = alt.into();
        self
    }

    /// The logo's display size, CSS pixels (default 32×32).
    #[must_use]
    pub fn logo_size(mut self, width: u16, height: u16) -> Self {
        self.logo_width = width;
        self.logo_height = height;
        self
    }

    /// A tile colour behind the logo.
    #[must_use]
    pub fn logo_tile(mut self, colour: impl Into<String>) -> Self {
        self.logo_bg = Some(colour.into());
        self
    }

    /// The light scheme.
    #[must_use]
    pub fn light(mut self, palette: Palette) -> Self {
        self.light = palette;
        self
    }

    /// The dark scheme.
    #[must_use]
    pub fn dark(mut self, palette: Palette) -> Self {
        self.dark = palette;
        self
    }

    /// Card and button corner radii, CSS pixels.
    #[must_use]
    pub fn radii(mut self, card: u8, button: u8) -> Self {
        self.radius = card;
        self.button_radius = button;
        self
    }

    /// Appends one footer line.
    #[must_use]
    pub fn footer_line(mut self, line: impl Into<String>) -> Self {
        self.footer.push(line.into());
        self
    }

    /// The contact address shown in the footer.
    #[must_use]
    pub fn contact(mut self, address: impl Into<String>) -> Self {
        self.contact = Some(address.into());
        self
    }

    /// The name to write in a mail: `brand_name`, or `fallback` (the
    /// venture's config name a module passes) when the theme has none.
    pub fn name_or<'a>(&'a self, fallback: &'a str) -> &'a str {
        if self.brand_name.trim().is_empty() {
            fallback
        } else {
            &self.brand_name
        }
    }

    /// Cratefield's own theme (cratefield.com's tokens): for the control
    /// plane's mail and the Cratefield venture itself, and a worked example
    /// of a theme. Square corners, the blue primary button with ground-
    /// coloured text, warm off-white in light and the site's ground in dark.
    pub fn cratefield() -> Self {
        Self::new("Cratefield", "https://cratefield.com")
            .wordmark("Cratefield")
            .logo(
                "https://cratefield.com/assets/email/logo-64.png",
                "Cratefield",
            )
            .light(Palette {
                bg: "#F4F3EF".to_owned(),
                card: "#FFFFFF".to_owned(),
                border: "#E2E0DA".to_owned(),
                ink: "#0A0A0B".to_owned(),
                text: "#3A3A3F".to_owned(),
                muted: "#6B6B70".to_owned(),
                accent: "#3A5BEF".to_owned(),
                button: "#4C6FFF".to_owned(),
                button_text: "#0A0A0B".to_owned(),
                code_bg: "#F4F3EF".to_owned(),
            })
            .dark(Palette {
                bg: "#0A0A0B".to_owned(),
                card: "#0E0E10".to_owned(),
                border: "#2A2A2E".to_owned(),
                ink: "#EDEBE6".to_owned(),
                text: "#A9A8A5".to_owned(),
                muted: "#8A8A8E".to_owned(),
                accent: "#8FA3FF".to_owned(),
                button: "#4C6FFF".to_owned(),
                button_text: "#0A0A0B".to_owned(),
                code_bg: "#141416".to_owned(),
            })
            .font("Archivo,'Helvetica Neue',Helvetica,Arial,system-ui,sans-serif")
            .mono("'IBM Plex Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace")
            .radii(0, 0)
            .contact("hello@cratefield.com")
    }

    /// The neutral theme a venture gets when it composed none: its name and
    /// public URL, and what its core [`Brand`](cratefield_core::Brand)
    /// already says — the accent for links, the logo, the footer line.
    pub fn for_venture(venture: &Venture) -> Self {
        let mut theme = Self::new(venture.name.clone(), venture.public_url.clone());
        theme.apply_brand(&venture.brand);
        theme
    }

    fn apply_brand(&mut self, brand: &cratefield_core::Brand) {
        if is_hex_colour(&brand.accent) {
            self.light.accent.clone_from(&brand.accent);
            self.dark.accent.clone_from(&brand.accent);
        }
        self.logo_url.clone_from(&brand.logo_url);
        if let Some(footer) = &brand.footer {
            self.footer.push(footer.clone());
        }
    }

    /// The theme for a module that has no composed theme of its own:
    /// [`MailTheme::for_venture`] with the deployment's
    /// [`THEME_CONFIG_KEY`] merged over it.
    pub fn from_config(venture: &Venture, config: &dyn Config) -> Self {
        let base = Self::for_venture(venture);
        match config_override(config) {
            Some(overrides) => base.merged(&overrides),
            None => base,
        }
    }

    /// Parses a JSON object over the [default](MailTheme::default) theme.
    ///
    /// # Errors
    ///
    /// When `json` is not an object of this shape.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// This theme with `overrides` (a JSON object of any subset of the
    /// fields) merged over it. A value of the wrong shape leaves the theme
    /// as it was: a typo in config must not stop mail.
    #[must_use]
    pub fn merged(&self, overrides: &Value) -> Self {
        if !overrides.is_object() {
            return self.clone();
        }
        let Ok(mut base) = serde_json::to_value(self) else {
            return self.clone();
        };
        merge(&mut base, overrides);
        match serde_json::from_value(base) {
            Ok(theme) => theme,
            Err(error) => {
                tracing::warn!(%error, "MAIL_THEME does not fit the theme; ignoring it");
                self.clone()
            }
        }
    }

    /// Sanitized for rendering: colours that are not hex fall back to the
    /// neutral palette, font stacks lose characters that could leave a
    /// CSS declaration, a logo URL that is not `https://` or `http://`
    /// is dropped.
    pub(crate) fn sanitized(&self) -> Self {
        let mut theme = self.clone();
        theme.light = self.light.sanitized(&Palette::neutral_light());
        theme.dark = self.dark.sanitized(&Palette::neutral_dark());
        let defaults = Self::default();
        theme.font = font_stack(&self.font, &defaults.font);
        theme.mono = font_stack(&self.mono, &defaults.mono);
        theme.logo_url = self.logo_url.clone().filter(|url| is_web_url(url));
        theme.logo_bg = self.logo_bg.clone().filter(|c| is_hex_colour(c));
        theme.logo_width = self.logo_width.clamp(8, 280);
        theme.logo_height = self.logo_height.clamp(8, 120);
        theme.radius = self.radius.min(32);
        theme.button_radius = self.button_radius.min(32);
        self.site_url
            .trim_end_matches('/')
            .clone_into(&mut theme.site_url);
        if !is_web_url(&theme.site_url) {
            theme.site_url = String::new();
        }
        theme
    }
}

/// Puts the theme a module resolved from its context into a template's
/// `data`: [`MailTheme::from_config`] under [`DATA_THEME`], and the raw
/// [`THEME_CONFIG_KEY`] object, when set, under [`DATA_THEME_OVERRIDE`].
/// `data` that is not an object is left alone.
pub fn attach_theme(data: &mut Value, venture: &Venture, config: &dyn Config) {
    let theme = MailTheme::from_config(venture, config);
    let overrides = config_override(config);
    if let Value::Object(map) = data {
        if let Ok(theme) = serde_json::to_value(theme) {
            map.insert(DATA_THEME.to_owned(), theme);
        }
        if let Some(overrides) = overrides {
            map.insert(DATA_THEME_OVERRIDE.to_owned(), overrides);
        }
    }
}

/// The theme a template renders with: the theme it was composed with
/// (`themed_templates(&theme)` in each module) with the deployment's
/// override applied, else the theme the module attached to `data`, else
/// the neutral default.
pub fn theme_for_template(composed: Option<&MailTheme>, data: &Value) -> MailTheme {
    if let Some(theme) = composed {
        return match data.get(DATA_THEME_OVERRIDE) {
            Some(overrides) => theme.merged(overrides),
            None => theme.clone(),
        };
    }
    if let Some(theme) = data
        .get(DATA_THEME)
        .and_then(|theme| serde_json::from_value(theme.clone()).ok())
    {
        return theme;
    }
    // Data a module built before themes existed: what its `venture` and
    // core `brand` fields say, as `for_venture` would.
    let name = data
        .get("venture")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut theme = MailTheme::new(name, "");
    if let Some(brand) = data
        .get("brand")
        .and_then(|brand| serde_json::from_value::<cratefield_core::Brand>(brand.clone()).ok())
    {
        theme.apply_brand(&brand);
    }
    theme
}

fn config_override(config: &dyn Config) -> Option<Value> {
    let raw = config.get(THEME_CONFIG_KEY)?;
    if raw.trim().is_empty() {
        return None;
    }
    match serde_json::from_str::<Value>(&raw) {
        Ok(value) if value.is_object() => Some(value),
        _ => {
            tracing::warn!("MAIL_THEME is not a JSON object; ignoring it");
            None
        }
    }
}

fn merge(base: &mut Value, overrides: &Value) {
    match (base, overrides) {
        (Value::Object(base), Value::Object(overrides)) => {
            for (key, value) in overrides {
                match base.get_mut(key) {
                    Some(slot) if slot.is_object() && value.is_object() => merge(slot, value),
                    _ => {
                        base.insert(key.clone(), value.clone());
                    }
                }
            }
        }
        (base, overrides) => *base = overrides.clone(),
    }
}

/// `#rgb`, `#rgba`, `#rrggbb` or `#rrggbbaa`.
pub(crate) fn is_hex_colour(value: &str) -> bool {
    let Some(hex) = value.strip_prefix('#') else {
        return false;
    };
    matches!(hex.len(), 3 | 4 | 6 | 8) && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

pub(crate) fn is_web_url(value: &str) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    (lower.starts_with("https://") || lower.starts_with("http://")) && lower.len() > 8
}

/// Keeps letters, digits, spaces, commas, hyphens, dots and single quotes;
/// a double quote becomes a single one (the stack sits in a double-quoted
/// attribute). Empty after that means the default.
fn font_stack(value: &str, default: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|c| if c == '"' { '\'' } else { c })
        .filter(|c| c.is_alphanumeric() || matches!(c, ' ' | ',' | '-' | '.' | '\'' | '_'))
        .collect();
    if cleaned.trim().is_empty() {
        default.to_owned()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::{Brand, MapConfig};
    use serde_json::json;

    fn venture() -> Venture {
        Venture::new("acme", "acme.test").brand(Brand {
            accent: "#123456".to_owned(),
            logo_url: Some("https://acme.test/logo.png".to_owned()),
            footer: Some("Acme, 1 Road".to_owned()),
        })
    }

    #[test]
    fn the_venture_default_carries_its_brand() {
        let theme = MailTheme::for_venture(&venture());
        assert_eq!(theme.brand_name, "acme");
        assert_eq!(theme.site_url, "https://acme.test");
        assert_eq!(theme.light.accent, "#123456");
        assert_eq!(
            theme.logo_url.as_deref(),
            Some("https://acme.test/logo.png")
        );
        assert_eq!(theme.footer, vec!["Acme, 1 Road".to_owned()]);
    }

    #[test]
    fn config_merges_field_by_field_and_a_bad_value_changes_nothing() {
        let cfg = MapConfig::from_pairs([(
            THEME_CONFIG_KEY,
            r##"{"brand_name":"Acme","light":{"button":"#FF0000"}}"##,
        )]);
        let theme = MailTheme::from_config(&venture(), &cfg);
        assert_eq!(theme.brand_name, "Acme");
        assert_eq!(theme.light.button, "#FF0000");
        // Untouched siblings survive the nested merge.
        assert_eq!(theme.light.accent, "#123456");

        for raw in ["not json", "[1,2]", r#"{"radius":"big"}"#] {
            let cfg = MapConfig::from_pairs([(THEME_CONFIG_KEY, raw)]);
            assert_eq!(
                MailTheme::from_config(&venture(), &cfg),
                MailTheme::for_venture(&venture()),
                "{raw}"
            );
        }
    }

    #[test]
    fn a_composed_theme_wins_and_the_deployment_override_still_applies() {
        let composed = MailTheme::new("Composed", "https://composed.test");
        let cfg =
            MapConfig::from_pairs([(THEME_CONFIG_KEY, r##"{"light":{"accent":"#00FF00"}}"##)]);
        let mut data = json!({ "venture": "acme" });
        attach_theme(&mut data, &venture(), &cfg);

        let from_data = theme_for_template(None, &data);
        assert_eq!(from_data.brand_name, "acme");
        assert_eq!(from_data.light.accent, "#00FF00");

        let themed = theme_for_template(Some(&composed), &data);
        assert_eq!(themed.brand_name, "Composed");
        assert_eq!(themed.light.accent, "#00FF00");

        assert_eq!(theme_for_template(None, &json!({})), MailTheme::default());
        // Data from before themes: the venture name and core brand.
        let legacy = theme_for_template(
            None,
            &json!({ "venture": "acme", "brand": { "accent": "#ABCDEF", "logo_url": null, "footer": "Acme, 1 Road" } }),
        );
        assert_eq!(legacy.brand_name, "acme");
        assert_eq!(legacy.light.accent, "#ABCDEF");
        assert_eq!(legacy.footer, vec!["Acme, 1 Road".to_owned()]);
    }

    #[test]
    fn sanitizing_refuses_css_injection_through_a_theme() {
        let theme = MailTheme::new("x", "javascript:alert(1)")
            .light(Palette::neutral_light().bg("red;background:url(https://evil.test/p)"))
            .font("x\";background:url(evil)")
            .logo("javascript:alert(1)", "x")
            .logo_tile("expression(alert(1))")
            .sanitized();
        assert_eq!(theme.light.bg, Palette::neutral_light().bg);
        assert!(
            !theme.font.contains(';') && !theme.font.contains('"') && !theme.font.contains('(')
        );
        assert_eq!(theme.logo_url, None);
        assert_eq!(theme.logo_bg, None);
        assert_eq!(theme.site_url, "");
    }

    #[test]
    fn hex_colours() {
        for ok in ["#fff", "#FFFF", "#a1b2c3", "#a1b2c3d4"] {
            assert!(is_hex_colour(ok), "{ok}");
        }
        for bad in ["fff", "#ggg", "#12345", "red", "#fff;"] {
            assert!(!is_hex_colour(bad), "{bad}");
        }
    }
}
