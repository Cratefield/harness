//! Branded transactional mail for Cratefield ventures: one email-client-safe
//! layout, themed with the venture's own website colours, logo and fonts,
//! and a plain-text twin for every message.
//!
//! Two parts:
//!
//! - [`MailTheme`] — brand name, wordmark, hosted logo and alt text,
//!   light and dark [`Palette`]s, font stacks, footer lines. Modules get it
//!   from the venture's composition (`themed_templates(&theme)` on each
//!   mail-sending module), the deployment's `MAIL_THEME` config (merged
//!   on top), or — with neither — [`MailTheme::for_venture`], a neutral
//!   theme built from the venture's name, public URL and core `Brand`.
//! - [`Message`] — a builder for one mail: heading, paragraphs, facts, a
//!   primary button with its fallback link, a code value, notes and the
//!   footer. [`Message::render`] returns an [`Email`] with the HTML and the
//!   text part.
//!
//! ```
//! use cratefield_mail_templates::{MailTheme, Message};
//!
//! let theme = MailTheme::new("Acme", "https://acme.test");
//! let email = Message::new("Sign in to Acme", "Sign in to Acme")
//!     .preheader("This link works once, for 15 minutes.")
//!     .paragraph("Use the button below to sign in.")
//!     .button("Sign in", "https://api.acme.test/v1/auth-magic-link/consume?token=abc")
//!     .fallback_link()
//!     .note("If you didn't ask for this, ignore this email.")
//!     .recipient("ada@example.com")
//!     .why("someone asked to sign in to Acme with this address")
//!     .render(&theme);
//! assert!(email.html.contains("consume?token=abc"));
//! assert!(email.text.contains("consume?token=abc"));
//! ```
//!
//! **Email-client safety.** Table layout, every style inline (the single
//! `<style>` block only adds the narrow-screen and `prefers-color-scheme:
//! dark` overrides, which clients without `<style>` support skip), no web
//! fonts, no tracking pixel, no click tracking, `lang` and `dir` on the
//! document. The only image is the theme's hosted logo, with alt text; the
//! layout reads the same without it.
//!
//! **Escaping.** Every value — the builder's text, the theme's strings and
//! anything a person typed — reaches the HTML through [`escape`], and the
//! text part with control characters removed, so no value can add markup
//! or forge a line. Theme colours and fonts are checked before they reach a
//! `style` attribute, and only `https:`, `http:` and `mailto:` URLs become
//! links.

#![forbid(unsafe_code)]

mod theme;

use std::fmt::Write as _;

pub use theme::{
    DATA_THEME, DATA_THEME_OVERRIDE, MailTheme, Palette, THEME_CONFIG_KEY, attach_theme,
    theme_for_template,
};

/// One rendered mail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email {
    /// The `Subject:` header.
    pub subject: String,
    /// The preview line most inboxes show beside the subject; also the
    /// hidden first line of the HTML.
    pub preheader: String,
    /// The `text/plain` part.
    pub text: String,
    /// The `text/html` part.
    pub html: String,
}

impl From<Email> for cratefield_core::Rendered {
    fn from(email: Email) -> Self {
        Self {
            subject: email.subject,
            html: email.html,
            text: email.text,
        }
    }
}

/// Escapes text for HTML element content and quoted attribute values.
/// Control characters become spaces.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// A value for the text part or a header: control characters (a newline
/// in a name, say) become spaces, so no value can forge a line.
pub fn plain(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Whether `url` may be a link: `https:`, `http:` or `mailto:`. Anything
/// else (`javascript:`, `data:`, a relative path that means nothing in an
/// inbox) is shown as text instead.
pub fn is_linkable(url: &str) -> bool {
    let lower = url.trim_start().to_ascii_lowercase();
    lower.starts_with("https://") || lower.starts_with("http://") || lower.starts_with("mailto:")
}

/// Text direction of the mail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Dir {
    /// Left to right.
    #[default]
    Ltr,
    /// Right to left.
    Rtl,
}

impl Dir {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ltr => "ltr",
            Self::Rtl => "rtl",
        }
    }
}

#[derive(Debug, Clone)]
struct Fact {
    label: String,
    value: String,
    code: bool,
}

/// One mail, built up and then [rendered](Message::render) with a theme.
#[derive(Debug, Clone)]
#[must_use]
pub struct Message {
    subject: String,
    heading: String,
    preheader: String,
    lang: String,
    dir: Dir,
    paragraphs: Vec<String>,
    facts: Vec<Fact>,
    button: Option<(String, String)>,
    fallback_link: bool,
    link_intro: String,
    code: Option<(String, String)>,
    notes: Vec<String>,
    recipient: Option<String>,
    why: Option<String>,
    footer_links: Vec<(String, String)>,
}

impl Message {
    /// A mail with this subject and heading, in English, left to right.
    pub fn new(subject: impl Into<String>, heading: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            heading: heading.into(),
            preheader: String::new(),
            lang: "en".to_owned(),
            dir: Dir::Ltr,
            paragraphs: Vec::new(),
            facts: Vec::new(),
            button: None,
            fallback_link: false,
            link_intro: "Or paste this link into your browser:".to_owned(),
            code: None,
            notes: Vec::new(),
            recipient: None,
            why: None,
            footer_links: Vec::new(),
        }
    }

    /// The preview line inboxes show beside the subject.
    pub fn preheader(mut self, text: impl Into<String>) -> Self {
        self.preheader = text.into();
        self
    }

    /// The document language, a BCP 47 tag (default `en`).
    pub fn lang(mut self, tag: impl Into<String>) -> Self {
        self.lang = tag.into();
        self
    }

    /// The text direction (default left to right).
    pub fn dir(mut self, dir: Dir) -> Self {
        self.dir = dir;
        self
    }

    /// Appends a paragraph of body text.
    pub fn paragraph(mut self, text: impl Into<String>) -> Self {
        self.paragraphs.push(text.into());
        self
    }

    /// Appends a labelled value (`Organization: Acme`).
    pub fn fact(mut self, label: impl Into<String>, value: impl Into<String>) -> Self {
        self.facts.push(Fact {
            label: label.into(),
            value: value.into(),
            code: false,
        });
        self
    }

    /// Appends a labelled value shown as code (a key prefix, a URL that
    /// should be read, not clicked).
    pub fn code_fact(mut self, label: impl Into<String>, value: impl Into<String>) -> Self {
        self.facts.push(Fact {
            label: label.into(),
            value: value.into(),
            code: true,
        });
        self
    }

    /// The primary button. One per mail.
    pub fn button(mut self, label: impl Into<String>, url: impl Into<String>) -> Self {
        self.button = Some((label.into(), url.into()));
        self
    }

    /// Also prints the button's URL as text, for clients that strip links
    /// and people who would rather paste.
    pub fn fallback_link(mut self) -> Self {
        self.fallback_link = true;
        self
    }

    /// The sentence before the fallback link (default "Or paste this link
    /// into your browser:").
    pub fn link_intro(mut self, text: impl Into<String>) -> Self {
        self.link_intro = text.into();
        self
    }

    /// A code to copy by hand (an invitation token), after `intro`.
    pub fn code(mut self, intro: impl Into<String>, value: impl Into<String>) -> Self {
        self.code = Some((intro.into(), value.into()));
        self
    }

    /// Appends a muted note under a rule: link expiry, "ignore this if you
    /// didn't ask".
    pub fn note(mut self, text: impl Into<String>) -> Self {
        self.notes.push(text.into());
        self
    }

    /// The address the mail goes to, named in the footer.
    pub fn recipient(mut self, address: impl Into<String>) -> Self {
        self.recipient = Some(address.into());
        self
    }

    /// Why this person got this mail, completing "Sent to … because …".
    pub fn why(mut self, reason: impl Into<String>) -> Self {
        self.why = Some(reason.into());
        self
    }

    /// Appends a footer link (unsubscribe, preferences).
    pub fn footer_link(mut self, label: impl Into<String>, url: impl Into<String>) -> Self {
        self.footer_links.push((label.into(), url.into()));
        self
    }

    /// Renders the HTML and text parts with `theme`.
    pub fn render(&self, theme: &MailTheme) -> Email {
        let theme = theme.sanitized();
        Email {
            subject: plain(&self.subject),
            preheader: plain(&self.preheader),
            text: self.render_text(&theme),
            html: self.render_html(&theme),
        }
    }

    fn footer_sentence(&self) -> Option<String> {
        match (&self.recipient, &self.why) {
            (Some(to), Some(why)) => Some(format!("Sent to {to} because {why}.")),
            (Some(to), None) => Some(format!("This mail was sent to {to}.")),
            (None, Some(why)) => Some(format!("You are receiving this because {why}.")),
            (None, None) => None,
        }
    }

    fn render_text(&self, theme: &MailTheme) -> String {
        let mut t = String::new();
        let _ = writeln!(t, "{}\n", plain(&self.heading));
        for p in &self.paragraphs {
            let _ = writeln!(t, "{}\n", plain(p));
        }
        if !self.facts.is_empty() {
            for f in &self.facts {
                let _ = writeln!(t, "{}: {}", plain(&f.label), plain(&f.value));
            }
            t.push('\n');
        }
        if let Some((label, url)) = &self.button {
            let _ = writeln!(t, "{}:\n{}\n", plain(label), plain(url));
        }
        if let Some((intro, value)) = &self.code {
            let _ = writeln!(t, "{}\n{}\n", plain(intro), plain(value));
        }
        for n in &self.notes {
            let _ = writeln!(t, "{}\n", plain(n));
        }
        t.push_str("--\n");
        if let Some(sentence) = self.footer_sentence() {
            let _ = writeln!(t, "{}", plain(&sentence));
        }
        for (label, url) in &self.footer_links {
            let _ = writeln!(t, "{}:\n{}", plain(label), plain(url));
        }
        for line in &theme.footer {
            let _ = writeln!(t, "{}", plain(line));
        }
        let mut sign_off = Vec::new();
        if !theme.brand_name.is_empty() {
            sign_off.push(plain(&theme.brand_name));
        }
        if !theme.site_url.is_empty() {
            sign_off.push(plain(&theme.site_url));
        }
        if let Some(contact) = &theme.contact {
            sign_off.push(plain(contact));
        }
        if !sign_off.is_empty() {
            let _ = writeln!(t, "{}", sign_off.join(" · "));
        }
        t
    }

    #[allow(clippy::too_many_lines, reason = "one email layout, top to bottom")]
    fn render_html(&self, theme: &MailTheme) -> String {
        let e = escape;
        let l = &theme.light;
        let font = &theme.font;
        let mono = &theme.mono;
        let mut h = String::with_capacity(8 * 1024);
        let _ = write!(
            h,
            "<!doctype html>\
<html lang=\"{lang}\" dir=\"{dir}\" xmlns=\"http://www.w3.org/1999/xhtml\">\
<head>\
<meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<meta name=\"x-apple-disable-message-reformatting\">\
<meta name=\"format-detection\" content=\"telephone=no,address=no,email=no,date=no,url=no\">\
<meta name=\"color-scheme\" content=\"light dark\">\
<meta name=\"supported-color-schemes\" content=\"light dark\">\
<title>{title}</title>\
<style>{style}</style>\
</head>\
<body class=\"cf-bg\" style=\"margin:0;padding:0;background:{bg};-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%\">",
            lang = e(&self.lang),
            dir = self.dir.as_str(),
            title = e(&self.subject),
            style = head_style(theme),
            bg = l.bg,
        );
        if !self.preheader.is_empty() {
            // Padded so clients don't pull body text into the preview.
            let _ = write!(
                h,
                "<div style=\"display:none;max-height:0;max-width:0;overflow:hidden;opacity:0;mso-hide:all;\
font-size:1px;line-height:1px;color:{bg}\">{}{}</div>",
                e(&self.preheader),
                "&#847;&zwnj;&nbsp;".repeat(60),
                bg = l.bg,
            );
        }
        let _ = write!(
            h,
            "<table role=\"presentation\" class=\"cf-bg\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" \
style=\"background:{bg};border-collapse:collapse\"><tr>\
<td class=\"cf-outer\" align=\"center\" style=\"padding:32px 16px\">\
<!--[if mso]><table role=\"presentation\" width=\"600\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\"><tr><td><![endif]-->\
<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" \
style=\"max-width:600px;border-collapse:separate\">",
            bg = l.bg,
        );
        let banded = Self::write_brand_row(&mut h, theme);
        // The card. Under a header band it joins the band: no top border,
        // no top corners.
        let card_edges = if banded {
            format!(
                "border:1px solid {border};border-top:0;border-radius:0 0 {r}px {r}px",
                border = l.border,
                r = theme.radius,
            )
        } else {
            format!(
                "border:1px solid {border};border-radius:{r}px",
                border = l.border,
                r = theme.radius,
            )
        };
        let _ = write!(
            h,
            "<tr><td class=\"cf-card\" bgcolor=\"{card}\" \
style=\"background:{card};{card_edges};padding:36px 40px;font-family:{font}\">\
<h1 class=\"cf-h1 cf-ink\" style=\"margin:0 0 16px;font-family:{display};font-size:26px;line-height:32px;font-weight:700;letter-spacing:-0.4px;color:{ink}\">{heading}</h1>",
            card = l.card,
            display = theme.display_font,
            ink = l.ink,
            heading = e(&self.heading),
        );
        for p in &self.paragraphs {
            let _ = write!(
                h,
                "<p class=\"cf-text\" style=\"margin:0 0 20px;font-family:{font};font-size:16px;line-height:24px;color:{text}\">{}</p>",
                e(p),
                text = l.text,
            );
        }
        if !self.facts.is_empty() {
            h.push_str(
                "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"margin:0 0 24px;border-collapse:collapse\">",
            );
            for f in &self.facts {
                let value = if f.code {
                    code_span(theme, &f.value)
                } else {
                    e(&f.value)
                };
                let _ = write!(
                    h,
                    "<tr>\
<td class=\"cf-fact-l cf-mut\" width=\"132\" valign=\"top\" style=\"width:132px;padding:6px 12px 6px 0;font-family:{font};font-size:14px;line-height:22px;color:{muted}\">{label}</td>\
<td class=\"cf-fact-v cf-ink\" valign=\"top\" style=\"padding:6px 0;font-family:{font};font-size:15px;line-height:22px;color:{ink};word-break:break-word\">{value}</td>\
</tr>",
                    label = e(&f.label),
                    muted = l.muted,
                    ink = l.ink,
                );
            }
            h.push_str("</table>");
        }
        if let Some((label, url)) = &self.button {
            if is_linkable(url) {
                let _ = write!(
                    h,
                    "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"margin:4px 0 24px\"><tr>\
<td class=\"cf-btn\" bgcolor=\"{button}\" style=\"border-radius:{r}px;background:{button}\">\
<a class=\"cf-btn-a\" href=\"{url}\" target=\"_blank\" rel=\"noopener\" style=\"display:inline-block;padding:14px 24px;font-family:{font};font-size:16px;line-height:20px;font-weight:700;color:{button_text};text-decoration:none;border-radius:{r}px\">{label}</a>\
</td></tr></table>",
                    button = l.button,
                    button_text = l.button_text,
                    r = theme.button_radius,
                    url = e(url),
                    label = e(label),
                );
            }
            if self.fallback_link || !is_linkable(url) {
                let shown = if is_linkable(url) {
                    format!(
                        "<a class=\"cf-link\" href=\"{u}\" style=\"color:{accent};text-decoration:underline\">{u}</a>",
                        u = e(url),
                        accent = l.accent,
                    )
                } else {
                    format!(
                        "<span class=\"cf-ink\" style=\"color:{}\">{}</span>",
                        l.ink,
                        e(url)
                    )
                };
                let _ = write!(
                    h,
                    "<p class=\"cf-mut\" style=\"margin:0 0 6px;font-family:{font};font-size:14px;line-height:20px;color:{muted}\">{intro}</p>\
<p style=\"margin:0 0 24px;font-family:{mono};font-size:13px;line-height:20px;word-break:break-all;overflow-wrap:anywhere\">{shown}</p>",
                    intro = e(if is_linkable(url) {
                        &self.link_intro
                    } else {
                        label
                    }),
                    muted = l.muted,
                );
            }
        }
        if let Some((intro, value)) = &self.code {
            let _ = write!(
                h,
                "<p class=\"cf-mut\" style=\"margin:0 0 6px;font-family:{font};font-size:14px;line-height:20px;color:{muted}\">{intro}</p>\
<p style=\"margin:0 0 24px\">{code}</p>",
                intro = e(intro),
                code = code_span(theme, value),
                muted = l.muted,
            );
        }
        if !self.notes.is_empty() {
            let _ = write!(
                h,
                "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\"><tr>\
<td class=\"cf-rule\" style=\"border-top:1px solid {border};padding-top:20px\">",
                border = l.border,
            );
            for n in &self.notes {
                let _ = write!(
                    h,
                    "<p class=\"cf-mut\" style=\"margin:0 0 8px;font-family:{font};font-size:14px;line-height:21px;color:{muted}\">{}</p>",
                    e(n),
                    muted = l.muted,
                );
            }
            h.push_str("</td></tr></table>");
        }
        h.push_str("</td></tr>");
        self.write_footer(&mut h, theme);
        h.push_str(
            "</table><!--[if mso]></td></tr></table><![endif]--></td></tr></table></body></html>\n",
        );
        // A line break after each block, so the source (and its snapshot)
        // reads line by line. Values are escaped, so none of these tags can
        // appear inside them.
        [
            "</head>", "</div>", "<tr>", "</tr>", "</h1>", "</p>", "</style>",
        ]
        .iter()
        .fold(h, |h, tag| h.replace(tag, &format!("{tag}\n")))
    }

    /// The logo row; `true` when it was drawn as a header band.
    fn write_brand_row(h: &mut String, theme: &MailTheme) -> bool {
        let e = escape;
        let l = &theme.light;
        let font = &theme.font;
        let label = if theme.wordmark.is_empty() && theme.logo_url.is_none() {
            theme.brand_name.as_str()
        } else {
            theme.wordmark.as_str()
        };
        if label.is_empty() && theme.logo_url.is_none() {
            return false;
        }
        let band = theme.header_bg.as_deref();
        let label_ink = theme.header_text.as_deref().unwrap_or(&l.ink);
        let mut inner = String::from(
            "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\"><tr>",
        );
        if let Some(logo) = &theme.logo_url {
            let (w, hgt) = (theme.logo_width, theme.logo_height);
            let alt = if theme.logo_alt.is_empty() {
                &theme.brand_name
            } else {
                &theme.logo_alt
            };
            let tile = theme
                .logo_bg
                .as_deref()
                .map_or_else(String::new, |bg| format!(" bgcolor=\"{bg}\""));
            let tile_style = theme.logo_bg.as_deref().map_or_else(String::new, |bg| {
                format!("background:{bg};border-radius:{}px;", (hgt / 4).min(12))
            });
            let _ = write!(
                inner,
                "<td width=\"{w}\" height=\"{hgt}\"{tile} style=\"width:{w}px;height:{hgt}px;{tile_style}\">\
<img src=\"{src}\" width=\"{w}\" height=\"{hgt}\" alt=\"{alt}\" \
style=\"display:block;width:{w}px;height:{hgt}px;border:0;outline:none;text-decoration:none;color:{ink};font-family:{font};font-size:12px;line-height:{hgt}px;font-weight:700\">\
</td>",
                src = e(logo),
                alt = e(alt),
                ink = l.ink,
            );
        }
        if !label.is_empty() {
            let pad = if theme.logo_url.is_some() {
                "padding-left:10px;"
            } else {
                ""
            };
            // On a band the wordmark keeps the band's colour in both
            // schemes, so it loses the class the dark scheme repaints.
            let _ = write!(
                inner,
                "<td{class} style=\"{pad}font-family:{display};font-size:20px;line-height:32px;font-weight:700;letter-spacing:-0.5px;color:{ink}\">{label}</td>",
                class = if band.is_some() {
                    ""
                } else {
                    " class=\"cf-ink\""
                },
                display = theme.display_font,
                ink = if band.is_some() { label_ink } else { &l.ink },
                label = e(label),
            );
        }
        inner.push_str("</tr></table>");
        let row = if theme.site_url.is_empty() {
            inner
        } else {
            format!(
                "<a href=\"{site}/\" style=\"text-decoration:none;color:{ink}\">{inner}</a>",
                site = e(&theme.site_url),
                ink = l.ink,
            )
        };
        if let Some(bg) = band {
            let r = theme.radius;
            let _ = write!(
                h,
                "<tr><td class=\"cf-band\" bgcolor=\"{bg}\" style=\"background:{bg};padding:20px 40px;border-radius:{r}px {r}px 0 0\">{row}</td></tr>"
            );
            true
        } else {
            let _ = write!(h, "<tr><td style=\"padding:0 4px 20px\">{row}</td></tr>");
            false
        }
    }

    fn write_footer(&self, h: &mut String, theme: &MailTheme) {
        let e = escape;
        let l = &theme.light;
        let muted = &l.muted;
        let link = |label: &str, url: &str| {
            if is_linkable(url) {
                format!(
                    "<a class=\"cf-mut\" href=\"{}\" style=\"color:{muted};text-decoration:underline\">{}</a>",
                    e(url),
                    e(label)
                )
            } else {
                e(label)
            }
        };
        let mut lines = Vec::new();
        if let Some(sentence) = self.footer_sentence() {
            lines.push(e(&sentence));
        }
        if !self.footer_links.is_empty() {
            lines.push(
                self.footer_links
                    .iter()
                    .map(|(label, url)| link(label, url))
                    .collect::<Vec<_>>()
                    .join(" &middot; "),
            );
        }
        for line in &theme.footer {
            lines.push(e(line));
        }
        let mut sign_off = Vec::new();
        if !theme.brand_name.is_empty() {
            sign_off.push(e(&theme.brand_name));
        }
        if !theme.site_url.is_empty() {
            let host = theme
                .site_url
                .trim_start_matches("https://")
                .trim_start_matches("http://");
            sign_off.push(link(host, &format!("{}/", theme.site_url)));
        }
        if let Some(contact) = &theme.contact {
            sign_off.push(link(contact, &format!("mailto:{contact}")));
        }
        if !sign_off.is_empty() {
            lines.push(sign_off.join(" &middot; "));
        }
        if lines.is_empty() {
            return;
        }
        let _ = write!(
            h,
            "<tr><td class=\"cf-mut\" style=\"padding:24px 8px 0;font-family:{font};font-size:13px;line-height:20px;color:{muted}\">",
            font = theme.font,
        );
        let last = lines.len() - 1;
        for (i, line) in lines.iter().enumerate() {
            let margin = if i == last { "0" } else { "0 0 6px" };
            let _ = write!(h, "<p style=\"margin:{margin}\">{line}</p>");
        }
        h.push_str("</td></tr>");
    }
}

fn code_span(theme: &MailTheme, value: &str) -> String {
    let l = &theme.light;
    format!(
        "<span class=\"cf-code\" style=\"display:inline-block;max-width:100%;padding:2px 8px;\
border:1px solid {border};border-radius:{r}px;background:{code_bg};font-family:{mono};font-size:14px;line-height:22px;\
color:{ink};word-break:break-all;overflow-wrap:anywhere\">{v}</span>",
        border = l.border,
        code_bg = l.code_bg,
        mono = theme.mono,
        ink = l.ink,
        r = theme.button_radius.min(6),
        v = escape(value),
    )
}

/// The narrow-screen and dark-mode overrides. Only classes; every base
/// style is inline. Colours are sanitized hex values.
fn head_style(theme: &MailTheme) -> String {
    let d = &theme.dark;
    format!(
        "body{{margin:0!important;padding:0!important;width:100%!important}}\
a[x-apple-data-detectors]{{color:inherit!important;text-decoration:none!important}}\
@media (max-width:620px){{\
.cf-outer{{padding:20px 12px!important}}\
.cf-card{{padding:28px 20px!important}}\
.cf-h1{{font-size:22px!important;line-height:28px!important}}\
}}\
@media (max-width:480px){{\
.cf-fact-l{{display:block!important;width:auto!important;padding:0 0 2px!important}}\
.cf-fact-v{{display:block!important;padding:0 0 12px!important}}\
}}\
@media (prefers-color-scheme:dark){{\
.cf-bg{{background:{bg}!important}}\
.cf-card{{background:{card}!important;border-color:{border}!important}}\
.cf-ink{{color:{ink}!important}}\
.cf-text{{color:{text}!important}}\
.cf-mut{{color:{muted}!important}}\
.cf-code{{background:{code_bg}!important;color:{ink}!important;border-color:{border}!important}}\
.cf-rule{{border-color:{border}!important}}\
.cf-btn{{background:{button}!important}}\
.cf-btn-a{{color:{button_text}!important}}\
.cf-link{{color:{accent}!important}}\
}}",
        bg = d.bg,
        card = d.card,
        border = d.border,
        ink = d.ink,
        text = d.text,
        muted = d.muted,
        code_bg = d.code_bg,
        button = d.button,
        button_text = d.button_text,
        accent = d.accent,
    ) + if theme.header_bg.is_some() {
        // The band narrows with the card on a phone.
        "@media (max-width:620px){.cf-band{padding:16px 20px!important}}"
    } else {
        ""
    }
}

/// Representative messages with sample values: what `render-emails`
/// writes for a theme and what the snapshots cover.
pub fn samples() -> Vec<(&'static str, Message)> {
    let link =
        "https://api.acme.test/v1/auth-magic-link/consume?token=Jx3mQ9vT0cWb8nL2kPz7rY5sHd1fGa4e";
    vec![
        (
            "sign-in",
            Message::new("Sign in to Acme", "Sign in to Acme")
                .preheader(
                    "This link works once, for 15 minutes. If you didn't ask for it, ignore this email.",
                )
                .paragraph("Use the button below to sign in to Acme.")
                .button("Sign in", link)
                .fallback_link()
                .note("This link works once and expires in 15 minutes.")
                .note(
                    "If you didn't ask to sign in, ignore this email: nobody can use the link \
                     without opening it, and it expires on its own.",
                )
                .recipient("ada@example.com")
                .why("someone asked to sign in to Acme with this address"),
        ),
        (
            "invitation",
            Message::new("You have been invited to join Analytical Engines", "You're invited")
                .preheader("Join Analytical Engines on Acme as admin.")
                .paragraph("You have been invited to join an organization on Acme.")
                .fact("Organization", "Analytical Engines")
                .fact("Role", "admin")
                .button(
                    "Accept the invitation",
                    "https://api.acme.test/v1/orgs/invitations/accept?token=01J9ZQ4M8K2D7X3B",
                )
                .code(
                    "Or paste this token into the accept page:",
                    "01J9ZQ4M8K2D7X3B6N5R0T1V2W",
                )
                .note("This invitation expires in 7 days.")
                .recipient("ada@example.com")
                .why("someone invited this address to an organization on Acme"),
        ),
        (
            "notification",
            Message::new("Your export is ready", "Your export is ready")
                .preheader("The CSV of your March orders is ready to download.")
                .paragraph("The CSV of your March orders is ready to download.")
                .button("Open", "https://acme.test/exports/42")
                .footer_link(
                    "Stop receiving these",
                    "https://api.acme.test/v1/notifications/unsubscribe?t=abc",
                )
                .footer_link(
                    "stop all notification email",
                    "https://api.acme.test/v1/notifications/unsubscribe?t=all",
                ),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_covers_markup_quotes_and_control_characters() {
        assert_eq!(
            escape("<a href=\"x\" onclick='y'>&</a>"),
            "&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;&lt;/a&gt;"
        );
        assert_eq!(escape("a\r\nb"), "a  b");
        assert_eq!(plain("a\r\nBcc: x"), "a  Bcc: x");
    }

    #[test]
    fn only_web_and_mailto_urls_are_links() {
        assert!(is_linkable("https://a.test/x"));
        assert!(is_linkable("mailto:a@b.test"));
        assert!(!is_linkable("javascript:alert(1)"));
        assert!(!is_linkable(" JavaScript:alert(1)"));
        assert!(!is_linkable("/relative"));
    }
}
