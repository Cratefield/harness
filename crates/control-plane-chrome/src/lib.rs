//! The control plane's own page chrome.
//!
//! Every control-plane screen — the console, the wizard, the dashboard —
//! renders server-side HTML from inside a Worker, and each one was free to
//! invent its own look. This crate is the one they share: the stylesheet,
//! the masthead, the page shell and the small vocabulary of status chips
//! and escaping helpers that every screen needs.
//!
//! The look is **cratefield.com's**, so the product a customer signs in to
//! resembles the site they signed up from: the same ground and panels, the
//! same single accent, the same mono-uppercase labels, and the same
//! `.dash__*` class names as the preview published at `/dashboard/`.
//! Ported rather than imported — the site is a separate repository and a
//! static build, and a Worker cannot link its stylesheet.
//!
//! This is deliberately **not** `cratefield-ui`'s `cf.css`. That one is
//! venture-facing: it renders a customer's own signup form inside the
//! customer's own site, and its own comments say it must not drag a colour
//! scheme in with it. This one is Cratefield's surface and is branded on
//! purpose.
//!
//! Mount [`Chrome`] once in the composition; every other screen links
//! [`STYLESHEET_PATH`].

#![forbid(unsafe_code)]

use axum::response::{IntoResponse, Response};
use axum::routing::get;
use cratefield_core::{Migrations, Module, ModuleContext, Port};
use http::{StatusCode, header};

/// The stylesheet, compiled in. One file, one copy, one place to change it.
pub const STYLESHEET: &str = include_str!("../assets/chrome.css");

/// Where [`Chrome`] serves [`STYLESHEET`]. Screens link this.
pub const STYLESHEET_PATH: &str = "/v1/chrome/chrome.css";

/// The fonts the site uses. A screen that wants to look like cratefield.com
/// needs these; the token stacks fall back to system faces without them, so
/// a blocked or slow font host degrades to a readable page rather than an
/// invisible one.
const FONTS: &str = concat!(
    r#"<link rel="preconnect" href="https://fonts.googleapis.com">"#,
    r#"<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>"#,
    r#"<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;600&"#,
    r#"family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">"#,
);

/// Serves the shared stylesheet. Owns no tables and needs no ports.
pub struct Chrome;

impl Module for Chrome {
    fn name(&self) -> &'static str {
        "chrome"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn requires(&self) -> &'static [Port] {
        &[]
    }

    fn migrations(&self) -> Migrations {
        Migrations::sqlite(&[])
    }

    fn validate_config(
        &self,
        _cfg: &dyn cratefield_core::Config,
    ) -> Result<(), cratefield_core::ConfigError> {
        Ok(())
    }

    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        axum::Router::new().route("/chrome.css", get(stylesheet))
    }
}

async fn stylesheet() -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            // The file is compiled in, so it only changes with a deploy.
            // An hour is long enough to be worth having and short enough
            // that a restyle is visible the same working day.
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        STYLESHEET,
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// The page shell
// ---------------------------------------------------------------------------

/// One item in a screen's left-hand navigation.
pub struct NavItem<'a> {
    pub label: &'a str,
    /// `None` renders the item as present but unavailable, which is how a
    /// screen says "this exists in the design and is not built" without
    /// pretending it works.
    pub href: Option<&'a str>,
    pub current: bool,
}

impl<'a> NavItem<'a> {
    #[must_use]
    pub fn to(label: &'a str, href: &'a str) -> Self {
        Self {
            label,
            href: Some(href),
            current: false,
        }
    }

    #[must_use]
    pub fn here(label: &'a str, href: &'a str) -> Self {
        Self {
            label,
            href: Some(href),
            current: true,
        }
    }

    /// Present in the design, not built. Rendered dim and inert.
    #[must_use]
    pub fn unbuilt(label: &'a str) -> Self {
        Self {
            label,
            href: None,
            current: false,
        }
    }
}

/// A rendered page: the masthead, the shell, and whatever the screen put
/// inside it.
pub struct Page<'a> {
    /// Goes in `<title>`, before the site name.
    pub title: &'a str,
    /// Shown at the top right, when there is a session.
    pub signed_in_as: Option<&'a str>,
    /// The screen's own markup. Already escaped by its author.
    pub body: &'a str,
}

/// Renders a whole page. `body` is inserted verbatim: it is the caller's
/// job to have escaped anything that came from a database or a request,
/// which is what [`escape`] is for.
#[must_use]
pub fn render(page: &Page) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"color-scheme\" content=\"dark\">\
         <title>{title} · Cratefield</title>\
         <meta name=\"robots\" content=\"noindex, nofollow\">\
         {FONTS}\
         <link rel=\"stylesheet\" href=\"{STYLESHEET_PATH}\">\
         </head><body>\
         <a class=\"skip\" href=\"#main\">Skip to content</a>\
         {masthead}\
         <main class=\"shell\" id=\"main\">{body}</main>\
         </body></html>",
        title = escape(page.title),
        masthead = masthead(page.signed_in_as),
        body = page.body,
    )
}

fn masthead(who: Option<&str>) -> String {
    let who = match who {
        Some(identity) => format!(
            "<div class=\"masthead__who\"><span>signed in as <strong>{}</strong></span>\
             <a href=\"/v1/console/logout\">Sign out</a></div>",
            escape(identity)
        ),
        None => String::new(),
    };
    format!(
        "<header class=\"masthead\"><div class=\"masthead__inner\">\
         <a class=\"wordmark\" href=\"/v1/console\" aria-label=\"Cratefield control plane\">\
         <span class=\"wordmark__grid\" aria-hidden=\"true\">\
         <i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i></span>\
         <span class=\"wordmark__text\">CRATEFIELD</span></a>{who}</div></header>"
    )
}

/// Renders a left-hand navigation list for the dashboard frame.
#[must_use]
#[allow(clippy::format_push_string)] // the house idiom for HTML building
pub fn nav(items: &[NavItem]) -> String {
    let mut out = String::from("<ul class=\"dash__nav\">");
    for item in items {
        let label = escape(item.label);
        match (item.href, item.current) {
            (Some(href), true) => out.push_str(&format!(
                "<li><a class=\"is-on\" href=\"{}\" aria-current=\"page\">\
                 <span class=\"dash__dot dash__dot--live\"></span>{label}</a></li>",
                escape(href)
            )),
            (Some(href), false) => out.push_str(&format!(
                "<li><a href=\"{}\"><span class=\"dash__dot\"></span>{label}</a></li>",
                escape(href)
            )),
            (None, _) => out.push_str(&format!(
                "<li><span class=\"is-off\" title=\"not built\">\
                 <span class=\"dash__dot\"></span>{label}</span></li>"
            )),
        }
    }
    out.push_str("</ul>");
    out
}

/// HTML-escapes text for both element content and double-quoted attribute
/// values.
#[must_use]
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stylesheet_is_not_empty_and_carries_the_sites_tokens() {
        // A missing asset compiles to an empty string and every page then
        // renders unstyled, which looks like a CSS bug rather than a
        // build one.
        assert!(STYLESHEET.len() > 2000, "got {} bytes", STYLESHEET.len());
        for token in ["--ground: #0a0a0b", "--accent: #4c6fff", "--mono:"] {
            assert!(STYLESHEET.contains(token), "missing {token}");
        }
    }

    #[test]
    fn a_page_links_the_shared_stylesheet_rather_than_inlining_one() {
        let page = render(&Page {
            title: "Ventures",
            signed_in_as: Some("op@example.com"),
            body: "<p>hello</p>",
        });
        assert!(page.contains(&format!("href=\"{STYLESHEET_PATH}\"")));
        assert!(
            !page.contains("<style"),
            "the point of the crate is one shared sheet, not per-page CSS"
        );
        assert!(page.contains("op@example.com"));
        assert!(page.contains("<p>hello</p>"));
    }

    #[test]
    fn the_masthead_is_anonymous_without_a_session() {
        let page = render(&Page {
            title: "Sign in",
            signed_in_as: None,
            body: "",
        });
        assert!(!page.contains("signed in as"));
        assert!(!page.contains("Sign out"));
    }

    #[test]
    fn an_identity_with_html_in_it_cannot_reach_the_page_unescaped() {
        let page = render(&Page {
            title: "Ventures",
            signed_in_as: Some("<script>alert(1)</script>@x.co"),
            body: "",
        });
        assert!(!page.contains("<script>alert"));
        assert!(page.contains("&lt;script&gt;"));
    }

    #[test]
    fn an_unbuilt_nav_item_is_inert_and_says_so() {
        let html = nav(&[
            NavItem::here("Overview", "/v1/dashboard"),
            NavItem::to("Modules", "/v1/dashboard/modules"),
            NavItem::unbuilt("Logs"),
        ]);
        assert!(html.contains("aria-current=\"page\""));
        assert!(html.contains("href=\"/v1/dashboard/modules\""));
        // The unbuilt one is not a link at all: nothing to click, nothing
        // to 404 on.
        assert!(!html.contains(">Logs</a>"));
        assert!(html.contains("is-off"));
    }

    #[test]
    fn escape_covers_both_element_and_attribute_contexts() {
        assert_eq!(
            escape(r#"<a href="x" title='y'>&</a>"#),
            "&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;&lt;/a&gt;"
        );
    }
}
