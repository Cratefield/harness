//! The hosted page shell every auth module renders into (issue #840):
//! the instance's [`Brand`] theme, a notice stack, and the response
//! headers a page that posts back to itself needs.
//!
//! **Why `Referrer-Policy: same-origin`.** The harness stamps
//! `no-referrer` on `/v1/*` and on any token-carrying URL, and under
//! `no-referrer` a browser serialises the `Origin` of a form POST as
//! `null` — even a POST from our own page to our own page (Fetch,
//! "append a request `Origin` header"). The login-CSRF guard
//! ([`crate::csrf::require_same_origin`]) refuses `Origin: null`, as it
//! must, and only lets the POST through when the browser also sends
//! `Sec-Fetch-Site: same-origin`. Gmail's in-app browser, other webviews
//! and older Safari send no fetch metadata at all, so the confirm button
//! in a magic-link mail was refused for exactly the people most likely
//! to open it there. `same-origin` sends the real `Origin` (and a
//! `Referer`) to this origin only, and nothing to any other site, so the
//! token in the page's URL still never leaves it and the guard keeps its
//! full strength. The harness keeps a handler's `same-origin` and
//! overwrites anything weaker.

use askama::Template;
use axum::response::{IntoResponse, Response};
use cratefield_core::Problem;
use http::{HeaderMap, HeaderValue, StatusCode, header};

use crate::brand::Brand;

/// The referrer policy every hosted page answers with: see the module
/// documentation for why it is not `no-referrer`.
pub const PAGE_REFERRER_POLICY: &str = "same-origin";

/// What a notice is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToastKind {
    /// Something went wrong and the person has something to do.
    Error,
    /// Something worked.
    Success,
}

impl ToastKind {
    /// The class suffix the stylesheet keys on.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Success => "success",
        }
    }

    /// The ARIA role: an error interrupts, a success waits its turn.
    #[must_use]
    pub fn role(self) -> &'static str {
        match self {
            Self::Error => "alert",
            Self::Success => "status",
        }
    }
}

/// A link a notice offers as the next step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action {
    /// The link text.
    pub label: String,
    /// Where it goes: a path on this service.
    pub href: String,
}

/// One notice in the page's stack (top-right, newest on top; across the
/// top on a phone). Every field is text and is escaped when rendered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Toast {
    /// Error or success.
    pub kind: ToastKind,
    /// The short line above the message.
    pub title: String,
    /// The message itself.
    pub text: String,
    /// The next step, when there is one.
    pub action: Option<Action>,
}

impl Toast {
    /// An error notice.
    #[must_use]
    pub fn error(title: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            kind: ToastKind::Error,
            title: title.into(),
            text: text.into(),
            action: None,
        }
    }

    /// A success notice.
    #[must_use]
    pub fn success(title: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            kind: ToastKind::Success,
            ..Self::error(title, text)
        }
    }

    /// Adds the next step.
    #[must_use]
    pub fn action(mut self, label: impl Into<String>, href: impl Into<String>) -> Self {
        self.action = Some(Action {
            label: label.into(),
            href: href.into(),
        });
        self
    }
}

#[derive(Template)]
#[template(path = "hosted_page.html")]
struct HostedPageTemplate<'a> {
    brand: &'a Brand,
    title: &'a str,
    body: &'a str,
    toasts: &'a [Toast],
}

/// One hosted page: a title, a body, and any notices.
///
/// The body is markup the caller built and is written as it is; every
/// value a caller interpolates into it goes through [`escape`] first.
/// The title and the notices are text and are escaped here.
#[derive(Clone, Debug)]
pub struct HostedPage {
    status: StatusCode,
    title: String,
    body: String,
    toasts: Vec<Toast>,
}

impl HostedPage {
    /// A `200` page titled `title`.
    #[must_use]
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            status: StatusCode::OK,
            title: title.into(),
            body: String::new(),
            toasts: Vec::new(),
        }
    }

    /// The status code.
    #[must_use]
    pub fn status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    /// The page's markup, already escaped by the caller.
    #[must_use]
    pub fn body(mut self, trusted_html: impl Into<String>) -> Self {
        self.body = trusted_html.into();
        self
    }

    /// Adds a notice. The newest goes on top.
    #[must_use]
    pub fn toast(mut self, toast: Toast) -> Self {
        self.toasts.insert(0, toast);
        self
    }

    /// The page as an HTML response in `brand`'s theme, never cached,
    /// with [`PAGE_REFERRER_POLICY`].
    #[must_use]
    pub fn render(&self, brand: &Brand) -> Response {
        let rendered = HostedPageTemplate {
            brand,
            title: &self.title,
            body: &self.body,
            toasts: &self.toasts,
        }
        .render();
        match rendered {
            Ok(document) => with_page_headers(
                (
                    self.status,
                    [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    document,
                )
                    .into_response(),
            ),
            Err(err) => {
                tracing::error!(error = %err, "a hosted page failed to render");
                Problem::internal().into_response()
            }
        }
    }
}

/// Adds the headers every hosted page carries: `no-store` and
/// [`PAGE_REFERRER_POLICY`].
#[must_use]
pub fn with_page_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static(PAGE_REFERRER_POLICY),
    );
    response
}

/// Escapes the five characters that can leave an HTML attribute or a
/// text node, for values a caller writes into a [`HostedPage::body`].
#[must_use]
pub fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Whether the request came from a browser page rather than an API
/// client: its `Accept` names `text/html`. A form submission always
/// does; `fetch` and curl do not unless asked to.
#[must_use]
pub fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| accept.to_ascii_lowercase().contains("text/html"))
}

/// A refusal a browser form post got, as a page instead of problem JSON:
/// what happened in words a person can act on, the next step as a
/// button, and the request id for support. The status stays the
/// problem's own. `next` is `(label, path)`.
#[must_use]
pub fn problem_page(brand: &Brand, problem: &Problem, next: (&str, &str)) -> Response {
    let (heading, text) = match problem.slug {
        "auth/cross-site-request" => (
            "We could not confirm that here",
            "Your browser did not show that this came from this page, so nothing was done. \
             Open the link from your email again, or send yourself a new one.",
        ),
        "rate-limited" => ("Too many attempts", "Wait a minute, then try again."),
        _ if problem.status.is_server_error() => (
            "Something went wrong on our side",
            "Nothing was changed. Try again in a moment.",
        ),
        _ => (
            "That did not work",
            "Nothing was changed. Start again from the sign-in page.",
        ),
    };
    let (label, href) = next;
    let reference = problem.instance.as_deref().map_or_else(String::new, |id| {
        format!("<p><code>request {}</code></p>", escape(id))
    });
    let body = format!(
        "<h1>{heading}</h1><p class=\"sub\">{text}</p>\
<a class=\"cf-primary\" href=\"{href}\">{label}</a>{reference}",
        heading = escape(heading),
        text = escape(text),
        href = escape(href),
        label = escape(label),
    );
    HostedPage::new(heading)
        .status(problem.status)
        .body(body)
        .toast(Toast::error(heading, text).action(label, href))
        .render(brand)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::{MapConfig, Venture};

    fn brand() -> Brand {
        Brand::from_config(
            &MapConfig::default(),
            &Venture::new("acme", "auth.acme.example"),
        )
    }

    fn body(response: Response) -> String {
        let bytes = pollster::block_on(axum::body::to_bytes(response.into_body(), usize::MAX))
            .expect("body reads");
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[test]
    fn a_page_carries_the_theme_and_the_same_origin_policy() {
        let response = HostedPage::new("Sign in")
            .body("<h1>Hi</h1>")
            .render(&brand());
        assert_eq!(
            response.headers().get(header::REFERRER_POLICY).unwrap(),
            "same-origin"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let html = body(response);
        assert!(html.contains("--cf-bg:"), "{html}");
        assert!(html.contains("<h1>Hi</h1>"), "{html}");
        assert!(html.contains("<title>Sign in · acme</title>"), "{html}");
    }

    #[test]
    fn notices_are_escaped_and_the_newest_is_on_top() {
        let html = body(
            HostedPage::new("x")
                .toast(Toast::error("first", "<script>alert(1)</script>"))
                .toast(Toast::success("second", "ok").action("Go", "/v1/x?a=1&b=2"))
                .render(&brand()),
        );
        assert!(!html.contains("<script>alert(1)"), "{html}");
        let (first, second) = (html.find("first").unwrap(), html.find("second").unwrap());
        assert!(second < first, "the newest notice is not on top: {html}");
        assert!(html.contains("role=\"alert\""), "{html}");
        assert!(html.contains("role=\"status\""), "{html}");
    }

    #[test]
    fn a_refused_form_post_becomes_a_page_with_a_next_step() {
        let problem = Problem::new(&crate::csrf::CROSS_SITE_REQUEST).instance("01REQ");
        let response = problem_page(&brand(), &problem, ("Send a new link", "/v1/m/start"));
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let html = body(response);
        assert!(html.contains("href=\"/v1/m/start\""), "{html}");
        assert!(html.contains("request 01REQ"), "{html}");
        assert!(!html.contains("\"type\""), "problem JSON leaked: {html}");
    }

    #[test]
    fn only_a_page_asking_for_html_gets_one() {
        let mut headers = HeaderMap::new();
        assert!(!wants_html(&headers));
        headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        assert!(!wants_html(&headers));
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("text/html,application/xhtml+xml,*/*;q=0.8"),
        );
        assert!(wants_html(&headers));
    }
}
