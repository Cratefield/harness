//! The markup contract (ADR 0010, `docs/UI.md`). Every element carries a
//! `cf-*` class and, where it maps to the surface, a `data-cf-*`
//! attribute. No shadow DOM, no inline styles, no ids except the ones
//! that tie a `<label>` to its control. Changing a class name here is a
//! breaking change of the UI contract; the snapshot test guards it.

use maud::{DOCTYPE, Markup, PreEscaped, html};

use crate::fields::{Field, Values, Widget, humanize};

/// Cloudflare Turnstile's script and iframe origin, allowed by the page
/// CSP only when a captcha widget is rendered.
pub const TURNSTILE_ORIGIN: &str = "https://challenges.cloudflare.com";
const TURNSTILE_SCRIPT: &str = "https://challenges.cloudflare.com/turnstile/v0/api.js";

/// What a form needs to render, independent of where it came from.
pub struct FormSpec<'a> {
    pub module: &'a str,
    pub action: &'a str,
    /// `POST` target; the `/ui` route, never `/v1`.
    pub post_to: &'a str,
    pub fields: &'a [Field],
    pub values: &'a Values,
    /// Field name to message; a key of `""` is the form-level error.
    pub errors: &'a [(String, String)],
    /// Turnstile site key when the action wants a captcha and one is
    /// configured.
    pub captcha_site_key: Option<&'a str>,
    pub submit_label: &'a str,
}

/// The form fragment.
#[must_use]
pub fn form(spec: &FormSpec<'_>) -> Markup {
    let form_error = spec.errors.iter().find(|(name, _)| name.is_empty());
    html! {
        form class="cf-form" data-cf-module=(spec.module) data-cf-action=(spec.action)
            method="post" action=(spec.post_to) novalidate {
            @if let Some((_, message)) = form_error {
                p class="cf-error cf-error--form" role="alert" { (message) }
            }
            @for field in spec.fields {
                (field_markup(spec, field))
            }
            @if let Some(site_key) = spec.captcha_site_key {
                div class="cf-field cf-field--captcha" data-cf-field="captchaToken" {
                    div class="cf-turnstile" data-sitekey=(site_key) {}
                }
            }
            div class="cf-actions" {
                button class="cf-submit" type="submit" { (spec.submit_label) }
            }
        }
    }
}

fn field_markup(spec: &FormSpec<'_>, field: &Field) -> Markup {
    let value = spec.values.get(&field.name).map(String::as_str);
    if field.widget == Widget::Hidden {
        return html! {
            @if let Some(value) = value {
                input type="hidden" name=(field.name) value=(value);
            }
        };
    }
    let error = spec
        .errors
        .iter()
        .find(|(name, _)| name == &field.name)
        .map(|(_, message)| message.as_str());
    let id = format!("cf-{}-{}-{}", spec.module, spec.action, field.name);
    let classes = if error.is_some() {
        "cf-field cf-field--invalid"
    } else {
        "cf-field"
    };
    html! {
        div class=(classes) data-cf-field=(field.name) {
            @if field.widget == Widget::Checkbox {
                label class="cf-label cf-label--checkbox" for=(id) {
                    input class="cf-input cf-input--checkbox" type="checkbox" id=(id)
                        name=(field.name) required[field.required]
                        checked[value.is_some_and(|v| matches!(v, "on" | "true" | "1"))];
                    span { (field.label) }
                }
            } @else {
                label class="cf-label" for=(id) {
                    (field.label)
                    @if field.required { span class="cf-required" aria-hidden="true" { "*" } }
                }
                (control(field, &id, value))
            }
            @if let Some(help) = &field.help {
                p class="cf-help" { (help) }
            }
            @if let Some(message) = error {
                p class="cf-error" role="alert" { (message) }
            }
        }
    }
}

fn control(field: &Field, id: &str, value: Option<&str>) -> Markup {
    match field.widget {
        Widget::Select => html! {
            select class="cf-input cf-input--select" id=(id) name=(field.name)
                required[field.required] {
                @if !field.required || value.is_none() {
                    option value="" { (field.placeholder.as_deref().unwrap_or("Choose")) }
                }
                @for option in &field.options {
                    option value=(option.value) selected[value == Some(option.value.as_str())] {
                        (option.label)
                    }
                }
            }
        },
        Widget::Textarea => html! {
            textarea class="cf-input cf-input--textarea" id=(id) name=(field.name)
                required[field.required] placeholder=[field.placeholder.as_deref()] {
                @if let Some(value) = value { (value) }
            }
        },
        Widget::Email | Widget::Number | Widget::Text | Widget::Checkbox | Widget::Hidden => {
            let kind = match field.widget {
                Widget::Email => "email",
                Widget::Number => "number",
                _ => "text",
            };
            html! {
                input class="cf-input" type=(kind) id=(id) name=(field.name)
                    required[field.required] placeholder=[field.placeholder.as_deref()]
                    value=[value] autocomplete=[(field.widget == Widget::Email).then_some("email")];
            }
        }
    }
}

/// A notice: the outcome of a successful action, or a landing page.
#[must_use]
pub fn notice(module: &str, action: &str, tone: &str, title: &str, message: &str) -> Markup {
    let class = format!("cf-notice cf-notice--{tone}");
    html! {
        div class=(class) data-cf-module=(module) data-cf-action=(action) role="status" {
            h2 class="cf-notice-title" { (title) }
            p class="cf-notice-text" { (message) }
        }
    }
}

/// A `Json` outcome rendered as a definition list, one row per top-level
/// key. Nested values are shown as JSON text.
#[must_use]
pub fn status(module: &str, action: &str, value: &serde_json::Value) -> Markup {
    html! {
        dl class="cf-status" data-cf-module=(module) data-cf-action=(action) {
            @if let Some(object) = value.as_object() {
                @for (key, item) in object {
                    div class="cf-status-row" data-cf-field=(key) {
                        dt class="cf-status-key" { (humanize(key)) }
                        dd class="cf-status-value" { (scalar(item)) }
                    }
                }
            } @else {
                div class="cf-status-row" {
                    dd class="cf-status-value" { (scalar(value)) }
                }
            }
        }
    }
}

fn scalar(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// What a full page needs around a fragment.
pub struct PageSpec<'a> {
    pub venture: &'a str,
    pub title: &'a str,
    /// `/ui/cf.css` and `/ui/cf.js` relative to the API origin; the
    /// venture's own theme stylesheet, if configured, is linked after.
    pub theme_css: Option<&'a str>,
    pub turnstile: bool,
}

/// Wraps a fragment in the page shell. Scripts: none of ours; Turnstile's
/// only when a captcha widget is on the page.
#[must_use]
pub fn page(spec: &PageSpec<'_>, body: &Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                meta name="robots" content="noindex";
                title { (spec.title) " · " (spec.venture) }
                link rel="stylesheet" href="/ui/cf.css";
                @if let Some(theme) = spec.theme_css {
                    link rel="stylesheet" href=(theme);
                }
                @if spec.turnstile {
                    script src=(TURNSTILE_SCRIPT) async defer {}
                }
            }
            body class="cf-page" {
                main class="cf-main" {
                    header class="cf-header" {
                        p class="cf-venture" { (spec.venture) }
                        h1 class="cf-title" { (spec.title) }
                    }
                    (body)
                }
            }
        }
    }
}

/// Raw markup from a trusted source (the base stylesheet, the embed
/// script), for the tests that snapshot them.
#[must_use]
pub fn raw(text: &str) -> Markup {
    PreEscaped(text.to_owned())
}
