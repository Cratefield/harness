//! `cratefield-ui` renders the harness's UI surface (ADR 0010) as HTML from
//! inside the Worker: full pages at `/ui/<module>/<action>`, the same as a
//! fragment with `?fragment=1`, landing pages at
//! `/ui/<module>/<action>/<page>`, and the base stylesheet at
//! `/ui/cf.css`. A form posts to its own `/ui` route; the handler turns
//! the form into the JSON the module accepts and dispatches it
//! **in-process** to the `/v1` router, then renders the `202`, the
//! `problem+json` or the `303`. Modules stay JSON-only.
//!
//! Mount with `Harness::builder().ui(cratefield_ui::Ui::default())`.
//!
//! Web-agnostic like every other crate: no `worker`, `tokio` or
//! `std::fs`; `maud` builds strings, and the wasm build of
//! `examples/venture` proves it.

#![forbid(unsafe_code)]

mod admin;
mod fields;
pub mod render;
pub mod spec;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use cratefield_core::{
    Action, Audience, Outcome, Problem, Scope, UiContext, UiMount, require_admin,
};
use serde_json::Value;
use tower::ServiceExt;

pub use fields::{Field, JsonType, Values, Widget, fields_of, form_to_json, humanize};
pub use spec::{
    ActionSpec, FieldSpec, ModuleSpec, PageCopy, Theme, UI_SPEC_KEY, UI_SPEC_VERSION, UiSpec,
};

/// The base stylesheet served at `/ui/cf.css`: `@layer cf`, `--cf-*`
/// custom properties, nothing that an unlayered venture rule cannot beat.
pub const CF_CSS: &str = include_str!("../assets/cf.css");
/// The embed served at `/ui/cf.js` (issue #73); empty until then.
pub const CF_JS: &str = include_str!("../assets/cf.js");

/// Config key for the Turnstile **site** key (public; the secret stays
/// with the adapter). Without it a captcha action renders no widget, and
/// the module's captcha check answers as it does for any missing token.
pub const TURNSTILE_SITE_KEY: &str = "TURNSTILE_SITE_KEY";

/// Renderer configuration; mounted with `HarnessBuilder::ui`.
#[derive(Debug, Clone, Default)]
pub struct Ui {
    theme_css: Option<String>,
    spec: UiSpec,
}

impl Ui {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A stylesheet linked after `cf.css` on every page: the venture's
    /// theme. Absolute URL or a path on the API origin. The spec's
    /// `theme.css_url` wins when both are set.
    #[must_use]
    pub fn theme_css(mut self, url: impl Into<String>) -> Self {
        self.theme_css = Some(url.into());
        self
    }

    /// The venture's `UiSpec` as JSON (`include_str!("../ui.json")`).
    /// Parsed here; validated against the surface by `Harness::build`.
    /// A runtime `UI_SPEC` in config replaces it without a rebuild.
    ///
    /// # Errors
    ///
    /// The parse error, with its path.
    pub fn from_spec(json: &str) -> Result<Self, String> {
        Ok(Self::new().spec(UiSpec::parse(json)?))
    }

    #[must_use]
    pub fn spec(mut self, spec: UiSpec) -> Self {
        self.spec = spec;
        self
    }
}

impl UiMount for Ui {
    fn validate(
        &self,
        surface: &cratefield_core::SurfaceDocument,
        errors: &mut cratefield_core::ConfigError,
    ) {
        if let Err(problems) = self.spec.validate(surface) {
            for problem in problems {
                errors.push(format!("ui spec: {problem}"));
            }
        }
    }

    fn describe(&self) -> Option<Value> {
        (self.spec != UiSpec::default())
            .then(|| serde_json::to_value(&self.spec).ok())
            .flatten()
    }

    fn router(&self, ctx: UiContext) -> Router {
        // A runtime spec replaces the built-in one; a broken runtime spec
        // takes the whole UI down loudly rather than rendering from half
        // of it, and says why on every request.
        let runtime = ctx
            .config
            .get(UI_SPEC_KEY)
            .filter(|json| !json.trim().is_empty())
            .map(|json| {
                UiSpec::parse(&json).and_then(|spec| {
                    spec.validate(&ctx.surface.built())
                        .map(|()| spec)
                        .map_err(|problems| {
                            format!("ui spec ({UI_SPEC_KEY}): {}", problems.join("; "))
                        })
                })
            });
        let spec = match runtime {
            Some(Ok(spec)) => spec,
            Some(Err(problem)) => {
                tracing::error!(%problem, "runtime UI spec rejected; /ui is disabled");
                return Router::new().fallback(move |scope: Scope| {
                    let problem = problem.clone();
                    async move {
                        Problem::internal()
                            .with_detail(problem)
                            .instance(&scope.request_id)
                    }
                });
            }
            None => self.spec.clone(),
        };
        let state = Arc::new(UiState {
            ui: self.clone(),
            spec,
            ctx,
        });
        Router::new()
            .route("/theme.css", get(theme_css))
            .route("/spec.json", get(spec_json))
            .route("/cf.css", get(css))
            .route("/cf.js", get(js))
            .route("/admin", get(admin::index))
            .route(
                "/admin/login",
                get(admin::login_get).post(admin::login_post),
            )
            .route("/admin/logout", axum::routing::post(admin::logout))
            .route(
                "/admin/{module}/{action}",
                get(admin::page_get).post(admin::page_post),
            )
            .route("/{module}/{action}", get(page_get).post(page_post))
            .route("/{module}/{action}/{landing}", get(landing))
            .with_state(state)
    }
}

struct UiState {
    ui: Ui,
    /// The effective spec: runtime `UI_SPEC` if set, else the builder's.
    spec: UiSpec,
    ctx: UiContext,
}

async fn theme_css(State(state): State<Arc<UiState>>) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        state.spec.theme_css(),
    )
}

/// The effective spec, for tooling and the control plane to read back.
async fn spec_json(State(state): State<Arc<UiState>>) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        serde_json::to_string(&state.spec).unwrap_or_else(|_| "{}".to_owned()),
    )
}

async fn css() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        CF_CSS,
    )
}

async fn js() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        CF_JS,
    )
}

/// Looks an action up; admin actions are not served here until the admin
/// UI (issue #74) exists, so they are `404` like an unknown one.
fn find_action<'a>(
    surface: &'a cratefield_core::SurfaceDocument,
    module: &str,
    action: &str,
) -> Option<&'a Action> {
    surface
        .modules
        .iter()
        .find(|m| m.name == module)?
        .surface
        .actions
        .iter()
        .find(|a| a.name == action && a.audience != Audience::Admin)
}

fn not_found(scope: &Scope, what: &str) -> Response {
    Problem::not_found()
        .with_detail(format!("no UI for {what}"))
        .instance(&scope.request_id)
        .into_response()
}

/// Query switches the renderer consumes rather than pre-fills:
/// `fragment=1` and `hide=<field,field>` (a page that supplies a value
/// and does not want the visitor to change it, which is what the embed
/// sends for every attribute-supplied field).
struct Switches {
    fragment: bool,
    hide: Vec<String>,
}

fn split_switches(mut query: Values) -> (Values, Switches) {
    let fragment = query
        .remove("fragment")
        .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes"));
    let hide = query
        .remove("hide")
        .map(|list| {
            list.split(',')
                .map(str::trim)
                .filter(|f| !f.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    (query, Switches { fragment, hide })
}

fn split_fragment(query: Values) -> (Values, bool) {
    let (values, switches) = split_switches(query);
    (values, switches.fragment)
}

/// Fields the page asked to hide render as hidden inputs (with the
/// supplied value) instead of controls.
fn apply_hide(fields: &mut [Field], hide: &[String]) {
    for field in fields.iter_mut() {
        if hide.iter().any(|h| h == &field.name) {
            field.widget = Widget::Hidden;
        }
    }
}

/// `GET /ui/<module>/<action>`: the form for a `POST` action (query
/// parameters pre-fill and hide fields, which is how a page passes
/// `product=` or `ref=`), or the result of a `GET` action dispatched with
/// the same query (a status page, a signed link).
async fn page_get(
    scope: Scope,
    State(state): State<Arc<UiState>>,
    Path((module, action)): Path<(String, String)>,
    Query(query): Query<Values>,
    headers: HeaderMap,
) -> Response {
    let surface = state.ctx.surface.current().await;
    let Some(spec) = find_action(&surface, &module, &action) else {
        return not_found(&scope, &format!("{module}/{action}"));
    };
    let (values, switches) = split_switches(query);
    let fragment = switches.fragment;
    if spec.method == Method::POST {
        let mut fields = spec
            .input
            .as_ref()
            .map(|s| fields_of(s.as_value()))
            .unwrap_or_default();
        apply_hide(&mut fields, &switches.hide);
        let body = render_form(&state, spec, &module, &fields, &values, &[]);
        return respond(&state, fragment, body);
    }
    let query_string = serde_urlencoded_encode(&values);
    let response = dispatch(&state, &scope, &headers, spec, &module, &query_string, None).await;
    render_result(&state, &scope, spec, &module, fragment, response, None).await
}

/// `POST /ui/<module>/<action>`: the form comes back, becomes JSON, and
/// is dispatched in-process; the module's answer is rendered.
async fn page_post(
    scope: Scope,
    State(state): State<Arc<UiState>>,
    Path((module, action)): Path<(String, String)>,
    Query(query): Query<Values>,
    headers: HeaderMap,
    axum::Form(form): axum::Form<Vec<(String, String)>>,
) -> Response {
    let surface = state.ctx.surface.current().await;
    let Some(spec) = find_action(&surface, &module, &action) else {
        return not_found(&scope, &format!("{module}/{action}"));
    };
    if spec.method != Method::POST {
        return Problem::not_found()
            .with_detail(format!("{module}/{action} does not take a form"))
            .instance(&scope.request_id)
            .into_response();
    }
    let (_, switches) = split_switches(query);
    let fragment = switches.fragment;
    let mut fields = spec
        .input
        .as_ref()
        .map(|s| fields_of(s.as_value()))
        .unwrap_or_default();
    apply_hide(&mut fields, &switches.hide);
    let mut values: Values = form.into_iter().collect();
    // Turnstile posts its token under its own name; the module wants it
    // as `captchaToken`.
    if let Some(token) = values.remove("cf-turnstile-response") {
        values.insert("captchaToken".to_owned(), token);
    }
    let json = Value::Object(form_to_json(&fields, &values));
    let response = dispatch(&state, &scope, &headers, spec, &module, "", Some(json)).await;
    render_result(
        &state,
        &scope,
        spec,
        &module,
        fragment,
        response,
        Some((fields, values)),
    )
    .await
}

/// `GET /ui/<module>/<action>/<landing>`: where a module's signed links
/// send the browser when the UI is mounted (`done`, `expired`).
async fn landing(
    scope: Scope,
    State(state): State<Arc<UiState>>,
    Path((module, action, landing)): Path<(String, String, String)>,
    Query(query): Query<Values>,
) -> Response {
    let surface = state.ctx.surface.current().await;
    if find_action(&surface, &module, &action).is_none() {
        return not_found(&scope, &format!("{module}/{action}"));
    }
    let (_, fragment) = split_fragment(query);
    let (tone, title, message) = match (action.as_str(), landing.as_str()) {
        ("confirm", "done") => (
            "success",
            "Confirmed".to_owned(),
            "Your email address is confirmed.".to_owned(),
        ),
        ("unsubscribe", "done") => (
            "success",
            "Unsubscribed".to_owned(),
            "You will not receive further email from us.".to_owned(),
        ),
        (_, "expired") => (
            "warning",
            "Link expired".to_owned(),
            "This link is no longer valid. Please start again.".to_owned(),
        ),
        (_, "done") => ("success", "Done".to_owned(), "Done.".to_owned()),
        _ => return not_found(&scope, &format!("{module}/{action}/{landing}")),
    };
    let copy = state
        .spec
        .action(&module, &action)
        .and_then(|c| c.pages.get(&landing));
    let title = copy.and_then(|c| c.title.clone()).unwrap_or(title);
    let message = copy.and_then(|c| c.message.clone()).unwrap_or(message);
    let body = render::notice(&module, &action, tone, &title, &message);
    respond(&state, fragment, (title, body, false))
}

fn render_form(
    state: &UiState,
    spec: &Action,
    module: &str,
    fields: &[Field],
    values: &Values,
    errors: &[(String, String)],
) -> (String, maud::Markup, bool) {
    let site_key = (spec.captcha && state.ctx.captcha_configured)
        .then(|| state.ctx.config.get(TURNSTILE_SITE_KEY))
        .flatten()
        .filter(|key| !key.is_empty());
    let post_to = format!("/ui/{module}/{}", spec.name);
    let copy = state.spec.action(module, &spec.name);
    let title = copy
        .and_then(|c| c.title.clone())
        .unwrap_or_else(|| humanize(&spec.name));
    let submit = copy
        .and_then(|c| c.submit.clone())
        .unwrap_or_else(|| humanize(&spec.name));
    let fields = apply_spec(fields, copy);
    let body = render::form(&render::FormSpec {
        module,
        action: &spec.name,
        post_to: &post_to,
        intro: copy.and_then(|c| c.intro.as_deref()),
        fields: &fields,
        values,
        errors,
        captcha_site_key: site_key.as_deref(),
        submit_label: &submit,
    });
    (title, body, site_key.is_some())
}

/// Copy overrides, hidden flags and order from the spec, over the
/// fields the schema produced.
fn apply_spec(fields: &[Field], copy: Option<&ActionSpec>) -> Vec<Field> {
    let Some(copy) = copy else {
        return fields.to_vec();
    };
    let mut out: Vec<Field> = fields
        .iter()
        .map(|field| {
            let mut field = field.clone();
            if let Some(over) = copy.fields.get(&field.name) {
                if let Some(label) = &over.label {
                    field.label = label.clone();
                }
                if over.placeholder.is_some() {
                    field.placeholder = over.placeholder.clone();
                }
                if over.help.is_some() {
                    field.help = over.help.clone();
                }
                if over.hidden {
                    field.widget = Widget::Hidden;
                }
            }
            field
        })
        .collect();
    if !copy.order.is_empty() {
        let rank = |name: &str| {
            copy.order
                .iter()
                .position(|n| n == name)
                .unwrap_or(copy.order.len())
        };
        out.sort_by_key(|field| rank(&field.name));
    }
    out
}

/// Whether an action is admin-gated: declared for the `Admin` audience,
/// or served under `/admin/` no matter what the surface declares.
///
/// Security invariant (issue #130): the audience filter in [`find_action`]
/// and the public subset of `/__surface` are *visibility*, not
/// authorization. A surface document that reaches the renderer at runtime
/// (a sidecar's, merged per request) is not re-validated by this host, so
/// an entry could claim a public audience over an admin path. Execution
/// therefore re-derives the gate from the path as well as the audience,
/// and [`dispatch`] checks it with the same [`require_admin`] the target
/// route uses.
fn is_admin_gated(spec: &Action) -> bool {
    spec.audience == Audience::Admin || spec.path == "/admin" || spec.path.starts_with("/admin/")
}

/// Builds the internal request and sends it through the `/v1` router.
/// The caller's `Scope` rides along in the extensions (the scope layer
/// sits above `/v1` and will not run again), and the headers that
/// identify the caller are forwarded so rate limiting, captcha and admin
/// checks see the browser, not the renderer.
///
/// An admin-gated action ([`is_admin_gated`]) is authorized here, before
/// anything is sent: [`require_admin`] over the forwarded headers is the
/// same check the target route runs, so in-process dispatch cannot be a
/// path around it. On failure the problem the direct request would have
/// answered (`401`/`403`) is returned and the module is never invoked.
async fn dispatch(
    state: &UiState,
    scope: &Scope,
    headers: &HeaderMap,
    spec: &Action,
    module: &str,
    query: &str,
    json: Option<Value>,
) -> Response {
    if is_admin_gated(spec)
        && let Err(problem) = require_admin(&*state.ctx.config, headers)
    {
        return problem.instance(&scope.request_id).into_response();
    }
    // An action at `/` is the nest root: `/v1/<module>`, no trailing
    // slash, or axum's nesting answers 404.
    let mut uri = format!("/v1/{module}{}", spec.path.trim_end_matches('/'));
    if !query.is_empty() {
        uri.push('?');
        uri.push_str(query);
    }
    let mut builder = Request::builder().method(spec.method.clone()).uri(uri);
    for name in [
        "cf-connecting-ip",
        "x-forwarded-for",
        "x-real-ip",
        "user-agent",
        "accept-language",
        "authorization",
        "x-request-id",
    ] {
        if let Some(value) = headers.get(name) {
            builder = builder.header(name, value.clone());
        }
    }
    let request = match json {
        Some(json) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json.to_string())),
        None => builder.body(Body::empty()),
    };
    let mut request = match request {
        Ok(request) => request,
        Err(err) => {
            tracing::error!(error = %err, "ui dispatch could not build the internal request");
            return Problem::internal()
                .instance(&scope.request_id)
                .into_response();
        }
    };
    request.extensions_mut().insert(scope.clone());
    match state.ctx.api.clone().oneshot(request).await {
        Ok(response) => response,
        Err(never) => match never {},
    }
}

/// Renders whatever the module answered: `2xx` as the outcome the surface
/// declares, `3xx` passed to the browser, a problem as the form with the
/// error on its field (or above the form when it names none).
async fn render_result(
    state: &UiState,
    scope: &Scope,
    spec: &Action,
    module: &str,
    fragment: bool,
    response: Response,
    form: Option<(Vec<Field>, Values)>,
) -> Response {
    let status = response.status();
    if status.is_redirection() {
        return response;
    }
    let (_parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, 1024 * 1024)
        .await
        .unwrap_or_default();
    let json: Option<Value> = serde_json::from_slice(&bytes).ok();
    // Status only: a body may carry an address, and the logging policy
    // (`cratefield_core::RedactingVisitor`) is not applied to free text.
    tracing::debug!(status = %status, "ui dispatch answered");

    if status.is_success() {
        let copy = state.spec.action(module, &spec.name);
        let title = copy
            .and_then(|c| c.title.clone())
            .unwrap_or_else(|| humanize(&spec.name));
        let body = match &spec.outcome {
            Outcome::Json => {
                render::status(module, &spec.name, json.as_ref().unwrap_or(&Value::Null))
            }
            Outcome::Accepted { message } => {
                let message = copy.and_then(|c| c.success.as_deref()).unwrap_or(message);
                render::notice(module, &spec.name, "success", &title, message)
            }
            Outcome::Redirect => render::notice(module, &spec.name, "success", &title, "Done."),
        };
        return respond(state, fragment, (title, body, false));
    }

    let problem = json.as_ref();
    let detail = problem
        .and_then(|p| p.get("detail").and_then(Value::as_str))
        .map(str::to_owned);
    let title_text = problem
        .and_then(|p| p.get("title").and_then(Value::as_str))
        .map(str::to_owned);
    let message = match status {
        StatusCode::TOO_MANY_REQUESTS => "Too many attempts. Please try again later.".to_owned(),
        // A 503 names its cause in the title (mail not configured, not
        // ready); a 500 never says more than the request id.
        StatusCode::SERVICE_UNAVAILABLE => format!(
            "{}. Please try again later. Request id {}.",
            title_text.as_deref().unwrap_or("Service unavailable"),
            scope.request_id
        ),
        s if s.is_server_error() => format!(
            "Something went wrong on our side. Request id {}.",
            scope.request_id
        ),
        _ => detail
            .clone()
            .or(title_text)
            .unwrap_or_else(|| "The request was not accepted.".to_owned()),
    };
    let Some((fields, mut values)) = form else {
        let body = render::notice(module, &spec.name, "error", &humanize(&spec.name), &message);
        let mut out = respond(state, fragment, (humanize(&spec.name), body, false));
        *out.status_mut() = status;
        return out;
    };
    let slug = problem
        .and_then(|p| p.get("type").and_then(Value::as_str))
        .and_then(|t| t.rsplit('/').next())
        .unwrap_or_default();
    let field = detail
        .as_deref()
        .and_then(|d| attribute_to_field(d, &fields))
        .or_else(|| attribute_by_slug(slug, &fields))
        .unwrap_or_default();
    // "email: email must contain exactly one @" next to the email field
    // reads twice; drop the prefix the module put there for API clients.
    let message = message
        .strip_prefix(&format!("{field}: "))
        .filter(|_| !field.is_empty())
        .map_or(message.clone(), str::to_owned);
    let errors = vec![(field, message)];
    // A captcha token is single-use: the widget issues a fresh one.
    values.remove("captchaToken");
    let mut out = respond(
        state,
        fragment,
        render_form(state, spec, module, &fields, &values, &errors),
    );
    // Keep the browser on the form: a validation error is the form's
    // state, not a new page, so `400` becomes `422` like a validating
    // handler would answer. Every other status (a `429` with its
    // `Retry-After` semantics, a `5xx`) is kept.
    *out.status_mut() = if status == StatusCode::BAD_REQUEST {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        status
    };
    out
}

/// A module's `detail` starts with the field it is about ("email must
/// contain exactly one @"); match that word against the declared fields,
/// by name or by label, case-insensitively.
fn attribute_to_field(detail: &str, fields: &[Field]) -> Option<String> {
    let first: String = detail
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
        .collect::<String>()
        .to_ascii_lowercase();
    if first.is_empty() {
        return None;
    }
    fields
        .iter()
        .find(|f| {
            f.name.to_ascii_lowercase() == first
                || f.label.to_ascii_lowercase() == first
                || humanize(&f.name).to_ascii_lowercase() == first
        })
        .map(|f| f.name.clone())
}

/// A problem slug that names a field (`unknown-product`) attributes to
/// it when the detail did not.
fn attribute_by_slug(slug: &str, fields: &[Field]) -> Option<String> {
    slug.split('-')
        .find_map(|token| fields.iter().find(|f| f.name.eq_ignore_ascii_case(token)))
        .map(|f| f.name.clone())
}

/// Wraps a fragment for the wire: as is with `?fragment=1`, inside the
/// page shell with a CSP otherwise.
///
/// Every rendered page and fragment is `no-store` (issue #130): the same
/// URL can carry one visitor's pre-filled values, dispatched results and
/// landing states, and nothing an intermediary could serve to the next
/// caller. The static assets (`cf.css`, `cf.js`, `theme.css`) are the
/// cacheable exceptions.
fn respond(
    state: &UiState,
    fragment: bool,
    (title, body, turnstile): (String, maud::Markup, bool),
) -> Response {
    if fragment {
        let mut out = Html(body.into_string()).into_response();
        out.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return out;
    }
    let theme = effective_theme_css(state);
    let page = render::page(
        &render::PageSpec {
            venture: &state.ctx.venture.name,
            title: &title,
            theme_tokens: !state.spec.theme.tokens.is_empty(),
            theme_css: theme.as_deref(),
            turnstile,
            admin: false,
        },
        &body,
    );
    let mut response = Html(page.into_string()).into_response();
    let csp = content_security_policy(theme.as_deref(), turnstile);
    if let Ok(value) = HeaderValue::from_str(&csp) {
        response
            .headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, value);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// An admin page: the shell with the admin navigation, never cached
/// (`private, no-store` — a session-gated response must not be stored by
/// a shared cache even for revalidation, issue #130), never framed.
/// `logged_in` decides whether the navigation shows.
fn respond_admin(state: &UiState, title: &str, body: &maud::Markup, logged_in: bool) -> Response {
    let theme = effective_theme_css(state);
    let page = render::page(
        &render::PageSpec {
            venture: &state.ctx.venture.name,
            title,
            theme_tokens: !state.spec.theme.tokens.is_empty(),
            theme_css: theme.as_deref(),
            turnstile: false,
            admin: logged_in,
        },
        body,
    );
    let mut response = Html(page.into_string()).into_response();
    let csp = content_security_policy(theme.as_deref(), false);
    if let Ok(value) = HeaderValue::from_str(&csp) {
        response
            .headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, value);
    }
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    response
}

/// The spec's stylesheet wins over the builder's.
fn effective_theme_css(state: &UiState) -> Option<String> {
    state
        .spec
        .theme
        .css_url
        .clone()
        .or_else(|| state.ui.theme_css.clone())
}

fn content_security_policy(theme_css: Option<&str>, turnstile: bool) -> String {
    let mut style = String::from("'self'");
    if let Some(origin) = theme_css.and_then(origin_of) {
        style.push(' ');
        style.push_str(&origin);
    }
    let (script, frame) = if turnstile {
        (
            render::TURNSTILE_ORIGIN.to_owned(),
            render::TURNSTILE_ORIGIN.to_owned(),
        )
    } else {
        ("'none'".to_owned(), "'none'".to_owned())
    };
    format!(
        "default-src 'none'; style-src {style}; script-src {script}; frame-src {frame}; \
         img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    )
}

fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let host = rest.split('/').next()?;
    (!host.is_empty()).then(|| format!("{scheme}://{host}"))
}

fn serde_urlencoded_encode(values: &BTreeMap<String, String>) -> String {
    let mut out = String::new();
    for (key, value) in values {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(&percent_encode(key));
        out.push('=');
        out.push_str(&percent_encode(value));
    }
    out
}

fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csp_opens_only_what_the_page_uses() {
        let plain = content_security_policy(None, false);
        assert!(plain.contains("script-src 'none'"));
        assert!(plain.contains("style-src 'self';"));
        let themed = content_security_policy(Some("https://cdn.example/theme.css"), true);
        assert!(themed.contains("style-src 'self' https://cdn.example;"));
        assert!(themed.contains("script-src https://challenges.cloudflare.com;"));
        assert!(themed.contains("frame-src https://challenges.cloudflare.com;"));
        let local = content_security_policy(Some("/theme.css"), false);
        assert!(local.contains("style-src 'self';"));
    }

    #[test]
    fn detail_attribution_matches_name_or_label() {
        let fields = fields_of(&serde_json::json!({
            "type": "object",
            "properties": {
                "email": {"type": "string", "x-cf-label": "Your email"},
                "product": {"type": "string"}
            }
        }));
        assert_eq!(
            attribute_to_field("email must contain exactly one @", &fields).as_deref(),
            Some("email")
        );
        assert_eq!(
            attribute_to_field("Product is not open for signups", &fields).as_deref(),
            Some("product")
        );
        assert_eq!(attribute_to_field("nothing here", &fields), None);
        assert_eq!(attribute_to_field("", &fields), None);
        assert_eq!(
            attribute_by_slug("unknown-product", &fields).as_deref(),
            Some("product")
        );
        assert_eq!(attribute_by_slug("captcha-failed", &fields), None);
    }

    #[test]
    fn query_encoding_is_strict() {
        let values: Values = [("token".to_owned(), "a b&c=d".to_owned())].into();
        assert_eq!(serde_urlencoded_encode(&values), "token=a%20b%26c%3Dd");
    }
}
