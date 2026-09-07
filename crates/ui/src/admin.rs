//! The admin pages (issue #74): a token login that sets a signed session
//! cookie, an index of every module's admin surface, `Table` views over
//! the admin exports, admin actions with a body as forms, and row
//! actions (delete) with a confirm step that is a normal form post.
//!
//! The session proves the admin token was presented once; it never holds
//! the token. On every admin dispatch the harness attaches
//! `Authorization: Bearer <ADMIN_TOKEN>` from its own config, so the
//! modules' `require_admin` stays the single gate. No `Signer` or no
//! `ADMIN_TOKEN` means no admin UI, the way the admin routes are off.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use cratefield_core::{
    Action, Audience, Clock, Kid, Payload, Problem, Scope, View, client_ip, constant_time_eq,
};
use maud::Markup;
use serde_json::Value;

use crate::fields::{Field, Values, fields_of, form_to_json, humanize};
use crate::{UiState, dispatch, render, render_form, respond_admin};

const COOKIE: &str = "cf_admin";
const PURPOSE: &str = "admin-session";
/// A session lasts a working day; the login is one field.
const SESSION_TTL: Duration = Duration::from_hours(12);

/// Whether the admin UI is switched on at all: a signer for the cookie
/// and an `ADMIN_TOKEN` to compare against.
fn enabled(state: &UiState) -> bool {
    state.ctx.signer.is_some() && admin_token(state).is_some()
}

fn admin_token(state: &UiState) -> Option<String> {
    state
        .ctx
        .config
        .get("ADMIN_TOKEN")
        .filter(|token| !token.is_empty())
}

fn cookie_value(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|line| line.split(';'))
        .map(str::trim)
        .find_map(|pair| {
            pair.strip_prefix(COOKIE)
                .and_then(|rest| rest.strip_prefix('='))
        })
        .map(str::to_owned)
}

/// `true` when the request carries a valid, unexpired session cookie.
fn has_session(state: &UiState, headers: &HeaderMap) -> bool {
    let Some(signer) = &state.ctx.signer else {
        return false;
    };
    cookie_value(headers)
        .and_then(|token| signer.verify(&token, PURPOSE))
        .is_some()
}

fn set_cookie(value: &str, max_age: Duration) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{COOKIE}={value}; Max-Age={}; Path=/ui/admin; HttpOnly; Secure; SameSite=Strict",
        max_age.as_secs()
    ))
    .expect("cookie is ascii")
}

fn to_login() -> Response {
    Redirect::to("/ui/admin/login").into_response()
}

/// Admin POSTs must come from a page this origin served: `Origin` (or
/// `Referer`) must match `Host`. `SameSite=Strict` already keeps the
/// cookie off cross-site posts; this catches the browsers that do not.
fn same_origin(headers: &HeaderMap) -> bool {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let source = headers
        .get(header::ORIGIN)
        .or_else(|| headers.get(header::REFERER))
        .and_then(|v| v.to_str().ok());
    match source {
        Some(url) => url
            .split("://")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .is_some_and(|h| h.eq_ignore_ascii_case(host)),
        None => false,
    }
}

fn forbidden(scope: &Scope, detail: &str) -> Response {
    Problem::new(&cratefield_core::SLUGS.admin_forbidden)
        .with_detail(detail)
        .instance(&scope.request_id)
        .into_response()
}

fn login_fields() -> Vec<Field> {
    fields_of(&serde_json::json!({
        "type": "object",
        "required": ["token"],
        "properties": {
            "token": {
                "type": "string",
                "x-cf-label": "Admin token",
                "x-cf-widget": "password",
                "x-cf-help": "The ADMIN_TOKEN this venture was deployed with."
            }
        }
    }))
}

fn login_page(state: &UiState, errors: &[(String, String)]) -> Response {
    let action = Action::post("login", "/login");
    let (title, body, _) = render_form(
        state,
        &action,
        "admin",
        &login_fields(),
        &Values::new(),
        errors,
    );
    let _ = title;
    let body = if enabled(state) {
        body
    } else {
        render::notice(
            "admin",
            "login",
            "warning",
            "Admin is switched off",
            "Set ADMIN_TOKEN and HARNESS_SECRET to enable the admin pages.",
        )
    };
    respond_admin(state, "Log in", &body, false)
}

pub(crate) async fn login_get(State(state): State<Arc<UiState>>, headers: HeaderMap) -> Response {
    if has_session(&state, &headers) {
        return Redirect::to("/ui/admin").into_response();
    }
    login_page(&state, &[])
}

pub(crate) async fn login_post(
    scope: Scope,
    State(state): State<Arc<UiState>>,
    headers: HeaderMap,
    axum::Form(form): axum::Form<Vec<(String, String)>>,
) -> Response {
    if !enabled(&state) {
        return login_page(&state, &[]);
    }
    if !same_origin(&headers) {
        return forbidden(&scope, "login must be posted from this origin");
    }
    if let Some(limiter) = &state.ctx.rate_limiter {
        let key = format!("admin-login:ip:{}", client_ip(&headers).unwrap_or_default());
        match limiter.limit(&key).await {
            Ok(decision) if !decision.ok => {
                let mut out = login_page(
                    &state,
                    &[(
                        String::new(),
                        "Too many attempts. Please try again later.".into(),
                    )],
                );
                *out.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                return out;
            }
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(error = %err, "admin login rate limiter unavailable; failing open");
            }
        }
    }
    let presented = form
        .iter()
        .find(|(k, _)| k == "token")
        .map(|(_, v)| v.as_str())
        .unwrap_or_default();
    let expected = admin_token(&state).unwrap_or_default();
    if presented.is_empty() || !constant_time_eq(presented.as_bytes(), expected.as_bytes()) {
        let mut out = login_page(
            &state,
            &[(
                "token".to_owned(),
                "That is not the admin token.".to_owned(),
            )],
        );
        *out.status_mut() = StatusCode::FORBIDDEN;
        return out;
    }
    let signer = state
        .ctx
        .signer
        .as_ref()
        .expect("enabled() checked the signer");
    // The Clock port, not `SystemTime`: the latter panics on
    // `wasm32-unknown-unknown`.
    let now = u64::try_from(cratefield_core::SystemClock.now().unix_timestamp().max(0))
        .unwrap_or_default();
    let session = signer.sign(&Payload {
        purpose: PURPOSE.to_owned(),
        subject: "admin".to_owned(),
        exp: Some(now.saturating_add(SESSION_TTL.as_secs())),
        kid: Kid::Cur,
    });
    let mut out = Redirect::to("/ui/admin").into_response();
    out.headers_mut()
        .insert(header::SET_COOKIE, set_cookie(&session, SESSION_TTL));
    out
}

pub(crate) async fn logout(State(state): State<Arc<UiState>>, headers: HeaderMap) -> Response {
    let _ = state;
    let _ = headers;
    let mut out = to_login();
    out.headers_mut()
        .insert(header::SET_COOKIE, set_cookie("", Duration::ZERO));
    out
}

/// The index: per module, links to its tables and its form actions.
pub(crate) async fn index(State(state): State<Arc<UiState>>, headers: HeaderMap) -> Response {
    if !has_session(&state, &headers) {
        return to_login();
    }
    let surface = state.ctx.surface.current().await;
    let entries: Vec<(String, Vec<(String, String)>)> = surface
        .modules
        .iter()
        .filter_map(|m| {
            let mut links = Vec::new();
            for view in &m.surface.views {
                if let View::Table { source, .. } = view
                    && admin_action(&surface, &m.name, source).is_some()
                {
                    links.push((
                        format!("/ui/admin/{}/{source}", m.name),
                        format!("{} table", humanize(source)),
                    ));
                }
            }
            for action in &m.surface.actions {
                if action.audience == Audience::Admin
                    && action.method == Method::POST
                    && action.input.is_some()
                {
                    links.push((
                        format!("/ui/admin/{}/{}", m.name, action.name),
                        humanize(&action.name),
                    ));
                }
            }
            (!links.is_empty()).then(|| (m.name.clone(), links))
        })
        .collect();
    respond_admin(&state, "Admin", &render::admin_index(&entries), true)
}

type Doc = cratefield_core::SurfaceDocument;

fn admin_action<'a>(surface: &'a Doc, module: &str, action: &str) -> Option<&'a Action> {
    surface
        .modules
        .iter()
        .find(|m| m.name == module)?
        .surface
        .actions
        .iter()
        .find(|a| a.name == action && a.audience == Audience::Admin)
}

fn table_view<'a>(surface: &'a Doc, module: &str, source: &str) -> Option<&'a View> {
    surface
        .modules
        .iter()
        .find(|m| m.name == module)?
        .surface
        .views
        .iter()
        .find(|v| matches!(v, View::Table { source: s, .. } if s == source))
}

/// The row actions a table offers: admin `DELETE` actions whose path
/// parameter names one of the table's columns.
fn row_actions<'a>(surface: &'a Doc, module: &str) -> Vec<(&'a Action, String)> {
    let Some(m) = surface.modules.iter().find(|m| m.name == module) else {
        return Vec::new();
    };
    m.surface
        .actions
        .iter()
        .filter(|a| a.audience == Audience::Admin && a.method == Method::DELETE)
        .filter_map(|a| {
            let start = a.path.find('{')?;
            let end = a.path[start..].find('}')? + start;
            Some((a, a.path[start + 1..end].to_owned()))
        })
        .collect()
}

/// Headers for an admin dispatch: the caller's, plus the bearer from
/// config so the module's own admin check passes.
fn bearer_headers(state: &UiState, headers: &HeaderMap) -> HeaderMap {
    let mut out = headers.clone();
    if let Some(token) = admin_token(state)
        && let Ok(value) = HeaderValue::from_str(&format!("Bearer {token}"))
    {
        out.insert(header::AUTHORIZATION, value);
    }
    out
}

/// `GET /ui/admin/<module>/<action>`: a table over an admin export, or
/// the form of an admin `POST` action.
pub(crate) async fn page_get(
    scope: Scope,
    State(state): State<Arc<UiState>>,
    Path((module, action)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if !has_session(&state, &headers) {
        return to_login();
    }
    let surface = state.ctx.surface.current().await;
    let Some(spec) = admin_action(&surface, &module, &action) else {
        return Problem::not_found()
            .with_detail(format!("no admin UI for {module}/{action}"))
            .instance(&scope.request_id)
            .into_response();
    };
    if spec.method == Method::POST {
        let fields = spec
            .input
            .as_ref()
            .map(|s| fields_of(s.as_value()))
            .unwrap_or_default();
        let (title, body, _) = render_form(&state, spec, &module, &fields, &Values::new(), &[]);
        let body = retarget(body, &module, &action);
        return respond_admin(&state, &title, &body, true);
    }
    let Some(View::Table { columns, .. }) = table_view(&surface, &module, &action) else {
        return Problem::not_found()
            .with_detail(format!("{module}/{action} has no table view"))
            .instance(&scope.request_id)
            .into_response();
    };
    let response = dispatch(
        &state,
        &scope,
        &bearer_headers(&state, &headers),
        spec,
        &module,
        "",
        None,
    )
    .await;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap_or_default();
    if !status.is_success() {
        let body = render::notice(
            &module,
            &action,
            "error",
            &humanize(&action),
            &format!(
                "The export answered {status}. Request id {}.",
                scope.request_id
            ),
        );
        let mut out = respond_admin(&state, &humanize(&action), &body, true);
        *out.status_mut() = status;
        return out;
    }
    let text = String::from_utf8_lossy(&bytes);
    let (header_row, records) = parse_csv(&text);
    let keys: Vec<&str> = if columns.is_empty() {
        header_row.iter().map(String::as_str).collect()
    } else {
        columns.iter().map(|c| c.key.as_str()).collect()
    };
    let labels: Vec<&str> = if columns.is_empty() {
        header_row.iter().map(String::as_str).collect()
    } else {
        columns.iter().map(|c| c.label.as_str()).collect()
    };
    let actions = row_actions(&surface, &module);
    let rows: Vec<render::TableRow<'_>> = records
        .iter()
        .map(|record| render::TableRow {
            cells: keys
                .iter()
                .map(|k| record.get(*k).map_or("", String::as_str))
                .collect(),
            actions: actions
                .iter()
                .filter_map(|(a, param)| {
                    let value = record.get(param.as_str())?;
                    Some((a.name.as_str(), vec![(param.as_str(), value.as_str())]))
                })
                .collect(),
        })
        .collect();
    let body = render::table(&module, &action, &labels, &rows);
    respond_admin(
        &state,
        &format!("{} · {}", humanize(&module), humanize(&action)),
        &body,
        true,
    )
}

/// The public form renders with `action="/ui/<module>/<action>"`; the
/// admin copy must post to `/ui/admin/...`.
fn retarget(body: Markup, module: &str, action: &str) -> Markup {
    let from = format!("action=\"/ui/{module}/{action}\"");
    let to = format!("action=\"/ui/admin/{module}/{action}\"");
    maud::PreEscaped(body.into_string().replacen(&from, &to, 1))
}

/// `POST /ui/admin/<module>/<action>`: an admin form dispatched as JSON,
/// or a row action: without `confirm=1` the confirm page, with it the
/// `DELETE` and a redirect back to the table.
pub(crate) async fn page_post(
    scope: Scope,
    State(state): State<Arc<UiState>>,
    Path((module, action)): Path<(String, String)>,
    headers: HeaderMap,
    axum::Form(form): axum::Form<Vec<(String, String)>>,
) -> Response {
    if !has_session(&state, &headers) {
        return to_login();
    }
    if !same_origin(&headers) {
        return forbidden(&scope, "admin actions must be posted from this origin");
    }
    let surface = state.ctx.surface.current().await;
    let Some(spec) = admin_action(&surface, &module, &action) else {
        return Problem::not_found()
            .with_detail(format!("no admin UI for {module}/{action}"))
            .instance(&scope.request_id)
            .into_response();
    };
    let values: Values = form.into_iter().collect();
    let bearer = bearer_headers(&state, &headers);
    match spec.method {
        Method::POST => {
            let fields = spec
                .input
                .as_ref()
                .map(|s| fields_of(s.as_value()))
                .unwrap_or_default();
            let json = Value::Object(form_to_json(&fields, &values));
            let response = dispatch(&state, &scope, &bearer, spec, &module, "", Some(json)).await;
            let status = response.status();
            let body = if status.is_success() {
                match &spec.outcome {
                    cratefield_core::Outcome::Accepted { message } => {
                        render::notice(&module, &action, "success", &humanize(&action), message)
                    }
                    _ => render::notice(&module, &action, "success", &humanize(&action), "Done."),
                }
            } else {
                render::notice(
                    &module,
                    &action,
                    "error",
                    &humanize(&action),
                    &format!(
                        "The module answered {status}. Request id {}.",
                        scope.request_id
                    ),
                )
            };
            let mut out = respond_admin(&state, &humanize(&action), &body, true);
            if !status.is_success() {
                *out.status_mut() = status;
            }
            out
        }
        Method::DELETE => {
            let Some((_, param)) = row_actions(&surface, &module)
                .into_iter()
                .find(|(a, _)| a.name == action)
            else {
                return forbidden(&scope, "this action is not a row action");
            };
            let Some(target) = values.get(&param).filter(|v| !v.is_empty()) else {
                return Problem::validation_failed(format!("{param} is required"))
                    .instance(&scope.request_id)
                    .into_response();
            };
            let back = back_to_table(&surface, &module);
            if values.get("confirm").map(String::as_str) != Some("1") {
                let hidden = vec![(param.clone(), target.clone())];
                let body = render::confirm(&module, &action, target, &hidden, &back);
                return respond_admin(&state, &humanize(&action), &body, true);
            }
            // Substitute the path parameter and dispatch the DELETE.
            let mut filled = spec.clone();
            filled.path = spec
                .path
                .replace(&format!("{{{param}}}"), &crate::percent_encode(target));
            let response = dispatch(&state, &scope, &bearer, &filled, &module, "", None).await;
            let status = response.status();
            if status.is_success() {
                return Redirect::to(&back).into_response();
            }
            let body = render::notice(
                &module,
                &action,
                "error",
                &humanize(&action),
                &format!(
                    "The module answered {status}. Request id {}.",
                    scope.request_id
                ),
            );
            let mut out = respond_admin(&state, &humanize(&action), &body, true);
            *out.status_mut() = status;
            out
        }
        _ => forbidden(&scope, "this action does not take a form"),
    }
}

/// After a row action: the module's first table, else the index.
fn back_to_table(surface: &Doc, module: &str) -> String {
    surface
        .modules
        .iter()
        .find(|m| m.name == module)
        .and_then(|m| {
            m.surface.views.iter().find_map(|v| match v {
                View::Table { source, .. } => Some(format!("/ui/admin/{module}/{source}")),
                _ => None,
            })
        })
        .unwrap_or_else(|| "/ui/admin".to_owned())
}

/// RFC 4180: quoted fields, doubled quotes, `\r\n` or `\n`. Returns the
/// header and one map per record. The writer side is
/// `cratefield_core::csv_row`; this is its inverse.
pub(crate) fn parse_csv(text: &str) -> (Vec<String>, Vec<BTreeMap<String, String>>) {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut cell = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if quoted {
            match c {
                '"' if chars.peek() == Some(&'"') => {
                    chars.next();
                    cell.push('"');
                }
                '"' => quoted = false,
                other => cell.push(other),
            }
            continue;
        }
        match c {
            '"' => quoted = true,
            ',' => row.push(std::mem::take(&mut cell)),
            '\r' => {}
            '\n' => {
                row.push(std::mem::take(&mut cell));
                rows.push(std::mem::take(&mut row));
            }
            other => cell.push(other),
        }
    }
    if !cell.is_empty() || !row.is_empty() {
        row.push(cell);
        rows.push(row);
    }
    let mut iter = rows.into_iter();
    let header = iter.next().unwrap_or_default();
    let records = iter
        .filter(|r| !(r.len() == 1 && r[0].is_empty()))
        .map(|r| {
            header
                .iter()
                .cloned()
                .zip(r.into_iter().chain(std::iter::repeat(String::new())))
                .collect()
        })
        .collect();
    (header, records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::Widget;
    use cratefield_core::csv_row;

    #[test]
    fn csv_round_trips_the_writer() {
        let text = format!(
            "id,email,note\n{}{}",
            csv_row(&["1", "a@b.co", "plain"]),
            csv_row(&["2", "c,d@e.f", "say \"hi\"\nthere"])
        );
        let (header, records) = parse_csv(&text);
        assert_eq!(header, ["id", "email", "note"]);
        assert_eq!(records.len(), 2);
        assert_eq!(records[1]["email"], "c,d@e.f");
        assert_eq!(records[1]["note"], "say \"hi\"\nthere");
        let (_, none) = parse_csv("id,email\n");
        assert!(none.is_empty());
    }

    #[test]
    fn cookie_is_found_among_others() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; cf_admin=tok.en; b=2"),
        );
        assert_eq!(cookie_value(&headers).as_deref(), Some("tok.en"));
        headers.insert(header::COOKIE, HeaderValue::from_static("cf_admins=x"));
        assert_eq!(cookie_value(&headers), None);
    }

    #[test]
    fn same_origin_compares_host() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("api.example.com"));
        assert!(!same_origin(&headers), "no origin, no referer: refused");
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://api.example.com"),
        );
        assert!(same_origin(&headers));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        assert!(!same_origin(&headers));
        headers.remove(header::ORIGIN);
        headers.insert(
            header::REFERER,
            HeaderValue::from_static("https://API.example.com/ui/admin/x"),
        );
        assert!(same_origin(&headers));
    }

    #[test]
    fn login_form_is_a_password_field() {
        let fields = login_fields();
        assert_eq!(fields[0].widget, Widget::Password);
        assert!(fields[0].required);
    }
}
