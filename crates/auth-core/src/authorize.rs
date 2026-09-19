//! The authorization code flow's browser endpoints (issue #10):
//! `GET /authorize` and `GET /logout` — which asks, `POST
//! /logout/confirm` being what acts (issue #439) — with the
//! server-rendered login chooser, confirmation and error pages.
//!
//! The two redirect rules everything here bends to:
//!
//! 1. **An unregistered `redirect_uri` never receives a redirect** —
//!    an unknown client, an unregistered URI and a disabled client
//!    all render the same generic error page, so the response cannot
//!    leak whether a client id exists and an attacker's URI is never
//!    validated by a redirect. Validation failures *after* the client
//!    and URI check (bad `response_type`, missing or non-S256
//!    challenge) redirect back to the registered URI with OAuth
//!    `error` parameters — spec-recommended, and safe because the URI
//!    is by then exact-matched against the registration.
//! 2. **No session, no code** — `/authorize` without a live session
//!    renders the login chooser, which offers the methods
//!    `AUTH_CORE_LOGIN_METHODS` names and carries this request as
//!    `return_to` so a person comes back to it (issue #33, ADR 0203).
//!    Redirect-shaped methods are links; a passkey is a scripted button,
//!    because a WebAuthn ceremony only runs on the origin its credential
//!    is bound to and so cannot happen anywhere but here.
//!
//! Authorization codes are 32 random bytes, base64url, stored only as
//! their SHA-256 in a `single_use_tokens` row of kind
//! `authorization_code` carrying the client id, redirect URI, code
//! challenge and session id, expiring in 60 seconds.

use askama::Template;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Form, OriginalUri, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64ct::{Base64UrlUnpadded, Encoding};
use cratefield_core::{Clock, Config, Database, ModuleConfig, Problem, Scope, subject_hash};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::ModuleState;
use crate::redirect_uri::matches_any;
use crate::secrets;
use crate::sessions;
use crate::store::{self, TOKEN_AUTHORIZATION_CODE};

/// Authorization-code lifetime: 60 seconds, single-use.
pub(crate) const CODE_LIFETIME_SECS: i64 = 60;

/// The generic `/authorize` failure page's one message: same words
/// for unknown client, unregistered URI and disabled client, because
/// the page is the only channel that could leak the difference.
const AUTHORIZE_REFUSED_MESSAGE: &str =
    "The sign-in request did not match a registered application.";

/// Where the chooser sends somebody when the request has no path at all,
/// which a well-formed HTTP request cannot produce.
const DEFAULT_CHOOSER_RETURN_TO: &str = "/";

/// The config key naming which login methods this deployment offers.
///
/// Explicit rather than sniffed from the other modules' keys. auth-core
/// does not import the login-method crates and must not learn their
/// configuration either, and a method whose module is not mounted would
/// otherwise get a button that 404s. Unknown slugs fail `validate_config`.
pub const LOGIN_METHODS_KEY: &str = "LOGIN_METHODS";

/// How a method is started from the chooser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MethodKind {
    /// A plain link: the browser is redirected and comes back.
    Redirect,
    /// A WebAuthn ceremony, which is script on this origin and nowhere
    /// else. See [`enabled_login_methods`].
    Passkey,
}

/// Every method the chooser knows how to start, by slug.
///
/// Adding a redirect-shaped provider is a row here. The label and the
/// path are auth-core's, because the chooser is auth-core's page.
///
/// A row is **data, not a dependency**: auth-core links none of the
/// login-method crates, so a slug can be listed before its module exists
/// and offering it is still `AUTH_CORE_LOGIN_METHODS`'s decision. That is
/// what lets a provider be added here and implemented separately.
const CATALOGUE: &[(&str, &str, &str, MethodKind)] = &[
    (
        "passkey",
        "Continue with a passkey",
        "",
        MethodKind::Passkey,
    ),
    (
        "google",
        "Continue with Google",
        "/v1/auth-oidc/google/start",
        MethodKind::Redirect,
    ),
    (
        "apple",
        "Continue with Apple",
        "/v1/auth-oidc/apple/start",
        MethodKind::Redirect,
    ),
    (
        "meta",
        "Continue with Facebook",
        "/v1/auth-meta/start",
        MethodKind::Redirect,
    ),
    // A link, like the providers, even though the method needs a typed
    // address: `auth-magic-link` serves the form itself at `/start`, so
    // the chooser hands off the same way it does for Google. The
    // alternative was a third `MethodKind` that renders a field on this
    // page, which would put one module's input handling — its validation,
    // its rate-limit refusal, its "check your inbox" — inside another
    // module's template.
    (
        "magic-link",
        "Email me a sign-in link",
        "/v1/auth-magic-link/start",
        MethodKind::Redirect,
    ),
    // Same shape and the same reason: two fields have to be typed, and a
    // wrong password has to be answerable on the page it was typed into,
    // so `auth-password` serves its own form and the chooser links to it.
    (
        "password",
        "Sign in with a password",
        "/v1/auth-password/start",
        MethodKind::Redirect,
    ),
];

/// The slugs `AUTH_CORE_LOGIN_METHODS` accepts.
#[must_use]
pub fn known_method_slugs() -> Vec<&'static str> {
    CATALOGUE.iter().map(|(slug, ..)| *slug).collect()
}

/// A button on the login chooser.
pub(crate) struct LoginMethod {
    /// The method's identifier, e.g. `passkey`.
    pub slug: String,
    pub label: String,
    /// Where the button goes. Empty for a passkey, which is started by
    /// script rather than followed.
    pub href: String,
    /// Whether the template renders this as the scripted passkey button
    /// rather than a link. A field rather than a match in the template,
    /// because askama templates should not carry logic.
    pub is_passkey: bool,
}

/// Renders an askama template to an HTML response.
///
/// askama 0.14 does not implement axum's `IntoResponse` (the
/// `askama_axum` bridge crate was discontinued), so templates are
/// rendered explicitly. A render failure is a bug in our own template,
/// never caller input, so it becomes a 500 problem rather than leaking
/// the template error to the browser.
fn html(template: &impl Template) -> Response {
    match template.render() {
        Ok(body) => axum::response::Html(body).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "auth template failed to render");
            Problem::internal().into_response()
        }
    }
}

#[derive(Template)]
#[template(path = "login_chooser.html")]
struct LoginChooserTemplate {
    methods: Vec<LoginMethod>,
    /// Whether to emit the passkey script at all. A page that offers no
    /// passkey carries no script.
    has_passkey: bool,
    /// The pending `/authorize`, for the button to navigate back to.
    return_to: String,
}

#[derive(Template)]
#[template(path = "authorize_error.html")]
struct AuthorizeErrorTemplate {
    message: &'static str,
    request_id: String,
}

#[derive(Template)]
#[template(path = "signed_out.html")]
struct SignedOutTemplate;

/// The page a `GET /logout` carrying a live session renders instead of
/// acting: it asks, and the form's POST is what acts (issue #439).
#[derive(Template)]
#[template(path = "confirm_logout.html")]
struct ConfirmLogoutTemplate {
    /// Where the form posts — this request's path with `/confirm`
    /// appended, computed rather than hardcoded so the module's mount
    /// point stays the harness's decision (`/v1/{module name}`).
    action: String,
    /// The client id the GET carried, for the POST to confirm — present
    /// only when the pair it belongs to validated.
    client_id: Option<String>,
    /// The validated post-logout redirect, likewise.
    post_logout_redirect_uri: Option<String>,
}

fn iso(t: OffsetDateTime) -> String {
    t.replace_nanosecond(0)
        .expect("truncation stays in range")
        .format(&Rfc3339)
        .expect("rfc3339 formats")
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

/// The methods this deployment offers, in the order the operator listed
/// them, each carrying `return_to` so a person lands back on the
/// `/authorize` they started from.
///
/// **Why passkeys cannot be a link.** A WebAuthn credential is bound to a
/// relying-party id, and a browser will only run a ceremony for an RP id
/// that matches the page it is on. A passkey registered here can therefore
/// only ever be used on a page served by this service: a consuming app on
/// its own domain is physically unable to run the ceremony, whatever code
/// it ships. So either this service renders a page with script, or passkeys
/// are unreachable through the authorization flow. It renders the page
/// (ADR 0203); redirect-shaped methods stay plain links, which work with
/// script switched off.
#[must_use]
pub(crate) fn enabled_login_methods(cfg: &dyn Config, return_to: &str) -> Vec<LoginMethod> {
    let module = ModuleConfig::new("auth-core", cfg);
    let Some(raw) = module.get_opt(LOGIN_METHODS_KEY) else {
        return Vec::new();
    };
    // The same encoder the OAuth error redirect uses. What goes in is a
    // path carrying a query of its own, so every `&`, `=` and `?` must
    // survive as data or the provider's `/start` reads the tail as its
    // own parameters.
    let encoded = encode_query_component(return_to);
    raw.split(',')
        .map(str::trim)
        .filter(|slug| !slug.is_empty())
        .filter_map(|slug| {
            CATALOGUE
                .iter()
                .find(|(known, ..)| *known == slug)
                .map(|(slug, label, path, kind)| LoginMethod {
                    slug: (*slug).to_owned(),
                    label: (*label).to_owned(),
                    href: match kind {
                        MethodKind::Redirect => format!("{path}?return_to={encoded}"),
                        // Started by script, not followed.
                        MethodKind::Passkey => String::new(),
                    },
                    is_passkey: *kind == MethodKind::Passkey,
                })
        })
        .collect()
}

fn error_page(scope: &Scope) -> Response {
    let page = html(&AuthorizeErrorTemplate {
        message: AUTHORIZE_REFUSED_MESSAGE,
        request_id: scope.request_id.clone(),
    });
    // A refused /authorize must not redirect: sending the browser to an
    // unregistered URI is the vulnerability exact matching prevents
    // (issue #7). 400 with a page, never 302.
    (StatusCode::BAD_REQUEST, page).into_response()
}

/// Percent-encodes one query component: unreserved characters pass,
/// everything else becomes `%XX`. The code is base64url already; the
/// client-supplied `state` is arbitrary text and must round-trip.
fn encode_query_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

/// Builds the redirect back to the registered URI, appending to any
/// query the registration itself carries.
fn redirect_with_params(uri: &str, params: &[(&str, String)]) -> String {
    let separator = if uri.contains('?') { '&' } else { '?' };
    let query = params
        .iter()
        .map(|(key, value)| format!("{key}={}", encode_query_component(value)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{uri}{separator}{query}")
}

/// Redirects to the validated URI with an OAuth error code; used only
/// after the client and URI checks passed.
fn oauth_error_redirect(uri: &str, error: &str, state: Option<&str>) -> Response {
    let mut params = vec![("error", error.to_owned())];
    if let Some(state) = state {
        params.push(("state", state.to_owned()));
    }
    (
        StatusCode::FOUND,
        [(header::LOCATION, redirect_with_params(uri, &params))],
    )
        .into_response()
}

fn is_base64url_43(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[derive(Deserialize)]
struct AuthorizeQuery {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
}

/// Validates the client and the exact redirect URI. `Err` renders the
/// generic error page — never a redirect — and never distinguishes an
/// unknown client from an unregistered URI or a disabled client.
async fn validate_client_and_uri(
    db: &dyn Database,
    client_id: &str,
    redirect_uri: &str,
) -> Result<store::ClientRow, ()> {
    let Some(client) = store::client_by_id(db, client_id).await.map_err(|_| ())? else {
        return Err(());
    };
    let registered = store::redirect_uris_for_client(db, client_id)
        .await
        .map_err(|_| ())?
        .into_iter()
        .map(|row| row.uri)
        .collect::<Vec<_>>();
    if !matches_any(&registered, redirect_uri) {
        return Err(());
    }
    if secrets::ensure_client_usable(&client).is_err() {
        return Err(());
    }
    Ok(client)
}

// The /authorize handler is one linear ceremony — validate client and
// URI, require a session, mint the code, redirect — and splitting it
// into fragments that each take eight arguments would obscure the order
// the security argument depends on. Kept whole, deliberately.
#[allow(clippy::too_many_lines)]
async fn authorize(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    OriginalUri(original_uri): OriginalUri,
    headers: HeaderMap,
    query: Result<Query<AuthorizeQuery>, QueryRejection>,
) -> Result<Response, Problem> {
    let Query(query) = query.map_err(|_| Problem::internal())?;
    let (Some(db), Some(clock), Some(id_gen)) = (
        state.ctx.ports.db.clone(),
        state.ctx.ports.clock.clone(),
        state.ctx.ports.id_gen.clone(),
    ) else {
        return Err(Problem::internal());
    };

    // Client and URI first: any failure here renders the page, never
    // a redirect (the brief's one hard rule).
    if query.client_id.is_empty()
        || query.redirect_uri.is_empty()
        || validate_client_and_uri(&*db, &query.client_id, &query.redirect_uri)
            .await
            .is_err()
    {
        return Ok(error_page(&scope));
    }

    // From here the URI is registered: parameter failures redirect
    // back with OAuth error codes, as RFC 6749 section 4.1.2.1
    // recommends.
    if query.response_type != "code" {
        return Ok(oauth_error_redirect(
            &query.redirect_uri,
            "unsupported_response_type",
            query.state.as_deref(),
        ));
    }
    let challenge_ok = query.code_challenge.as_deref().is_some_and(is_base64url_43);
    let method_ok = query.code_challenge_method.as_deref() == Some("S256");
    if !challenge_ok || !method_ok {
        // Missing challenge, wrong length, or any method other than
        // S256 — which includes `plain`, refused outright.
        return Ok(oauth_error_redirect(
            &query.redirect_uri,
            "invalid_request",
            query.state.as_deref(),
        ));
    }
    if let Some(state_param) = query.state.as_deref()
        && state_param.len() > 2048
    {
        return Ok(oauth_error_redirect(
            &query.redirect_uri,
            "invalid_request",
            None,
        ));
    }

    // A session is required to mint a code; without one, the login
    // chooser. Its buttons carry this very request as `return_to`, so a
    // person lands back on the pending `/authorize` rather than on the
    // service's root with their request lost.
    //
    // `OriginalUri` and not `Uri`: the module is nested under
    // `/v1/auth-core`, and a nested handler sees the URI with the prefix
    // already stripped, so `Uri` alone would send people to `/authorize`,
    // which does not exist.
    let chooser = || {
        // Path and query, never `to_string()`. On Workers the runtime
        // builds the request from `req.url()`, so the URI is **absolute**:
        // `https://auth.example/v1/auth-core/authorize?...`. Every
        // provider's `safe_return_to` refuses anything not starting with
        // `/`, so an absolute value is silently replaced by the default
        // and the person lands on `/` with their authorization request
        // gone — which is the exact thing this page exists to prevent.
        // On the native runtime the same URI arrives in origin form, so
        // the bug only appears in production, which is why the tests were
        // green. See the test that sends an absolute-form target.
        let return_to = original_uri.path_and_query().map_or_else(
            || DEFAULT_CHOOSER_RETURN_TO.to_owned(),
            |path_and_query| path_and_query.as_str().to_owned(),
        );
        let methods = enabled_login_methods(&*state.ctx.config, &return_to);
        html(&LoginChooserTemplate {
            has_passkey: methods.iter().any(|method| method.is_passkey),
            methods,
            return_to,
        })
    };
    let Some(cookie) = sessions::cookie_value(&headers) else {
        return Ok(chooser());
    };
    let session = sessions::validate(&*db, &*clock, &cookie)
        .await
        .map_err(|_| Problem::internal())?;
    let Some(session) = session else {
        return Ok(chooser());
    };

    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|err| {
        tracing::error!(error = %err, "code entropy source failed");
        Problem::internal()
    })?;
    let code = Base64UrlUnpadded::encode_string(&bytes);
    let now = clock.now().replace_nanosecond(0).expect("in range");
    store::insert_single_use_token(
        &*db,
        &store::SingleUseTokenRow {
            id: id_gen.ulid(),
            kind: TOKEN_AUTHORIZATION_CODE.to_owned(),
            token_hash: store::Redacted(sha256(code.as_bytes())),
            user_id: Some(session.user_id.clone()),
            client_id: Some(query.client_id.clone()),
            payload: Some(
                json!({
                    "redirect_uri": query.redirect_uri,
                    "code_challenge": query.code_challenge,
                    "sid": session.id,
                })
                .to_string(),
            ),
            expires_at: iso(now.saturating_add(time::Duration::seconds(CODE_LIFETIME_SECS))),
            consumed_at: None,
        },
    )
    .await?;

    tracing::info!(
        audit = true,
        action = "authorize.grant",
        client_id = %query.client_id,
        subject_hash = %subject_hash(&session.user_id),
        "authorization code issued"
    );
    let mut params = vec![("code", code)];
    if let Some(state_param) = query.state.clone() {
        params.push(("state", state_param));
    }
    Ok((
        StatusCode::FOUND,
        [(
            header::LOCATION,
            redirect_with_params(&query.redirect_uri, &params),
        )],
    )
        .into_response())
}

#[derive(Deserialize)]
struct LogoutQuery {
    client_id: Option<String>,
    post_logout_redirect_uri: Option<String>,
}

/// RP-initiated logout, in the shape the OIDC spec recommends when the
/// request carries no `id_token_hint`: **GET asks, POST acts.**
///
/// The session cookie is `SameSite=Lax`, which the browser *does* send on
/// a cross-site top-level GET — so a GET that revoked would let any page
/// on the internet sign anyone out with an `<img>` tag. RP-initiated
/// logout is legitimately that navigation (the relying party redirects
/// here), so the GET cannot simply be refused; instead it renders the
/// confirmation page, and only the same-origin POST ends the session.
///
/// Either way a redirect happens **only** to a registered URI of a
/// registered, active client — an unregistered target renders the error
/// page and never redirects.
async fn logout(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    OriginalUri(original_uri): OriginalUri,
    query: Result<Query<LogoutQuery>, QueryRejection>,
) -> Result<Response, Problem> {
    let Query(query) = query.map_err(|_| Problem::internal())?;
    let (Some(db), Some(clock)) = (state.ctx.ports.db.clone(), state.ctx.ports.clock.clone())
    else {
        return Err(Problem::internal());
    };

    // The same client / URI check as ever, before anything else about the
    // session is even looked at. A refused pair renders the error page —
    // not a `Problem`, but *the* response.
    let Ok(target) = validated_target(
        &*db,
        query.client_id.as_deref(),
        query.post_logout_redirect_uri.as_deref(),
    )
    .await
    else {
        return Ok(error_page(&scope));
    };

    // A live session is asked, not told: render the confirmation and
    // revoke nothing, clear nothing. `OriginalUri` and not `Uri` — the
    // module is nested under `/v1/auth-core` and a nested handler sees
    // the prefix already stripped (see `/authorize`), while the form's
    // action has to be the path the browser can actually post to.
    if let Some(cookie) = sessions::cookie_value(&headers)
        && matches!(
            sessions::validate(&*db, &*clock, &cookie).await,
            Ok(Some(_))
        )
    {
        // The hidden inputs carry the pair only once it validated, so the
        // POST confirms exactly the request the GET was given.
        let (client_id, redirect) = if target.is_empty() {
            (None, None)
        } else {
            (query.client_id.clone(), Some(target.clone()))
        };
        return Ok(html(&ConfirmLogoutTemplate {
            action: confirm_action(original_uri.path()),
            client_id,
            post_logout_redirect_uri: redirect,
        }));
    }

    // No cookie that validates: there is nothing to revoke, so this path
    // is safe even for the cross-site GET a hostile page can produce.
    // Clearing an already-invalid cookie changes nothing an attacker
    // cares about, and the person still gets today's answer — the
    // validated redirect, or the signed-out page.
    sign_out(&*db, &*clock, sessions::cookie_value(&headers), target).await
}

#[derive(Deserialize)]
struct LogoutConfirmForm {
    client_id: Option<String>,
    post_logout_redirect_uri: Option<String>,
}

/// `POST /logout/confirm` — the act the GET only asked about. The
/// same-origin guard runs first: `sec-fetch-site` and `origin` are the
/// two signals a browser sends and a page cannot forge, and they are
/// what make "a POST from this venture's own confirmation form" a
/// checked fact rather than an assumption (issue #439). Everything after
/// the guard is what `GET /logout` used to do.
async fn logout_confirm(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    uri: Uri,
    Form(form): Form<LogoutConfirmForm>,
) -> Result<Response, Problem> {
    crate::csrf::require_same_origin(&headers, &uri)
        .map_err(|problem| problem.instance(&scope.request_id))?;
    let (Some(db), Some(clock)) = (state.ctx.ports.db.clone(), state.ctx.ports.clock.clone())
    else {
        return Err(Problem::internal());
    };
    let Ok(target) = validated_target(
        &*db,
        form.client_id.as_deref(),
        form.post_logout_redirect_uri.as_deref(),
    )
    .await
    else {
        return Ok(error_page(&scope));
    };
    sign_out(&*db, &*clock, sessions::cookie_value(&headers), target).await
}

/// The post-logout redirect target, after the one client / URI check both
/// logout paths run: the redirect only when a pair was named and it
/// validated. `Err(())` is a refused pair — the caller renders the
/// generic error page, never a redirect, and never a word that
/// distinguishes an unknown client from an unregistered URI or a
/// disabled client.
async fn validated_target(
    db: &dyn Database,
    client_id: Option<&str>,
    redirect: Option<&str>,
) -> Result<String, ()> {
    match (client_id, redirect) {
        (Some(client_id), Some(redirect)) => {
            match validate_client_and_uri(db, client_id, redirect).await {
                Ok(_) => Ok(redirect.to_owned()),
                Err(()) => Err(()),
            }
        }
        (_, Some(_)) => Err(()),
        // No post-logout redirect requested (or a client id without
        // one): sign out and render the signed-out page.
        (_, None) => Ok(String::new()),
    }
}

/// Everything that actually ends a session: revoke the one the cookie
/// names, if any, emit the audit event, clear the cookie either way, and
/// land the person on the validated post-logout redirect or the
/// signed-out page. Shared by the confirming POST and the GET that found
/// no live session, so the two cannot grow different rules about who is
/// revoked or where a sign-out ends.
async fn sign_out(
    db: &dyn Database,
    clock: &dyn Clock,
    cookie: Option<String>,
    target: String,
) -> Result<Response, Problem> {
    if let Some(value) = cookie.as_deref()
        && let Ok(Some(session)) = sessions::validate(db, clock, value).await
    {
        store::revoke_session(db, &session.id, &iso(clock.now())).await?;
        tracing::info!(
            audit = true,
            action = "logout.rp",
            subject_hash = %subject_hash(&session.user_id),
            "session revoked at logout"
        );
    }

    let clear = [(header::SET_COOKIE, sessions::clear_cookie())];
    if target.is_empty() {
        return Ok((clear, html(&SignedOutTemplate)).into_response());
    }
    Ok((StatusCode::FOUND, clear, [(header::LOCATION, target)]).into_response())
}

/// The confirmation form's action: this path with `/confirm` appended,
/// any trailing slash trimmed first. Computed from the request so the
/// module's mount point (`/v1/{module name}`, set by the harness) stays
/// the harness's decision rather than a constant in this file.
fn confirm_action(path: &str) -> String {
    format!("{}/confirm", path.trim_end_matches('/'))
}

pub(crate) fn router() -> axum::Router<Arc<ModuleState>> {
    axum::Router::new()
        .route("/authorize", get(authorize))
        .route("/logout", get(logout))
        .route("/logout/confirm", post(logout_confirm))
}

#[cfg(test)]
mod tests {

    /// The template must escape `return_to`, whatever it holds.
    ///
    /// The HTTP path cannot deliver a raw `<` — `http::Uri` refuses one —
    /// so this renders the template directly with a value no request could
    /// carry. That is the point: the escaping is the defence, and it must
    /// hold without depending on the URI parser to be the thing that saves
    /// us. If `return_to` ever moves into the script body, this fails.
    #[test]
    fn a_hostile_return_to_cannot_break_out_of_the_page() {
        let hostile = "/authorize?state=</script><script>alert(1)</script>";
        let page = LoginChooserTemplate {
            methods: vec![LoginMethod {
                slug: "passkey".to_owned(),
                label: "Continue with a passkey".to_owned(),
                href: String::new(),
                is_passkey: true,
            }],
            has_passkey: true,
            return_to: hostile.to_owned(),
        }
        .render()
        .expect("renders");

        assert!(
            !page.contains("</script><script>alert(1)"),
            "return_to escaped into the page: {page}"
        );
        // askama escapes with numeric entities (`&#60;`), not named ones.
        // Asserted on the escaped form rather than the absence of the raw
        // one, so this fails loudly if the value ever stops being escaped
        // rather than quietly if it stops being present.
        assert!(
            page.contains("&#60;/script&#62;") || page.contains("&lt;/script&gt;"),
            "the value should be present and escaped: {page}"
        );
    }
    use super::*;

    /// The confirmation page must escape whatever its hidden inputs
    /// carry, whatever the logout query held. The HTTP path cannot
    /// deliver a raw `<` — `http::Uri` refuses one — so, like the
    /// chooser test above, this renders the template directly with
    /// values no request could carry: the escaping is the defence, and
    /// it must hold without the URI parser being the thing that saves
    /// us. If `client_id` or `post_logout_redirect_uri` ever moves out
    /// of an attribute, this fails.
    #[test]
    fn a_hostile_redirect_pair_cannot_break_out_of_the_confirmation() {
        let hostile = "https://app.example/cb?next=\"><script>alert(1)</script>";
        let page = ConfirmLogoutTemplate {
            action: "/v1/auth-core/logout/confirm".to_owned(),
            client_id: Some("\"><script>alert(1)</script>".to_owned()),
            post_logout_redirect_uri: Some(hostile.to_owned()),
        }
        .render()
        .expect("renders");

        assert!(
            !page.contains("</script><script>alert(1)"),
            "a hidden input escaped into the page: {page}"
        );
        // askama escapes with numeric entities (`&#60;`), not named ones.
        // The quote matters as much as the brackets: an unescaped `"`
        // would close the `value="…"` attribute and let the rest of the
        // value become markup.
        assert!(
            page.contains("&#60;script&#62;") || page.contains("&lt;script&gt;"),
            "the value should be present and escaped: {page}"
        );
        assert!(
            page.contains("&#34;") || page.contains("&quot;"),
            "the double quote should be escaped inside the attribute: {page}"
        );
    }

    #[test]
    fn the_confirm_action_appends_to_the_request_path() {
        // Origin form on the native runtime.
        assert_eq!(
            confirm_action("/v1/auth-core/logout"),
            "/v1/auth-core/logout/confirm"
        );
        // A trailing slash must not double up.
        assert_eq!(
            confirm_action("/v1/auth-core/logout/"),
            "/v1/auth-core/logout/confirm"
        );
    }

    #[test]
    fn query_components_round_trip_through_percent_encoding() {
        assert_eq!(encode_query_component("abcXYZ09-_.~"), "abcXYZ09-_.~");
        assert_eq!(encode_query_component("a b&c=d"), "a%20b%26c%3Dd");
        assert_eq!(encode_query_component("héllo"), "h%C3%A9llo");
    }

    #[test]
    fn redirects_append_to_the_registered_query_properly() {
        assert_eq!(
            redirect_with_params("https://app.example/cb", &[("code", "c".to_owned())]),
            "https://app.example/cb?code=c"
        );
        assert_eq!(
            redirect_with_params(
                "https://app.example/cb?x=1",
                &[("code", "c".to_owned()), ("state", "s s".to_owned())]
            ),
            "https://app.example/cb?x=1&code=c&state=s%20s"
        );
    }

    #[test]
    fn challenges_must_be_43_base64url_characters() {
        assert!(is_base64url_43(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        ));
        assert!(!is_base64url_43("short"));
        assert!(!is_base64url_43(&"x".repeat(44)));
        assert!(!is_base64url_43(
            "d+BjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX"
        ));
    }
}
