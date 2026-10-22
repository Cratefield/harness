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
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64ct::{Base64UrlUnpadded, Encoding};
use cratefield_core::{Clock, Config, Database, IdGen, ModuleConfig, Problem, Scope, subject_hash};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::ModuleState;
use crate::brand::Brand;
use crate::intents;
use crate::page::wants_html;
use crate::redirect_uri::matches_any;
use crate::secrets;
use crate::sessions;
use crate::sign_in_step::{MARKER_COOKIE, SignIn};
use crate::sso;
use crate::store::{self, TOKEN_AUTHORIZATION_CODE};
use crate::token_endpoint;

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

/// The link-shaped sign-in methods this deployment offers, as
/// `(label, href)`, each carrying `return_to` (a path on this service) so
/// a person lands back where they started. For a hosted page outside the
/// authorization flow that needs a signed-in person — adding a passkey,
/// for one. The passkey method is left out: it is started by the
/// chooser's script, not by a link, and a page that asks someone to sign
/// in first is usually there because they have no passkey yet.
#[must_use]
pub fn sign_in_links(cfg: &dyn Config, return_to: &str) -> Vec<(String, String)> {
    enabled_login_methods(cfg, return_to)
        .into_iter()
        .filter(|method| !method.is_passkey)
        .map(|method| (method.label, method.href))
        .collect()
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
        // Every page here is a hosted page: `same-origin`, so the
        // chooser's passkey `fetch` and the sign-out form send a real
        // `Origin` (issue #840; see `crate::page`).
        Ok(body) => crate::page::with_page_headers(axum::response::Html(body).into_response()),
        Err(err) => {
            tracing::error!(error = %err, "auth template failed to render");
            Problem::internal().into_response()
        }
    }
}

#[derive(Template)]
#[template(path = "login_chooser.html")]
struct LoginChooserTemplate {
    brand: Brand,
    /// The link-shaped methods other than the email step, in the operator's
    /// order. Shown under "Other ways to continue".
    methods: Vec<LoginMethod>,
    /// Whether to emit the passkey script at all. A page that offers no
    /// passkey carries no script.
    has_passkey: bool,
    /// Whether the email step is offered (the magic link is enabled here).
    has_email: bool,
    /// Whether this deployment creates accounts from an email. When it does
    /// not, the page says the app is invite-only, for every address alike.
    registration_open: bool,
    /// The address `login_hint` named, when it is a valid one. Its presence
    /// skips the email step: the method choice is shown straight away.
    hint: Option<String>,
    /// The pending `/authorize`, for the buttons to navigate back to.
    return_to: String,
    /// The same request without `login_hint`, for "Use a different address".
    return_to_without_hint: String,
    /// The Turnstile widget for the email form, when the instance has a captcha.
    turnstile_widget: Option<String>,
    /// The Turnstile loader script, with the widget.
    turnstile_script: Option<&'static str>,
}

#[derive(Template)]
#[template(path = "authorize_error.html")]
struct AuthorizeErrorTemplate {
    brand: Brand,
    message: &'static str,
    request_id: String,
}

#[derive(Template)]
#[template(path = "signed_out.html")]
struct SignedOutTemplate {
    brand: Brand,
}

/// The page a `GET /logout` carrying a live session renders instead of
/// acting: it asks, and the form's POST is what acts (issue #439).
#[derive(Template)]
#[template(path = "confirm_logout.html")]
struct ConfirmLogoutTemplate {
    brand: Brand,
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

/// The instance's branding for a page this module renders.
fn brand_of(state: &ModuleState) -> Brand {
    Brand::from_config(&*state.ctx.config, &state.ctx.venture)
}

fn error_page(scope: &Scope, brand: Brand) -> Response {
    let page = html(&AuthorizeErrorTemplate {
        brand,
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

/// Where an `/authorize` that named an SSO connection — or that a
/// `login_hint` routed to one — sends the browser: that connection's
/// start, carrying this request back as `return_to` exactly as the
/// chooser's buttons do, so the person returns to the pending
/// authorization with nothing lost.
///
/// The path is another module's route, spelled here the same way the
/// `CATALOGUE` rows spell theirs: a path is data, not a dependency, and
/// auth-core links no login-method crate.
fn sso_start_redirect(connection_id: &str, return_to: &str) -> Response {
    let encoded = encode_query_component(return_to);
    (
        StatusCode::FOUND,
        [(
            header::LOCATION,
            format!("/v1/auth-oidc/sso/{connection_id}/start?return_to={encoded}"),
        )],
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
    /// An enterprise SSO connection to sign in through (issue #627). Only
    /// one of *this* client's own active connections is routable.
    connection: Option<String>,
    /// An address whose domain may name the connection to sign in
    /// through, for a caller that knows the person's address but not the
    /// connection. A hint, never an instruction.
    login_hint: Option<String>,
    /// OpenID Connect `prompt` (Core section 3.1.2.1): space-separated
    /// values. `login` forces a fresh ceremony even with a live session
    /// (issue #912); `none` forbids any interaction.
    prompt: Option<String>,
    /// OpenID Connect `max_age` (Core section 3.1.2.1), as sent: the
    /// longest acceptable time since the last authentication, in seconds.
    /// `0` means the person must authenticate now. Parsed by
    /// [`parse_max_age`] so a malformed value is refused with an OAuth
    /// error rather than a rejected query.
    max_age: Option<String>,
    /// OpenID Connect `nonce`: echoed into the ID token so the client can
    /// tie the token to its own request (issue #912).
    nonce: Option<String>,
    /// OpenID Connect `scope`. An ID token is issued only when it includes
    /// `openid`.
    scope: Option<String>,
    /// The step-up transaction a login returns with (issue #912). Written
    /// into the chooser's return path by this module; a value that names no
    /// live transaction of this account and client does nothing.
    step_up: Option<String>,
    /// The sign-up intents the application collected itself, comma-separated
    /// (see [`crate::intents`]). Each must be on the client's list; given, the
    /// hosted "What brings you here?" step is skipped.
    intents: Option<String>,
}

/// The longest `nonce` accepted. Opaque to this service and echoed
/// verbatim into the ID token, so the bound is a sanity limit.
const MAX_NONCE_BYTES: usize = 512;

/// The `prompt` values this service understands: `none`, `login`, and
/// `consent` / `select_account`, which name interactions it does not
/// have and so accepts without acting on.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Prompt {
    none: bool,
    login: bool,
    /// `intents`: ask the signed-in person what brings them here, again, and
    /// record the answer (this module's extension; see [`crate::intents`]).
    intents: bool,
}

/// Reads `prompt`. Any unknown value, or `none` alongside another value
/// (OpenID Connect Core section 3.1.2.1 forbids that), is an error.
fn parse_prompt(raw: Option<&str>) -> Result<Prompt, ()> {
    let mut prompt = Prompt::default();
    let Some(raw) = raw else {
        return Ok(prompt);
    };
    let values: Vec<&str> = raw.split_ascii_whitespace().collect();
    for value in &values {
        match *value {
            "none" => prompt.none = true,
            "login" => prompt.login = true,
            "intents" => prompt.intents = true,
            "consent" | "select_account" => {}
            _ => return Err(()),
        }
    }
    if prompt.none && values.len() > 1 {
        return Err(());
    }
    Ok(prompt)
}

/// Reads `max_age`: decimal digits only, so `-1`, `+5` and `1.5` are all
/// refused. An absent value is no requirement.
fn parse_max_age(raw: Option<&str>) -> Result<Option<i64>, ()> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if raw.is_empty() || raw.len() > 10 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    raw.parse::<i64>().map(Some).map_err(|_| ())
}

/// `path_and_query` with the named query parameters removed. The login
/// chooser hands the pending request back to itself; a demand the login
/// it is about to complete has already met must not travel with it.
fn without_query_params(path_and_query: &str, names: &[&str]) -> String {
    let Some((path, query)) = path_and_query.split_once('?') else {
        return path_and_query.to_owned();
    };
    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| !names.contains(&pair.split('=').next().unwrap_or_default()))
        .collect();
    if kept.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{}", kept.join("&"))
    }
}

/// How long a step-up transaction stays good, from the moment the demand
/// was made (issue #912).
const STEP_UP_TTL_SECS: i64 = 600;

/// The most a ceremony's session may be old, in milliseconds, and still be
/// the ceremony a transaction asked for.
const STEP_UP_MAX_SESSION_AGE_MS: i64 = 120_000;

/// How long after a passkey or address change the account's passkey and email
/// ceremonies stop counting as a step-up. A credential enrolled or an address
/// changed by a session the attacker holds must not be the thing that lets
/// that session pass a step-up (issue #912, second review).
const SECURITY_QUIET_SECS: i64 = 24 * 60 * 60;

/// The most open demands made before anyone was signed in, for one client. Past
/// it the oldest is evicted, so an anonymous caller can never lock another out
/// (issue #912, fifth review).
const MAX_OPEN_UNBOUND_PER_CLIENT: usize = 1000;

/// The most open anonymous demands naming one account (`login_hint`). Counted
/// apart from the account's signed-in demands, and past it the new one is
/// refused, never an older one evicted (fifth review).
const MAX_OPEN_ANONYMOUS_HINT_PER_ACCOUNT: usize = 5;

/// The rate limit an anonymous caller's demands are held to, per caller
/// address. `None` when the caller is within it, or when there is no limiter.
///
/// `Err` when the limiter itself fails: an anonymous demand is then refused
/// (fail closed), because nothing bounds it while the limiter is down (issue
/// #912, final review).
async fn step_up_limit(
    state: &ModuleState,
    headers: &HeaderMap,
) -> Result<Option<cratefield_core::Decision>, ()> {
    let Some(limiter) = state.ctx.ports.rate_limiter.as_deref() else {
        return Err(());
    };
    let ip = cratefield_core::client_ip(headers);
    for key in cratefield_core::rate_limit_keys(ip.as_deref(), None) {
        match limiter.limit(&format!("auth-core:step-up:{key}")).await {
            Ok(decision) if !decision.ok => return Ok(Some(decision)),
            Ok(_) => {}
            Err(err) => {
                tracing::error!(error = %err, "the auth-core rate limiter failed; refusing an anonymous demand");
                return Err(());
            }
        }
    }
    Ok(None)
}

/// The most open transactions one account may hold. The oldest are dropped
/// when a new one would exceed it.
const MAX_OPEN_STEP_UPS_PER_ACCOUNT: usize = 20;

/// The authentication methods a step-up ceremony may complete with. A passkey
/// is verified here and an email link proves the mailbox here. A federated or
/// SSO sign-in is not: the upstream's authentication is not checked by this
/// service. `pwd` is left out too: a password is what the person already
/// holds, not a fresh act of the same kind.
const STEP_UP_METHODS: [&str; 2] = ["passkey", "email"];

/// The authentication context a session carries once it has spent a step-up
/// transaction (`acr`, issue #912).
pub(crate) const STEP_UP_ACR: &str = "urn:cratefield:stepup";

/// The query parameter that carries a step-up transaction through the login
/// and back to `/authorize`. Written by this module into the chooser's return
/// path only.
const STEP_UP_PARAM: &str = "step_up";

/// The cookie that binds a demand made before anyone is signed in to the
/// browser that made it. Set by the chooser, `HttpOnly`, and read back on the
/// return from the login.
const BROWSER_COOKIE: &str = "__Host-step-up";

/// The outcome of checking a request's step-up demand against the browser's
/// session.
enum StepUp {
    /// Nothing more is asked of the session.
    Met,
    /// The session's ceremony spent a transaction at `at` (RFC 3339): the
    /// request is met, and the authorization code it earns carries `acr`.
    SteppedUp { at: String },
    /// The session must authenticate again. `transaction` is the value the
    /// chooser carries through the login, when this request made a demand.
    Required { transaction: Option<String> },
}

/// What a request asks of the live session.
struct StepUpAsk<'a> {
    prompt: Prompt,
    max_age: Option<i64>,
    /// The transaction value the request came back with, if any.
    presented: Option<&'a str>,
    client_id: &'a str,
    /// Whether a demand may be recorded. A `prompt=none` request is answered
    /// with `login_required` and writes nothing.
    record: bool,
    /// The hash of this browser's step-up cookie, if it sent one.
    browser_hash: Option<String>,
}

/// The current instant in milliseconds since the epoch.
fn now_ms(clock: &dyn Clock) -> i64 {
    i64::try_from(clock.now().unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX)
}

/// Whether the live session satisfies the request's step-up demand (issue
/// #912, OpenID Connect Core section 3.1.2.1).
///
/// - `max_age=N` with N > 0 is a plain age check against the session's
///   creation, the moment of its last real authentication. It records nothing
///   and it does not imply a method: a federated sign-in ends a `max_age`
///   window like any other. A step-up caller uses `prompt=login`.
/// - `prompt=login` and `max_age=0` demand a ceremony that happens after this
///   request. The demand is a server-side transaction, and only a passkey or
///   email ceremony satisfies it, in the way [`transaction_satisfied`] checks.
async fn step_up_decision(
    db: &dyn Database,
    clock: &dyn Clock,
    id_gen: &dyn IdGen,
    session: &sessions::ValidSession,
    ask: StepUpAsk<'_>,
) -> Result<StepUp, Problem> {
    let must_ceremony = ask.prompt.login || ask.max_age == Some(0);
    if !must_ceremony && ask.max_age.is_none() {
        return Ok(StepUp::Met);
    }
    // Fail closed: a session that cannot be read needs the ceremony.
    let Some(row) = store::session_by_id(db, &session.id)
        .await
        .map_err(|_| Problem::internal())?
    else {
        return Ok(StepUp::Required { transaction: None });
    };
    let now = clock.now().replace_nanosecond(0).expect("in range");
    let within_max_age = match ask.max_age {
        Some(limit) if limit > 0 => (now - parse_time(&row.created_at)?).whole_seconds() <= limit,
        _ => true,
    };
    if !must_ceremony {
        return Ok(if within_max_age {
            StepUp::Met
        } else {
            StepUp::Required { transaction: None }
        });
    }
    if within_max_age
        && let Some(presented) = ask.presented
        && let Some(at) =
            transaction_satisfied(db, clock, &session.id, &row, &ask, presented).await?
    {
        return Ok(StepUp::SteppedUp { at });
    }
    if !ask.record {
        return Ok(StepUp::Required { transaction: None });
    }
    let transaction = new_step_up(
        db,
        clock,
        id_gen,
        Some(&session.user_id),
        ask.client_id,
        None,
    )
    .await?;
    Ok(StepUp::Required {
        transaction: Some(transaction),
    })
}

/// Whether `presented` names an unspent transaction that this session's
/// ceremony completes, and spends it when it does.
///
/// A transaction made by a signed-in session belongs to that account. One
/// made before anyone was signed in belongs to the browser that asked, and
/// goes to the account whose ceremony answers it. Either way the ceremony must
/// be a passkey or an email one, begun after the demand (to the millisecond)
/// and at most two minutes old, and the account must not have changed its
/// passkeys or address in the last 24 hours.
///
/// One ceremony satisfies every transaction its account holds, one at a time:
/// each request spends the transaction it presents, and the rest stay open
/// until they expire or are used.
async fn transaction_satisfied(
    db: &dyn Database,
    clock: &dyn Clock,
    session_id: &str,
    session: &store::SessionRow,
    ask: &StepUpAsk<'_>,
    presented: &str,
) -> Result<Option<String>, Problem> {
    let hash = sessions::sha256_hex(presented.as_bytes());
    let Some(transaction) = store::step_up_by_hash(db, &hash)
        .await
        .map_err(|_| Problem::internal())?
    else {
        return Ok(None);
    };
    let now = clock.now().replace_nanosecond(0).expect("in range");
    let now_text = iso(now);
    if transaction.consumed_at.is_some()
        || transaction.expires_at <= now_text
        || transaction.client_id != ask.client_id
    {
        return Ok(None);
    }
    match &transaction.user_id {
        Some(owner) if *owner != session.user_id => return Ok(None),
        Some(_) => {}
        // An unbound demand is answered only by the browser that asked.
        None => {
            if transaction.browser_hash.is_none() || ask.browser_hash != transaction.browser_hash {
                return Ok(None);
            }
        }
    }
    let demanded = transaction.created_ms;
    let created = match store::session_created_ms(db, session_id)
        .await
        .map_err(|_| Problem::internal())?
    {
        Some(ms) => ms,
        None => parse_time(&session.created_at)?.unix_timestamp() * 1_000,
    };
    let current = now_ms(clock);
    // The ceremony began after the demand, to the millisecond, and is recent.
    if created <= demanded || current < created || current - created > STEP_UP_MAX_SESSION_AGE_MS {
        return Ok(None);
    }
    let methods = token_endpoint::amr_of(session);
    if !methods
        .iter()
        .any(|method| STEP_UP_METHODS.contains(&method.as_str()))
    {
        return Ok(None);
    }
    if !account_quiet(db, clock, &session.user_id).await? {
        return Ok(None);
    }
    // Spent here. Of two requests racing on one transaction, one wins. The
    // session itself is not marked: the authorization code this request earns
    // carries the context (issue #912, third review).
    let spent = store::consume_step_up(db, &transaction.id, &session.user_id, &now_text)
        .await
        .map_err(|_| Problem::internal())?
        == 1;
    Ok(spent.then_some(now_text))
}

/// Whether the account's passkeys and address have been left alone for the
/// last 24 hours. An account that has never changed them is quiet.
async fn account_quiet(
    db: &dyn Database,
    clock: &dyn Clock,
    user_id: &str,
) -> Result<bool, Problem> {
    match store::security_changed_at(db, user_id)
        .await
        .map_err(|_| Problem::internal())?
    {
        None => Ok(true),
        Some(raw) => {
            let changed = parse_time(&raw)?;
            Ok((clock.now() - changed).whole_seconds() >= SECURITY_QUIET_SECS)
        }
    }
}

/// Records an anonymous demand that names an account (`login_hint`) and
/// returns the value to carry through the login (fifth review). It is counted
/// apart from the account's signed-in demands, and it never evicts one. A
/// browser's earlier anonymous demand for the same account is replaced, not
/// accumulated. `None` when the account already holds its cap of these, which
/// the caller answers with a refusal.
async fn new_anonymous_hint(
    db: &dyn Database,
    clock: &dyn Clock,
    id_gen: &dyn IdGen,
    user_id: &str,
    client_id: &str,
    request_browser: Option<&str>,
    issued_browser: &str,
) -> Result<Option<String>, Problem> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|err| {
        tracing::error!(error = %err, "step-up entropy source failed");
        Problem::internal()
    })?;
    let value = Base64UrlUnpadded::encode_string(&bytes);
    let now = clock.now().replace_nanosecond(0).expect("in range");
    let now_text = iso(now);
    store::purge_step_ups(db, &now_text)
        .await
        .map_err(|_| Problem::internal())?;
    let mut open = store::open_anonymous_hint_step_ups(db, user_id, &now_text)
        .await
        .map_err(|_| Problem::internal())?;
    // The same browser asking again replaces its own earlier demand.
    if let Some(browser) = request_browser {
        for (id, _) in open.iter().filter(|(_, hash)| hash == browser) {
            store::delete_step_up(db, id)
                .await
                .map_err(|_| Problem::internal())?;
        }
        open.retain(|(_, hash)| hash != browser);
    }
    if open.len() >= MAX_OPEN_ANONYMOUS_HINT_PER_ACCOUNT {
        return Ok(None);
    }
    store::insert_step_up(
        db,
        &store::StepUpRow {
            id: id_gen.ulid(),
            user_id: Some(user_id.to_owned()),
            client_id: client_id.to_owned(),
            token_hash: sessions::sha256_hex(value.as_bytes()),
            browser_hash: Some(issued_browser.to_owned()),
            created_at: now_text,
            created_ms: now_ms(clock),
            expires_at: iso(now.saturating_add(time::Duration::seconds(STEP_UP_TTL_SECS))),
            consumed_at: None,
        },
    )
    .await
    .map_err(|_| Problem::internal())?;
    Ok(Some(value))
}

/// Records a new step-up transaction and returns the value to carry through
/// the login. Only its hash is stored. Spent and expired transactions are
/// purged first, and an account holding too many open ones drops its oldest.
async fn new_step_up(
    db: &dyn Database,
    clock: &dyn Clock,
    id_gen: &dyn IdGen,
    user_id: Option<&str>,
    client_id: &str,
    browser_hash: Option<String>,
) -> Result<String, Problem> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|err| {
        tracing::error!(error = %err, "step-up entropy source failed");
        Problem::internal()
    })?;
    let value = Base64UrlUnpadded::encode_string(&bytes);
    let now = clock.now().replace_nanosecond(0).expect("in range");
    let now_text = iso(now);
    store::purge_step_ups(db, &now_text)
        .await
        .map_err(|_| Problem::internal())?;
    // Signed-in demands: past the account's cap the oldest is dropped.
    // Anonymous ones: past the client's cap the oldest is evicted, so no caller
    // can stop another from asking (issue #912, fifth review).
    let (open, cap) = match user_id {
        Some(owner) => (
            store::open_step_ups_for_user(db, owner, &now_text)
                .await
                .map_err(|_| Problem::internal())?,
            MAX_OPEN_STEP_UPS_PER_ACCOUNT,
        ),
        None => (
            store::open_unbound_step_ups(db, client_id, &now_text)
                .await
                .map_err(|_| Problem::internal())?,
            MAX_OPEN_UNBOUND_PER_CLIENT,
        ),
    };
    let excess = (open.len() + 1).saturating_sub(cap);
    for id in open.iter().take(excess) {
        store::delete_step_up(db, id)
            .await
            .map_err(|_| Problem::internal())?;
    }
    store::insert_step_up(
        db,
        &store::StepUpRow {
            id: id_gen.ulid(),
            user_id: user_id.map(str::to_owned),
            client_id: client_id.to_owned(),
            token_hash: sessions::sha256_hex(value.as_bytes()),
            browser_hash,
            created_at: now_text,
            created_ms: now_ms(clock),
            expires_at: iso(now.saturating_add(time::Duration::seconds(STEP_UP_TTL_SECS))),
            consumed_at: None,
        },
    )
    .await
    .map_err(|_| Problem::internal())?;
    Ok(value)
}

/// Checks that the session may make an account change that a stolen session
/// must not be able to make (issue #912, second review): adding or removing a
/// passkey, and changing the address. The session must have been created by a
/// passkey or email ceremony at most two minutes ago, and the account must
/// have been quiet for 24 hours. A refusal is the reauthentication problem,
/// the same one an address change always answered.
///
/// # Errors
///
/// [`Problem`] with `auth/reauthentication-required` when the session does not
/// qualify, or an internal problem when a read fails.
pub async fn require_recent_ceremony(
    db: &dyn Database,
    clock: &dyn Clock,
    session_id: &str,
    user_id: &str,
) -> Result<(), Problem> {
    let refused = || Problem::new(&crate::email::REAUTHENTICATION_REQUIRED);
    let Some(row) = store::session_by_id(db, session_id)
        .await
        .map_err(|_| Problem::internal())?
    else {
        return Err(refused());
    };
    let created = match store::session_created_ms(db, session_id)
        .await
        .map_err(|_| Problem::internal())?
    {
        Some(ms) => ms,
        None => parse_time(&row.created_at)?.unix_timestamp() * 1_000,
    };
    let current = now_ms(clock);
    if current < created || current - created > STEP_UP_MAX_SESSION_AGE_MS {
        return Err(refused());
    }
    let methods = token_endpoint::amr_of(&row);
    if !methods
        .iter()
        .any(|method| STEP_UP_METHODS.contains(&method.as_str()))
    {
        return Err(refused());
    }
    if !account_quiet(db, clock, user_id).await? {
        return Err(refused());
    }
    Ok(())
}

/// Checks that the session was signed in at most two minutes ago, by any
/// method. This is the gate on an account's first passkey (issue #912, third
/// review): a password-only or federated-only account must be able to enrol
/// one, and the fresh sign-in is what proves the person is present.
///
/// # Errors
///
/// [`Problem`] with `auth/reauthentication-required` when the session is older,
/// or an internal problem when a read fails.
pub async fn require_recent_session(
    db: &dyn Database,
    clock: &dyn Clock,
    session_id: &str,
) -> Result<(), Problem> {
    let refused = || Problem::new(&crate::email::REAUTHENTICATION_REQUIRED);
    let Some(row) = store::session_by_id(db, session_id)
        .await
        .map_err(|_| Problem::internal())?
    else {
        return Err(refused());
    };
    let created = match store::session_created_ms(db, session_id)
        .await
        .map_err(|_| Problem::internal())?
    {
        Some(ms) => ms,
        None => parse_time(&row.created_at)?.unix_timestamp() * 1_000,
    };
    let current = now_ms(clock);
    if current < created || current - created > STEP_UP_MAX_SESSION_AGE_MS {
        return Err(refused());
    }
    Ok(())
}

/// Whether the session was signed in by a passkey or an email ceremony, the two
/// methods that can satisfy a step-up. A session that cannot be read is not one
/// (fifth review): the caller then treats the enrolment as weak.
pub async fn session_proves_by_passkey_or_email(db: &dyn Database, session_id: &str) -> bool {
    match store::session_by_id(db, session_id).await {
        Ok(Some(row)) => token_endpoint::amr_of(&row)
            .iter()
            .any(|method| STEP_UP_METHODS.contains(&method.as_str())),
        _ => false,
    }
}

/// The gate on enrolling a passkey on an account that already has one (issue
/// #914). A recovery sign-in may enrol one, fresh, without the quiet check:
/// that is what the recovery code is for, and the enrolment itself starts the
/// quiet period. Anything else needs `require_recent_ceremony`.
///
/// # Errors
///
/// [`Problem`] as [`require_recent_ceremony`] answers.
pub async fn require_enrolment_ceremony(
    db: &dyn Database,
    clock: &dyn Clock,
    session_id: &str,
    user_id: &str,
) -> Result<(), Problem> {
    let recovered = match store::session_by_id(db, session_id)
        .await
        .map_err(|_| Problem::internal())?
    {
        Some(row) => token_endpoint::amr_of(&row).iter().any(|m| m == "recovery"),
        None => false,
    };
    if recovered {
        return require_recent_session(db, clock, session_id).await;
    }
    require_recent_ceremony(db, clock, session_id, user_id).await
}

/// Whether this browser's marker cookie names this session: the step already
/// answered here for this sign-in, so it is not asked again.
fn step_answered_here(headers: &HeaderMap, session_id: &str) -> bool {
    let prefix = format!("{MARKER_COOKIE}=");
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().strip_prefix(prefix.as_str()))
        .any(|value| value == session_id)
}

/// The methods a session was signed in by, as its row records them. A
/// session that cannot be read has none.
async fn session_methods(db: &dyn Database, session_id: &str) -> Result<Vec<String>, Problem> {
    Ok(store::session_by_id(db, session_id)
        .await
        .map_err(|_| Problem::internal())?
        .map(|row| token_endpoint::amr_of(&row))
        .unwrap_or_default())
}

/// Whether the session was signed in by a recovery code and nothing else. Such
/// a session is for enrolling a passkey only (issue #914).
async fn recovery_only(db: &dyn Database, session_id: &str) -> Result<bool, Problem> {
    let Some(row) = store::session_by_id(db, session_id)
        .await
        .map_err(|_| Problem::internal())?
    else {
        return Ok(false);
    };
    let methods = token_endpoint::amr_of(&row);
    Ok(!methods.is_empty() && methods.iter().all(|method| method == "recovery"))
}

/// Records that the account's passkeys or address just changed, so that the
/// next 24 hours' ceremonies do not count as a step-up.
///
/// # Errors
///
/// [`cratefield_core::DbError`] when the write fails.
///
/// # Panics
///
/// Never in practice: the documented panic is the `time` crate's nanosecond
/// truncation, infallible on this path.
pub async fn record_security_change(
    db: &dyn Database,
    clock: &dyn Clock,
    user_id: &str,
) -> Result<(), cratefield_core::DbError> {
    store::set_security_changed_at(
        db,
        user_id,
        &iso(clock.now().replace_nanosecond(0).expect("in range")),
    )
    .await
    .map(|_| ())
}

/// An RFC 3339 timestamp read back from the store.
fn parse_time(raw: &str) -> Result<OffsetDateTime, Problem> {
    OffsetDateTime::parse(raw, &Rfc3339).map_err(|_| Problem::internal())
}

/// The value of this browser's step-up cookie, if it sent one.
fn browser_cookie_of(headers: &HeaderMap) -> Option<String> {
    for header in headers.get_all(header::COOKIE) {
        let Ok(raw) = header.to_str() else {
            continue;
        };
        for pair in raw.split(';') {
            if let Some(value) = pair.trim().strip_prefix(BROWSER_COOKIE)
                && let Some(value) = value.strip_prefix('=')
            {
                return Some(value.trim().to_owned());
            }
        }
    }
    None
}

/// The `Set-Cookie` that gives a browser its step-up binding for ten minutes.
fn browser_cookie_header(value: &str) -> String {
    format!(
        "{BROWSER_COOKIE}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={STEP_UP_TTL_SECS}"
    )
}

/// A fresh value for the browser binding, of the same shape as a token.
fn new_browser_cookie() -> Result<String, Problem> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|err| {
        tracing::error!(error = %err, "step-up entropy source failed");
        Problem::internal()
    })?;
    Ok(Base64UrlUnpadded::encode_string(&bytes))
}

/// The path the login chooser hands back to: this request as it came, without
/// any step-up value the client sent, and with the transaction value this
/// request made when there is one. `prompt` and `max_age` stay, because the login
/// they ask for is the one the transaction is answered by.
fn return_path(uri: &Uri, transaction: Option<&str>) -> String {
    let path_and_query = uri.path_and_query().map_or_else(
        || DEFAULT_CHOOSER_RETURN_TO.to_owned(),
        |path_and_query| path_and_query.as_str().to_owned(),
    );
    let stripped = without_query_params(&path_and_query, &[STEP_UP_PARAM]);
    match transaction {
        None => stripped,
        Some(value) => {
            let separator = if stripped.contains('?') { '&' } else { '?' };
            format!("{stripped}{separator}{STEP_UP_PARAM}={value}")
        }
    }
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
        return Ok(error_page(&scope, brand_of(&state)));
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
    // Step-up parameters (issue #912): a malformed one is an OAuth error
    // from the registered URI, the same as any other bad parameter.
    let (Ok(prompt), Ok(max_age)) = (
        parse_prompt(query.prompt.as_deref()),
        parse_max_age(query.max_age.as_deref()),
    ) else {
        return Ok(oauth_error_redirect(
            &query.redirect_uri,
            "invalid_request",
            query.state.as_deref(),
        ));
    };
    if query
        .nonce
        .as_deref()
        .is_some_and(|nonce| nonce.len() > MAX_NONCE_BYTES)
    {
        return Ok(oauth_error_redirect(
            &query.redirect_uri,
            "invalid_request",
            query.state.as_deref(),
        ));
    }

    // `intents` (see `crate::intents`): the application's own answer to the
    // "What brings you here?" question. Every key must be on the client's
    // list; a bad one is an OAuth error to the registered URI, like any other
    // bad parameter. Without a list, any `intents` is refused.
    let requested_intents: Option<Vec<String>> = match query.intents.as_deref() {
        None => None,
        Some(raw) => {
            let keys = intents::parse_param(raw);
            let list = intents::client_list(&*db, &query.client_id)
                .await
                .map_err(|_| Problem::internal())?;
            match list.map(|list| intents::check_selection(&list, &keys)) {
                Some(Ok(chosen)) => Some(chosen),
                _ => {
                    return Ok(oauth_error_redirect(
                        &query.redirect_uri,
                        "invalid_request",
                        query.state.as_deref(),
                    ));
                }
            }
        }
    };

    // The session, read once: the SSO routing below and the code minting
    // further down both decide on it.
    let session = match sessions::cookie_value(&headers) {
        Some(cookie) => sessions::validate(&*db, &*clock, &cookie)
            .await
            .map_err(|_| Problem::internal())?,
        None => None,
    };
    // A recovery sign-in is not a session a relying party can use: it can enrol
    // a passkey and nothing else, so for this request the person is signed out
    // (issue #914, security review).
    let session = match session {
        Some(live) => {
            if recovery_only(&*db, &live.id).await? {
                None
            } else {
                Some(live)
            }
        }
        None => None,
    };

    // `OriginalUri` and not `Uri`: the module is nested under
    // `/v1/auth-core`, and a nested handler sees the URI with the prefix
    // already stripped, so `Uri` alone would send people to `/authorize`,
    // which does not exist.

    // Path and query, never `to_string()`: on Workers the runtime builds
    // the request from `req.url()`, so the URI is **absolute**:
    // `https://auth.example/v1/auth-core/authorize?...`. Every provider's
    // `safe_return_to` refuses anything not starting with `/`, so an
    // absolute value is silently replaced by the default and the person
    // lands on `/` with their authorization request gone — which is the
    // exact thing the chooser and the SSO start both exist to prevent. On
    // the native runtime the same URI arrives in origin form, so the bug
    // only appears in production, which is why the tests were green. See
    // the test that sends an absolute-form target.
    //
    // Without a session the chooser's login is itself the fresh
    // ceremony, so `prompt` and `max_age` are dropped on the way back:
    // the request they would demand has been met by the login that is
    // about to happen, and carrying them would ask for a second one.
    // A session is required to mint a code; without one, the login
    // chooser. Its buttons carry this very request as `return_to`, so a
    // person lands back on the pending `/authorize` rather than on the
    // service's root with their request lost.
    let return_to = |transaction: Option<&str>| return_path(&original_uri, transaction);
    let browser_hash =
        browser_cookie_of(&headers).map(|cookie| sessions::sha256_hex(cookie.as_bytes()));
    let step_up_wanted = !prompt.none && (prompt.login || max_age == Some(0));

    // Step-up (issue #912) decides before any routing or minting. A demand
    // made before anyone is signed in is bound to this browser by a cookie the
    // chooser sets, and to the account whose ceremony answers it. With
    // `prompt=none` the answer is a refusal, and nothing is recorded.
    let mut browser_cookie: Option<String> = None;
    let step_up = match &session {
        Some(live) => {
            step_up_decision(
                &*db,
                &*clock,
                &*id_gen,
                live,
                StepUpAsk {
                    prompt,
                    max_age,
                    presented: query.step_up.as_deref(),
                    client_id: &query.client_id,
                    record: !prompt.none,
                    browser_hash,
                },
            )
            .await?
        }
        None if step_up_wanted => {
            // Demands made by anonymous callers are the cheapest thing an
            // outsider can make this service store, so each caller is
            // rate-limited and each client's open ones are capped (issue #912,
            // third review).
            match step_up_limit(&state, &headers).await {
                Ok(None) => {}
                Ok(Some(decision)) => {
                    return Ok(cratefield_core::rate_limited(&decision).into_response());
                }
                Err(()) => {
                    return Ok(oauth_error_redirect(
                        &query.redirect_uri,
                        "temporarily_unavailable",
                        query.state.as_deref(),
                    ));
                }
            }
            // A login_hint that names an account binds the demand to that
            // account now, so a ceremony by anyone else cannot answer it (login
            // CSRF). A relying party must still compare `sub` (see README).
            let bound_to = match query
                .login_hint
                .as_deref()
                .map(cratefield_core::normalize_email)
            {
                Some(email) if cratefield_core::is_valid(&email) => {
                    store::user_by_primary_email(&*db, &email)
                        .await
                        .map_err(|_| Problem::internal())?
                        .filter(|user| user.status == store::STATUS_ACTIVE)
                        .map(|user| user.id)
                }
                _ => None,
            };
            let cookie = new_browser_cookie()?;
            let issued = sessions::sha256_hex(cookie.as_bytes());
            let transaction = match bound_to {
                Some(user) => {
                    match new_anonymous_hint(
                        &*db,
                        &*clock,
                        &*id_gen,
                        &user,
                        &query.client_id,
                        browser_hash.as_deref(),
                        &issued,
                    )
                    .await?
                    {
                        Some(value) => value,
                        // The account already holds its anonymous demands. Rather
                        // than refuse, this request gets the same ordinary
                        // browser-bound demand an unknown address gets, so the
                        // response does not reveal whether the account exists
                        // (issue #912, final review). No signed-in demand is
                        // touched either way.
                        None => {
                            new_step_up(
                                &*db,
                                &*clock,
                                &*id_gen,
                                None,
                                &query.client_id,
                                Some(issued.clone()),
                            )
                            .await?
                        }
                    }
                }
                None => {
                    new_step_up(
                        &*db,
                        &*clock,
                        &*id_gen,
                        None,
                        &query.client_id,
                        Some(issued),
                    )
                    .await?
                }
            };
            browser_cookie = Some(cookie);
            StepUp::Required {
                transaction: Some(transaction),
            }
        }
        None => StepUp::Met,
    };
    let (step_up_required, step_up_transaction) = match &step_up {
        StepUp::Required { transaction } => (true, transaction.clone()),
        StepUp::Met | StepUp::SteppedUp { .. } => (false, None),
    };
    let stepped_up_at = match &step_up {
        StepUp::SteppedUp { at } => Some(at.clone()),
        StepUp::Met | StepUp::Required { .. } => None,
    };
    if prompt.none && (session.is_none() || step_up_required) {
        return Ok(oauth_error_redirect(
            &query.redirect_uri,
            "login_required",
            query.state.as_deref(),
        ));
    }

    let chooser = |transaction: Option<&str>, cookie: Option<&str>| {
        let return_to = return_to(transaction);
        let return_to_without_hint = without_query_params(&return_to, &["login_hint"]);
        let hint = query
            .login_hint
            .as_deref()
            .map(cratefield_core::normalize_email)
            .filter(|email| cratefield_core::is_valid(email));
        let all = enabled_login_methods(&*state.ctx.config, &return_to);
        let has_email = all.iter().any(|method| method.slug == "magic-link");
        let has_passkey = all.iter().any(|method| method.is_passkey);
        // The email step and the passkey are the Continue screen's own
        // controls; what is left is offered under "Other ways to continue".
        let methods = all
            .into_iter()
            .filter(|method| !method.is_passkey && method.slug != "magic-link")
            .collect();
        // The email step is a form, so when the instance has a captcha it
        // carries the Turnstile widget, the same as the magic link's own form.
        // Without the widget the form would post with no answer and be
        // refused silently.
        let brand = brand_of(&state);
        let turnstile = crate::page::turnstile_site_key(state.ctx.as_ref())
            .filter(|_| has_email)
            .map(|key| crate::page::turnstile_widget(&key, "magic-link", brand.theme.scheme));
        let csp = crate::page::chooser_turnstile_csp(
            brand.theme.font_css_url.as_deref(),
            brand.logo_url.as_deref(),
        );
        let has_widget = turnstile.is_some();
        let mut response = html(&LoginChooserTemplate {
            brand,
            has_passkey,
            has_email,
            registration_open: magic_link_registration_open(&*state.ctx.config),
            hint,
            methods,
            return_to,
            return_to_without_hint,
            turnstile_script: turnstile
                .is_some()
                .then_some(cratefield_ui::render::TURNSTILE_SCRIPT),
            turnstile_widget: turnstile,
        });
        if has_widget {
            crate::page::with_csp(&mut response, &csp);
        }
        if let Some(cookie) = cookie
            && let Ok(value) = HeaderValue::from_str(&browser_cookie_header(cookie))
        {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
        response
    };
    // A connection named outright (issue #627). Only this client's own
    // active connections are routable: another client's id, an id that
    // does not exist and a disabled one are refused *identically*, with
    // the generic page and no redirect — to the IdP or anywhere else — so
    // a probe learns nothing and an attacker is never walked to someone
    // else's identity provider.
    if let Some(connection_id) = query.connection.as_deref() {
        let own_active = matches!(
            store::sso_connection_by_id(&*db, connection_id)
                .await
                .map_err(|_| Problem::internal())?,
            Some(connection)
                if connection.client_id == query.client_id
                    && connection.status == store::STATUS_ACTIVE
        );
        if !own_active {
            return Ok(error_page(&scope, brand_of(&state)));
        }
        // Already signed in through this very connection: the request
        // proceeds to a code like any other session's. Anything else —
        // no session, or a session from another way in, or from another
        // connection — has to go and become one first.
        //
        // A step-up demand (issue #912) is never met by the connection the
        // session already came through: it goes back to the IdP.
        let on_this_connection = !step_up_required
            && session.as_ref().and_then(|s| s.sso_connection.as_deref()) == Some(connection_id);
        if !on_this_connection {
            // A federated sign-in cannot meet a step-up demand (issue #912):
            // the person is offered the chooser, where a passkey or an
            // email link can.
            if step_up_required {
                return Ok(chooser(
                    step_up_transaction.as_deref(),
                    browser_cookie.as_deref(),
                ));
            }
            return Ok(sso_start_redirect(connection_id, &return_to(None)));
        }
    } else if session.is_none()
        && !step_up_required
        && let Some(domain) = query.login_hint.as_deref().and_then(sso::domain_of_email)
    {
        // A hint, and only a hint: it routes when its domain is one of
        // this client's own active connections claims, and otherwise
        // falls through to the chooser rather than refusing. It can
        // neither probe nor steer any other client's organization.
        let connections = store::sso_connections_for_client(&*db, &query.client_id, None)
            .await
            .map_err(|_| Problem::internal())?;
        if let Some(connection) = connections.iter().find(|connection| {
            connection.status == store::STATUS_ACTIVE && connection.domains.contains(&domain)
        }) {
            return Ok(sso_start_redirect(&connection.id, &return_to(None)));
        }
    }

    let Some(session) = session else {
        return Ok(chooser(
            step_up_transaction.as_deref(),
            browser_cookie.as_deref(),
        ));
    };
    // A live session that has to make the ceremony again (issue #912) gets
    // the chooser, carrying this request and its transaction back, rather
    // than a code.
    if step_up_required {
        return Ok(chooser(
            step_up_transaction.as_deref(),
            browser_cookie.as_deref(),
        ));
    }

    // "What brings you here?" on demand (prompt=intents, see `crate::intents`):
    // a signed-in person is asked again and the answer is recorded. Skipped
    // when the application supplied its own answer, when the client has no
    // list, and under prompt=none, which shows nothing.
    if prompt.intents
        && !prompt.none
        && requested_intents.is_none()
        && let Some(list) = intents::client_list(&*db, &query.client_id)
            .await
            .map_err(|_| Problem::internal())?
    {
        let chosen_now = intents::chosen(&*db, &session.user_id, &query.client_id)
            .await
            .map_err(|_| Problem::internal())?
            .unwrap_or_default();
        let return_to_without_intents = without_prompt_value(&return_to(None), "intents");
        let action = format!("{}/intents", module_base(&original_uri));
        return Ok(intents::step_page(
            &brand_of(&state),
            &action,
            &[("return_to", &return_to_without_intents)],
            &list,
            &intents::request_locale(&headers),
            &chosen_now,
        ));
    }

    // A sign-in that has just happened may be sent through the composition's
    // post-sign-in step (the passkey offer) before its code is minted. Only
    // a real, fresh, non-step-up, page-wanting sign-in qualifies, so a long
    // session or an API client is never interrupted (see `SignInStep`).
    if let Some(step) = state.sign_in_step.clone()
        && !prompt.none
        && !prompt.login
        && max_age.is_none()
        && query.step_up.is_none()
        && stepped_up_at.is_none()
        && wants_html(&headers)
        && !step_answered_here(&headers, &session.id)
        && require_recent_session(&*db, &*clock, &session.id)
            .await
            .is_ok()
    {
        let amr = session_methods(&*db, &session.id).await?;
        let continue_to = return_to(None);
        let sign_in = SignIn {
            user_id: &session.user_id,
            session_id: &session.id,
            amr: &amr,
            continue_to: &continue_to,
        };
        if let Some(location) = step.divert(&state.ctx, sign_in).await? {
            return Ok((StatusCode::FOUND, [(header::LOCATION, location)]).into_response());
        }
    }

    // The application's own answer (`intents=`) is recorded for this account
    // and client. It is the application's to make, and it grants nothing: the
    // `roles` claim is read from the account's role, never from here.
    // Only when the account has no answer for this client yet: the
    // application's `intents=` never silently replaces what the person chose
    // (`prompt=intents` is how they change it).
    if let Some(chosen) = &requested_intents {
        intents::record_if_unset(&*db, &*clock, &session.user_id, &query.client_id, chosen)
            .await
            .map_err(|_| Problem::internal())?;
    }
    let openid = query.scope.as_deref().is_some_and(|scope| {
        scope
            .split_ascii_whitespace()
            .any(|value| value == "openid")
    });
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
                    // The request's nonce, echoed into the ID token
                    // (issue #912). Absent when the client sent none.
                    "nonce": query.nonce,
                    // Whether the request asked for an ID token (OpenID
                    // Connect Core section 3.1.2.1).
                    "openid": openid,
                    // The context a spent step-up transaction earned, and when
                    // it was spent. Only this code carries them: a refresh or
                    // another client's code never does (issue #912, third
                    // review).
                    "acr": stepped_up_at.as_ref().map(|_| STEP_UP_ACR),
                    "stepped_up_at": stepped_up_at,
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

/// Whether the magic-link module registers new accounts from an email
/// (`AUTH_MAGIC_LINK_ALLOW_REGISTRATION`). Read here so the page can say the
/// app is invite-only; the module decides what actually happens, and unset
/// means no, as it does there.
fn magic_link_registration_open(cfg: &dyn Config) -> bool {
    matches!(
        ModuleConfig::new("auth-magic-link", cfg)
            .get_opt("ALLOW_REGISTRATION")
            .as_deref()
            .map(str::trim),
        Some("true" | "1")
    )
}

/// The module's mount, from the request's own path: `/v1/auth-core` for
/// `/v1/auth-core/authorize`. Forms and redirects are written against it, so
/// they keep working wherever the module is mounted.
fn module_base(uri: &Uri) -> String {
    let path = uri.path();
    path.strip_suffix("/authorize").unwrap_or(path).to_owned()
}

/// `path_and_query` with one value of the `prompt` parameter removed. A
/// `prompt` left with nothing in it is dropped altogether. Used to hand the
/// request back once the intents step is answered, so that the step is not
/// asked again.
fn without_prompt_value(path_and_query: &str, value: &str) -> String {
    let (path, query) = path_and_query
        .split_once('?')
        .map_or((path_and_query, ""), |(path, query)| (path, query));
    let pairs: Vec<String> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| {
            let Some((key, raw)) = pair.split_once('=') else {
                return Some(pair.to_owned());
            };
            if key != "prompt" {
                return Some(pair.to_owned());
            }
            let kept: Vec<&str> = raw
                .split(['+', ' '])
                .flat_map(|part| part.split("%20"))
                .filter(|part| !part.is_empty() && *part != value)
                .collect();
            (!kept.is_empty()).then(|| format!("prompt={}", kept.join("+")))
        })
        .collect();
    if pairs.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{}", pairs.join("&"))
    }
}

/// `GET /signup` and `GET /signin`: the two addresses an application's links
/// were written against before there was one entry flow. Both now go to
/// `/authorize`, the Continue screen, with every parameter they were given.
async fn signup_redirect(OriginalUri(uri): OriginalUri) -> Response {
    to_authorize(&uri)
}

async fn signin_redirect(OriginalUri(uri): OriginalUri) -> Response {
    to_authorize(&uri)
}

fn to_authorize(uri: &Uri) -> Response {
    // The module's mount is everything before the last segment (`signup` or
    // `signin`), so the redirect lands on this module's own `/authorize`.
    let base = uri.path().rsplit_once('/').map_or("", |(base, _)| base);
    let target = format!(
        "{base}/authorize{}",
        uri.query()
            .map(|query| format!("?{query}"))
            .unwrap_or_default()
    );
    (StatusCode::FOUND, [(header::LOCATION, target)]).into_response()
}

/// Whether a `return_to` names this module's `/authorize`: a path on this
/// service, never an absolute or protocol-relative URL.
///
/// The same rules `magic-link`'s `safe_return_to` applies to its own
/// `return_to`: trimmed, a bounded length, a path on this service, and no
/// control characters. The caller redirects to the trimmed value.
fn is_authorize_path(candidate: &str) -> bool {
    // Control characters are refused in the value as sent, before any trim: a
    // trailing newline must not be quietly cut and the rest accepted.
    let value = candidate.trim();
    candidate.len() <= MAX_RETURN_TO
        && !candidate.chars().any(char::is_control)
        && value.starts_with('/')
        && !value.starts_with("//")
        && !value.starts_with("/\\")
        && value
            .split('?')
            .next()
            .is_some_and(|path| path.ends_with("/authorize"))
}

/// The longest `return_to` the flow carries, the same bound the magic link
/// applies.
const MAX_RETURN_TO: usize = 4096;

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
        return Ok(error_page(&scope, brand_of(&state)));
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
            brand: brand_of(&state),
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
    sign_out(
        &*db,
        &*clock,
        sessions::cookie_value(&headers),
        target,
        brand_of(&state),
    )
    .await
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
        return Ok(error_page(&scope, brand_of(&state)));
    };
    sign_out(
        &*db,
        &*clock,
        sessions::cookie_value(&headers),
        target,
        brand_of(&state),
    )
    .await
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
    brand: Brand,
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
        return Ok((clear, html(&SignedOutTemplate { brand })).into_response());
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

/// The authorize endpoint's path under this module's mount prefix. Named so
/// `locale` can recognise the endpoint whose query carries `ui_locales`
/// without a second copy of the route.
pub(crate) const AUTHORIZE_ROUTE: &str = "/authorize";

/// `POST /intents`: the signed-in person's answer to "What brings you here?"
/// (`prompt=intents`). Same-origin only, like every form that acts. The
/// request it returns to is re-validated the way `/authorize` validates it,
/// so the form cannot send the browser anywhere the flow would not go.
async fn intents_submit(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    uri: Uri,
    body: String,
) -> Result<Response, Problem> {
    let brand = brand_of(&state);
    if let Err(problem) = crate::csrf::require_same_origin(&headers, &uri) {
        return Err(problem.instance(&scope.request_id));
    }
    let fields: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    let field = |name: &str| {
        fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    let Some(return_to) = field("return_to")
        .filter(|value| is_authorize_path(value))
        .map(|value| value.trim().to_owned())
    else {
        return Ok(error_page(&scope, brand));
    };
    let query_part = return_to.split_once('?').map_or("", |(_, query)| query);
    let params: Vec<(String, String)> = url::form_urlencoded::parse(query_part.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    let param = |name: &str| {
        params
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    let (Some(client_id), Some(redirect_uri)) = (param("client_id"), param("redirect_uri")) else {
        return Ok(error_page(&scope, brand));
    };
    let (Some(db), Some(clock)) = (state.ctx.ports.db.clone(), state.ctx.ports.clock.clone())
    else {
        return Err(Problem::internal());
    };
    if validate_client_and_uri(&*db, &client_id, &redirect_uri)
        .await
        .is_err()
    {
        return Ok(error_page(&scope, brand));
    }
    let Some(cookie) = sessions::cookie_value(&headers) else {
        return Ok(see_other(&return_to));
    };
    let live = match sessions::validate(&*db, &*clock, &cookie)
        .await
        .map_err(|_| Problem::internal())?
    {
        Some(live) if !recovery_only(&*db, &live.id).await? => live,
        _ => return Ok(see_other(&return_to)),
    };
    let Some(list) = intents::client_list(&*db, &client_id)
        .await
        .map_err(|_| Problem::internal())?
    else {
        return Ok(error_page(&scope, brand));
    };
    let keys: Vec<String> = fields
        .iter()
        .filter(|(key, _)| key == "intents")
        .map(|(_, value)| value.clone())
        .collect();
    let Ok(chosen) = intents::check_selection(&list, &keys) else {
        return Ok(error_page(&scope, brand));
    };
    intents::record(&*db, &*clock, &live.user_id, &client_id, &chosen)
        .await
        .map_err(|_| Problem::internal())?;
    Ok(see_other(&return_to))
}

/// A `303` back to a path this module already validated.
fn see_other(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, location.to_owned())],
    )
        .into_response()
}

pub(crate) fn router() -> axum::Router<Arc<ModuleState>> {
    axum::Router::new()
        .route(AUTHORIZE_ROUTE, get(authorize))
        .route("/logout", get(logout))
        .route("/logout/confirm", post(logout_confirm))
        .route("/signup", get(signup_redirect))
        .route("/signin", get(signin_redirect))
        .route("/intents", post(intents_submit))
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
            brand: test_brand(),
            methods: vec![LoginMethod {
                slug: "passkey".to_owned(),
                label: "Continue with a passkey".to_owned(),
                href: String::new(),
                is_passkey: true,
            }],
            has_passkey: true,
            has_email: false,
            registration_open: false,
            hint: None,
            return_to: hostile.to_owned(),
            return_to_without_hint: hostile.to_owned(),
            turnstile_widget: None,
            turnstile_script: None,
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

    fn test_brand() -> Brand {
        Brand::from_config(
            &cratefield_core::MapConfig::default(),
            &cratefield_core::Venture::new("acme", "auth.acme.example"),
        )
    }

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
            brand: test_brand(),
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

    #[test]
    fn prompt_values_are_read_strictly() {
        assert_eq!(parse_prompt(None), Ok(Prompt::default()));
        assert_eq!(
            parse_prompt(Some("login")),
            Ok(Prompt {
                none: false,
                login: true,
                intents: false,
            })
        );
        assert_eq!(
            parse_prompt(Some("consent select_account")),
            Ok(Prompt::default())
        );
        assert_eq!(
            parse_prompt(Some("none")),
            Ok(Prompt {
                none: true,
                login: false,
                intents: false,
            })
        );
        // `none` is never combined, and an unknown value is refused.
        assert_eq!(parse_prompt(Some("none login")), Err(()));
        assert_eq!(parse_prompt(Some("bogus")), Err(()));
        assert_eq!(parse_prompt(Some("login bogus")), Err(()));
    }

    #[test]
    fn max_age_accepts_only_decimal_digits() {
        assert_eq!(parse_max_age(None), Ok(None));
        assert_eq!(parse_max_age(Some("0")), Ok(Some(0)));
        assert_eq!(parse_max_age(Some("300")), Ok(Some(300)));
        for bad in ["", "-1", "+5", "1.5", "abc", "99999999999"] {
            assert_eq!(parse_max_age(Some(bad)), Err(()), "{bad:?}");
        }
    }

    #[test]
    fn stripping_a_demand_leaves_the_rest_of_the_request_intact() {
        assert_eq!(
            without_query_params(
                "/v1/auth-core/authorize?client_id=c&prompt=login&state=s&max_age=0",
                &["prompt", "max_age"]
            ),
            "/v1/auth-core/authorize?client_id=c&state=s"
        );
        assert_eq!(
            without_query_params(
                "/v1/auth-core/authorize?prompt=login",
                &["prompt", "max_age"]
            ),
            "/v1/auth-core/authorize"
        );
        assert_eq!(
            without_query_params("/v1/auth-core/authorize?state=x&promptx=1", &["prompt"]),
            "/v1/auth-core/authorize?state=x&promptx=1"
        );
        assert_eq!(without_query_params("/plain", &["prompt"]), "/plain");
    }
}
