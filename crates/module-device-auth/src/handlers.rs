//! HTTP handlers for `/v1/device-auth` (RFC 8628, issue #587).
//!
//! Five routes, split by who calls them. `/code` and `/token` are called by
//! a machine with no browser and no session: they take their parameters
//! either way — a JSON tool body or an HTML form — and they answer the
//! OAuth 2.0 error shape (`{"error": ..., "error_description": ...}`), not
//! RFC 9457, because their callers are OAuth clients that already parse
//! that dialect. `/`, `/approve` and `/deny` are called by a browser and
//! answer HTML.
//!
//! # The two codes, and why neither is stored
//!
//! `device_code` is the bearer credential the polling client presents, so
//! it is 32 random bytes from the builder's `RandomBytes` and only its
//! SHA-256 reaches the database. `user_code` is the eight characters a
//! person reads off a screen, drawn from a 20-letter alphabet with no
//! look-alikes (`B`, not `8`; `F`, not `E`), and only its hash is stored
//! too. The `store` module holds the rest of that reasoning.
//!
//! # At most once
//!
//! The poll that wins the guarded `approved` → `consumed` update calls the
//! [`Issuer`](crate::Issuer) exactly once, and nothing regresses the row if
//! that call fails: the code is spent, the credential is lost, and the
//! person re-runs the client. That is the deliberate trade — a credential
//! minted twice is worse than one that has to be asked for again.

use std::sync::Arc;

use axum::extract::{FromRequest, OriginalUri, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use cratefield_core::{
    Clock, Decision, ModuleConfig, ModuleContext, Problem, ProblemDef, RandomBytes, RateLimit,
    RateLimitFailure, Scope, SystemClock, check_rate_limit, client_ip, rate_limit_keys,
    rate_limited,
};

use crate::store;
use crate::{
    Approval, Approver, CallerApprover, DeviceClient, IssueRequest, Issuer, device_code_hash,
    normalize_user_code, user_code_hash,
};

/// The one grant type this endpoint implements (RFC 8628 §3.4).
pub(crate) const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// The alphabet a user code is drawn from: twenty capitals with no
/// look-alike pairs, so the code survives being read off one screen and
/// typed into another. `I`/`O`/`U`/`0`/`1`/`8` are all absent.
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

/// The largest byte that maps uniformly onto the twenty-letter alphabet:
/// `12 * 20`. A byte at or above it is discarded and redrawn rather than
/// folded, so every letter is equally likely.
const USER_CODE_CEILING: u8 = 240;

/// The refusal for a request the browser reports as coming from another
/// site, which is the first thing `/approve` and `/deny` check.
pub(crate) const CROSS_SITE_REQUEST: ProblemDef = ProblemDef {
    slug: "device-auth/cross-site-request",
    status: StatusCode::FORBIDDEN,
    title: "A same-origin request is required",
    description: "The approval form accepts only a request a browser reports as coming \
                  from this venture's own origin.",
};

/// The refusal for an approval attempt with no signed-in person behind it.
pub(crate) const APPROVER_REQUIRED: ProblemDef = ProblemDef {
    slug: "device-auth/approver-required",
    status: StatusCode::UNAUTHORIZED,
    title: "Sign in to approve a device",
    description: "The device page is served only to a signed-in person; no subject was \
                  identified.",
};

/// The answer to a user code that names no pending, unexpired request — a
/// mistyped code, one already answered, or one past its expiry.
pub(crate) const UNKNOWN_USER_CODE: ProblemDef = ProblemDef {
    slug: "device-auth/unknown-user-code",
    status: StatusCode::NOT_FOUND,
    title: "Unknown or expired code",
    description: "No pending, unexpired device request carries that user code.",
};

/// The refusal after one approver has entered wrong codes too often.
pub(crate) const TOO_MANY_ATTEMPTS: ProblemDef = ProblemDef {
    slug: "device-auth/too-many-attempts",
    status: StatusCode::TOO_MANY_REQUESTS,
    title: "Too many attempts",
    description: "One approver has entered wrong user codes more often than the \
                  configured allowance.",
};

/// The builder's settings, cloned into the router state alongside the
/// module context. Every field is what the builder set; nothing here reads
/// the environment, which is `validate_config`'s job.
#[derive(Clone)]
pub(crate) struct Settings {
    /// The declared clients. A `client_id` not in this list is not a
    /// client, and a scope not in that client's list is not a scope.
    pub clients: Vec<DeviceClient>,
    /// The hook that decides who may approve, when the builder set one.
    pub approver: Option<Arc<dyn Approver>>,
    /// The hook that mints the credential. Required.
    pub issuer: Option<Arc<dyn Issuer>>,
    /// The entropy source the two codes are drawn from. Required: core
    /// carries no CSPRNG, so the builder supplies one.
    pub random: Option<Arc<dyn RandomBytes>>,
    /// Where `CallerApprover` sends an anonymous browser to sign in.
    pub sign_in_url: Option<String>,
    /// How long a device code stays usable.
    pub expires_in_secs: i64,
    /// The interval RFC 8628 §3.5 asks a client to poll at.
    pub interval_secs: i64,
    /// The wrong-entry allowance per approver, encoded into the limiter
    /// key so a deployment's per-key policy can read it.
    pub max_wrong_entries: u32,
}

pub(crate) struct ModuleState {
    pub ctx: Arc<ModuleContext>,
    pub settings: Settings,
    /// The resolved approver: the builder's, or the stock `CallerApprover`
    /// over the `Auth` port when one is mounted and the builder set none.
    pub approver: Option<Arc<dyn Approver>>,
}

impl Settings {
    /// The declared client with this id, if any.
    fn client(&self, id: &str) -> Option<&DeviceClient> {
        self.clients.iter().find(|client| client.id() == id)
    }
}

/// The module's routes, mounted at `/v1/device-auth`.
pub(crate) fn router(ctx: ModuleContext, settings: Settings) -> axum::Router {
    let approver = settings.approver.clone().or_else(|| {
        ctx.ports.auth.clone().map(|auth| {
            let sign_in_url = settings
                .sign_in_url
                .clone()
                .unwrap_or_else(|| "/login".to_owned());
            Arc::new(CallerApprover::new(auth, sign_in_url)) as Arc<dyn Approver>
        })
    });
    let state = Arc::new(ModuleState {
        ctx: Arc::new(ctx),
        settings,
        approver,
    });
    axum::Router::new()
        .route("/", get(page))
        .route("/code", post(create_code))
        .route("/token", post(poll_token))
        .route("/approve", post(approve))
        .route("/deny", post(deny))
        .with_state(state)
}

/// "Now" through the Clock port when present, `SystemClock` otherwise —
/// the port is what makes expiry and the poll interval deterministic under
/// the test kit's clock.
pub(crate) fn now_of(ctx: &ModuleContext) -> OffsetDateTime {
    ctx.ports
        .clock
        .as_ref()
        .map_or_else(|| SystemClock.now(), |clock| clock.now())
}

/// An RFC 3339 UTC timestamp with whole seconds, the only shape written to
/// or compared against a timestamp column.
pub(crate) fn stamp(at: OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .expect("truncation stays in range")
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// The OAuth 2.0 error body (RFC 6749 §5.2) these two machine routes
/// answer with, always a 400.
fn oauth_error(error: &str, description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

fn internal(scope: &Scope) -> Problem {
    Problem::internal().instance(&scope.request_id)
}

fn see_other(location: String) -> Response {
    (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response()
}

/// A `200 text/html` body.
fn html(body: String) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}

/// The five characters that can end a piece of text early in HTML.
fn escape_html(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// Refuses a request the browser reports as coming from another site, in
/// the same shape `auth-core`'s login guard uses: `sec-fetch-site` is
/// checked first (`same-origin` and `none` pass, everything else —
/// `same-site` included, because a sibling subdomain can post here — is
/// refused), then `Origin` must be this venture's own origin judged
/// against the host the request reached. A request carrying neither header
/// is a non-browser client and is accepted.
///
/// # Errors
///
/// [`CROSS_SITE_REQUEST`] whenever either signal reports another site.
fn require_same_origin(headers: &HeaderMap, uri: &Uri) -> Result<(), Problem> {
    if let Some(site) = headers.get("sec-fetch-site") {
        let Ok(site) = site.to_str() else {
            return Err(refused(
                "sec-fetch-site was not valid UTF-8; only same-origin or none is accepted",
            ));
        };
        match site.to_ascii_lowercase().as_str() {
            "same-origin" | "none" => {}
            other => {
                return Err(refused(format!(
                    "sec-fetch-site is {other}; only same-origin or none is accepted"
                )));
            }
        }
    }
    if let Some(origin) = headers.get(header::ORIGIN) {
        let Ok(origin) = origin.to_str() else {
            return Err(refused("origin was not valid UTF-8"));
        };
        if origin == "null" {
            return Err(refused(
                "origin is null; requests must come from this venture's own origin",
            ));
        }
        let Some((scheme, authority)) = origin.split_once("://") else {
            return Err(refused(format!(
                "origin {origin} carries no scheme; expected an origin like https://…"
            )));
        };
        let loopback = is_loopback_host(authority_host(authority));
        if scheme != "https" && !(scheme == "http" && loopback) {
            return Err(refused(format!(
                "origin {origin} is not https (http is accepted only for a loopback host)"
            )));
        }
        let Some(own) = own_host(headers, uri) else {
            return Err(refused(
                "origin was present but the request named no host to check it against",
            ));
        };
        if !same_authority(authority, own, scheme) {
            return Err(refused(format!(
                "origin {origin} does not match the host this request reached ({own})"
            )));
        }
    }
    Ok(())
}

/// The 403 for a refused request; `detail` names the signal.
fn refused(detail: impl Into<String>) -> Problem {
    Problem::new(&CROSS_SITE_REQUEST).with_detail(detail)
}

/// The host this request reached: the `Host` header when present and
/// non-empty, else the URI's authority.
fn own_host<'a>(headers: &'a HeaderMap, uri: &'a Uri) -> Option<&'a str> {
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .filter(|host| !host.is_empty())
        .or_else(|| uri.authority().map(axum::http::uri::Authority::as_str))
}

/// The host part of an authority, with any port removed. A bracketed IPv6
/// host keeps its colons.
fn authority_host(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        return match rest.find(']') {
            Some(close) => &authority[..=close + 1],
            None => authority,
        };
    }
    match authority.rsplit_once(':') {
        Some((host, _port)) => host,
        None => authority,
    }
}

/// The loopback names `http` is accepted on.
fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host.eq_ignore_ascii_case("[::1]")
}

/// The authority with the scheme's default port removed.
fn without_default_port<'a>(authority: &'a str, scheme: &str) -> &'a str {
    let default = match scheme {
        "https" => "443",
        "http" => "80",
        _ => return authority,
    };
    if authority.ends_with(']') {
        return authority;
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if port == default => host,
        _ => authority,
    }
}

/// Whether the origin's authority and the host the request reached name
/// the same thing.
fn same_authority(origin_authority: &str, own_host: &str, scheme: &str) -> bool {
    without_default_port(origin_authority, scheme)
        .eq_ignore_ascii_case(without_default_port(own_host, scheme))
}

/// The API origin the two verification URIs are built under, exactly as
/// `module-email-signup` resolves it: the venture's `API_BASE` when set,
/// `https://api.<domain>` otherwise.
fn api_base(cfg: &ModuleConfig, ctx: &ModuleContext) -> String {
    cfg.get_opt("API_BASE")
        .unwrap_or_else(|| format!("https://api.{}", ctx.venture.domain))
}

/// The path and query of this request — what an approver hands to a
/// sign-in page so it can come back. It is deliberately **relative**, never
/// an absolute URL: every sign-in implementation in the harness requires a
/// leading `/` and refuses an absolute value as an open redirect, and a URL
/// built from the request's `Host`/`x-forwarded-proto` headers is one an
/// attacker could point at another origin. On Workers the request URI is
/// already absolute, so `path_and_query` is what keeps the value relative
/// there too (the shape `auth-core`'s `/authorize` uses).
fn return_to(uri: &Uri) -> String {
    uri.path_and_query().map_or_else(
        || "/".to_owned(),
        |path_and_query| path_and_query.as_str().to_owned(),
    )
}

/// The rate-limit keys for one device route, prefixed the way the D1
/// limiter's documentation describes (`plan:pro:ip:…`): a deployment's
/// per-key policy matches the `device-auth:<kind>:` prefix, and the keys
/// `rate_limit_keys` builds slot in unchanged behind it.
fn device_keys(headers: &HeaderMap, kind: &str) -> Vec<String> {
    rate_limit_keys(client_ip(headers).as_deref(), None)
        .into_iter()
        .map(|key| format!("device-auth:{kind}:{key}"))
        .collect()
}

/// The `429` for a limiter denial on `/code`. Fails open on a limiter
/// transport error: issuing a device code is cheap and the code is the
/// only thing it grants, so a limiter outage must not stop sign-in.
async fn limit_code(state: &ModuleState, headers: &HeaderMap) -> Option<Response> {
    let keys = device_keys(headers, "code");
    match check_rate_limit(
        state.ctx.ports.rate_limiter.as_ref(),
        &keys,
        RateLimitFailure::FailOpen,
    )
    .await
    {
        RateLimit::Denied { decision } => Some(rate_limited(&decision)),
        RateLimit::Allowed => None,
    }
}

/// The `429` for a limiter denial on `/approve` or `/deny`, under this
/// module's own slug. Fails closed on a transport error: the limiter is the
/// only thing between an approver and a brute-force budget over the
/// 32-bit-shaped user code space, so an outage cannot be an opening.
fn too_many_attempts(scope: &Scope, decision: &Decision, allowance: u32) -> Response {
    let problem = Problem::new(&TOO_MANY_ATTEMPTS)
        .with_detail(format!(
            "more than {allowance} wrong codes have been entered from this approver"
        ))
        .instance(&scope.request_id);
    let mut response = problem.into_response();
    let pause = decision
        .retry_after
        .or_else(|| decision.quota.as_ref().map(|quota| quota.reset));
    if let Some(pause) = pause {
        let seconds = u64::try_from(pause.as_millis())
            .unwrap_or(u64::MAX)
            .div_ceil(1_000)
            .max(1);
        if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
    }
    response
}

/// A request body read as JSON when the caller named a JSON content type
/// and as an HTML form otherwise. The device endpoints take their
/// parameters both ways — an RFC 8628 client posts a form, an API tool
/// posts JSON — so one type serves both and the handlers validate the
/// fields themselves, which is what keeps the OAuth error shapes under
/// this module's control rather than an extractor's.
struct Params<T>(T);

impl<T, S> FromRequest<S> for Params<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Problem;

    async fn from_request(
        request: axum::extract::Request,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let instance = request
            .extensions()
            .get::<Scope>()
            .map(|scope| scope.request_id.clone());
        let is_json = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("json"));
        let parsed = if is_json {
            axum::Json::<T>::from_request(request, state)
                .await
                .map(|axum::Json(value)| value)
                .map_err(|rejection| rejection.body_text())
        } else {
            axum::Form::<T>::from_request(request, state)
                .await
                .map(|axum::Form(value)| value)
                .map_err(|rejection| rejection.body_text())
        };
        parsed.map(Params).map_err(|detail| {
            let problem = Problem::validation_failed(detail);
            match instance {
                Some(id) => problem.instance(&id),
                None => problem,
            }
        })
    }
}

// ---------------------------------------------------------------------------
// POST /v1/device-auth/code

/// The device authorization request (RFC 8628 §3.1).
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct DeviceCodeParams {
    /// The client this request is for. It must have been declared.
    #[serde(default)]
    pub client_id: Option<String>,
    /// Space-separated scopes; each must be one the client declared.
    #[serde(default)]
    pub scope: Option<String>,
    /// A short label for the device, shown on the approval page.
    #[serde(default)]
    pub name: Option<String>,
}

/// The device authorization response (RFC 8628 §3.2).
#[derive(Debug, serde::Serialize, schemars::JsonSchema)]
pub(crate) struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: i64,
    pub interval: i64,
}

/// The longest `name` the approval page will carry, in characters.
const MAX_NAME_CHARS: usize = 100;

async fn create_code(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    Params(body): Params<DeviceCodeParams>,
) -> Result<Response, Problem> {
    if let Some(denied) = limit_code(&state, &headers).await {
        return Ok(denied);
    }
    let Some(client) = body
        .client_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .and_then(|id| state.settings.client(id))
    else {
        return Ok(oauth_error(
            "invalid_client",
            "client_id is missing, or names a client this venture has not declared",
        ));
    };
    let scopes = parse_scope(body.scope.as_deref());
    if let Some(bad) = scopes.iter().find(|scope| !client.declares_scope(scope)) {
        return Ok(oauth_error(
            "invalid_scope",
            &format!("scope `{bad}` is not declared for this client"),
        ));
    }
    if let Some(name) = body.name.as_deref()
        && name.chars().count() > MAX_NAME_CHARS
    {
        return Ok(oauth_error(
            "invalid_request",
            &format!("name must be at most {MAX_NAME_CHARS} characters"),
        ));
    }
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let Some(random) = state.settings.random.clone() else {
        return Err(internal(&scope));
    };

    let now = now_of(&state.ctx);
    let expires_at = now + time::Duration::seconds(state.settings.expires_in_secs);
    let device_code = match new_device_code(&*random) {
        Ok(code) => code,
        Err(err) => {
            tracing::error!(error = %err, "the entropy source failed to mint a device code");
            return Err(internal(&scope));
        }
    };
    let Some(user_code) = fresh_user_code(&*db, &*random).await? else {
        tracing::error!("the entropy source failed to mint a user code");
        return Err(internal(&scope));
    };

    store::insert(
        &*db,
        &store::NewCode {
            device_code_hash: &device_code_hash(&device_code),
            user_code_hash: &user_code_hash(&user_code),
            client_id: client.id(),
            scopes: &scopes.join(" "),
            name: body.name.as_deref(),
            now: &stamp(now),
            expires_at: &stamp(expires_at),
            interval_secs: state.settings.interval_secs,
        },
    )
    .await?;

    let base = api_base(
        &ModuleConfig::new("device-auth", &*state.ctx.config),
        &state.ctx,
    );
    let verification_uri = format!("{base}/v1/device-auth");
    let display = display_user_code(&user_code);
    Ok((
        StatusCode::OK,
        axum::Json(DeviceCodeResponse {
            device_code,
            user_code: display.clone(),
            verification_uri: verification_uri.clone(),
            verification_uri_complete: format!("{verification_uri}?user_code={display}"),
            expires_in: state.settings.expires_in_secs,
            interval: state.settings.interval_secs,
        }),
    )
        .into_response())
}

/// The scopes a request asked for: space-separated, empty ones dropped.
fn parse_scope(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or("")
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

/// 32 random bytes in the RFC 7636 base64url alphabet without padding.
fn new_device_code(random: &dyn RandomBytes) -> Result<String, cratefield_core::RandomError> {
    let mut bytes = [0u8; 32];
    random.fill(&mut bytes)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Eight characters from the look-alike-free alphabet, redrawn when the
/// database already holds a hash of the same code. `Ok(None)` is an
/// entropy failure; the collision loop is bounded by the code space, and a
/// code that collides this many times means the source is not random.
async fn fresh_user_code(
    db: &dyn cratefield_core::Database,
    random: &dyn RandomBytes,
) -> Result<Option<String>, Problem> {
    for _ in 0..8 {
        let mut code = String::with_capacity(8);
        while code.len() < 8 {
            let mut buf = [0u8; 8];
            if random.fill(&mut buf).is_err() {
                return Ok(None);
            }
            for byte in buf {
                if byte < USER_CODE_CEILING {
                    code.push(USER_CODE_ALPHABET[usize::from(byte % 20)] as char);
                    if code.len() == 8 {
                        break;
                    }
                }
            }
        }
        if !store::user_code_exists(db, &user_code_hash(&code)).await? {
            return Ok(Some(code));
        }
    }
    Ok(None)
}

/// `XXXX-XXXX`, the display form a person reads off the screen.
fn display_user_code(code: &str) -> String {
    format!("{}-{}", &code[..4], &code[4..])
}

// ---------------------------------------------------------------------------
// POST /v1/device-auth/token

/// The device access-token request (RFC 8628 §3.4).
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct DeviceTokenParams {
    #[serde(default)]
    pub grant_type: Option<String>,
    #[serde(default)]
    pub device_code: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
}

async fn poll_token(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    Params(body): Params<DeviceTokenParams>,
) -> Result<Response, Problem> {
    if body.grant_type.as_deref() != Some(GRANT_TYPE) {
        return Ok(oauth_error(
            "unsupported_grant_type",
            &format!("grant_type must be {GRANT_TYPE}"),
        ));
    }
    let (Some(device_code), Some(client_id)) = (
        body.device_code.as_deref().filter(|code| !code.is_empty()),
        body.client_id.as_deref().filter(|id| !id.is_empty()),
    ) else {
        return Ok(oauth_error(
            "invalid_request",
            "device_code and client_id are both required",
        ));
    };
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(&scope));
    };
    let hash = device_code_hash(device_code);
    let Some(row) = store::find_by_device(&*db, &hash, client_id).await? else {
        return Ok(oauth_error(
            "invalid_grant",
            "the device code is unknown, or was issued to another client",
        ));
    };
    let now = now_of(&state.ctx);
    let now_stamp = stamp(now);

    if row.status == "denied" {
        return Ok(oauth_error("access_denied", "the request was denied"));
    }
    if row.status == "consumed" || row.expires_at.as_str() <= now_stamp.as_str() {
        return Ok(oauth_error("expired_token", "the device code has expired"));
    }
    if row.status == "approved" {
        return consume_and_issue(&state, &scope, &*db, &hash, client_id, row, &now_stamp).await;
    }
    if row.status != "pending" {
        tracing::error!(status = %row.status, "a device code row is in an unknown state");
        return Err(internal(&scope));
    }
    gate_poll(
        &state,
        &*db,
        &hash,
        client_id,
        &now,
        &now_stamp,
        row.interval_secs,
    )
    .await
}

/// The RFC 8628 §3.5 interval gate: a poll that has waited out the row's
/// interval is answered `authorization_pending`, and one that has not is
/// answered `slow_down` after the interval widens by five seconds. Both
/// are 400s — `slow_down` is a pacing instruction, not a failure.
async fn gate_poll(
    state: &ModuleState,
    db: &dyn cratefield_core::Database,
    hash: &str,
    client_id: &str,
    now: &OffsetDateTime,
    now_stamp: &str,
    interval_secs: i64,
) -> Result<Response, Problem> {
    let not_after = stamp(*now - time::Duration::seconds(interval_secs));
    if store::touch_poll(db, hash, client_id, now_stamp, &not_after).await? == 1 {
        return Ok(oauth_error(
            "authorization_pending",
            "the person has not approved this device yet",
        ));
    }
    // Too early, or another poller won this interval: widen the wait so the
    // instruction sticks, then say `slow_down`.
    store::widen_interval(db, hash, client_id).await?;
    if state.settings.interval_secs > 0 {
        tracing::debug!(
            client_id,
            "a device poll arrived before its interval elapsed"
        );
    }
    Ok(oauth_error(
        "slow_down",
        "poll slower; the interval has been increased",
    ))
}

/// The at-most-once consume, then one [`Issuer`] call. Reaching this point
/// means the row is `approved` and unexpired; the guarded update decides
/// which of two racing polls wins, and the loser is told `expired_token`
/// rather than being handed a second credential.
async fn consume_and_issue(
    state: &ModuleState,
    scope: &Scope,
    db: &dyn cratefield_core::Database,
    hash: &str,
    client_id: &str,
    row: store::CodeRow,
    now_stamp: &str,
) -> Result<Response, Problem> {
    if store::consume(db, hash, client_id, now_stamp).await? != 1 {
        return Ok(oauth_error(
            "expired_token",
            "the device code has already been used",
        ));
    }
    let Some(issuer) = state.settings.issuer.clone() else {
        tracing::error!(
            "the device code was consumed but no issuer is configured; the credential is lost"
        );
        return Err(internal(scope));
    };
    let request = IssueRequest {
        subject: row.approver_subject.clone().unwrap_or_default(),
        client_id: client_id.to_owned(),
        name: row.name.clone(),
        scopes: parse_scope(Some(&row.scopes)),
    };
    match issuer.issue(request).await {
        Ok(credential) => {
            let mut response = (StatusCode::OK, axum::Json(credential)).into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            Ok(response)
        }
        Err(err) => {
            // The row is spent and stays spent: a credential minted twice
            // is worse than one the person has to ask for again. That is
            // the trade documented at the top of this module.
            tracing::error!(
                error = %err,
                "the issuer failed after the device code was consumed; the credential is lost \
                 and the client must start again"
            );
            Err(internal(scope))
        }
    }
}

// ---------------------------------------------------------------------------
// GET /v1/device-auth

/// The approval page's query: the code the person typed, when there is one.
#[derive(Debug, Default, Deserialize)]
struct DevicePageQuery {
    #[serde(default)]
    user_code: Option<String>,
}

/// The browser page (RFC 8628 §3.3). It asks the approver who is asking
/// first; an anonymous visitor is sent to sign in and comes back here with
/// the code still in the URL. A signed-in visitor with no code gets the
/// form; one with a code gets the request's details and the two buttons.
async fn page(
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, Problem> {
    let Some(approver) = state.approver.clone() else {
        tracing::error!("the device page was reached with no approver configured");
        return Err(Problem::internal());
    };
    let target = return_to(&uri);
    let subject = match approver.approve(&headers, &target).await {
        Ok(Approval::Subject(subject)) => subject,
        Ok(Approval::SignIn { location }) => return Ok(see_other(location)),
        Err(err) => {
            tracing::error!(error = %err, "the approver could not identify the caller");
            return Err(Problem::internal());
        }
    };
    tracing::debug!(approver = %subject, "a signed-in person opened the device page");
    let path = uri.path().to_owned();
    let query: DevicePageQuery = uri
        .query()
        .and_then(|query| serde_urlencoded::from_str(query).ok())
        .unwrap_or_default();
    let Some(raw) = query.user_code.as_deref() else {
        return Ok(html(code_form(&path)));
    };
    let code = normalize_user_code(raw);
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(Problem::internal());
    };
    let now_stamp = stamp(now_of(&state.ctx));
    let Some(row) = store::find_pending_by_user(&*db, &user_code_hash(&code), &now_stamp).await?
    else {
        return Ok(html(unknown_code_page(&path)));
    };
    Ok(html(approval_page(&path, &row, &display_user_code(&code))))
}

/// The form a person with no code yet sees.
fn code_form(path: &str) -> String {
    format!(
        "<!doctype html><meta charset=utf-8><title>Connect a device</title>\
         <h1>Connect a device</h1>\
         <p>Enter the code shown on your device.</p>\
         <form method=\"get\" action=\"{action}\">\
         <input name=\"user_code\" autocomplete=\"off\" autocapitalize=\"characters\" \
         spellcheck=\"false\" placeholder=\"XXXX-XXXX\" required>\
         <button type=\"submit\">Continue</button></form>",
        action = escape_html(path)
    )
}

/// The page for a code that names nothing pending.
fn unknown_code_page(path: &str) -> String {
    format!(
        "<!doctype html><meta charset=utf-8><title>Unknown code</title>\
         <h1>That code is not valid</h1>\
         <p>It may have been typed wrong, already answered, or expired.</p>\
         <p><a href=\"{action}\">Try again</a></p>",
        action = escape_html(path)
    )
}

/// The page that shows what the device asked for and asks the person to
/// decide. Every interpolated value is escaped: `client_id` and `name` are
/// the caller's bytes, and `scopes` came from the request that created the
/// row.
fn approval_page(path: &str, row: &store::CodeRow, code: &str) -> String {
    let path = escape_html(path);
    let name = row
        .name
        .as_deref()
        .map(|name| format!(" &mdash; {}", escape_html(name)))
        .unwrap_or_default();
    let scopes = if row.scopes.trim().is_empty() {
        "no scopes".to_owned()
    } else {
        escape_html(&row.scopes)
    };
    format!(
        "<!doctype html><meta charset=utf-8><title>Approve a device</title>\
         <h1>Approve this device?</h1>\
         <p><strong>{client}</strong>{name}</p>\
         <p>Asking for: {scopes}</p>\
         <p>Code: <code>{code}</code></p>\
         <form method=\"post\" action=\"{path}/approve\">\
         <input type=\"hidden\" name=\"user_code\" value=\"{code}\">\
         <button type=\"submit\">Approve</button></form>\
         <form method=\"post\" action=\"{path}/deny\">\
         <input type=\"hidden\" name=\"user_code\" value=\"{code}\">\
         <button type=\"submit\">Deny</button></form>",
        client = escape_html(&row.client_id),
        code = escape_html(code),
    )
}

// ---------------------------------------------------------------------------
// POST /v1/device-auth/approve and /deny

/// The two decision forms carry only the code; the approver comes from the
/// session, never the body.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct DecisionParams {
    #[serde(default)]
    pub user_code: Option<String>,
}

async fn approve(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    axum::Form(body): axum::Form<DecisionParams>,
) -> Result<Response, Problem> {
    decide(
        &state,
        &scope,
        &headers,
        &uri,
        body.user_code.as_deref(),
        "approved",
    )
    .await
}

async fn deny(
    scope: Scope,
    State(state): State<Arc<ModuleState>>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    axum::Form(body): axum::Form<DecisionParams>,
) -> Result<Response, Problem> {
    decide(
        &state,
        &scope,
        &headers,
        &uri,
        body.user_code.as_deref(),
        "denied",
    )
    .await
}

/// The shared decision path. The order is the security property: the
/// same-origin check runs before the body is trusted, the approver is
/// required before a code is looked up, and the per-approver limiter runs
/// before the guess reaches the database.
async fn decide(
    state: &ModuleState,
    scope: &Scope,
    headers: &HeaderMap,
    uri: &Uri,
    raw_code: Option<&str>,
    status: &str,
) -> Result<Response, Problem> {
    if let Err(problem) = require_same_origin(headers, uri) {
        return Err(problem.instance(&scope.request_id));
    }
    let Some(approver) = state.approver.clone() else {
        tracing::error!("an approval form was submitted with no approver configured");
        return Err(internal(scope));
    };
    let target = return_to(uri);
    let subject = match approver.approve(headers, &target).await {
        Ok(Approval::Subject(subject)) => subject,
        Ok(Approval::SignIn { location }) => return Ok(see_other(location)),
        Err(err) => {
            tracing::error!(error = %err, "the approver could not identify the caller");
            return Err(Problem::new(&APPROVER_REQUIRED).instance(&scope.request_id));
        }
    };
    let allowance = state.settings.max_wrong_entries;
    let keys = vec![format!("device-auth:guess:{allowance}:{subject}")];
    if let RateLimit::Denied { decision } = check_rate_limit(
        state.ctx.ports.rate_limiter.as_ref(),
        &keys,
        RateLimitFailure::FailClosed,
    )
    .await
    {
        return Ok(too_many_attempts(scope, &decision, allowance));
    }
    let Some(code) = raw_code
        .map(normalize_user_code)
        .filter(|code| code.len() == 8)
    else {
        return Err(Problem::new(&UNKNOWN_USER_CODE).instance(&scope.request_id));
    };
    let Some(db) = state.ctx.ports.db.clone() else {
        return Err(internal(scope));
    };
    let now_stamp = stamp(now_of(&state.ctx));
    let rows = store::decide(&*db, &user_code_hash(&code), status, &subject, &now_stamp).await?;
    if rows == 1 {
        Ok(html(decision_page(status)))
    } else {
        Err(Problem::new(&UNKNOWN_USER_CODE).instance(&scope.request_id))
    }
}

/// What the person sees after deciding.
fn decision_page(status: &str) -> String {
    let (title, heading, body) = if status == "approved" {
        (
            "Device approved",
            "Device approved",
            "You can return to your terminal.",
        )
    } else {
        (
            "Request denied",
            "Request denied",
            "The device was not connected.",
        )
    };
    format!(
        "<!doctype html><meta charset=utf-8><title>{title}</title>\
         <h1>{heading}</h1><p>{body}</p>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CountingRandom(u8);

    impl RandomBytes for CountingRandom {
        fn fill(&self, dest: &mut [u8]) -> Result<(), cratefield_core::RandomError> {
            for byte in dest.iter_mut() {
                *byte = self.0;
            }
            Ok(())
        }
    }

    #[test]
    fn a_device_code_is_32_bytes_of_base64url_without_padding() {
        let code = new_device_code(&CountingRandom(0x41)).expect("entropy is infallible here");
        assert_eq!(code.len(), 43, "{code}");
        assert!(!code.contains('='), "{code}");
        assert!(!code.contains('+') && !code.contains('/'), "{code}");
    }

    #[test]
    fn user_codes_use_the_look_alike_free_alphabet_in_pairs_of_four() {
        // Byte values below 240 map onto the alphabet; 0x41 is 65 → 65 % 20
        // = 5 → `H`, so the whole code is `HHHHHHHH` and reads `HHHH-HHHH`.
        let code = display_user_code("HHHHHHHH");
        assert_eq!(code, "HHHH-HHHH");
        for byte in USER_CODE_ALPHABET {
            assert!(char::from(*byte).is_ascii_uppercase(), "{}", *byte as char);
            assert!(
                !b"IOU018".contains(byte),
                "{} is a look-alike",
                *byte as char
            );
        }
        assert_eq!(USER_CODE_ALPHABET.len(), 20);
    }

    #[test]
    fn the_scope_parser_drops_empty_runs() {
        assert_eq!(parse_scope(None), Vec::<String>::new());
        assert_eq!(parse_scope(Some("  read   write ")), ["read", "write"]);
    }

    #[test]
    fn html_escaping_covers_the_five_characters() {
        assert_eq!(
            escape_html("<b>&\"'</b>"),
            "&lt;b&gt;&amp;&quot;&#39;&lt;/b&gt;"
        );
    }
}
