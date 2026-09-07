//! The control-plane **console** module (epic #1, issue #3): the first thing a
//! visitor meets. It owns the session gate, the login skeleton, and the
//! operator allowlist action, and — mounted in the venture — it is the
//! composition pattern the wizard (#8) and dashboard (#11) follow.
//!
//! **Login is stubbed, deliberately.** #3 signs in through `Factory-Zero/auth`,
//! which has no deployable Worker yet (auth#41), so `/auth/callback` cannot yet
//! receive a verified identity. Everything around that is real and tested: the
//! session cookie ([`cratefield_access`]), the guard that redirects an
//! unauthenticated request to `/login`, the admission decision, and the audited
//! operator invite. [`complete_login`] is the seam the real exchange plugs into
//! the moment it exists — it is unit-tested end to end with a
//! [`VerifiedIdentity`].

#![forbid(unsafe_code)]

mod google;
pub use google::{GoogleClient, GoogleError};

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::{AppendHeaders, Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use cratefield_access::{
    Admission, Allowlist, DEFAULT_TTL_SECS, EntryKind, Session, VerifiedIdentity,
    clear_session_cookie, issue_session, read_session, session_cookie,
    session_token_from_cookie_header,
};
use cratefield_core::{
    Config, ConfigError, Migrations, Module, ModuleConfig, ModuleContext, Port, Signer,
    SqlMigration, require_admin,
};
use http::{HeaderMap, StatusCode, header};
use time::format_description::well_known::Rfc3339;

/// Where the console is mounted (`/v1/<name>`), so its own redirects resolve.
const BASE: &str = "/v1/console";

/// The short-lived CSRF cookie carrying the OAuth `state` across the Google
/// round-trip. `SameSite=Lax` so it *is* sent on the top-level GET redirect
/// back from Google (Strict would not be).
const STATE_COOKIE: &str = "cf_oauth_state";

/// The control-plane console.
pub struct Console;

impl Module for Console {
    fn name(&self) -> &'static str {
        "console"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn requires(&self) -> &'static [Port] {
        // The signer proves the session cookie; the database holds the
        // allowlist and its audit; the http client runs the Google exchange.
        &[Port::Signer, Port::Db, Port::HttpClient]
    }

    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [cratefield_access::MIGRATION];
        Migrations::sqlite(&MIGRATIONS)
    }

    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        // Nothing is required for the stub. The Google/auth-service settings
        // land with the real exchange (auth#41).
        Ok(())
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let state = Arc::new(ConsoleState { ctx: Arc::new(ctx) });
        axum::Router::new()
            .route("/", get(home))
            .route("/login", get(login_page))
            .route("/auth/start", get(auth_start))
            .route("/auth/callback", get(callback))
            .route("/logout", get(logout))
            .route("/admin/allowlist", post(invite))
            .with_state(state)
    }
}

struct ConsoleState {
    ctx: Arc<ModuleContext>,
}

// ---------------------------------------------------------------------------
// Session guard
// ---------------------------------------------------------------------------

/// The proven session for this request, or `None` when the cookie is missing,
/// tampered, expired, or the signer is unavailable. This is the one gate every
/// protected route calls; the wizard and dashboard reuse it.
#[must_use]
pub fn current_session(ctx: &ModuleContext, headers: &HeaderMap) -> Option<Session> {
    let signer: &dyn Signer = ctx.ports.signer.as_deref()?;
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    let token = session_token_from_cookie_header(cookie)?;
    read_session(signer, token)
}

/// A guarded page: `Ok(session)` when signed in, `Err(redirect to /login)`
/// otherwise. A protected handler is one line — `let session = guard(..)?;`.
#[allow(clippy::result_large_err)] // Err is an axum Response, returned by value on purpose
fn guard(ctx: &ModuleContext, headers: &HeaderMap) -> Result<Session, Response> {
    current_session(ctx, headers)
        .ok_or_else(|| Redirect::to(&format!("{BASE}/login")).into_response())
}

// ---------------------------------------------------------------------------
// Login skeleton (the exchange is stubbed on auth#41)
// ---------------------------------------------------------------------------

/// The outcome of admitting a verified identity: a `Set-Cookie` to log in with,
/// or a refusal (not on the allowlist).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginOutcome {
    Admitted { set_cookie: String },
    Refused,
}

/// The real login logic, independent of where the [`VerifiedIdentity`] came
/// from: check the allowlist, and on admission mint a session cookie. The HTTP
/// callback calls this once the auth exchange yields an identity; today it is
/// exercised directly by the tests.
///
/// # Errors
///
/// Propagates a [`cratefield_access::AccessError`] if the allowlist read fails.
#[allow(clippy::result_large_err)] // mirrors the access crate's own AccessError return
pub async fn complete_login(
    signer: &dyn Signer,
    allowlist: &Allowlist,
    identity: &VerifiedIdentity,
    now: u64,
) -> Result<LoginOutcome, cratefield_access::AccessError> {
    match allowlist.admit(identity).await? {
        Admission::Admitted { identity, .. } => {
            let token = issue_session(signer, &identity, now, DEFAULT_TTL_SECS);
            Ok(LoginOutcome::Admitted {
                set_cookie: session_cookie(&token, DEFAULT_TTL_SECS),
            })
        }
        Admission::Refused => Ok(LoginOutcome::Refused),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn home(State(state): State<Arc<ConsoleState>>, headers: HeaderMap) -> Response {
    let session = match guard(&state.ctx, &headers) {
        Ok(session) => session,
        Err(redirect) => return redirect,
    };
    Html(page(
        "Cratefield console",
        &format!(
            "<p>Signed in as <strong>{}</strong>.</p>\
             <p>The provisioning wizard (#8) and the account dashboard (#11) land here.</p>\
             <p><a href=\"{BASE}/logout\">Sign out</a></p>",
            escape(&session.account_id)
        ),
    ))
    .into_response()
}

async fn login_page() -> Response {
    Html(page(
        "Sign in · Cratefield",
        &format!(
            "<p>Cratefield is invite-only. Sign in with the Google account on the allowlist.</p>\
             <p><a class=\"btn\" href=\"{BASE}/auth/start\">Sign in with Google</a></p>",
        ),
    ))
    .into_response()
}

/// Begins the OAuth flow: mints a CSRF `state`, sets it as a `SameSite=Lax`
/// cookie, and redirects to Google. Returns a plain page when the console has
/// no Google client configured (`CONSOLE_GOOGLE_CLIENT_*`).
async fn auth_start(State(state): State<Arc<ConsoleState>>) -> Response {
    let ctx = &state.ctx;
    let Some(client) = google_client(ctx) else {
        return not_configured();
    };
    let token = ctx
        .ports
        .id_gen
        .as_ref()
        .map_or_else(|| "state".to_owned(), |generator| generator.ulid());
    (
        AppendHeaders([(header::SET_COOKIE, set_state_cookie(&token))]),
        Redirect::to(&client.authorize_url(&token)),
    )
        .into_response()
}

#[derive(serde::Deserialize)]
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
}

/// The OAuth redirect target: verify the CSRF `state`, exchange the `code` for
/// a Google-verified identity, and admit it (session) or refuse it
/// (invite-only). Card-clean: only Google identifiers cross here.
async fn callback(
    State(app): State<Arc<ConsoleState>>,
    headers: HeaderMap,
    Query(params): Query<CallbackParams>,
) -> Response {
    let ctx = &app.ctx;
    let Some(client) = google_client(ctx) else {
        return not_configured();
    };
    let (Some(code), Some(returned_state)) = (params.code, params.state) else {
        return (StatusCode::BAD_REQUEST, "missing code or state").into_response();
    };
    // CSRF: the state returned by Google must match the cookie we set.
    match state_from_cookies(&headers) {
        Some(cookie_state) if cookie_state == returned_state => {}
        _ => return (StatusCode::BAD_REQUEST, "state mismatch").into_response(),
    }

    let (Some(http), Some(db), Some(signer)) = (
        ctx.ports.http.clone(),
        ctx.ports.db.clone(),
        ctx.ports.signer.clone(),
    ) else {
        return internal("a required port is unavailable");
    };

    let identity = match client.exchange(http.as_ref(), &code).await {
        Ok(identity) => identity,
        Err(err) => {
            tracing::error!(error = %err, "google exchange failed");
            return (StatusCode::BAD_GATEWAY, "sign-in with Google failed").into_response();
        }
    };

    let now = ctx.ports.clock.as_ref().map_or(0, |clock| {
        u64::try_from(clock.now().unix_timestamp()).unwrap_or(0)
    });
    let allowlist = Allowlist::new(db);
    match complete_login(signer.as_ref(), &allowlist, &identity, now).await {
        Ok(LoginOutcome::Admitted { set_cookie }) => (
            AppendHeaders([
                (header::SET_COOKIE, set_cookie),
                (header::SET_COOKIE, clear_state_cookie()),
            ]),
            Redirect::to(&format!("{BASE}/")),
        )
            .into_response(),
        Ok(LoginOutcome::Refused) => (
            StatusCode::FORBIDDEN,
            Html(page(
                "Invite-only · Cratefield",
                &format!(
                    "<p><strong>{}</strong> is not on the Cratefield allowlist.</p>\
                     <p>Cratefield is invite-only. No account was created.</p>",
                    escape(&identity.email)
                ),
            )),
        )
            .into_response(),
        Err(err) => {
            tracing::error!(error = %err, "login failed");
            internal("login failed")
        }
    }
}

async fn logout() -> Response {
    (
        [(header::SET_COOKIE, clear_session_cookie())],
        Redirect::to(&format!("{BASE}/login")),
    )
        .into_response()
}

/// The operator invite: add (or update) an allowlist entry, audited. Gated by
/// `ADMIN_TOKEN` — an operator action, never a public form (#3).
async fn invite(
    State(state): State<Arc<ConsoleState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let ctx = &state.ctx;
    if let Err(problem) = require_admin(&*ctx.config, &headers) {
        return problem.into_response();
    }
    let Some(db) = ctx.ports.db.clone() else {
        return internal("database port unavailable");
    };

    let request: InviteRequest = match serde_json::from_str(&body) {
        Ok(request) => request,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid request body: {err}"),
            )
                .into_response();
        }
    };
    let kind = match request.kind.as_str() {
        "email" => EntryKind::Email,
        "domain" => EntryKind::Domain,
        other => {
            return (
                StatusCode::BAD_REQUEST,
                format!("kind must be \"email\" or \"domain\", got {other:?}"),
            )
                .into_response();
        }
    };

    let audit_id = ctx
        .ports
        .id_gen
        .as_ref()
        .map_or_else(|| "audit".to_owned(), |generator| generator.ulid());
    let now = ctx
        .ports
        .clock
        .as_ref()
        .and_then(|clock| clock.now().format(&Rfc3339).ok())
        .unwrap_or_default();

    let allowlist = Allowlist::new(db);
    match allowlist
        .allow(
            &request.value,
            kind,
            &request.note,
            "operator",
            &audit_id,
            &now,
        )
        .await
    {
        Ok(entry) => (StatusCode::OK, axum::Json(entry)).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "allowlist invite failed");
            internal("could not add the allowlist entry")
        }
    }
}

#[derive(serde::Deserialize)]
struct InviteRequest {
    value: String,
    kind: String,
    #[serde(default)]
    note: String,
}

/// The console's Google client from config, or `None` if `CONSOLE_GOOGLE_*`
/// are not set (then sign-in is disabled and [`auth_start`] says so).
fn google_client(ctx: &ModuleContext) -> Option<crate::google::GoogleClient> {
    let cfg = ModuleConfig::new("console", &*ctx.config);
    let client_id = cfg.get_str("GOOGLE_CLIENT_ID", "");
    let client_secret = cfg.get_str("GOOGLE_CLIENT_SECRET", "");
    let base = cfg.get_str("BASE_URL", "");
    if client_id.is_empty() || client_secret.is_empty() || base.is_empty() {
        return None;
    }
    Some(crate::google::GoogleClient {
        client_id,
        client_secret,
        redirect_uri: format!("{}{BASE}/auth/callback", base.trim_end_matches('/')),
    })
}

fn set_state_cookie(state: &str) -> String {
    format!("{STATE_COOKIE}={state}; HttpOnly; Secure; SameSite=Lax; Path={BASE}; Max-Age=600")
}

fn clear_state_cookie() -> String {
    format!("{STATE_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path={BASE}; Max-Age=0")
}

fn state_from_cookies(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        (name == STATE_COOKIE).then(|| value.to_owned())
    })
}

fn not_configured() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Html(page(
            "Sign-in unavailable · Cratefield",
            "<p>Google sign-in is not configured on this console              (<code>CONSOLE_GOOGLE_CLIENT_ID</code>/<code>_SECRET</code>/<code>BASE_URL</code>).</p>",
        )),
    )
        .into_response()
}

fn internal(detail: &str) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, detail.to_owned()).into_response()
}

// ---------------------------------------------------------------------------
// Minimal HTML (no template engine; escape all dynamic text)
// ---------------------------------------------------------------------------

fn page(title: &str, body_html: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{}</title></head><body><main>{body_html}</main></body></html>",
        escape(title)
    )
}

/// Escapes text for inclusion in HTML (the account email on the home page, an
/// operator-supplied value never reaches a page, but be safe by default).
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_adapter_sqlite::SqliteDatabase;
    use cratefield_core::{Database, HmacSigner};

    const SECRET: &str = "a-test-harness-secret-0123456789abcd";

    fn signer() -> HmacSigner {
        HmacSigner::new(SECRET, None).expect("signer")
    }

    fn db() -> Arc<dyn Database> {
        let db = SqliteDatabase::in_memory().expect("sqlite");
        db.apply_migrations("access", &[cratefield_access::MIGRATION])
            .expect("access schema");
        Arc::new(db)
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn identity(email: &str) -> VerifiedIdentity {
        VerifiedIdentity {
            email: email.to_owned(),
            name: "Test Operator".to_owned(),
            hosted_domain: None,
        }
    }

    #[test]
    fn an_allowlisted_identity_gets_a_session_cookie() {
        let db = db();
        let allowlist = Allowlist::new(db.clone());
        pollster::block_on(async {
            allowlist
                .allow(
                    "op@cratefield.com",
                    EntryKind::Email,
                    "founder",
                    "seed",
                    "id1",
                    "2026-09-08T00:00:00Z",
                )
                .await
                .unwrap();

            let outcome =
                complete_login(&signer(), &allowlist, &identity("op@cratefield.com"), now())
                    .await
                    .unwrap();
            let LoginOutcome::Admitted { set_cookie } = outcome else {
                panic!("expected admission");
            };
            assert!(set_cookie.contains("cf_session="));
            assert!(set_cookie.contains("HttpOnly"));
            assert!(set_cookie.contains("SameSite=Strict"));

            // And the minted cookie proves a session for that identity.
            let token = session_token_from_cookie_header(&set_cookie).unwrap();
            let session = read_session(&signer(), token).unwrap();
            assert_eq!(session.account_id, "op@cratefield.com");
        });
    }

    #[test]
    fn an_identity_not_on_the_allowlist_is_refused() {
        let allowlist = Allowlist::new(db());
        let outcome = pollster::block_on(complete_login(
            &signer(),
            &allowlist,
            &identity("stranger@example.com"),
            1_700_000_000,
        ))
        .unwrap();
        assert_eq!(outcome, LoginOutcome::Refused);
    }

    #[test]
    fn the_guard_refuses_a_request_with_no_session_cookie() {
        // current_session returns None without a valid cookie; the guard then
        // redirects. We assert the None here (the redirect is axum plumbing).
        let ctx = test_ctx(db());
        let headers = HeaderMap::new();
        assert!(current_session(&ctx, &headers).is_none());
    }

    #[test]
    fn the_guard_admits_a_request_carrying_a_valid_session() {
        let ctx = test_ctx(db());
        let token = issue_session(&signer(), "op@cratefield.com", now(), DEFAULT_TTL_SECS);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            session_cookie(&token, DEFAULT_TTL_SECS).parse().unwrap(),
        );
        // The cookie header the browser sends is just `name=value`; build that.
        let mut sent = HeaderMap::new();
        sent.insert(
            header::COOKIE,
            format!("cf_session={token}").parse().unwrap(),
        );
        let session = current_session(&ctx, &sent).expect("valid session");
        assert_eq!(session.account_id, "op@cratefield.com");
    }

    /// Builds a `ModuleContext` with a signer + db for the guard tests.
    fn test_ctx(db: Arc<dyn Database>) -> ModuleContext {
        use cratefield_core::{EmptyConfig, EventBus, Ports, TemplateRegistry, Venture};
        let mut ports = Ports::with_config(Arc::new(EmptyConfig));
        ports.signer = Some(Arc::new(signer()));
        ports.db = Some(db);
        ModuleContext {
            ports,
            config: Arc::new(EmptyConfig),
            events: EventBus::default(),
            templates: Arc::new(TemplateRegistry::default()),
            venture: Arc::new(Venture::new("cratefield-control-plane", "cratefield.com")),
            ui_mounted: false,
        }
    }
}
