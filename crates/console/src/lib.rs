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

use std::sync::Arc;

use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use cratefield_access::{
    Admission, Allowlist, DEFAULT_TTL_SECS, EntryKind, Session, VerifiedIdentity,
    clear_session_cookie, issue_session, read_session, session_cookie,
    session_token_from_cookie_header,
};
use cratefield_core::{
    Config, ConfigError, Migrations, Module, ModuleContext, Port, Signer, SqlMigration,
    require_admin,
};
use http::{HeaderMap, StatusCode, header};
use time::format_description::well_known::Rfc3339;

/// Where the console is mounted (`/v1/<name>`), so its own redirects resolve.
const BASE: &str = "/v1/console";

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
        // allowlist and its audit.
        &[Port::Signer, Port::Db]
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
    // The button is inert until the auth service can receive the callback
    // (auth#41). The page is honest about it rather than dead.
    Html(page(
        "Sign in · Cratefield",
        &format!(
            "<p>Cratefield is invite-only. Sign in with the Google account on the allowlist.</p>\
             <p><a class=\"btn\" href=\"{BASE}/auth/callback\">Sign in with Google</a></p>\
             <p class=\"muted\">Sign-in is not live yet: it goes through the Factory Zero auth \
             service, which is not deployable yet (auth#41). The session, allowlist and guard are \
             in place; the exchange plugs in when auth ships.</p>",
        ),
    ))
    .into_response()
}

async fn callback() -> Response {
    // The real handler will exchange the auth service's response for a
    // `VerifiedIdentity`, then call `complete_login`. Until auth is deployable
    // there is nothing to exchange, so we say so plainly rather than pretend.
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Html(page(
            "Sign-in unavailable · Cratefield",
            "<p>Sign-in is not available yet: the Factory Zero auth service is not deployed \
             (auth#41). No account was created.</p>",
        )),
    )
        .into_response()
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
