//! The control-plane **dashboard** module (issue #11): one account's
//! ventures, managed from one screen.
//!
//! The point of the screen is that **a degraded venture reads as degraded,
//! not as loading.** This repository shipped a bug where a failing call
//! looked like an empty state, and the issue calls it out by name, so every
//! rendered verdict here is one the dashboard actually observed: the status
//! comes from the `venture` row, the health verdict from a real fetch of the
//! venture's `/__health`, and the provisioning failure from
//! `provision_progress`. Where the dashboard cannot know something — the
//! venture audit trail, secret names — it says so in plain text rather than
//! rendering a plausible placeholder. No screen lies.
//!
//! Read-only, except one action: archiving (issue #11 §3 — stop it, keep
//! the record). The read-only half is built and tested here; the live
//! provisioning engine (`Deployer` onto Cloudflare) is not wired, so
//! `docs/DASHBOARD.md` names exactly which half is missing and why.

#![forbid(unsafe_code)]

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use cratefield_accounts::{Repository, Venture, VentureStatus};
use cratefield_console::{LOGIN_PATH, current_session};
use cratefield_core::{Database, Migrations, Module, ModuleContext, Port, SqlMigration, Statement};
use http::{HeaderMap, StatusCode, header};
use time::format_description::well_known::Rfc3339;

/// Where the dashboard is mounted (`/v1/<name>`), so its own links resolve.
const BASE: &str = "/v1/dashboard";

/// The control-plane account dashboard.
pub struct Dashboard;

impl Module for Dashboard {
    fn name(&self) -> &'static str {
        "dashboard"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn requires(&self) -> &'static [Port] {
        // The signer proves the session cookie (shared with the console);
        // the database holds the account, venture, progress and connection
        // rows; the http client runs the `/__health` checks; the clock and
        // id-gen mint timestamps and ids.
        &[
            Port::Signer,
            Port::Db,
            Port::HttpClient,
            Port::Clock,
            Port::IdGen,
        ]
    }

    fn migrations(&self) -> Migrations {
        // The dashboard owns no tables of its own: it reads the schema its
        // domain crates use (accounts + ventures, provisioning progress,
        // connection metadata). Re-id the three sub-schemas so they are
        // unique WITHIN this module — each crate's own MIGRATION is id
        // "0001", which would collide under one module — exactly the way
        // the console (issue #3) does it. Same SQL, distinct ids.
        const MIGRATIONS: [SqlMigration; 3] = [
            SqlMigration {
                id: "0001",
                name: "accounts",
                sql: cratefield_accounts::MIGRATION.sql,
            },
            SqlMigration {
                id: "0002",
                name: "provisioning",
                sql: cratefield_provisioning::MIGRATION.sql,
            },
            SqlMigration {
                id: "0003",
                name: "connections",
                sql: cratefield_connections::MIGRATION.sql,
            },
        ];
        // The array is the apply order; this refuses a gap, a duplicate
        // or an entry out of order at build time (issue #27).
        const _: () = cratefield_core::assert_migration_set(&MIGRATIONS);
        Migrations::sqlite(&MIGRATIONS)
    }

    fn validate_config(
        &self,
        _cfg: &dyn cratefield_core::Config,
    ) -> Result<(), cratefield_core::ConfigError> {
        // The dashboard has no configuration of its own: it renders what
        // the other modules recorded. Nothing to validate.
        Ok(())
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let state = Arc::new(DashboardState { ctx: Arc::new(ctx) });
        axum::Router::new()
            .route("/", get(ventures))
            .route("/ventures/{id}", get(venture_detail))
            .route("/ventures/{id}/archive", post(archive))
            .with_state(state)
    }
}

struct DashboardState {
    ctx: Arc<ModuleContext>,
}

// ---------------------------------------------------------------------------
// Session guard and account resolution
// ---------------------------------------------------------------------------

/// A guarded page: `Ok(())` when signed in, `Err(redirect to the login
/// gate)` otherwise. The session proof itself is the console's
/// [`current_session`]: one signer, one cookie (`cf_session`), one gate —
/// the wizard and dashboard reuse it, exactly as the console's docs say.
///
/// The redirect goes to the console's [`LOGIN_PATH`], not to a `/login`
/// under this module: the dashboard serves no login route, so sending a
/// signed-out visitor to `{BASE}/login` would 404 them.
#[allow(clippy::result_large_err)]
fn guard(ctx: &ModuleContext, headers: &HeaderMap) -> Result<(), Response> {
    if current_session(ctx, headers).is_some() {
        Ok(())
    } else {
        Err(Redirect::to(LOGIN_PATH).into_response())
    }
}

/// The signed-in account (created on first login by the console) and a
/// repository over it. Every venture read below goes through this
/// repository, so isolation stays by query: no handler can name a venture
/// outside the account.
#[allow(clippy::result_large_err)]
async fn account_of(
    ctx: &ModuleContext,
    account_id: &str,
) -> Result<(cratefield_accounts::Account, Repository), Response> {
    let db = ctx
        .ports
        .db
        .clone()
        .ok_or_else(|| internal("db port unavailable"))?;
    let repo = Repository::new(db);
    let account = repo
        .account_for_login(account_id, account_id, &ulid(ctx), &now_rfc3339(ctx))
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "account_for_login failed");
            internal("could not load the account")
        })?;
    Ok((account, repo))
}

// ---------------------------------------------------------------------------
// The health verdict: the screen's reason to exist
// ---------------------------------------------------------------------------

/// What the dashboard actually observed about a venture's `/__health`.
/// Every variant is a first-hand observation or a deliberate refusal to
/// check; there is no "checking" state, because a venture whose health is
/// unknown must never be rendered as if it were merely slow (the bug issue
/// #11 calls out by name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthVerdict {
    /// The venture answered `/__health` with a success status.
    Answering,
    /// The venture answered with a failure status; carries the status code.
    Failing(u16),
    /// The fetch itself failed (DNS, connection refused, transport);
    /// carries the transport message.
    Unreachable(String),
    /// Not checked: the venture is not in a state where it should be
    /// answering at all (draft, provisioning, archived).
    NotRunning,
}

impl HealthVerdict {
    /// The honest one-line rendering. A degraded or failing venture reads
    /// as failing — never as an empty state, never as "loading".
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Answering => "answering /__health".to_owned(),
            Self::Failing(code) => format!("FAILING /__health — HTTP {code}"),
            Self::Unreachable(detail) => format!("FAILING /__health — unreachable: {detail}"),
            Self::NotRunning => "not running — /__health not checked".to_owned(),
        }
    }

    /// Whether the verdict means the venture is failing right now.
    #[must_use]
    pub fn is_failing(&self) -> bool {
        matches!(self, Self::Failing(_) | Self::Unreachable(_))
    }
}

/// Checks a venture's `/__health` over the http port, for real. A venture
/// that is not live or degraded is not fetched at all: there is nothing
/// there to answer, and pretending to wait would be exactly the lie the
/// issue forbids.
async fn check_health(ctx: &ModuleContext, venture: &Venture) -> HealthVerdict {
    if !matches!(
        venture.status,
        VentureStatus::Live | VentureStatus::Degraded
    ) {
        return HealthVerdict::NotRunning;
    }
    let Some(http) = ctx.ports.http.as_deref() else {
        return HealthVerdict::Unreachable("http port unavailable".to_owned());
    };
    let url = format!("https://{}/__health", venture.subdomain);
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri(&url)
        .header(header::USER_AGENT, "cratefield-dashboard")
        .body(bytes::Bytes::new());
    let request = match request {
        Ok(request) => request,
        Err(err) => return HealthVerdict::Unreachable(err.to_string()),
    };
    match http.send(request).await {
        Ok(response) if response.status().is_success() => HealthVerdict::Answering,
        Ok(response) => HealthVerdict::Failing(response.status().as_u16()),
        Err(err) => HealthVerdict::Unreachable(err.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Reads over the schema the domain crates own
// ---------------------------------------------------------------------------

/// The venture's provisioning progress: the last step that completed, and
/// the recorded failure, if the run stopped. Read straight from
/// `provision_progress`, which the provisioning engine owns.
struct Progress {
    last_step: String,
    error: String,
    updated_at: String,
}

async fn progress_of(
    db: &dyn Database,
    venture_id: &str,
) -> Result<Progress, cratefield_core::DbError> {
    let rows = db
        .query(&Statement::with_values(
            "SELECT last_step, error, updated_at FROM provision_progress WHERE venture_id = ?",
            vec![text(venture_id)],
        ))
        .await?;
    let row = rows.first();
    Ok(Progress {
        last_step: row.and_then(|row| row.get("last_step")).unwrap_or_default(),
        error: row.and_then(|row| row.get("error")).unwrap_or_default(),
        updated_at: row
            .and_then(|row| row.get("updated_at"))
            .unwrap_or_default(),
    })
}

/// One of the venture's connections — metadata only, by design: the
/// `connection` table holds a non-secret hint, never a key. This is the
/// rendering the issue asks for, and it cannot leak a secret because none
/// is here.
struct ConnectionRow {
    kind: String,
    state: String,
    reason: String,
    hint: String,
}

async fn connections_of(
    db: &dyn Database,
    tenant_id: &str,
) -> Result<Vec<ConnectionRow>, cratefield_core::DbError> {
    let rows = db
        .query(&Statement::with_values(
            "SELECT kind, state, reason, hint FROM connection \
             WHERE tenant_id = ? ORDER BY kind ASC",
            vec![text(tenant_id)],
        ))
        .await?;
    Ok(rows
        .rows
        .iter()
        .map(|row| ConnectionRow {
            kind: row.get("kind").unwrap_or_default(),
            state: row.get("state").unwrap_or_default(),
            reason: row.get("reason").unwrap_or_default(),
            hint: row.get("hint").unwrap_or_default(),
        })
        .collect())
}

fn status_label(status: VentureStatus) -> &'static str {
    use VentureStatus::{Archived, Degraded, Draft, Live, Provisioning};
    match status {
        Draft => "draft",
        Provisioning => "provisioning",
        Live => "live",
        Degraded => "DEGRADED",
        Archived => "archived",
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

fn render_progress(progress: &Progress) -> String {
    if !progress.error.is_empty() {
        return format!(
            "<p class=\"status-degraded\"><strong>Provisioning failed</strong> after step \
             <code>{}</code>: {}</p>",
            escape(&progress.last_step),
            escape(&progress.error)
        );
    }
    if progress.last_step.is_empty() {
        return String::from("<p>No provisioning has run yet.</p>");
    }
    format!(
        "<p>Last completed step: <code>{}</code> ({}).</p>",
        escape(&progress.last_step),
        escape(&progress.updated_at)
    )
}

#[allow(clippy::format_push_string)]
fn render_connections(connections: &[ConnectionRow]) -> String {
    if connections.is_empty() {
        return String::from("<p>No connections.</p>");
    }
    let mut html = String::from("<ul>");
    for connection in connections {
        let mut line = format!(
            "<li><strong>{kind}</strong> — {state}",
            kind = escape(&connection.kind),
            state = escape(&connection.state),
        );
        if !connection.hint.is_empty() {
            line.push_str(&format!(" ({})", escape(&connection.hint)));
        }
        if !connection.reason.is_empty() {
            line.push_str(&format!(": {}", escape(&connection.reason)));
        }
        line.push_str("</li>");
        html.push_str(&line);
    }
    html.push_str("</ul>");
    html
}

/// The screen itself (issue #11 §1): every venture the account owns, each
/// with its status, its subdomain, and a real `/__health` verdict. A
/// degraded venture renders DEGRADED with the recorded provisioning error,
/// not a spinner, not an empty list.
#[allow(clippy::format_push_string)]
async fn ventures(State(state): State<Arc<DashboardState>>, headers: HeaderMap) -> Response {
    let ctx = &state.ctx;
    if let Err(redirect) = guard(ctx, &headers) {
        return redirect;
    }
    let session = current_session(ctx, &headers).expect("guard proved a session");
    let (account, repo) = match account_of(ctx, &session.account_id).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let ventures = match repo.ventures_for(&account.id).await {
        Ok(ventures) => ventures,
        Err(err) => {
            tracing::error!(error = %err, "venture list failed");
            return internal("could not load the ventures");
        }
    };

    let mut list = String::new();
    if ventures.is_empty() {
        list.push_str("<p>No ventures yet. Create one in the console.</p>");
    } else {
        for venture in &ventures {
            let health = check_health(ctx, venture).await;
            list.push_str(&format!(
                "<li><a href=\"{BASE}/ventures/{id}\">{slug}</a> — \
                 <strong>{status}</strong> · {subdomain} · {health}</li>",
                id = escape(&venture.id),
                slug = escape(&venture.slug),
                status = status_label(venture.status),
                subdomain = escape(&venture.subdomain),
                health = escape(&health.label()),
            ));
        }
    }

    Html(page(
        "Your ventures · Cratefield",
        &format!(
            "<h1>Your ventures</h1>\
             <p>Signed in as <strong>{email}</strong>.</p>\
             <ul>{list}</ul>\
             <p><a href=\"/v1/console\">Console</a></p>",
            email = escape(&session.account_id),
            list = list,
        ),
    ))
    .into_response()
}

/// One venture (issue #11 §2): the module set, the connections, the
/// provisioning progress and any recorded failure, the `/__health`
/// verdict — and, where the dashboard cannot know the truth (the audit
/// trail, secret names), a plain statement that it does not know rather
/// than an invented row.
#[allow(clippy::format_push_string)]
async fn venture_detail(
    State(state): State<Arc<DashboardState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let ctx = &state.ctx;
    if let Err(redirect) = guard(ctx, &headers) {
        return redirect;
    }
    let session = current_session(ctx, &headers).expect("guard proved a session");
    let (account, repo) = match account_of(ctx, &session.account_id).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let Some(db) = ctx.ports.db.clone() else {
        return internal("db port unavailable");
    };
    let venture = match repo.venture_for(&account.id, &id).await {
        Ok(Some(venture)) => venture,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such venture").into_response(),
        Err(err) => {
            tracing::error!(error = %err, "venture lookup failed");
            return internal("could not load the venture");
        }
    };
    let progress = match progress_of(db.as_ref(), &venture.id).await {
        Ok(progress) => progress,
        Err(err) => {
            tracing::error!(error = %err, "progress read failed");
            return internal("could not load the provisioning progress");
        }
    };
    let connections = match connections_of(db.as_ref(), &venture.tenant_id).await {
        Ok(connections) => connections,
        Err(err) => {
            tracing::error!(error = %err, "connections read failed");
            return internal("could not load the connections");
        }
    };
    let health = check_health(ctx, &venture).await;

    let status_line = if venture.status == VentureStatus::Degraded {
        String::from(
            "<p class=\"status-degraded\"><strong>DEGRADED</strong> — provisioned once, now \
             failing.</p>",
        )
    } else {
        format!(
            "<p>Status: <strong>{}</strong></p>",
            status_label(venture.status)
        )
    };

    let progress_html = render_progress(&progress);
    let connections_html = render_connections(&connections);

    let archive_html = if venture.status == VentureStatus::Archived {
        String::from("<p>This venture is archived. Its record is kept.</p>")
    } else {
        format!(
            "<form method=\"post\" action=\"{BASE}/ventures/{id}/archive\">\
             <button type=\"submit\">Archive</button></form>",
            id = escape(&venture.id),
        )
    };

    Html(page(
        &format!("{} · Cratefield", venture.slug),
        &format!(
            "<h1>{slug}</h1>{status_line}\
             <p>Subdomain: <strong>{subdomain}</strong> · Health: <strong>{health}</strong></p>\
             <h2>Modules</h2><p><code>{modules}</code></p>\
             <h2>Provisioning</h2>{progress_html}\
             <h2>Connections</h2>{connections_html}\
             <h2>Secrets</h2>\
             <p>Secrets are shown as names and versions only, never values. \
             No secret names are listed here yet: the control plane has no KMS wired \
             (the live deploy pipeline owns that wiring), so this screen would have \
             nothing truthful to list. It will not invent one.</p>\
             <h2>Audit trail</h2>\
             <p>Who touched what is not recorded per venture yet — the only audit \
             table today is the console's allowlist audit, which is account-level, \
             and the secrets log is tracing-only. This screen shows no audit rows \
             rather than made-up ones.</p>\
             {archive_html}\
             <p><a href=\"{BASE}\">Back</a></p>",
            slug = escape(&venture.slug),
            subdomain = escape(&venture.subdomain),
            health = escape(&health.label()),
            modules = escape(&venture.module_set),
            progress_html = progress_html,
            connections_html = connections_html,
            archive_html = archive_html,
        ),
    ))
    .into_response()
}

/// Archives a venture (issue #11 §3): stop it, keep the record. The move
/// goes through the accounts repository, so the lifecycle state machine
/// refuses what it refuses, and the row stays.
#[allow(clippy::result_large_err)]
async fn archive(
    State(state): State<Arc<DashboardState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let ctx = &state.ctx;
    if let Err(redirect) = guard(ctx, &headers) {
        return redirect;
    }
    let session = current_session(ctx, &headers).expect("guard proved a session");
    let (account, repo) = match account_of(ctx, &session.account_id).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    match repo
        .set_venture_status(&account.id, &id, VentureStatus::Archived, &now_rfc3339(ctx))
        .await
    {
        Ok(_) => Redirect::to(&format!("{BASE}/ventures/{id}")).into_response(),
        Err(cratefield_accounts::RepoError::IllegalTransition { from, to }) => (
            StatusCode::CONFLICT,
            format!(
                "a venture cannot go from {} to {}",
                status_label(from),
                status_label(to)
            ),
        )
            .into_response(),
        Err(cratefield_accounts::RepoError::NotFound(_)) => {
            (StatusCode::NOT_FOUND, "no such venture").into_response()
        }
        Err(err) => {
            tracing::error!(error = %err, "archive failed");
            internal("could not archive the venture")
        }
    }
}

// ---------------------------------------------------------------------------
// Small helpers (shared shape with the console)
// ---------------------------------------------------------------------------

fn ulid(ctx: &ModuleContext) -> String {
    ctx.ports
        .id_gen
        .as_ref()
        .map_or_else(|| "id".to_owned(), |generator| generator.ulid())
}

fn now_rfc3339(ctx: &ModuleContext) -> String {
    ctx.ports
        .clock
        .as_ref()
        .and_then(|clock| clock.now().format(&Rfc3339).ok())
        .unwrap_or_default()
}

fn text(value: &str) -> sea_query::Value {
    sea_query::Value::String(Some(Box::new(value.to_owned())))
}

fn internal(detail: &str) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, detail.to_owned()).into_response()
}

/// Escapes text for inclusion in HTML. Every dynamic value on the page —
/// venture slugs, subdomains, transport messages — goes through this.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn page(title: &str, body_html: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{}</title></head><body><main>{body_html}</main></body></html>",
        escape(title)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_access::{DEFAULT_TTL_SECS, issue_session};
    use cratefield_testing::{FakeHttpClient, TestHarness};
    use http::{Method, Request as HttpRequest};
    use tower::util::ServiceExt;

    const EMAIL: &str = "op@cratefield.com";
    /// The kit's fixed clock reads `1_800_000_000`; mint sessions "now" so
    /// they are live, not expired.
    const NOW: u64 = 1_800_000_000;

    struct Reply {
        status: StatusCode,
        location: String,
        body: String,
    }

    async fn send(kit: &TestHarness, method: Method, uri: &str, cookie: Option<&str>) -> Reply {
        let mut builder = HttpRequest::builder().method(method).uri(uri);
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        let response = kit
            .router
            .clone()
            .oneshot(builder.body(axum::body::Body::empty()).expect("request"))
            .await
            .expect("router answers");
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, 1024 * 1024).await.expect("body");
        Reply {
            status: parts.status,
            location: parts
                .headers
                .get(header::LOCATION)
                .map(|value| value.to_str().unwrap().to_owned())
                .unwrap_or_default(),
            body: String::from_utf8(bytes.to_vec()).expect("utf-8"),
        }
    }

    /// A signed-in session cookie for the fixed test operator, minted by
    /// the kit's own signer — the same cookie the console's guard reads.
    fn cookie(kit: &TestHarness) -> String {
        let token = issue_session(kit.signer.as_ref(), EMAIL, NOW, DEFAULT_TTL_SECS);
        format!("cf_session={token}")
    }

    /// A harness with the dashboard module, an account, and one venture
    /// (`my-app`, module set `cms+waitlist`), already through provisioning
    /// to `status`.
    async fn seeded(status: VentureStatus) -> TestHarness {
        let kit = TestHarness::new(vec![Box::new(Dashboard)]);
        let repo = Repository::new(kit.db.clone());
        repo.account_for_login(EMAIL, "Op", "acc_1", "t0")
            .await
            .expect("account");
        repo.create_venture(
            "v1",
            "acc_1",
            "my-app",
            "my-app.cratefield.app",
            "cms+waitlist",
            "ten_1",
            "t0",
        )
        .await
        .expect("venture");
        if status != VentureStatus::Draft {
            repo.set_venture_status("acc_1", "v1", VentureStatus::Provisioning, "t1")
                .await
                .expect("provisioning");
            if status != VentureStatus::Provisioning {
                repo.set_venture_status("acc_1", "v1", status, "t2")
                    .await
                    .expect("status");
            }
        }
        kit
    }

    /// Records a provisioning failure against the venture, exactly the row
    /// the provisioning engine writes (real schema, no invention).
    async fn record_failure(kit: &TestHarness, step: &str, error: &str) {
        kit.db
            .execute(&Statement::with_values(
                "INSERT INTO provision_progress (venture_id, last_step, error, updated_at) \
                 VALUES (?, ?, ?, ?)",
                vec![text("v1"), text(step), text(error), text("t2")],
            ))
            .await
            .expect("progress row");
    }

    #[pollster::test]
    async fn a_degraded_venture_reads_as_degraded_not_as_loading() {
        let kit = seeded(VentureStatus::Degraded).await;
        record_failure(&kit, "route", "workers.dev route could not be added").await;

        let reply = send(
            &kit,
            Method::GET,
            &format!("{BASE}/ventures/v1"),
            Some(&cookie(&kit)),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        assert!(reply.body.contains("DEGRADED"), "{}", reply.body);
        assert!(
            reply.body.contains("workers.dev route could not be added"),
            "the recorded failure must be shown: {}",
            reply.body
        );
        for lying_wording in ["loading", "Loading", "checking…", "No ventures"] {
            assert!(
                !reply.body.contains(lying_wording),
                "a degraded venture must never read as {lying_wording}: {}",
                reply.body
            );
        }

        let home = send(&kit, Method::GET, BASE, Some(&cookie(&kit))).await;
        assert!(home.body.contains("DEGRADED"), "{}", home.body);
        assert!(home.body.contains("my-app.cratefield.app"), "{}", home.body);
    }

    #[pollster::test]
    async fn a_live_venture_whose_health_check_fails_reads_as_failing() {
        let kit = TestHarness::with_ports(vec![Box::new(Dashboard)], |ports| {
            ports.http = Some(Arc::new(FakeHttpClient::scripted(vec![Err(
                cratefield_core::HttpError::Transport("connection refused".to_owned()),
            )])));
        });
        let repo = Repository::new(kit.db.clone());
        repo.account_for_login(EMAIL, "Op", "acc_1", "t0")
            .await
            .unwrap();
        repo.create_venture(
            "v1",
            "acc_1",
            "my-app",
            "my-app.cratefield.app",
            "cms",
            "ten",
            "t0",
        )
        .await
        .unwrap();
        repo.set_venture_status("acc_1", "v1", VentureStatus::Provisioning, "t1")
            .await
            .unwrap();
        repo.set_venture_status("acc_1", "v1", VentureStatus::Live, "t2")
            .await
            .unwrap();

        let reply = send(
            &kit,
            Method::GET,
            &format!("{BASE}/ventures/v1"),
            Some(&cookie(&kit)),
        )
        .await;
        assert!(
            reply.body.contains("FAILING /__health — unreachable")
                && reply.body.contains("connection refused"),
            "a failing health check must read as failing: {}",
            reply.body
        );
    }

    #[pollster::test]
    async fn a_live_venture_answering_health_reads_as_answering() {
        let kit = TestHarness::with_ports(vec![Box::new(Dashboard)], |ports| {
            ports.http = Some(Arc::new(FakeHttpClient::ok_json("{\"ok\":true}")));
        });
        let repo = Repository::new(kit.db.clone());
        repo.account_for_login(EMAIL, "Op", "acc_1", "t0")
            .await
            .unwrap();
        repo.create_venture(
            "v1",
            "acc_1",
            "my-app",
            "my-app.cratefield.app",
            "cms",
            "ten",
            "t0",
        )
        .await
        .unwrap();
        repo.set_venture_status("acc_1", "v1", VentureStatus::Provisioning, "t1")
            .await
            .unwrap();
        repo.set_venture_status("acc_1", "v1", VentureStatus::Live, "t2")
            .await
            .unwrap();

        let reply = send(
            &kit,
            Method::GET,
            &format!("{BASE}/ventures/v1"),
            Some(&cookie(&kit)),
        )
        .await;
        assert!(reply.body.contains("answering /__health"), "{}", reply.body);
    }

    #[pollster::test]
    async fn a_draft_venture_is_reported_not_running_and_never_fetched() {
        let kit = TestHarness::with_ports(vec![Box::new(Dashboard)], |ports| {
            ports.http = Some(Arc::new(FakeHttpClient::scripted(vec![])));
        });
        let repo = Repository::new(kit.db.clone());
        repo.account_for_login(EMAIL, "Op", "acc_1", "t0")
            .await
            .unwrap();
        repo.create_venture(
            "v1",
            "acc_1",
            "my-app",
            "my-app.cratefield.app",
            "cms",
            "ten",
            "t0",
        )
        .await
        .unwrap();

        let reply = send(
            &kit,
            Method::GET,
            &format!("{BASE}/ventures/v1"),
            Some(&cookie(&kit)),
        )
        .await;
        assert!(
            reply.body.contains("not running — /__health not checked"),
            "{}",
            reply.body
        );
    }

    #[pollster::test]
    async fn archiving_stops_a_venture_and_keeps_the_record() {
        let kit = seeded(VentureStatus::Live).await;
        let reply = send(
            &kit,
            Method::POST,
            &format!("{BASE}/ventures/v1/archive"),
            Some(&cookie(&kit)),
        )
        .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        assert_eq!(reply.location, format!("{BASE}/ventures/v1"));

        let repo = Repository::new(kit.db.clone());
        let venture = repo
            .venture_for("acc_1", "v1")
            .await
            .expect("read")
            .expect("kept");
        assert_eq!(
            venture.status,
            VentureStatus::Archived,
            "the record is kept"
        );

        let detail = send(
            &kit,
            Method::GET,
            &format!("{BASE}/ventures/v1"),
            Some(&cookie(&kit)),
        )
        .await;
        assert!(detail.body.contains("archived"), "{}", detail.body);
        assert!(detail.body.contains("record is kept"), "{}", detail.body);

        // Re-archiving is idempotent: the repository allows a same-status
        // move, and the venture stays archived.
        let again = send(
            &kit,
            Method::POST,
            &format!("{BASE}/ventures/v1/archive"),
            Some(&cookie(&kit)),
        )
        .await;
        assert_eq!(again.status, StatusCode::SEE_OTHER, "{}", again.body);
        let venture = repo
            .venture_for("acc_1", "v1")
            .await
            .expect("read")
            .expect("kept");
        assert_eq!(venture.status, VentureStatus::Archived);
    }

    #[pollster::test]
    async fn one_account_cannot_open_anothers_venture() {
        let kit = TestHarness::new(vec![Box::new(Dashboard)]);
        let repo = Repository::new(kit.db.clone());
        repo.account_for_login("a@x.co", "A", "acc_a", "t0")
            .await
            .unwrap();
        repo.create_venture(
            "v1",
            "acc_a",
            "a-app",
            "a.cratefield.app",
            "cms",
            "ten_a",
            "t0",
        )
        .await
        .unwrap();

        let token = issue_session(kit.signer.as_ref(), "b@x.co", NOW, DEFAULT_TTL_SECS);
        let stranger = format!("cf_session={token}");
        let reply = send(
            &kit,
            Method::GET,
            &format!("{BASE}/ventures/v1"),
            Some(&stranger),
        )
        .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{}", reply.body);
    }

    #[pollster::test]
    async fn an_unauthenticated_request_is_redirected_to_the_login_gate() {
        let kit = seeded(VentureStatus::Live).await;
        let reply = send(&kit, Method::GET, BASE, None).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        // The console owns the one login gate; the dashboard serves no
        // /login of its own, so redirecting under BASE would 404.
        assert_eq!(reply.location, "/v1/console/login");
    }

    #[pollster::test]
    async fn the_detail_page_names_what_it_does_not_know_instead_of_inventing() {
        let kit = seeded(VentureStatus::Live).await;
        let reply = send(
            &kit,
            Method::GET,
            &format!("{BASE}/ventures/v1"),
            Some(&cookie(&kit)),
        )
        .await;
        assert!(
            reply.body.contains("names and versions only, never values"),
            "{}",
            reply.body
        );
        assert!(reply.body.contains("no KMS wired"), "{}", reply.body);
        assert!(
            reply.body.contains("not recorded per venture yet"),
            "{}",
            reply.body
        );
    }
}
