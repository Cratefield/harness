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

// One file per account-level screen, built or not, so that building one
// is a change to one file: the route and the navigation entry below are
// already there, and `planned.rs` is what a screen renders until somebody
// replaces it. Six of these were being built at once from six worktrees,
// which is what a shared table of screens would have turned into six-way
// conflicts in the same twenty lines.
mod backups;
mod billing;
mod data;
mod deploys;
mod diagram;
mod domains;
mod environments;
mod logs;
mod planned;
/// The secrets manager screen.
pub(crate) mod secrets_screen;

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Form, Path, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use cratefield_accounts::{Repository, Venture, VentureStatus};
use cratefield_catalog::{Catalog, CatalogModule, Tier};
use cratefield_chrome::{NavItem, Page, escape, nav, render};
use cratefield_console::{LOGIN_PATH, current_session};
use cratefield_core::{
    Database, HttpPolicy, Migrations, Module, ModuleContext, PersonalDataSet, Port, SqlMigration,
    Statement, Surface, SurfaceDocument, View,
};
use http::{HeaderMap, StatusCode, header};
use time::format_description::well_known::Rfc3339;

/// Where the dashboard is mounted (`/v1/<name>`), so its own links resolve.
pub(crate) const BASE: &str = "/v1/dashboard";

/// What the dashboard will spend on one venture's `/__health`.
///
/// The port's own default is [`DEFAULT_RESPONSE_TIMEOUT`] — ten seconds —
/// which is a sensible default for an API call and an eternity inside a
/// page render. A health endpoint that has not answered in three seconds
/// is not healthy, and `FAILING /__health — unreachable` is the truthful
/// thing to render about it. Four KiB is far more than `/__health`
/// returns, and caps what a compromised venture can make the control
/// plane buffer.
///
/// The bound is enforced by `BoundedHttpClient`, which both runtimes wrap
/// `ports.http` in, through the `Clock` port. A caller may only tighten
/// the port's bounds, never loosen them.
///
/// [`DEFAULT_RESPONSE_TIMEOUT`]: cratefield_core::DEFAULT_RESPONSE_TIMEOUT
const HEALTH_POLICY: HttpPolicy = HttpPolicy {
    max_response_bytes: 4 * 1024,
    timeout: Duration::from_secs(3),
};

/// The same budget for the venture's UI contract, with room for the
/// document itself — a surface with a JSON Schema per action is bigger than
/// a health probe and still nothing like a megabyte.
const SURFACE_POLICY: HttpPolicy = HttpPolicy {
    max_response_bytes: 256 * 1024,
    timeout: Duration::from_secs(3),
};

/// The control-plane account dashboard.
///
/// Carries the key manager for the secrets screen, when the composition
/// wired one: `Some(kms)` on the dev server (a `LocalFileKms` under a
/// development key file), `None` on the Worker, where no KMS exists yet
/// and the secrets screen says so rather than failing. The KMS travels
/// here rather than through a port because it is not a port — a module
/// must never see it, and `ModuleContext` never carries one.
#[derive(Default)]
pub struct Dashboard {
    kms: Option<Arc<dyn cratefield_kms::Kms>>,
}

impl Dashboard {
    /// The dashboard with the key manager the secrets screen should use,
    /// or `None` where no KMS is wired and the screen degrades honestly.
    #[must_use]
    pub fn new(kms: Option<Arc<dyn cratefield_kms::Kms>>) -> Self {
        Self { kms }
    }
}

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

    /// The tables this module's `migrations()` create (issue #280): the
    /// connection metadata it owns, and the secrets store's own tables,
    /// which this module applies on the control database and therefore
    /// declares — see `migrations` below for why they are here and not
    /// in the console's set.
    fn tables(&self) -> &'static [&'static str] {
        &[
            "connection",
            "harness_secrets",
            "harness_secret_keys",
            "harness_secret_audit",
        ]
    }

    /// What this module holds about a person, per table. The secrets
    /// tables are judged `none` explicitly rather than inherited: a
    /// secret row is a venture's own credential keyed to a store and a
    /// name, not to a person, and the audit chain records actors that
    /// are operator identities in a field no `… = ?` predicate for a
    /// subject is honest about — the same call the dashboard already
    /// made for `connection`, restated where a person deciding whether
    /// to trust this product can read it.
    fn personal_data(&self) -> &'static [PersonalDataSet] {
        const SETS: &[PersonalDataSet] = &[
            PersonalDataSet::none(
                "connection",
                "What a backend has connected, and whether each connection is healthy: the \
                 connection kind, its state, why it is invalid if it is, a non-secret label \
                 such as a public OAuth client id, and when it last changed. It is keyed to \
                 the backend's tenant, holds no credential, and names nobody.",
            ),
            PersonalDataSet::none(
                "harness_secrets",
                "A venture's own credentials, envelope-encrypted: a name, a version, the \
                 ciphertext and its nonce, and when it was written. The value is never \
                 in the clear and the row is keyed to a store and a name, not to a \
                 person; an export that handed over ciphertexts would be handing over \
                 noise.",
            ),
            PersonalDataSet::none(
                "harness_secret_keys",
                "The wrapped data keys that protect each store's secrets, with the key \
                 ids, states and the KMS reference that wrapped them. No key material is \
                 in the clear and nothing in a row names a person.",
            ),
            PersonalDataSet::none(
                "harness_secret_audit",
                "The tamper-evident audit chain of every access to a store's secrets: \
                 the action, the store, the secret's name and version, and the actor — \
                 an operator identity or a venture's scope, recorded because an \
                 unaccountable access to a credential is worse than none. It holds no \
                 secret value by construction, and it is append-only, so a subject's \
                 \u{201c}right to be forgotten\u{201d} stops where the record of what \
                 this product did with their data begins.",
            ),
        ];
        SETS
    }

    fn migrations(&self) -> Migrations {
        // The dashboard owns exactly one table of its own: `connection`.
        // Everything else it renders — accounts, ventures, provisioning
        // progress — belongs to the console, which declares those
        // sub-schemas and writes the rows; the dashboard only reads
        // them.
        //
        // It declared them too, once, and that did not survive contact
        // with a running control plane. Two modules in one harness each
        // emitting the same DDL is two migration files, not one: `collect`
        // keys on `<module>/<id>`, so the console's `provision_progress`
        // and the dashboard's copy were both written out and both applied,
        // and the second `CREATE TABLE provision_progress` failed on a
        // fresh database. No test caught it because no test mounted two
        // modules together. Declaring only what this module owns is what
        // makes the composition apply.
        //
        // The secrets store's tables are the one exception to "only what
        // it owns", and the reason is the same as the console's: no
        // composition applies them anywhere, and the secrets screen is
        // this module's. They are re-id-ed sub-schemas of
        // `cratefield_secrets`'s own sets (shared constants, not a second
        // copy of the SQL that could drift), applied here under ids that
        // cannot collide with anything else's.
        const MIGRATIONS: [SqlMigration; 5] = [
            if cratefield_connections::MIGRATION.transactional {
                SqlMigration::new("0001", "connections", cratefield_connections::MIGRATION.sql)
            } else {
                SqlMigration::new("0001", "connections", cratefield_connections::MIGRATION.sql)
                    .non_transactional()
            },
            secrets_sub_migration(0, "0002", "secrets-init"),
            secrets_sub_migration(1, "0003", "secrets-audit"),
            secrets_sub_migration(2, "0004", "secrets-audit-store"),
            secrets_sub_migration(3, "0005", "secrets-store-attribution"),
        ];
        // The array is the apply order; this refuses a gap, a duplicate
        // or an entry out of order at build time (issue #27).
        const _: () = cratefield_core::assert_migration_set(&MIGRATIONS);
        // The secrets tables are not portable SQL (BLOB vs BYTEA, and
        // the append-only trigger differs per engine), so the postgres
        // set ships alongside the sqlite one exactly as the secrets
        // crate ships both — re-id-ed the same way.
        const POSTGRES_SET: [SqlMigration; 5] = [
            if cratefield_connections::MIGRATION.transactional {
                SqlMigration::new("0001", "connections", cratefield_connections::MIGRATION.sql)
            } else {
                SqlMigration::new("0001", "connections", cratefield_connections::MIGRATION.sql)
                    .non_transactional()
            },
            secrets_sub_migration_pg(0, "0002", "secrets-init"),
            secrets_sub_migration_pg(1, "0003", "secrets-audit"),
            secrets_sub_migration_pg(2, "0004", "secrets-audit-store"),
            secrets_sub_migration_pg(3, "0005", "secrets-store-attribution"),
        ];
        const _: () = cratefield_core::assert_migration_set(&POSTGRES_SET);
        Migrations {
            sqlite: &MIGRATIONS,
            postgres: &POSTGRES_SET,
        }
    }

    fn validate_config(
        &self,
        cfg: &dyn cratefield_core::Config,
    ) -> Result<(), cratefield_core::ConfigError> {
        let mut errors = cratefield_core::ConfigError::new();
        // The development KEK file (DASHBOARD_DEV_KEK, read by the dev
        // server to wire `LocalFileKms`) may never be set in production,
        // exactly as the console treats `CONSOLE_DEV_LOGIN`: a key file
        // a stray environment variable can switch on would wrap every
        // secret this deployment ever stores under a key nobody has to
        // account for — the one mistake here that cannot be walked
        // back. `LocalFileKms::open` refuses on its own too; this is
        // the composition-level gate.
        let dev_kek = cratefield_core::ModuleConfig::new("dashboard", cfg).get_str("DEV_KEK", "");
        let production = cfg.get("ENV").as_deref() == Some("production");
        if !dev_kek.is_empty() && production {
            errors.push("DASHBOARD_DEV_KEK must never be set in production");
        }
        errors.into_result()
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let state = Arc::new(DashboardState {
            ctx: Arc::new(ctx),
            kms: self.kms.clone(),
        });
        axum::Router::new()
            .route("/", get(ventures))
            .route("/ventures/{id}", get(venture_detail))
            .route("/ventures/{id}/archive", post(archive))
            .route("/ventures/{id}/modules", post(set_modules))
            .route("/ventures/{id}/reprovision", post(reprovision))
            // The data browser (#28, read-only half): schema visualiser,
            // table detail, CSV export.
            .route("/data", get(data::screen))
            .route("/data/{table}", get(data::detail))
            .route("/data/{table}/export", get(data::export))
            // The secrets manager: account-level, so it sits beside the
            // venture screens rather than under one.
            .route("/secrets", get(secrets_screen::stores))
            .route("/secrets/{store}", get(secrets_screen::store_detail))
            .route("/secrets/{store}/put", post(secrets_screen::put_secret))
            .route(
                "/secrets/{store}/delete",
                post(secrets_screen::delete_secret),
            )
            .route("/secrets/{store}/rotate", post(secrets_screen::rotate))
            .route("/secrets/{store}/rewrap", post(secrets_screen::rewrap))
            // One route per screen, named. A catch-all over a table of
            // slugs was shorter, but it made "is this screen built yet"
            // a property of a table entry rather than of the file that
            // renders it, and every screen being built at once then
            // edits that one table.
            .route("/deploys", get(deploys::screen))
            .route("/logs", get(logs::screen))
            .route("/domains", get(domains::screen))
            .route("/backups", get(backups::screen))
            .route("/environments", get(environments::screen))
            .route("/billing", get(billing::screen))
            .with_state(state)
    }
}

/// One of the secrets store's migrations, re-id-ed into this module's
/// set. A const fn over the shared constants so the array
/// `assert_migration_set` checks is built from the same bytes the
/// secrets crate ships, not a second copy that could drift.
const fn secrets_sub_migration(index: usize, id: &'static str, name: &'static str) -> SqlMigration {
    sub_migration(&cratefield_secrets::SQLITE_MIGRATIONS, index, id, name)
}

/// The postgres twin of [`secrets_sub_migration`].
const fn secrets_sub_migration_pg(
    index: usize,
    id: &'static str,
    name: &'static str,
) -> SqlMigration {
    sub_migration(&cratefield_secrets::POSTGRES_MIGRATIONS, index, id, name)
}

const fn sub_migration(
    set: &'static [SqlMigration],
    index: usize,
    id: &'static str,
    name: &'static str,
) -> SqlMigration {
    let source = &set[index];
    if source.transactional {
        SqlMigration::new(id, name, source.sql)
    } else {
        SqlMigration::new(id, name, source.sql).non_transactional()
    }
}

pub(crate) struct DashboardState {
    pub(crate) ctx: Arc<ModuleContext>,
    /// The key manager the secrets screen opens stores through, when the
    /// composition wired one. `None` is a representable state, not an
    /// `expect`: the Worker composition carries it today.
    pub(crate) kms: Option<Arc<dyn cratefield_kms::Kms>>,
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
pub(crate) fn guard(ctx: &ModuleContext, headers: &HeaderMap) -> Result<(), Response> {
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
pub(crate) async fn account_of(
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
        .extension(HEALTH_POLICY)
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
// The venture's own screens, read from the contract it publishes
// ---------------------------------------------------------------------------

/// Fetches a venture's `/__surface`.
///
/// The screens a venture has are **not** something this dashboard should
/// know: they are whatever its module set declares, and the harness already
/// publishes that as a contract — `GET /__surface`, whose own documentation
/// names the control plane as a consumer. Reading it means adding a module
/// to a venture makes its screens appear here with no change to this crate,
/// which is the difference between a list that is generated and a list that
/// is maintained (and therefore, eventually, wrong).
///
/// What comes back is the **public subset**: the admin variant needs
/// `Authorization: Bearer <ADMIN_TOKEN>`, and the control plane has no way
/// to hold a venture's admin token until the secrets store is wired. The
/// screen says that rather than implying it has seen everything.
async fn surface_of(ctx: &ModuleContext, venture: &Venture) -> Result<SurfaceDocument, String> {
    if !matches!(
        venture.status,
        VentureStatus::Live | VentureStatus::Degraded
    ) {
        return Err(String::from("not running — nothing is serving a contract"));
    }
    let http = ctx
        .ports
        .http
        .as_deref()
        .ok_or_else(|| String::from("http port unavailable"))?;
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri(format!("https://{}/__surface", venture.subdomain))
        .header(header::USER_AGENT, "cratefield-dashboard")
        .header(header::ACCEPT, "application/json")
        .extension(SURFACE_POLICY)
        .body(bytes::Bytes::new())
        .map_err(|err| err.to_string())?;
    let response = http.send(request).await.map_err(|err| err.to_string())?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status().as_u16()));
    }
    serde_json::from_slice(response.body()).map_err(|err| format!("unreadable contract: {err}"))
}

/// Renders the screens a venture's modules bring.
///
/// Every row here is generated from the contract. Nothing about `cms` or
/// `waitlist` is written down in this file.
#[allow(clippy::format_push_string)] // the house idiom for HTML building
fn render_screens(doc: &SurfaceDocument, venture: &Venture) -> String {
    if doc.modules.is_empty() {
        return String::from(
            "<p class=\"dash__note\">The venture answered, and its contract declares no \
             screens at all. Every module it carries is API-only.</p>",
        );
    }
    let base = if doc.venture.public_url.is_empty() {
        format!("https://{}", venture.subdomain)
    } else {
        doc.venture.public_url.trim_end_matches('/').to_owned()
    };

    let mut out = String::new();
    for module in &doc.modules {
        let rows = render_module_screens(&base, &module.name, &module.surface);
        out.push_str(&format!(
            "<p class=\"dash__card-h\" style=\"margin-top:18px\">{name} \
             <span class=\"dash__tag\">{n} screen{s}</span></p>{rows}",
            name = escape(&module.name),
            n = module.surface.views.len(),
            s = if module.surface.views.len() == 1 {
                ""
            } else {
                "s"
            },
        ));
    }
    out.push_str(
        "<p class=\"dash__note\">These are the screens the venture's own contract \
         declares, fetched from its <code>/__surface</code> while this page rendered — \
         not a list kept in the dashboard. Adding a module to the set above makes its \
         screens appear here.</p>\
         <p class=\"dash__note\">This is the <strong>public</strong> subset. A module's \
         admin screens are served only against its admin token, and the control plane has \
         nowhere to hold one until the secrets store is wired, so it cannot ask for them \
         and does not pretend to have.</p>",
    );
    out
}

#[allow(clippy::format_push_string)] // the house idiom for HTML building
fn render_module_screens(base: &str, module: &str, surface: &Surface) -> String {
    if surface.views.is_empty() {
        return String::from("<p class=\"dash__note\">No screens: this module is API-only.</p>");
    }
    let mut rows = String::from("<div class=\"dash__list\">");
    for view in &surface.views {
        let (kind, action, detail) = match view {
            View::Form { action } => ("form", action.as_str(), String::new()),
            View::Status { action } => ("status", action.as_str(), String::new()),
            View::Table { source, columns } => (
                "table",
                source.as_str(),
                columns
                    .iter()
                    .map(|column| column.label.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        };
        // What the action actually is, from the same document: the method
        // it answers and who it is for.
        let declared = surface
            .actions
            .iter()
            .find(|candidate| candidate.name == action);
        let audience = declared.map_or("—", |declared| match declared.audience {
            cratefield_core::Audience::Public => "public",
            cratefield_core::Audience::Admin => "admin",
            cratefield_core::Audience::Link => "signed link",
        });
        rows.push_str(&format!(
            "<div class=\"dash__lrow dash__lrow--screens\">\
             <span><a href=\"{base}/ui/{module}/{action}\" rel=\"noopener\">{action}</a></span>\
             <span><em>{kind}</em></span>\
             <span>{audience}</span>\
             <span>{detail}</span></div>",
            base = escape(base),
            module = escape(module),
            action = escape(action),
            audience = escape(audience),
            detail = escape(&detail),
        ));
    }
    rows.push_str("</div>");
    rows
}

// ---------------------------------------------------------------------------
// Reads over the schema the domain crates own
// ---------------------------------------------------------------------------

/// The venture's provisioning progress: the last step that completed, and
/// the recorded failure, if the run stopped. Read straight from
/// `provision_progress`, which the provisioning engine owns.
#[derive(Debug)]
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
        // `last_step` is the last step that *completed*, so it is empty
        // when the very first step failed — which is the common case with
        // no deployer wired. "failed after step `` " is not a sentence.
        let after = if progress.last_step.is_empty() {
            String::from("on its first step")
        } else {
            format!("after <code>{}</code>", escape(&progress.last_step))
        };
        return format!(
            "<p class=\"dash__row\"><span class=\"dash__dot dash__dot--bad\"></span>\
             <strong>Provisioning stopped</strong> {after}</p>\
             <p class=\"dash__note\">{error}</p>\
             <p class=\"dash__note\">Recorded {when}. The run is resumable: it will \
             continue from the step after the last one that completed.</p>",
            error = escape(&progress.error),
            when = escape(&progress.updated_at),
        );
    }
    if progress.last_step.is_empty() {
        return String::from(
            "<p class=\"dash__note\">No provisioning has run for this venture yet.</p>",
        );
    }
    format!(
        "<p class=\"dash__row\"><span class=\"dash__dot dash__dot--live\"></span>\
         Last completed step <code>{}</code><span class=\"dash__meta\">{}</span></p>",
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

    // One fan-out, not a queue. The verdicts are independent, so awaiting
    // them one after another made the page cost the SUM of every
    // venture's timeout: ten unreachable ventures at the port's old
    // ten-second default was a hundred seconds of blank page. Polled
    // together, the page costs the slowest single check.
    //
    // `join_all` is cooperative concurrency in this one task, not spawned
    // work — which is the only kind available on the Workers runtime,
    // where these futures are `!Send`.
    let verdicts =
        futures_util::future::join_all(ventures.iter().map(|venture| check_health(ctx, venture)))
            .await;

    let mut rows = String::from(
        "<div class=\"dash__lrow dash__lrow--head\"><span>Venture</span>\
         <span>Subdomain</span><span>Status</span><span>Health</span></div>",
    );
    if ventures.is_empty() {
        rows.push_str(
            "<p class=\"dash__empty\">No ventures yet. \
             <a href=\"/v1/console/new\">Create one in the console.</a></p>",
        );
    } else {
        for (venture, health) in ventures.iter().zip(verdicts) {
            rows.push_str(&format!(
                "<div class=\"dash__lrow\">\
                 <span><a href=\"{BASE}/ventures/{id}\">{slug}</a></span>\
                 <span><em>{subdomain}</em></span>\
                 <span>{status}</span>\
                 <span>{dot}{health}</span></div>",
                id = escape(&venture.id),
                slug = escape(&venture.slug),
                subdomain = escape(&venture.subdomain),
                status = status_chip(venture.status),
                dot = health_dot(&health),
                health = escape(&health.label()),
            ));
        }
    }

    let live = ventures
        .iter()
        .filter(|v| v.status == VentureStatus::Live)
        .count();
    let degraded = ventures
        .iter()
        .filter(|v| v.status == VentureStatus::Degraded)
        .count();
    let alert = if degraded > 0 {
        format!(
            "<p class=\"dash__banner dash__banner--bad\">\
             <strong>{degraded}</strong> of your ventures {is} degraded: provisioned once, \
             now failing. Open {it} to see the step that stopped and the message it \
             recorded.</p>",
            is = if degraded == 1 { "is" } else { "are" },
            it = if degraded == 1 { "it" } else { "them" },
        )
    } else {
        String::new()
    };

    let body = format!(
        "{alert}<div class=\"dash__list\">{rows}</div>\
         <p class=\"dash__note\">Every health verdict on this page is a real request to \
         the venture's <code>/__health</code>, made while the page rendered, with a three \
         second budget. There is no \u{201c}checking\u{201d} state: a venture that is not \
         answering says so.</p>",
    );

    let nav_html = account_nav("ventures");

    let crumb = format!(
        "{total} venture{s} · {live} live · {degraded} degraded",
        total = ventures.len(),
        s = if ventures.len() == 1 { "" } else { "s" },
    );

    Html(render(&Page {
        title: "Ventures",
        signed_in_as: Some(&session.account_id),
        body: &format!(
            "<div class=\"page-h\"><h1>Your ventures</h1></div>\
             <p class=\"lede\">Every backend this account owns, what it is doing, and \
             whether it is answering.</p>{}",
            frame(&nav_html, &crumb, &body)
        ),
    }))
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
    // Both are real requests to the venture; polled together, so the page
    // costs the slower one rather than their sum.
    let (health, surface) =
        futures_util::future::join(check_health(ctx, &venture), surface_of(ctx, &venture)).await;

    Html(render_detail(
        &venture,
        &session.account_id,
        &progress,
        &connections,
        &health,
        surface.as_ref(),
    ))
    .into_response()
}

/// The venture page itself. Separated from the handler so the reads and
/// the rendering can be read one at a time.
#[allow(clippy::too_many_lines)]
fn render_detail(
    venture: &Venture,
    identity: &str,
    progress: &Progress,
    connections: &[ConnectionRow],
    health: &HealthVerdict,
    surface: Result<&SurfaceDocument, &String>,
) -> String {
    let catalog = cratefield_catalog::curated();
    let on_count = venture
        .module_set
        .split('+')
        .filter(|slug| !slug.is_empty())
        .count();
    // A venture sitting in `Provisioning` with a recorded failure is not a
    // run in flight — it is a run that stopped. Treating the two the same
    // locks the module set behind the very failure the operator came here
    // to fix.
    let stopped = !progress.error.is_empty();
    let editable = match venture.status {
        VentureStatus::Archived => false,
        VentureStatus::Provisioning => stopped,
        _ => true,
    };

    let overview = card(
        "Overview",
        None,
        &format!(
            "<dl class=\"kv\">\
             <div><dt>Status</dt><dd>{status}</dd></div>\
             <div><dt>Subdomain</dt><dd><em>{subdomain}</em></dd></div>\
             <div><dt>Health</dt><dd>{dot}{health}</dd></div>\
             <div><dt>Tenant</dt><dd><code>{tenant}</code></dd></div>\
             </dl>",
            status = status_chip(venture.status),
            subdomain = escape(&venture.subdomain),
            dot = health_dot(health),
            health = escape(&health.label()),
            tenant = escape(&venture.tenant_id),
        ),
        false,
    );

    let degraded_banner = if venture.status == VentureStatus::Degraded {
        "<p class=\"dash__banner dash__banner--bad\"><strong>DEGRADED</strong> — this venture \
         provisioned once and is now failing. The step that stopped and the message it \
         recorded are below; nothing here is a guess.</p>"
    } else {
        ""
    };

    let module_tag = format!("{} of {}", on_count, catalog.modules.len());
    let modules_card = card(
        "Modules",
        Some(&module_tag),
        &render_modules(&catalog, venture, editable),
        true,
    );
    let screens_card = card(
        "Screens",
        surface
            .ok()
            .map(|doc| {
                let n: usize = doc.modules.iter().map(|m| m.surface.views.len()).sum();
                format!("{n}")
            })
            .as_deref(),
        &match surface {
            Ok(doc) => render_screens(doc, venture),
            Err(why) => format!(
                "<p class=\"dash__note\">The venture's contract could not be read: \
                 {why}.</p>\
                 <p class=\"dash__note\">Its screens are whatever its modules declare at \
                 <code>/__surface</code>, and that is read from the venture itself rather \
                 than kept here — so until it answers, this screen has nothing truthful \
                 to list and will not guess from the module names.</p>",
                why = escape(why),
            ),
        },
        true,
    );
    let connections_card = card(
        "Connections",
        Some(&connections.len().to_string()),
        &render_connections(connections),
        true,
    );
    let actions = actions_row(venture, stopped);

    let body = format!(
        "{degraded_banner}\
         <div class=\"dash__grid\">{overview}{provisioning}{modules}{screens}\
         {connections}{secrets}{audit}</div>{actions}",
        overview = overview,
        provisioning = card("Provisioning", None, &render_progress(progress), false),
        modules = modules_card,
        screens = screens_card,
        connections = connections_card,
        secrets = card(
            "Secrets",
            None,
            "<p class=\"dash__note\">Secrets are shown as names and versions only, never \
             values. No secret names are listed here yet: the control plane has no KMS \
             wired — that wiring belongs to the live deploy pipeline — so this screen \
             would have nothing truthful to list. It will not invent one.</p>",
            false,
        ),
        audit = card(
            "Audit trail",
            None,
            "<p class=\"dash__note\">Who touched what is not recorded per venture yet. The \
             only audit table today is the console's allowlist audit, which is \
             account-level, and the secrets log is tracing-only. This screen shows no \
             audit rows rather than made-up ones.</p>",
            false,
        ),
        actions = actions,
    );

    // The planned screens are real pages now, so they are links rather
    // than dim words: each says what it will do and what to do today.
    let here = format!("{BASE}/ventures/{}", venture.id);
    let paths: Vec<String> = SCREENS
        .iter()
        .map(|(slug, _)| format!("{BASE}/{slug}"))
        .collect();
    let mut items = vec![
        NavItem::to("Ventures", BASE),
        NavItem::here("Overview", &here),
    ];
    for ((_, title), path) in SCREENS.iter().zip(&paths) {
        items.push(NavItem::to(title, path));
    }
    let nav_html = nav(&items);

    let shell = format!(
        "<p class=\"crumb\"><a href=\"{BASE}\">Ventures</a> / {slug}</p>\
         <div class=\"page-h\"><h1>{slug}</h1>{status}</div>\
         <p class=\"lede\">One backend: what it carries, how it got there, and what \
         this screen does not know.</p>{frame}",
        slug = escape(&venture.slug),
        status = status_chip(venture.status),
        frame = frame(&nav_html, "Overview", &body),
    );

    render(&Page {
        title: &venture.slug,
        signed_in_as: Some(identity),
        body: &shell,
    })
}

/// The row of things this screen can actually do to a venture: retry a
/// stopped provisioning run, and archive it. One row, so they read as the
/// two choices they are rather than as two unrelated widgets.
fn actions_row(venture: &Venture, stopped: bool) -> String {
    if venture.status == VentureStatus::Archived {
        return String::from(
            "<p class=\"dash__note\">This venture is archived and its record is kept. \
             Archived is terminal: there is no route back to live.</p>",
        );
    }
    let retry = if stopped {
        format!(
            "<form method=\"post\" action=\"{BASE}/ventures/{id}/reprovision\">\
             <button class=\"btn\" type=\"submit\">Retry provisioning</button></form>",
            id = escape(&venture.id),
        )
    } else {
        String::new()
    };
    format!(
        "<div class=\"dash__act\">{retry}\
         <form method=\"post\" action=\"{BASE}/ventures/{id}/archive\">\
         <button class=\"btn\" type=\"submit\">Archive</button></form></div>\
         <p class=\"dash__note\">Archiving stops the venture and keeps the record. It does \
         not yet shred the venture's keys before dropping its database — that is the \
         offboarding path, and it is not wired.</p>",
        id = escape(&venture.id),
    )
}

/// The module set, as the catalogue rather than as the stored string.
///
/// The venture carries a `module_set` — `"cms+waitlist"` — which is a
/// content key, not a list a person can act on. This renders the whole
/// catalogue with the venture's own set ticked, so what is *available* is
/// as visible as what is on, which is the difference between a screen that
/// reports and a screen you can use.
#[allow(clippy::format_push_string)] // the house idiom for HTML building
fn render_modules(catalog: &Catalog, venture: &Venture, editable: bool) -> String {
    let on: Vec<&str> = venture
        .module_set
        .split('+')
        .filter(|s| !s.is_empty())
        .collect();

    let mut items = String::from("<div class=\"mods\">");
    for module in &catalog.modules {
        items.push_str(&render_module(
            module,
            on.contains(&module.slug.as_str()),
            editable,
        ));
    }
    // A venture can carry a module the catalogue no longer offers — a
    // private module, or one withdrawn since. Saying so beats quietly
    // dropping it from a list the operator is about to submit.
    for slug in &on {
        if !catalog.modules.iter().any(|m| m.slug == **slug) {
            items.push_str(&format!(
                "<label class=\"mod mod--on\"><input type=\"checkbox\" name=\"module\" \
                 value=\"{slug}\" checked{disabled}><span>\
                 <span class=\"mod__name\"><code>{slug}</code> \
                 <span class=\"chip\">not in the catalogue</span></span>\
                 <span class=\"mod__sum\">This venture carries it, and the curated \
                 catalogue does not offer it. Unticking it removes it.</span></span></label>",
                slug = escape(slug),
                disabled = if editable { "" } else { " disabled" },
            ));
        }
    }
    items.push_str("</div>");

    if !editable {
        let why = if venture.status == VentureStatus::Archived {
            "This venture is archived, so its module set is fixed."
        } else {
            "A provisioning run is in flight. The set cannot change under a run that is \
             already building an artifact from it."
        };
        return format!("{items}<p class=\"dash__note\">{why}</p>");
    }

    format!(
        "<form method=\"post\" action=\"{BASE}/ventures/{id}/modules\">{items}\
         <div class=\"dash__act\">\
         <button class=\"btn btn--primary\" type=\"submit\">Save and re-provision</button>\
         <span class=\"dash__note\">The deployed artifact is a function of this set, so \
         changing it re-provisions through the engine rather than editing a column. The \
         run starts again at the first step, because a cached artifact built from the old \
         set is the wrong artifact.</span></div></form>",
        id = escape(&venture.id),
    )
}

fn render_module(module: &CatalogModule, on: bool, editable: bool) -> String {
    let core = module.tier == Tier::Core;
    // A disabled checkbox submits nothing, so a core module needs a hidden
    // field or saving would silently remove it.
    let keep = if core && on {
        format!(
            "<input type=\"hidden\" name=\"module\" value=\"{}\">",
            escape(&module.slug)
        )
    } else {
        String::new()
    };
    let deps = if module.depends_on.is_empty() {
        String::new()
    } else {
        format!(
            "<span class=\"chip\">needs {}</span>",
            escape(&module.depends_on.join(", "))
        )
    };
    format!(
        "<label class=\"mod{on_class}{core_class}\">{keep}\
         <input type=\"checkbox\" name=\"module\" value=\"{slug}\"{checked}{disabled}>\
         <span><span class=\"mod__name\">{name} <code>{slug}</code>{core_chip}{deps}</span>\
         <span class=\"mod__sum\">{summary}</span></span></label>",
        on_class = if on { " mod--on" } else { "" },
        core_class = if core { " mod--core" } else { "" },
        slug = escape(&module.slug),
        name = escape(&module.name),
        summary = escape(&module.summary),
        checked = if on { " checked" } else { "" },
        disabled = if core || !editable { " disabled" } else { "" },
        core_chip = if core {
            "<span class=\"chip\">always on</span>"
        } else {
            ""
        },
        deps = deps,
    )
}

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

/// Changes a venture's module set, and re-provisions it (issue #11 §2).
///
/// The deployed artifact is a **function of the module set** (ADR 0009), so
/// writing a new set into the column and stopping there would leave the
/// database claiming a venture carries a module its running Worker has
/// never heard of. The set is therefore resolved through the catalogue,
/// recorded, and then the provisioning engine is run.
///
/// Two things that are easy to get wrong and are not:
///
/// 1. **The recorded progress is cleared first.** `Engine::provision`
///    resumes from the step after the last one that completed, so a `Live`
///    venture — every step done — would be marked live again without
///    rebuilding anything. A module change invalidates the artifact, so the
///    run has to start at the first step.
/// 2. **The engine runs for real.** There is no [`Unwired`] deployer's
///    worth of pretending: the first step fails, the failure is recorded
///    against the venture with its reason, and the screen shows it. The day
///    a real deployer is passed here instead, nothing else changes.
///
/// [`Unwired`]: cratefield_provisioning::Unwired
async fn set_modules(
    State(state): State<Arc<DashboardState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<Vec<(String, String)>>,
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
    let stopped = match progress_of(db.as_ref(), &venture.id).await {
        Ok(progress) => !progress.error.is_empty(),
        Err(err) => {
            tracing::error!(error = %err, "progress read failed");
            return internal("could not read the provisioning progress");
        }
    };
    let editable = match venture.status {
        VentureStatus::Archived => false,
        // A stopped run is not a run in flight; see `venture_detail`.
        VentureStatus::Provisioning => stopped,
        _ => true,
    };
    if !editable {
        return (
            StatusCode::CONFLICT,
            "the module set cannot change while the venture is archived or a provisioning \
             run is in flight",
        )
            .into_response();
    }

    let chosen: Vec<String> = form
        .into_iter()
        .filter(|(field, _)| field == "module")
        .map(|(_, slug)| slug)
        .collect();

    // The catalogue resolves: it orders dependencies before dependants and
    // refuses a slug it does not offer, so a hand-made POST cannot put an
    // unknown module into a venture's set.
    let catalog = cratefield_catalog::curated();
    let chosen: Vec<&str> = chosen.iter().map(String::as_str).collect();
    let resolved = match catalog.resolve(&chosen) {
        Ok(set) => set,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };
    let module_set = resolved.slugs().join("+");

    // Compare the *sets*, not the strings. `resolve` orders dependencies
    // before dependants and is otherwise order-preserving, so ticking the
    // same modules in a different order yields a different content key for
    // the same selection — and comparing strings would tear down a working
    // venture to rebuild the artifact it already has.
    if same_set(&module_set, &venture.module_set) {
        return Redirect::to(&format!("{BASE}/ventures/{}", venture.id)).into_response();
    }

    let now = now_rfc3339(ctx);
    if let Err(err) = repo
        .set_venture_modules(&account.id, &venture.id, &module_set, &now)
        .await
    {
        tracing::error!(error = %err, "module set write failed");
        return internal("could not record the module set");
    }

    // See (1) above: the artifact is a function of the set, so a cached one
    // built from the old set is the wrong artifact and the run must not
    // resume past the step that builds it.
    if let Err(err) = db
        .execute(&Statement::with_values(
            "DELETE FROM provision_progress WHERE venture_id = ?",
            vec![text(&venture.id)],
        ))
        .await
    {
        tracing::error!(error = %err, "could not clear the provisioning progress");
        return internal("could not reset the provisioning progress");
    }

    let venture = Venture {
        module_set: module_set.clone(),
        ..venture
    };
    let engine = cratefield_provisioning::Engine::new(db);
    match engine
        .provision(&venture, &cratefield_provisioning::Unwired, &now)
        .await
    {
        Ok(_) | Err(cratefield_provisioning::ProvisionError::Step { .. }) => {
            // A step failure is a recorded, visible outcome, not a 500: the
            // engine wrote the step and the message against the venture and
            // the detail page renders them. Sending the operator to that
            // page is the answer.
            Redirect::to(&format!("{BASE}/ventures/{}", venture.id)).into_response()
        }
        Err(err) => {
            tracing::error!(error = %err, "re-provisioning failed before it could run");
            internal("could not start re-provisioning")
        }
    }
}

/// Resumes a stopped provisioning run (issue #11 §2).
///
/// Unlike [`set_modules`] this changes nothing about the venture: the
/// engine picks up from the step after the last one that completed, which
/// is exactly what its own documentation promises a retry does. With no
/// deployer wired it stops again in the same place, and the recorded reason
/// is refreshed rather than duplicated.
async fn reprovision(
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
    if venture.status == VentureStatus::Archived {
        return (
            StatusCode::CONFLICT,
            "an archived venture is not provisioned again",
        )
            .into_response();
    }

    let now = now_rfc3339(ctx);
    let engine = cratefield_provisioning::Engine::new(db);
    match engine
        .provision(&venture, &cratefield_provisioning::Unwired, &now)
        .await
    {
        Ok(_) | Err(cratefield_provisioning::ProvisionError::Step { .. }) => {
            Redirect::to(&format!("{BASE}/ventures/{}", venture.id)).into_response()
        }
        Err(err) => {
            tracing::error!(error = %err, "re-provisioning failed before it could run");
            internal("could not start re-provisioning")
        }
    }
}

// ---------------------------------------------------------------------------
// The screens the design has and the product does not
// ---------------------------------------------------------------------------

/// One screen the dashboard will have and does not yet.
///
/// Every account-level screen, in the order the navigation shows them.
///
/// The order is the only thing this table decides. What a screen renders,
/// and whether it is built at all, belongs to that screen's own file —
/// see [`planned`] for why.
const SCREENS: [(&str, &str); 8] = [
    ("data", "Data browser"),
    ("secrets", "Secrets"),
    ("deploys", "Deploys"),
    ("logs", "Logs"),
    ("domains", "Domains"),
    ("backups", "Backups"),
    ("environments", "Environments"),
    ("billing", "Billing"),
];

/// The navigation shared by every account-level screen, so the same list is
/// in the same order wherever you are.
pub(crate) fn account_nav(current: &str) -> String {
    // Leaked into a `String` would be a leak per render; these paths are
    // built once and borrowed for the life of the call, like the
    // planned-screen paths below.
    let mut items = vec![
        if current == "ventures" {
            NavItem::here("Ventures", BASE)
        } else {
            NavItem::to("Ventures", BASE)
        },
        NavItem::to("New venture", "/v1/console/new"),
    ];
    // Leaked into a `String` would be a leak per request; these paths are
    // built once per render and borrowed for the life of the call.
    let paths: Vec<String> = SCREENS
        .iter()
        .map(|(slug, _)| format!("{BASE}/{slug}"))
        .collect();
    for ((slug, title), path) in SCREENS.iter().zip(&paths) {
        items.push(if current == *slug {
            NavItem::here(title, path)
        } else {
            NavItem::to(title, path)
        });
    }
    nav(&items)
}

/// Whether two module-set content keys name the same selection.
///
/// A key is `"a+b+c"`, ordered so a module's dependencies precede it. Two
/// keys with the same members in a different order describe the same
/// venture, and the artifact built from either carries the same modules.
fn same_set(left: &str, right: &str) -> bool {
    let members = |key: &str| {
        let mut parts: Vec<String> = key
            .split('+')
            .filter(|slug| !slug.is_empty())
            .map(str::to_owned)
            .collect();
        parts.sort_unstable();
        parts.dedup();
        parts
    };
    members(left) == members(right)
}

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

pub(crate) fn internal(detail: &str) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, detail.to_owned()).into_response()
}

// ---------------------------------------------------------------------------
// Chrome: the frame every screen renders inside
// ---------------------------------------------------------------------------

/// The status chip: the one place a lifecycle status becomes a colour.
/// `Degraded` is the only one that shouts, because it is the only one the
/// operator has to do something about.
///
/// It shouts **in the markup**, not only in the stylesheet. The chips are
/// uppercased by CSS, so every other label can be written in lower case and
/// still read as small caps — but a rule in a stylesheet is not something a
/// test, a screen reader, or a page saved to disk can see. The word this
/// screen exists to make unmissable is spelled out.
fn status_chip(status: VentureStatus) -> String {
    let (class, label) = match status {
        VentureStatus::Draft => ("chip--archived", "draft"),
        VentureStatus::Provisioning => ("chip--working", "provisioning"),
        VentureStatus::Live => ("chip--live", "live"),
        VentureStatus::Degraded => ("chip--degraded", "DEGRADED"),
        VentureStatus::Archived => ("chip--archived", "archived"),
    };
    format!("<span class=\"chip {class}\">{label}</span>")
}

/// The dot beside a health verdict. Answering is the accent, a failure is
/// red, and a venture nothing should be answering for is the inert grey —
/// never the same as "we have not looked yet", because the dashboard has
/// no such state.
fn health_dot(health: &HealthVerdict) -> &'static str {
    match health {
        HealthVerdict::Answering => "<span class=\"dash__dot dash__dot--live\"></span>",
        HealthVerdict::Failing(_) | HealthVerdict::Unreachable(_) => {
            "<span class=\"dash__dot dash__dot--bad\"></span>"
        }
        HealthVerdict::NotRunning => "<span class=\"dash__dot\"></span>",
    }
}

/// The dashboard frame: the left navigation and the screen beside it.
pub(crate) fn frame(nav_html: &str, crumb: &str, body: &str) -> String {
    format!(
        "<div class=\"dash\"><div class=\"dash__body\">{nav_html}         <div class=\"dash__main\"><p class=\"dash__crumb\">{crumb}</p>{body}</div>         </div></div>"
    )
}

/// A panel.
pub(crate) fn card(title: &str, tag: Option<&str>, body: &str, wide: bool) -> String {
    let tag = tag.map_or_else(String::new, |t| {
        format!(" <span class=\"dash__tag\">{}</span>", escape(t))
    });
    format!(
        "<div class=\"dash__card{wide}\"><p class=\"dash__card-h\">{title}{tag}</p>{body}</div>",
        wide = if wide { " dash__card--wide" } else { "" },
        title = escape(title),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_access::{DEFAULT_TTL_SECS, issue_session};
    use cratefield_testing::{FakeHttpClient, TestHarness};
    use http::{Method, Request as HttpRequest};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::task::{Context, Poll};
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

    /// The control plane's own composition. The console owns the access,
    /// accounts and provisioning schemas and writes their rows; the
    /// dashboard owns `connection` and reads the rest. Mounting the
    /// dashboard alone is a composition that does not exist in production,
    /// and it is what hid a duplicate-DDL failure until a dev server
    /// mounting both refused to boot.
    fn modules() -> Vec<Box<dyn Module>> {
        vec![
            Box::new(cratefield_console::Console),
            Box::new(Dashboard::default()),
        ]
    }

    /// A harness with the dashboard module, an account, and one venture
    /// (`my-app`, module set `cms+waitlist`), already through provisioning
    /// to `status`.
    async fn seeded(status: VentureStatus) -> TestHarness {
        let kit = TestHarness::new(modules());
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

    // -----------------------------------------------------------------------
    // A probe that makes "concurrently" and "with a deadline" observable
    //
    // The kit's own `FakeHttpClient` can express neither: it answers
    // without ever yielding, so every caller looks serial to it, and it
    // drops the request's extensions, so the policy a caller attached is
    // gone by the time the test could look. A fake bounds what can be
    // tested, so this one records both.

    /// Pending once, then ready. One yield point, no timer and no runtime
    /// support, so the ordering a test observes is deterministic.
    #[derive(Default)]
    struct YieldOnce {
        yielded: bool,
    }

    impl Future for YieldOnce {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.yielded {
                Poll::Ready(())
            } else {
                self.yielded = true;
                // Ask to be polled again rather than waiting for a wake
                // that nothing would send.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    /// Counters only: `std::sync::Mutex` is a disallowed type here (ADR
    /// 0007, shared mutable state), and the worst case across every probe
    /// is a stronger thing to assert on than one recorded policy anyway.
    #[derive(Default)]
    struct ProbeInner {
        in_flight: AtomicUsize,
        peak: AtomicUsize,
        probes: AtomicUsize,
        /// The loosest deadline any probe asked for.
        widest_timeout_ms: AtomicU64,
        /// The largest body any probe agreed to buffer.
        widest_max_bytes: AtomicUsize,
    }

    /// Records the high-water mark of sends in flight at once, and the
    /// effective [`HttpPolicy`] of each. Every send registers itself,
    /// yields so the executor *may* poll its siblings, then answers 200 —
    /// so `peak()` is 1 when the caller awaits its sends one after
    /// another, and N when it polls N of them together.
    #[derive(Clone, Default)]
    struct ConcurrencyProbe {
        inner: Arc<ProbeInner>,
    }

    impl ConcurrencyProbe {
        fn peak(&self) -> usize {
            self.inner.peak.load(Ordering::SeqCst)
        }

        fn probes(&self) -> usize {
            self.inner.probes.load(Ordering::SeqCst)
        }

        /// The loosest policy any probe asked for, so an assertion on it
        /// holds for all of them.
        fn widest_policy(&self) -> HttpPolicy {
            HttpPolicy {
                max_response_bytes: self.inner.widest_max_bytes.load(Ordering::SeqCst),
                timeout: Duration::from_millis(self.inner.widest_timeout_ms.load(Ordering::SeqCst)),
            }
        }
    }

    #[async_trait::async_trait]
    impl cratefield_core::HttpClient for ConcurrencyProbe {
        async fn send(
            &self,
            request: http::Request<bytes::Bytes>,
        ) -> Result<http::Response<bytes::Bytes>, cratefield_core::HttpError> {
            let policy = HttpPolicy::of_request(&request);
            self.inner.probes.fetch_add(1, Ordering::SeqCst);
            self.inner.widest_timeout_ms.fetch_max(
                u64::try_from(policy.timeout.as_millis()).unwrap_or(u64::MAX),
                Ordering::SeqCst,
            );
            self.inner
                .widest_max_bytes
                .fetch_max(policy.max_response_bytes, Ordering::SeqCst);
            let now = self.inner.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.inner.peak.fetch_max(now, Ordering::SeqCst);
            YieldOnce::default().await;
            self.inner.in_flight.fetch_sub(1, Ordering::SeqCst);
            http::Response::builder()
                .status(200)
                .body(bytes::Bytes::new())
                .map_err(|err| cratefield_core::HttpError::Transport(err.to_string()))
        }
    }

    /// A harness whose http port is `probe`, with `count` live ventures.
    async fn seeded_live(probe: &ConcurrencyProbe, count: usize) -> TestHarness {
        let probe = probe.clone();
        let kit = TestHarness::with_ports(modules(), move |ports| {
            ports.http = Some(Arc::new(probe));
        });
        let repo = Repository::new(kit.db.clone());
        repo.account_for_login(EMAIL, "Op", "acc_1", "t0")
            .await
            .expect("account");
        for n in 0..count {
            let id = format!("v{n}");
            repo.create_venture(
                &id,
                "acc_1",
                &format!("app-{n}"),
                &format!("app-{n}.cratefield.app"),
                "cms",
                "ten_1",
                "t0",
            )
            .await
            .expect("venture");
            repo.set_venture_status("acc_1", &id, VentureStatus::Provisioning, "t1")
                .await
                .expect("provisioning");
            repo.set_venture_status("acc_1", &id, VentureStatus::Live, "t2")
                .await
                .expect("live");
        }
        kit
    }

    /// Posts a module selection as the form does: one `module` field per
    /// ticked box.
    async fn post_modules(kit: &TestHarness, venture: &str, modules: &[&str]) -> Reply {
        let body = modules
            .iter()
            .map(|slug| format!("module={slug}"))
            .collect::<Vec<_>>()
            .join("&");
        let request = HttpRequest::builder()
            .method(Method::POST)
            .uri(format!("{BASE}/ventures/{venture}/modules"))
            .header(header::COOKIE, cookie(kit))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(axum::body::Body::from(body))
            .expect("request");
        let response = kit
            .router
            .clone()
            .oneshot(request)
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

    /// Marks every provisioning step done, which is what a `Live` venture
    /// looks like to the engine.
    async fn record_fully_provisioned(kit: &TestHarness) {
        kit.db
            .execute(&Statement::with_values(
                "INSERT INTO provision_progress (venture_id, last_step, error, updated_at) \
                 VALUES (?, ?, ?, ?)",
                vec![text("v1"), text("health"), text(""), text("t3")],
            ))
            .await
            .expect("progress row");
    }

    async fn module_set_of(kit: &TestHarness) -> String {
        Repository::new(kit.db.clone())
            .venture_for("acc_1", "v1")
            .await
            .expect("read")
            .expect("venture")
            .module_set
    }

    #[pollster::test]
    async fn the_detail_page_offers_the_catalogue_not_just_what_is_installed() {
        let kit = seeded(VentureStatus::Live).await;
        let reply = send(
            &kit,
            Method::GET,
            &format!("{BASE}/ventures/v1"),
            Some(&cookie(&kit)),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);

        // The seeded venture carries cms+waitlist. Every other module the
        // catalogue offers has to be on the page too, or the screen is a
        // report rather than something you can act on.
        let catalog = cratefield_catalog::curated();
        assert!(catalog.modules.len() > 2, "the catalogue is the point");
        for module in &catalog.modules {
            assert!(
                reply.body.contains(&format!("value=\"{}\"", module.slug)),
                "{} is in the catalogue and not on the page: {}",
                module.slug,
                reply.body
            );
        }
        // And the two it has are the ticked ones.
        assert!(
            reply.body.contains("value=\"cms\" checked"),
            "{}",
            reply.body
        );
        assert!(
            reply.body.contains("value=\"waitlist\" checked"),
            "{}",
            reply.body
        );
        assert!(
            !reply.body.contains("value=\"privacy\" checked"),
            "privacy is not installed and must not read as installed: {}",
            reply.body
        );
    }

    #[pollster::test]
    async fn changing_the_module_set_re_provisions_from_the_first_step() {
        let kit = seeded(VentureStatus::Live).await;
        record_fully_provisioned(&kit).await;

        let reply = post_modules(&kit, "v1", &["cms", "waitlist", "privacy"]).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);

        // `resolve` orders dependencies before dependants and is otherwise
        // order-preserving, so the key follows the order ticked.
        assert!(
            same_set(&module_set_of(&kit).await, "cms+waitlist+privacy"),
            "got {}",
            module_set_of(&kit).await
        );

        // The engine must NOT have seen a fully-provisioned venture and
        // waved it through: the artifact is a function of the module set,
        // so the run restarts at the first step. With no deployer wired
        // that step fails, and the failure is what is recorded.
        let progress = progress_of(kit.db.as_ref(), "v1").await.expect("progress");
        assert_eq!(
            progress.last_step, "",
            "a module change must not resume past the artifact step: {progress:?}"
        );
        assert!(
            progress.error.contains("no deployer is wired"),
            "the engine should have run and stopped: {progress:?}"
        );

        // And the venture is no longer claiming to be live with an
        // artifact that does not carry the module just added.
        let venture = Repository::new(kit.db.clone())
            .venture_for("acc_1", "v1")
            .await
            .expect("read")
            .expect("venture");
        assert_ne!(
            venture.status,
            VentureStatus::Live,
            "live would mean the running worker carries privacy, and it does not"
        );
    }

    #[pollster::test]
    async fn the_failed_run_is_shown_on_the_page_rather_than_being_a_500() {
        let kit = seeded(VentureStatus::Live).await;
        post_modules(&kit, "v1", &["cms"]).await;

        let reply = send(
            &kit,
            Method::GET,
            &format!("{BASE}/ventures/v1"),
            Some(&cookie(&kit)),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        assert!(
            reply.body.contains("no deployer is wired"),
            "the recorded reason belongs on the screen: {}",
            reply.body
        );
    }

    #[pollster::test]
    async fn an_unchanged_selection_does_not_tear_down_a_working_venture() {
        let kit = seeded(VentureStatus::Live).await;
        record_fully_provisioned(&kit).await;

        // Ticked in the opposite order to the stored key. Same selection.
        let reply = post_modules(&kit, "v1", &["waitlist", "cms"]).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);

        // Nothing was re-provisioned: a live venture is not torn down to
        // rebuild the artifact it already has.
        let progress = progress_of(kit.db.as_ref(), "v1").await.expect("progress");
        assert_eq!(progress.last_step, "health", "{progress:?}");
        assert_eq!(progress.error, "", "{progress:?}");
    }

    #[pollster::test]
    async fn a_module_the_catalogue_does_not_offer_is_refused() {
        let kit = seeded(VentureStatus::Live).await;
        let reply = post_modules(&kit, "v1", &["cms", "mining-rig"]).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
        assert_eq!(
            module_set_of(&kit).await,
            "cms+waitlist",
            "a refused post must change nothing"
        );
    }

    #[pollster::test]
    async fn an_archived_venture_module_set_is_fixed() {
        let kit = seeded(VentureStatus::Archived).await;

        let page = send(
            &kit,
            Method::GET,
            &format!("{BASE}/ventures/v1"),
            Some(&cookie(&kit)),
        )
        .await;
        assert!(
            !page.body.contains("Save and re-provision"),
            "an archived venture offers no editor: {}",
            page.body
        );

        let reply = post_modules(&kit, "v1", &["cms"]).await;
        assert_eq!(reply.status, StatusCode::CONFLICT, "{}", reply.body);
        assert_eq!(module_set_of(&kit).await, "cms+waitlist");
    }

    #[pollster::test]
    async fn one_account_cannot_change_anothers_module_set() {
        let kit = seeded(VentureStatus::Live).await;
        let repo = Repository::new(kit.db.clone());
        repo.account_for_login("b@x.co", "B", "acc_2", "t0")
            .await
            .expect("account");
        let token = issue_session(kit.signer.as_ref(), "b@x.co", NOW, DEFAULT_TTL_SECS);

        let request = HttpRequest::builder()
            .method(Method::POST)
            .uri(format!("{BASE}/ventures/v1/modules"))
            .header(header::COOKIE, format!("cf_session={token}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(axum::body::Body::from("module=cms"))
            .expect("request");
        let response = kit
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("router answers");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(module_set_of(&kit).await, "cms+waitlist");
    }

    #[pollster::test]
    async fn a_stopped_run_does_not_lock_the_module_set_behind_its_own_failure() {
        // The trap this exists for: the engine leaves a failed run in
        // `Provisioning`, and treating that as "a run is in flight" would
        // mean one failed save locks a venture's module set forever — with
        // no deployer wired, that is *every* save.
        let kit = seeded(VentureStatus::Live).await;
        post_modules(&kit, "v1", &["cms"]).await;

        let venture = Repository::new(kit.db.clone())
            .venture_for("acc_1", "v1")
            .await
            .expect("read")
            .expect("venture");
        assert_eq!(
            venture.status,
            VentureStatus::Provisioning,
            "the run stopped"
        );

        let page = send(
            &kit,
            Method::GET,
            &format!("{BASE}/ventures/v1"),
            Some(&cookie(&kit)),
        )
        .await;
        assert!(
            page.body.contains("Save and re-provision"),
            "the set must still be editable: {}",
            page.body
        );
        assert!(
            page.body.contains("Retry provisioning"),
            "a stopped run offers a retry: {}",
            page.body
        );
        // The sentence, not the empty <code></code> a first-step failure
        // used to render.
        assert!(
            page.body.contains("stopped</strong> on its first step"),
            "{}",
            page.body
        );

        // And a second change really does go through.
        let reply = post_modules(&kit, "v1", &["cms", "waitlist", "notifications"]).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        assert!(same_set(
            &module_set_of(&kit).await,
            "cms+waitlist+notifications"
        ));
    }

    #[pollster::test]
    async fn a_retry_resumes_the_run_without_changing_the_venture() {
        let kit = seeded(VentureStatus::Live).await;
        post_modules(&kit, "v1", &["cms"]).await;
        let before = module_set_of(&kit).await;

        let request = HttpRequest::builder()
            .method(Method::POST)
            .uri(format!("{BASE}/ventures/v1/reprovision"))
            .header(header::COOKIE, cookie(&kit))
            .body(axum::body::Body::empty())
            .expect("request");
        let response = kit
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("router answers");
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        assert_eq!(module_set_of(&kit).await, before, "a retry changes nothing");
        let progress = progress_of(kit.db.as_ref(), "v1").await.expect("progress");
        assert!(
            progress.error.contains("no deployer is wired"),
            "{progress:?}"
        );
    }

    /// An http port that answers `/__surface` with `document` and every
    /// other path with 200. Enough to drive the venture page with a
    /// contract of the test's choosing.
    #[derive(Clone)]
    struct SurfaceServer {
        document: Arc<String>,
    }

    #[async_trait::async_trait]
    impl cratefield_core::HttpClient for SurfaceServer {
        async fn send(
            &self,
            request: http::Request<bytes::Bytes>,
        ) -> Result<http::Response<bytes::Bytes>, cratefield_core::HttpError> {
            let body = if request.uri().path() == "/__surface" {
                bytes::Bytes::from(self.document.as_str().to_owned())
            } else {
                bytes::Bytes::new()
            };
            http::Response::builder()
                .status(200)
                .body(body)
                .map_err(|err| cratefield_core::HttpError::Transport(err.to_string()))
        }
    }

    async fn seeded_serving(document: &str) -> TestHarness {
        let server = SurfaceServer {
            document: Arc::new(document.to_owned()),
        };
        let kit = TestHarness::with_ports(modules(), move |ports| {
            ports.http = Some(Arc::new(server));
        });
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
        repo.set_venture_status("acc_1", "v1", VentureStatus::Provisioning, "t1")
            .await
            .expect("provisioning");
        repo.set_venture_status("acc_1", "v1", VentureStatus::Live, "t2")
            .await
            .expect("live");
        kit
    }

    #[pollster::test]
    async fn the_screens_come_from_the_ventures_contract_not_from_this_crate() {
        // The document names a module this crate has never heard of and
        // which is in no catalogue. If the screen list were written down
        // here, or derived from the venture's module_set, none of this
        // could appear.
        // Built from the core types and serialised, rather than
        // hand-written JSON: the contract's wire shape is the harness's to
        // decide, and a test that spells it out by hand tests the test.
        let surface = Surface::new()
            .action(cratefield_core::Action::post("enrol", "/enrol"))
            .action(
                cratefield_core::Action::get("roster", "/admin/roster")
                    .audience(cratefield_core::Audience::Admin),
            )
            .view(View::form("enrol"))
            .view(View::table(
                "roster",
                vec![
                    cratefield_core::Column::new("who", "Who"),
                    cratefield_core::Column::new("when", "When"),
                ],
            ));
        let document = serde_json::to_string(&SurfaceDocument {
            surface_api: 1,
            harness_api: 1,
            venture: cratefield_core::VentureSurface {
                name: "my-app".to_owned(),
                public_url: "https://my-app.example".to_owned(),
            },
            modules: vec![cratefield_core::ModuleSurface {
                name: "nobody-has-heard-of-this".to_owned(),
                version: "9.9.9".to_owned(),
                surface,
            }],
            ui: None,
        })
        .expect("serialise the contract");

        let kit = seeded_serving(&document).await;
        let reply = send(
            &kit,
            Method::GET,
            &format!("{BASE}/ventures/v1"),
            Some(&cookie(&kit)),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);

        assert!(
            reply.body.contains("nobody-has-heard-of-this"),
            "the module the contract declared is missing: {}",
            reply.body
        );
        // The links point at the venture's own renderer, at the public URL
        // the contract gave — not at a URL rebuilt from the subdomain.
        assert!(
            reply
                .body
                .contains("https://my-app.example/ui/nobody-has-heard-of-this/enrol"),
            "{}",
            reply.body
        );
        // Both views, their kinds, and the table's columns.
        assert!(reply.body.contains("roster"), "{}", reply.body);
        assert!(reply.body.contains("Who, When"), "{}", reply.body);
        assert!(reply.body.contains("admin"), "{}", reply.body);
    }

    #[pollster::test]
    async fn an_unreachable_venture_lists_no_screens_rather_than_guessing_them() {
        // The venture carries cms+waitlist, both of which really do declare
        // screens. The temptation is to render them from the module names.
        // The dashboard has not fetched a contract, so it does not know
        // this venture's screens, and says so.
        let kit = seeded(VentureStatus::Live).await; // the exhausted fake http
        let reply = send(
            &kit,
            Method::GET,
            &format!("{BASE}/ventures/v1"),
            Some(&cookie(&kit)),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        assert!(
            reply.body.contains("contract could not be read"),
            "{}",
            reply.body
        );
        assert!(
            !reply.body.contains("/ui/cms/"),
            "a screen link for a contract never read: {}",
            reply.body
        );
    }

    #[pollster::test]
    async fn a_draft_venture_is_not_asked_for_a_contract_either() {
        let kit = seeded(VentureStatus::Draft).await;
        let reply = send(
            &kit,
            Method::GET,
            &format!("{BASE}/ventures/v1"),
            Some(&cookie(&kit)),
        )
        .await;
        assert!(
            reply
                .body
                .contains("not running — nothing is serving a contract"),
            "{}",
            reply.body
        );
    }

    #[pollster::test]
    async fn every_screen_in_the_navigation_answers_and_none_of_them_bluffs() {
        let kit = seeded(VentureStatus::Live).await;
        for (slug, title) in &SCREENS {
            let reply = send(
                &kit,
                Method::GET,
                &format!("{BASE}/{slug}"),
                Some(&cookie(&kit)),
            )
            .await;
            assert_eq!(reply.status, StatusCode::OK, "{slug}: {}", reply.body);
            assert!(
                reply.body.contains(title),
                "{slug} must name itself: {}",
                reply.body
            );
            // The invariant that outlives these screens being built one
            // at a time: a screen may say it is not built, but then it
            // must say what to do today instead. It may not say only the
            // first half, and a screen that has been built says neither.
            if reply.body.contains("Not built.") {
                assert!(
                    reply.body.contains("Today you do this instead:"),
                    "{slug} says it is not built without saying what to do: {}",
                    reply.body
                );
            }
        }

        // And a screen that is not in the navigation is a 404, not a
        // blank page.
        let reply = send(
            &kit,
            Method::GET,
            &format!("{BASE}/teleportation"),
            Some(&cookie(&kit)),
        )
        .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
    }

    #[pollster::test]
    async fn the_control_plane_composition_migrates_a_fresh_database() {
        // Mounting the console and the dashboard together applies both
        // migration sets to one database, which is what the control plane
        // does and what `fz migrations collect` writes out. The dashboard
        // used to re-declare the console's provisioning sub-schema, so the
        // second `CREATE TABLE provision_progress` failed right here — on
        // every fresh database, including the first real deploy.
        let kit = TestHarness::new(modules());

        // Each table, from whichever module owns it.
        for table in ["account", "venture", "provision_progress", "connection"] {
            kit.db
                .query(&Statement::new(format!("SELECT 1 FROM {table} LIMIT 1")))
                .await
                .unwrap_or_else(|err| panic!("{table} is missing after migration: {err}"));
        }
    }

    #[pollster::test]
    async fn the_venture_health_checks_are_polled_together_not_one_after_another() {
        let probe = ConcurrencyProbe::default();
        let kit = seeded_live(&probe, 3).await;

        let reply = send(&kit, Method::GET, BASE, Some(&cookie(&kit))).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        assert_eq!(probe.probes(), 3, "every live venture is checked");

        // The whole point: awaiting the checks in a loop holds this at 1,
        // and the page then costs the SUM of three timeouts instead of the
        // longest one.
        assert_eq!(
            probe.peak(),
            3,
            "three checks should be in flight at once, not queued"
        );
    }

    #[pollster::test]
    async fn the_health_probe_carries_a_deadline_far_under_the_ports_default() {
        let probe = ConcurrencyProbe::default();
        let kit = seeded_live(&probe, 1).await;

        let reply = send(&kit, Method::GET, BASE, Some(&cookie(&kit))).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);

        assert_eq!(probe.probes(), 1, "one live venture, one probe");
        let policy = probe.widest_policy();
        // A page render must not inherit the port's API-call default.
        assert!(
            policy.timeout < cratefield_core::DEFAULT_RESPONSE_TIMEOUT,
            "the health probe must tighten the port default, got {:?}",
            policy.timeout,
        );
        assert!(
            policy.timeout <= Duration::from_secs(3),
            "three seconds is the budget for one health check, got {:?}",
            policy.timeout,
        );
        // And it should not agree to buffer a megabyte from a venture that
        // answers /__health with something else entirely.
        assert!(
            policy.max_response_bytes <= 4 * 1024,
            "got {}",
            policy.max_response_bytes,
        );
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
        let kit = TestHarness::with_ports(modules(), |ports| {
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
        let kit = TestHarness::with_ports(modules(), |ports| {
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
        let kit = TestHarness::with_ports(modules(), |ports| {
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
        let kit = TestHarness::new(modules());
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
