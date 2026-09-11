//! The control-plane **console** module (epic #1, issue #3): the first thing a
//! visitor meets. It owns the session gate, the login skeleton, and the
//! operator allowlist action, and — mounted in the venture — it is the
//! composition pattern the wizard (#8) and dashboard (#11) follow.
//!
//! **Login is stubbed, deliberately.** #3 signs in through the `auth-*` crates,
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
    Config, ConfigError, DataKind, Disposition, Migrations, Module, ModuleConfig, ModuleContext,
    PersonalDataSet, Port, Signer, SqlMigration, require_admin,
};
use http::{HeaderMap, StatusCode, header};
use time::format_description::well_known::Rfc3339;

/// Where the console is mounted (`/v1/<name>`), so its own redirects resolve.
const BASE: &str = "/v1/console";

/// The one login gate in the control plane. The console serves it; every
/// other screen redirects here rather than serving a gate of its own, so
/// there is exactly one path a signed-out visitor can land on.
pub const LOGIN_PATH: &str = "/v1/console/login";

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
        // allowlist and its audit; the http client runs the Google exchange;
        // the clock and id-gen mint sessions, ids and timestamps (without them
        // declared, view_for hides them and every session's expiry is 0).
        &[
            Port::Signer,
            Port::Db,
            Port::HttpClient,
            Port::Clock,
            Port::IdGen,
        ]
    }

    /// The five tables this module's `migrations()` create (issue #280). This
    /// list is also what a whole-database `fz data export`/`import` carries,
    /// so declaring it means the control plane's own database — its allowlist
    /// and its accounts — moves with the venture on a move. That is the right
    /// answer: a move that left the login gate behind would not boot.
    fn tables(&self) -> &'static [&'static str] {
        &[
            "allowlist",
            "allowlist_audit",
            "account",
            "venture",
            "provision_progress",
        ]
    }

    /// What the control plane holds about a person, table by table (issues
    /// #244, #280). The control plane is itself a harness venture, so "what
    /// do you hold about me" is a question an operator's subject can ask it,
    /// and until this existed the answer was: everything, undeclared.
    ///
    /// **Ordering, and why it is currently inert.** The catalogue is ordered
    /// so that, under reversal, `venture` is deleted before the `account`
    /// row it references — the same rule `auth-core` follows with `users`
    /// declared first. But that ordering protects nothing today, because
    /// erasure binds **one** subject value across every declaration and no
    /// single value matches both: `allowlist.value` and `account.identity`
    /// hold the operator's Google-verified email, while `venture.account_id`
    /// holds the account's ULID. With subject = the address, the `venture`
    /// delete removes nothing, the `account` delete then removes the parent,
    /// and `verify` re-counts `venture` with the address, finds zero, and
    /// writes a receipt saying the erasure completed — while the venture rows
    /// remain, pointing at an account id that no longer exists. The export
    /// has the same hole: a declaration promising "the backends you created"
    /// returns an empty set. Tracked as issue #288; the mechanism that fixes
    /// it is the declared join (#281's `subject_via`), which is deliberately
    /// not invented here.
    ///
    /// **Why `account` is `Erase` and not `Anonymise`.** Anonymising would
    /// need the identifying columns nullable, and the schema refuses that on
    /// purpose: `account.identity` is `NOT NULL UNIQUE` with no default, and
    /// `name` is `NOT NULL`. `identity` is the Google-verified email the
    /// control plane signs the person in with — the one identifier this
    /// database cannot keep once the person is gone, because a row that can
    /// still be signed into is not erased. So the account goes, and with it
    /// — by the ordering above — the venture rows that hang off it. That is
    /// a real consequence, not a side effect: a person leaving takes their
    /// backends' records with them, and offboarding the running Workers
    /// themselves is the deploy pipeline's job, not the erasure plan's.
    ///
    /// **Why `allowlist_audit` is `Retain`.** It is append-only by design:
    /// every add and every remove of an allowlist entry is kept, so the
    /// answer to "who let this address in, and who took it out" always
    /// exists. The reason is written for the subject to read, because it is
    /// published verbatim on the privacy page.
    ///
    /// **Two known gaps, both the same family: this catalogue type has no
    /// join, and both failures are what happens without one.**
    ///
    /// `allowlist.value` holds either an exact lowercased email or a
    /// `@domain`. A subject access request made with a person's address can
    /// never match a `@domain` row that admits them, because the row does
    /// not contain their address. And `venture` references its owner by the
    /// account's ULID rather than the address every other set here matches
    /// on, so the erasure and the export in the ordering note above never
    /// reach it at all. The declarations are still the honest ones — each
    /// names the column a person is identified by, when they are identified
    /// at all — but both need the declared join (#281's `subject_via`) to
    /// become complete, and both are tracked under issue #288 rather than
    /// papered over here with a mechanism this branch does not build.
    fn personal_data(&self) -> &'static [PersonalDataSet] {
        const SETS: &[PersonalDataSet] = &[
            PersonalDataSet {
                table: "allowlist",
                subject: "value",
                kind: DataKind::Contact,
                disposition: Disposition::Erase,
                description: "The invite list: the address (or whole domain) you were let in \
                              with, whether it was an address or a domain, the note the \
                              operator wrote when inviting you, who invited you, and when.",
                redacted: &[],
            },
            PersonalDataSet {
                table: "allowlist_audit",
                subject: "value",
                kind: DataKind::Contact,
                disposition: Disposition::Retain(
                    "This is the record of every change to the invite list: when your \
                     address was added, by whom, and when it was removed, by whom. It is \
                     kept on purpose and never rewritten, so the answer to who changed \
                     your access — including any removal you asked for — always exists. \
                     Erasing it would leave an access change nobody can account for.",
                ),
                description: "The audit trail of the invite list itself: every add and every \
                              remove, the address it concerned, and which operator did it \
                              and when. Append-only; a removal removes the invite but not \
                              the record of it.",
                redacted: &[],
            },
            PersonalDataSet {
                table: "account",
                subject: "identity",
                kind: DataKind::Contact,
                disposition: Disposition::Erase,
                description: "Your account with us: the Google-verified email address you \
                              sign in with, the name it gave us, whether the account is \
                              active, and when it was created.",
                redacted: &[],
            },
            // Declared after `account` so that, under reversal, these rows
            // would be deleted before the account row they reference. The
            // ordering is currently inert — no single subject value matches
            // both tables — which is the gap tracked in #288. See the doc
            // comment above.
            PersonalDataSet {
                table: "venture",
                subject: "account_id",
                kind: DataKind::Identifier,
                disposition: Disposition::Erase,
                description: "The backends you created: each one's name and subdomain, the \
                              modules it carries, where it is in its lifecycle, and when it \
                              was created and last changed.",
                redacted: &[],
            },
            // Keyed to a venture, not a person: the last provisioning step
            // that completed, the error message if the run stopped, and when.
            // No column in it names a human being, and the venture it belongs
            // to is erased with its account above.
            PersonalDataSet::none(
                "provision_progress",
                "One row per backend, holding where provisioning got to: the last step that \
                 completed and any error message a stopped run recorded. It is keyed to the \
                 backend's id and names nobody.",
            ),
        ];
        SETS
    }

    fn migrations(&self) -> Migrations {
        // The console owns the tables its domain crates use: the allowlist +
        // audit (access), accounts + ventures, and provisioning progress.
        // Re-id the three sub-schemas so they are unique WITHIN this module:
        // each crate's own MIGRATION is id "0001", which would collide under
        // one module and apply only one table set. Same SQL, same
        // transaction rule (copied, not restated: a sub-schema that later
        // needs to run outside a transaction must not silently run inside
        // one here), distinct ids.
        const MIGRATIONS: [SqlMigration; 3] = [
            SqlMigration {
                id: "0001",
                name: "access",
                sql: cratefield_access::MIGRATION.sql,
                transactional: cratefield_access::MIGRATION.transactional,
            },
            SqlMigration {
                id: "0002",
                name: "accounts",
                sql: cratefield_accounts::MIGRATION.sql,
                transactional: cratefield_accounts::MIGRATION.transactional,
            },
            SqlMigration {
                id: "0003",
                name: "provisioning",
                sql: cratefield_provisioning::MIGRATION.sql,
                transactional: cratefield_provisioning::MIGRATION.transactional,
            },
        ];
        // The array is the apply order; this refuses a gap, a duplicate
        // or an entry out of order at build time (issue #27).
        const _: () = cratefield_core::assert_migration_set(&MIGRATIONS);
        Migrations::sqlite(&MIGRATIONS)
    }

    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        let mut errors = ConfigError::new();
        // The dev-login bypass (CONSOLE_DEV_LOGIN) may never be enabled in
        // production — it would be an unauthenticated way into the console.
        let dev_login = ModuleConfig::new("console", cfg).get_str("DEV_LOGIN", "");
        let production = cfg.get("ENV").as_deref() == Some("production");
        if !dev_login.is_empty() && production {
            errors.push("CONSOLE_DEV_LOGIN must never be set in production");
        }
        errors.into_result()
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let state = Arc::new(ConsoleState { ctx: Arc::new(ctx) });
        axum::Router::new()
            .route("/", get(home))
            .route("/login", get(login_page))
            .route("/dev-login", get(dev_login))
            .route("/auth/start", get(auth_start))
            .route("/auth/callback", get(callback))
            .route("/logout", get(logout))
            .route("/new", get(new_wizard).post(create_venture_handler))
            .route("/ventures/{id}", get(venture_detail))
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
    current_session(ctx, headers).ok_or_else(|| Redirect::to(LOGIN_PATH).into_response())
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

#[allow(clippy::format_push_string)]
async fn home(State(state): State<Arc<ConsoleState>>, headers: HeaderMap) -> Response {
    let ctx = &state.ctx;
    let session = match guard(ctx, &headers) {
        Ok(session) => session,
        Err(redirect) => return redirect,
    };
    let (account, repo) = match account_of(ctx, &session).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let ventures = repo.ventures_for(&account.id).await.unwrap_or_default();

    let mut list = String::new();
    if ventures.is_empty() {
        list.push_str(
            "<p class=\"dash__empty\">No backends yet. The wizard takes a name and a \
             set of modules.</p>",
        );
    } else {
        list.push_str(
            "<div class=\"dash__lrow dash__lrow--head\"><span>Backend</span>\
             <span>Modules</span><span>Status</span></div>",
        );
        for venture in &ventures {
            list.push_str(&format!(
                "<div class=\"dash__lrow dash__lrow--three\">\
                 <span><a href=\"{BASE}/ventures/{id}\">{slug}</a></span>\
                 <span><em>{modules}</em></span>\
                 <span>{status}</span></div>",
                id = escape(&venture.id),
                slug = escape(&venture.slug),
                modules = escape(&venture.module_set),
                status = escape(status_label(venture.status)),
            ));
        }
    }

    let nav = cratefield_chrome::nav(&[
        cratefield_chrome::NavItem::here("Backends", BASE),
        cratefield_chrome::NavItem::to("New backend", &format!("{BASE}/new")),
        cratefield_chrome::NavItem::to("Dashboard", "/v1/dashboard"),
    ]);
    let crumb = format!(
        "{n} backend{s}",
        n = ventures.len(),
        s = if ventures.len() == 1 { "" } else { "s" },
    );
    let body = format!(
        "<div class=\"dash__list\">{list}</div>\
         <div class=\"dash__act\">\
         <a class=\"btn btn--primary\" href=\"{BASE}/new\">New backend</a></div>\
         <p class=\"dash__note\">The console creates and names a backend. What it is \
         doing once it exists — health, provisioning progress, connections — is the \
         <a href=\"/v1/dashboard\">dashboard</a>.</p>"
    );

    Html(page_for(
        "Console",
        Some(&session.account_id),
        &format!(
            "<div class=\"page-h\"><h1>Your backends</h1></div>\
             <p class=\"lede\">Every backend this account has created.</p>{}",
            chrome_frame(&nav, &crumb, &body)
        ),
    ))
    .into_response()
}

/// The dashboard frame, so the console's screens sit in the same furniture.
fn chrome_frame(nav: &str, crumb: &str, body: &str) -> String {
    format!(
        "<div class=\"dash\"><div class=\"dash__body\">{nav}\
         <div class=\"dash__main\"><p class=\"dash__crumb\">{crumb}</p>{body}</div>\
         </div></div>"
    )
}

/// The new-backend wizard (#8): pick modules from the catalog and name it.
/// Server-rendered; one page, dependencies resolved on submit.
#[allow(clippy::format_push_string)]
async fn new_wizard(State(state): State<Arc<ConsoleState>>, headers: HeaderMap) -> Response {
    let ctx = &state.ctx;
    if let Err(redirect) = guard(ctx, &headers) {
        return redirect;
    }
    let session = current_session(ctx, &headers).expect("guard proved a session");
    let catalog = cratefield_catalog::curated();
    let mut modules = String::from("<div class=\"mods\">");
    for module in &catalog.modules {
        modules.push_str(&format!(
            "<label class=\"mod\">\
             <input type=\"checkbox\" name=\"module\" value=\"{slug}\">\
             <span><span class=\"mod__name\">{name} <code>{slug}</code></span>\
             <span class=\"mod__sum\">{summary}</span></span></label>",
            slug = escape(&module.slug),
            name = escape(&module.name),
            summary = escape(&module.summary),
        ));
    }
    modules.push_str("</div>");

    let nav = cratefield_chrome::nav(&[
        cratefield_chrome::NavItem::to("Backends", BASE),
        cratefield_chrome::NavItem::here("New backend", &format!("{BASE}/new")),
        cratefield_chrome::NavItem::to("Dashboard", "/v1/dashboard"),
    ]);
    let body = format!(
        "<form method=\"post\" action=\"{BASE}/new\">\
         <p class=\"dash__card-h\">Pick what it does</p>{modules}\
         <p class=\"dash__card-h\" style=\"margin-top:20px\">Name it</p>\
         <p class=\"field\"><label for=\"slug\">Slug</label>\
         <input id=\"slug\" name=\"slug\" required autocomplete=\"off\" \
         placeholder=\"acme-waitlist\"></p>\
         <p class=\"dash__note\">The slug becomes the subdomain, so it is \
         lower-case letters, digits and hyphens.</p>\
         <div class=\"dash__act\">\
         <button class=\"btn btn--primary\" type=\"submit\">Create</button></div>\
         </form>\
         <p class=\"dash__note\">Creating records the backend and its module set. \
         Standing it up on Cloudflare is a separate step: there is no live deployer \
         yet, and the backend's page says so rather than implying it is running.</p>"
    );

    Html(page_for(
        "New backend",
        Some(&session.account_id),
        &format!(
            "<p class=\"crumb\"><a href=\"{BASE}\">Backends</a> / New</p>\
             <div class=\"page-h\"><h1>New backend</h1></div>\
             <p class=\"lede\">Choose the modules it carries. Dependencies are \
             resolved on submit.</p>{}",
            chrome_frame(&nav, "New backend", &body)
        ),
    ))
    .into_response()
}

/// Creates the venture record from the wizard: resolve the module set, then
/// `create_venture`. Provisioning it onto Cloudflare (the live deploy) is a
/// separate, needs-human step shown on the venture page.
async fn create_venture_handler(
    State(state): State<Arc<ConsoleState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let ctx = &state.ctx;
    let session = match guard(ctx, &headers) {
        Ok(session) => session,
        Err(redirect) => return redirect,
    };
    let (account, repo) = match account_of(ctx, &session).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };

    let form = parse_form(&body);
    let selected: Vec<String> = form
        .iter()
        .filter(|(k, _)| k == "module")
        .map(|(_, v)| v.clone())
        .collect();
    let slug = form
        .iter()
        .find(|(k, _)| k == "slug")
        .map(|(_, v)| v.trim().to_owned())
        .unwrap_or_default();
    if slug.is_empty() {
        return (StatusCode::BAD_REQUEST, "a slug is required").into_response();
    }

    let catalog = cratefield_catalog::curated();
    let selected_refs: Vec<&str> = selected.iter().map(String::as_str).collect();
    let module_set = match catalog.resolve(&selected_refs) {
        Ok(set) => set.content_key(),
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("could not resolve modules: {err}"),
            )
                .into_response();
        }
    };

    let id = ulid(ctx);
    let now = now_rfc3339(ctx);
    match repo
        .create_venture(&id, &account.id, &slug, &slug, &module_set, &id, &now)
        .await
    {
        Ok(venture) => Redirect::to(&format!("{BASE}/ventures/{}", venture.id)).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "create venture failed");
            internal("could not create the backend")
        }
    }
}

/// One venture: its module set and the provisioning plan (what would run on
/// Cloudflare). The live deploy is needs-human.
#[allow(clippy::format_push_string)]
async fn venture_detail(
    State(state): State<Arc<ConsoleState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let ctx = &state.ctx;
    let session = match guard(ctx, &headers) {
        Ok(session) => session,
        Err(redirect) => return redirect,
    };
    let (account, repo) = match account_of(ctx, &session).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let Some(db) = ctx.ports.db.clone() else {
        return internal("db port unavailable");
    };
    let venture = match repo.venture_for(&account.id, &id).await {
        Ok(Some(venture)) => venture,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such backend").into_response(),
        Err(err) => {
            tracing::error!(error = %err, "venture lookup failed");
            return internal("could not load the backend");
        }
    };

    let engine = cratefield_provisioning::Engine::new(db);
    let plan = engine.plan(&venture).await.unwrap_or_default();
    let mut steps = String::new();
    for step in &plan {
        steps.push_str(&format!(
            "<p class=\"dash__row\"><span class=\"dash__dot{done}\"></span>{desc}\
             <span class=\"dash__meta\">{mark}</span></p>",
            done = if step.done { " dash__dot--live" } else { "" },
            desc = escape(&step.description),
            mark = if step.done { "done" } else { "waiting" },
        ));
    }

    let nav = cratefield_chrome::nav(&[
        cratefield_chrome::NavItem::to("Backends", BASE),
        cratefield_chrome::NavItem::here(
            "Plan",
            &format!("{BASE}/ventures/{}", escape(&venture.id)),
        ),
        cratefield_chrome::NavItem::to("Dashboard", "/v1/dashboard"),
    ]);
    let body = format!(
        "<div class=\"dash__grid\">\
         <div class=\"dash__card\"><p class=\"dash__card-h\">Backend</p>\
         <dl class=\"kv\">\
         <div><dt>Modules</dt><dd><code>{modules}</code></dd></div>\
         <div><dt>Status</dt><dd>{status}</dd></div>\
         <div><dt>Subdomain</dt><dd><em>{subdomain}</em></dd></div></dl></div>\
         <div class=\"dash__card\"><p class=\"dash__card-h\">Provisioning plan \
         <span class=\"dash__tag\">{n} steps</span></p>{steps}</div></div>\
         <p class=\"dash__note\">This is the plan, produced without touching \
         Cloudflare — it is what <em>would</em> run. Standing the backend up needs the \
         account's Cloudflare credentials and a deploy pipeline, and neither is wired, \
         so nothing here has happened yet. What the backend is actually doing lives on \
         its <a href=\"/v1/dashboard/ventures/{id}\">dashboard page</a>.</p>",
        modules = escape(&venture.module_set),
        status = escape(status_label(venture.status)),
        subdomain = escape(&venture.subdomain),
        n = plan.len(),
        id = escape(&venture.id),
    );

    Html(page_for(
        &venture.slug,
        Some(&session.account_id),
        &format!(
            "<p class=\"crumb\"><a href=\"{BASE}\">Backends</a> / {slug}</p>\
             <div class=\"page-h\"><h1>{slug}</h1></div>\
             <p class=\"lede\">What provisioning this backend would do, step by \
             step.</p>{}",
            chrome_frame(&nav, "Plan", &body),
            slug = escape(&venture.slug),
        ),
    ))
    .into_response()
}

/// The signed-in account (created on first login) and a repository over it.
#[allow(clippy::result_large_err)]
async fn account_of(
    ctx: &ModuleContext,
    session: &Session,
) -> Result<
    (
        cratefield_accounts::Account,
        cratefield_accounts::Repository,
    ),
    Response,
> {
    let db = ctx
        .ports
        .db
        .clone()
        .ok_or_else(|| internal("db port unavailable"))?;
    let repo = cratefield_accounts::Repository::new(db);
    let account = repo
        .account_for_login(
            &session.account_id,
            &session.account_id,
            &ulid(ctx),
            &now_rfc3339(ctx),
        )
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "account_for_login failed");
            internal("could not load the account")
        })?;
    Ok((account, repo))
}

fn status_label(status: cratefield_accounts::VentureStatus) -> &'static str {
    use cratefield_accounts::VentureStatus::{Archived, Degraded, Draft, Live, Provisioning};
    match status {
        Draft => "draft",
        Provisioning => "provisioning",
        Live => "live",
        Degraded => "degraded",
        Archived => "archived",
    }
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

/// Parses an `application/x-www-form-urlencoded` body into ordered pairs,
/// keeping repeated keys (checkboxes) rather than collapsing them.
fn parse_form(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (urldecode(key), urldecode(value))
        })
        .collect()
}

fn urldecode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok();
                if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    out.push(byte);
                    index += 3;
                } else {
                    out.push(bytes[index]);
                    index += 1;
                }
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn login_page() -> Response {
    Html(page(
        "Sign in",
        &format!(
            "<div class=\"gate\"><div class=\"dash__card\">\
             <p class=\"dash__card-h\">Sign in</p>\
             <p class=\"dash__note\">Cratefield is invite-only. Sign in with the \
             Google account on the allowlist.</p>\
             <div class=\"dash__act\">\
             <a class=\"btn btn--primary\" href=\"{BASE}/auth/start\">\
             Sign in with Google</a></div></div></div>",
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
            Redirect::to(BASE),
        )
            .into_response(),
        Ok(LoginOutcome::Refused) => (
            StatusCode::FORBIDDEN,
            Html(page(
                "Invite-only",
                &format!(
                    "<div class=\"gate\"><div class=\"dash__card\">\
                     <p class=\"dash__card-h\">Invite only</p>\
                     <p class=\"dash__note\"><strong>{}</strong> is not on the \
                     Cratefield allowlist. No account was created.</p></div></div>",
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
        Redirect::to(LOGIN_PATH),
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
            "Sign-in unavailable",
            "<div class=\"gate\"><div class=\"dash__card\">\
             <p class=\"dash__card-h\">Sign-in unavailable</p>\
             <p class=\"dash__note\">Google sign-in is not configured on this console: \
             <code>CONSOLE_GOOGLE_CLIENT_ID</code>, <code>_SECRET</code> and \
             <code>_BASE_URL</code> are what it needs.</p></div></div>",
        )),
    )
        .into_response()
}

/// Whether the dev-login bypass is enabled (a non-empty `CONSOLE_DEV_LOGIN`).
/// `validate_config` guarantees it is never on in production.
fn dev_login_enabled(ctx: &ModuleContext) -> bool {
    !ModuleConfig::new("console", &*ctx.config)
        .get_str("DEV_LOGIN", "")
        .is_empty()
}

fn now_unix(ctx: &ModuleContext) -> u64 {
    ctx.ports.clock.as_ref().map_or(0, |clock| {
        u64::try_from(clock.now().unix_timestamp()).unwrap_or(0)
    })
}

/// A dev-only shortcut past Google sign-in, for local testing of the guarded
/// console (the wizard, the dashboard) without a Google client. Inert unless
/// `CONSOLE_DEV_LOGIN` is set, and `validate_config` forbids that in
/// production. Mints a session for a fixed local operator.
async fn dev_login(State(state): State<Arc<ConsoleState>>) -> Response {
    let ctx = &state.ctx;
    if !dev_login_enabled(ctx) {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let Some(signer) = ctx.ports.signer.clone() else {
        return internal("signer unavailable");
    };
    let token = issue_session(
        signer.as_ref(),
        "dev@cratefield.local",
        now_unix(ctx),
        DEFAULT_TTL_SECS,
    );
    // Dev-only: omit `Secure` so the cookie survives http://localhost (the
    // real login uses the Secure cookie from `access::session_cookie`).
    let cookie =
        format!("cf_session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={DEFAULT_TTL_SECS}");
    (
        AppendHeaders([(header::SET_COOKIE, cookie)]),
        Redirect::to(BASE),
    )
        .into_response()
}

fn internal(detail: &str) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, detail.to_owned()).into_response()
}

// ---------------------------------------------------------------------------
// Minimal HTML (no template engine; escape all dynamic text)
// ---------------------------------------------------------------------------

/// A signed-out page: the sign-in gate and the two pages that replace it
/// when the console cannot let someone in.
fn page(title: &str, body_html: &str) -> String {
    page_for(title, None, body_html)
}

/// A page rendered inside the shared control-plane chrome
/// ([`cratefield_chrome`]), so the console, the wizard and the dashboard
/// are one product rather than three. `identity` puts the operator in the
/// masthead; `None` leaves it anonymous.
fn page_for(title: &str, identity: Option<&str>, body_html: &str) -> String {
    cratefield_chrome::render(&cratefield_chrome::Page {
        title,
        signed_in_as: identity,
        body: body_html,
    })
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
        db.apply_migrations("accounts", &[cratefield_accounts::MIGRATION])
            .expect("accounts schema");
        db.apply_migrations("provisioning", &[cratefield_provisioning::MIGRATION])
            .expect("provisioning schema");
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

    #[test]
    fn every_console_page_wears_the_shared_chrome() {
        // The console's pages used to build their own bare <html>. The
        // whole point of `cratefield-chrome` is that they stop: a screen
        // that quietly reintroduces a local shell is how the console and
        // the dashboard drifted into looking like two products.
        let signed_out = page("Sign in", "<p>hello</p>");
        let signed_in = page_for("Console", Some("op@cratefield.com"), "<p>hello</p>");

        for rendered in [&signed_out, &signed_in] {
            assert!(
                rendered.contains(cratefield_chrome::STYLESHEET_PATH),
                "a console page must link the shared stylesheet: {rendered}"
            );
            assert!(
                !rendered.contains("<style"),
                "one shared sheet, not per-page CSS: {rendered}"
            );
            assert!(rendered.contains("<p>hello</p>"));
        }

        // And only the signed-in one names anybody.
        assert!(signed_in.contains("op@cratefield.com"));
        assert!(!signed_out.contains("signed in as"));
    }

    #[test]
    fn parse_form_keeps_repeated_checkbox_keys() {
        let pairs = parse_form("module=waitlist&module=cms&slug=my-app&x=a%20b");
        let modules: Vec<&str> = pairs
            .iter()
            .filter(|(k, _)| k == "module")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(modules, ["waitlist", "cms"]);
        assert_eq!(
            pairs
                .iter()
                .find(|(k, _)| k == "slug")
                .map(|(_, v)| v.as_str()),
            Some("my-app")
        );
        assert_eq!(
            pairs
                .iter()
                .find(|(k, _)| k == "x")
                .map(|(_, v)| v.as_str()),
            Some("a b"),
            "percent + plus decoded"
        );
    }

    #[test]
    fn account_and_venture_round_trip_with_a_plan() {
        let ctx = test_ctx(db());
        pollster::block_on(async {
            let session = Session {
                account_id: "op@cratefield.com".to_owned(),
                expires_at: None,
            };
            let (account, repo) = account_of(&ctx, &session).await.expect("account");
            assert_eq!(account.identity, "op@cratefield.com");

            let venture = repo
                .create_venture(
                    "v1",
                    &account.id,
                    "my-app",
                    "my-app",
                    "waitlist",
                    "v1",
                    "2026-09-08T00:00:00Z",
                )
                .await
                .expect("create venture");

            let listed = repo.ventures_for(&account.id).await.unwrap();
            assert_eq!(
                listed.iter().map(|v| v.slug.as_str()).collect::<Vec<_>>(),
                ["my-app"]
            );

            // The provisioning engine can plan the fresh venture (nothing done).
            let engine = cratefield_provisioning::Engine::new(ctx.ports.db.clone().unwrap());
            let plan = engine.plan(&venture).await.expect("plan");
            assert!(!plan.is_empty());
            assert!(plan.iter().all(|step| !step.done));
        });
    }

    /// Builds a `ModuleContext` with a signer + db for the guard tests.
    fn test_ctx(db: Arc<dyn Database>) -> ModuleContext {
        use cratefield_core::{EmptyConfig, EventBus, Ports, TemplateRegistry, Venture};
        let mut ports = Ports::with_config(Arc::new(EmptyConfig));
        ports.signer = Some(Arc::new(signer()));
        ports.db = Some(db);
        ports.id_gen = Some(Arc::new(cratefield_core::UlidIdGen));
        ports.clock = Some(Arc::new(cratefield_core::SystemClock));
        ModuleContext {
            ports,
            config: Arc::new(EmptyConfig),
            events: EventBus::default(),
            templates: Arc::new(TemplateRegistry::default()),
            venture: Arc::new(Venture::new("cratefield-control-plane", "cratefield.com")),
            unprotected_writes_accepted: false,
            personal_data: Arc::new(cratefield_core::PersonalDataCatalog::default()),
            ui_mounted: false,
        }
    }
}
