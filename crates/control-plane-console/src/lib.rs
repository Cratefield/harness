//! The control-plane **console** module (epic #1, issue #3): the first thing a
//! visitor meets. It owns the session gate, the login skeleton, and the
//! operator allowlist action, and — mounted in the venture — it is the
//! composition pattern the wizard (#8) and dashboard (#11) follow.
//!
//! **Four ways in, one gate.** The console signs an operator in with
//! Google, Apple, Facebook, or an emailed magic link (issue #3) — each a
//! flow the console runs itself, ending at a [`VerifiedIdentity`] that
//! goes through the one [`complete_login`] seam: the provider proves
//! *who*, the [`Allowlist`] decides *whether*. No provider adds a second
//! session model, a second identity store, or any way in that skips the
//! invite. The login page offers exactly the ways this deployment has
//! configured and says plainly which exist but are not set up here.
//!
//! **Why the console runs its own flows at all** is the deviation the
//! `google` module records in full (it is private, so this is a name and
//! not a link): the long-term design (#3) is to be
//! a relying party of the deployable `auth-worker`, which already
//! implements all four — but it cannot be deployed from here (Cloudflare,
//! #26), so the console runs provider flows of its own for all four
//! rather than for Google alone. The pieces of the auth crates that a
//! second implementation would drift from (Apple's ES256 secret minting,
//! Meta's Graph profile call) are used from those crates directly,
//! through APIs made public for exactly that.
//!
//! `CONSOLE_DEV_LOGIN` remains the local-testing bypass it always was,
//! including its refusal to start in production.

#![forbid(unsafe_code)]

mod apple;
mod google;
mod magic;
mod meta;
pub use apple::{AppleClient, AppleError};
pub use google::{GoogleClient, GoogleError};
pub use meta::{MetaClient, MetaError};

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
    PersonalDataSet, Port, Signer, SqlMigration, SubjectVia, require_admin,
};
use http::{HeaderMap, StatusCode, header};
use time::format_description::well_known::Rfc3339;

/// Where the console is mounted (`/v1/<name>`), so its own redirects resolve.
const BASE: &str = "/v1/console";

/// The one login gate in the control plane. The console serves it; every
/// other screen redirects here rather than serving a gate of its own, so
/// there is exactly one path a signed-out visitor can land on.
pub const LOGIN_PATH: &str = "/v1/console/login";

/// The short-lived CSRF cookie carrying the OAuth `state` across the
/// Google round-trip. `SameSite=Lax` so it *is* sent on the top-level GET
/// redirect back from Google (Strict would not be).
const STATE_COOKIE: &str = "cf_oauth_state";

/// Apple's state cookie. Apple posts the authorization response back as a
/// cross-site `form_post`, and a browser sends **no** `SameSite=Lax`
/// cookie on one — so this cookie is `SameSite=None; Secure`. With `Lax`
/// here the cookie never arrives, every Apple sign-in reads as a state
/// mismatch, and nothing in the logs says why. The widening costs little:
/// the value is a random CSRF token that is worthless without Apple's own
/// code and a matching state, and it lives ten minutes.
const APPLE_STATE_COOKIE: &str = "cf_apple_state";

/// Meta's state cookie. Meta redirects rather than posts, so `Lax`
/// arrives and nothing needs widening.
const META_STATE_COOKIE: &str = "cf_meta_state";

/// How long an OAuth state cookie lasts, shared by all three providers.
const STATE_COOKIE_MAX_AGE: u64 = 600;

/// The `SameSite` a provider's state cookie is sealed with, decided by how
/// that provider delivers its authorization response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SameSite {
    Lax,
    None,
}

impl SameSite {
    fn as_str(self) -> &'static str {
        match self {
            SameSite::Lax => "Lax",
            SameSite::None => "None",
        }
    }
}

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
        // allowlist and its audit; the http client runs the provider
        // exchanges; the clock and id-gen mint sessions, ids and timestamps
        // (without them declared, view_for hides them and every session's
        // expiry is 0).
        &[
            Port::Signer,
            Port::Db,
            Port::HttpClient,
            Port::Clock,
            Port::IdGen,
        ]
    }

    fn optional(&self) -> &'static [Port] {
        // The mailer carries the magic link, and the rate limiter bounds
        // how many the console will send. Both optional on purpose: a
        // deployment with no mail still offers its other ways in, and the
        // login page hides the magic-link option rather than offering a
        // form that cannot work (the limiter being absent simply means
        // unthrottled sends, the state every login route here shares with
        // auth-oidc's own optional limiter).
        &[Port::Mailer, Port::RateLimiter]
    }

    /// The eight tables this module's `migrations()` create (issues
    /// #280, #31, and the magic link's own). This list is also what a
    /// whole-database `fz data export`/`import` carries, so declaring it
    /// means the control plane's own database — its allowlist, its
    /// accounts and the environments that hang off its ventures — moves
    /// with the venture on a move. That is the right answer: a move that
    /// left the login gate behind would not boot, and one that left the
    /// environments behind would move a venture that had forgotten how
    /// to rehearse a change.
    fn tables(&self) -> &'static [&'static str] {
        &[
            "allowlist",
            "allowlist_audit",
            "account",
            "venture",
            "provision_progress",
            "environment",
            "environment_progress",
            "magic_link",
        ]
    }

    /// What the control plane holds about a person, table by table (issues
    /// #244, #280). The control plane is itself a harness venture, so "what
    /// do you hold about me" is a question an operator's subject can ask it,
    /// and until this existed the answer was: everything, undeclared.
    ///
    /// **Ordering.** The catalogue is ordered so that, under reversal,
    /// `venture` is deleted before the `account` row it references — the same
    /// rule `auth-core` follows with `users` declared first. That ordering is
    /// only load-bearing when one subject value reaches both tables, which it
    /// now does: `venture` declares a join (`subject_via`) through
    /// `account.identity`, so a request made with the operator's
    /// Google-verified address reaches the `venture` rows keyed on the
    /// account's ULID (issue #288). Before the join, the `venture` delete
    /// removed nothing, the `account` delete removed the parent, and `verify`
    /// re-counted with the address, found zero, and wrote a receipt saying
    /// the erasure completed while the rows remained.
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
    /// **One remaining gap: `allowlist.value`, and it is not a join.**
    ///
    /// `allowlist.value` holds either an exact lowercased email or a
    /// `@domain`. A subject access request made with a person's address can
    /// never match the `@domain` row that admits them, because the row does
    /// not contain their address. That cannot be expressed as a
    /// `subject_via` join: a join maps a column through another *table*, and
    /// there is no table mapping a person to the domain that admits them —
    /// the link is inside the value itself, not across a foreign key. What
    /// would close it is a predicate-level rule (for example, letting a
    /// declaration say the subject also matches `value = '@' ||
    /// substr-after-the-@` of the request), and that is a `subject_via`
    /// extension, not something this catalogue can declare today. Not
    /// tracked under #288, which was the join `venture` needed.
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
                subject_via: None,
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
                subject_via: None,
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
                subject_via: None,
            },
            // Declared after `account` so that, under reversal, these rows
            // are deleted before the account row they reference. The
            // ordering is live because of the join below: a request made
            // with the operator's address reaches these rows through
            // `account.identity`, so the child delete still finds them when
            // it runs (issue #288).
            PersonalDataSet {
                table: "venture",
                subject: "account_id",
                kind: DataKind::Identifier,
                disposition: Disposition::Erase,
                description: "The backends you created: each one's name and subdomain, the \
                              modules it carries, where it is in its lifecycle, and when it \
                              was created and last changed.",
                redacted: &[],
                subject_via: Some(SubjectVia {
                    table: "account",
                    subject: "identity",
                    key: "id",
                }),
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
            // The environments that hang off a venture (#31): a name like
            // `staging`, the tenant whose database and secrets the
            // environment owns, its module set, its subdomain. Keyed to a
            // venture and not to a person — the same call
            // `provision_progress` makes one table over — and it is erased
            // with the venture it belongs to rather than carrying a subject
            // of its own, which is why it is `none` rather than a join: the
            // one join it could declare (`venture`, on `account_id`) would
            // reach the account's ULID, and a subject request arrives as the
            // operator's address, a hop the declaration vocabulary does not
            // express.
            PersonalDataSet::none(
                "environment",
                "A backend's environments beside production: each one's name, the tenant whose \
                 database and secret store it owns, the module set it rehearses, and where it \
                 would answer. It is keyed to the backend's id and names nobody.",
            ),
            // An environment's provisioning progress: the same shape and the
            // same verdict as `provision_progress`, one ledger over, because
            // an environment's run is not the venture's run.
            PersonalDataSet::none(
                "environment_progress",
                "One row per environment, holding where its provisioning got to: the last step \
                 that completed and any error message a stopped run recorded. It is keyed to \
                 the environment's id and names nobody.",
            ),
            // The pending magic links (issue #3). A pending magic link **is
            // a person's email address**, with a use-by date: the row says
            // "we mailed this address a way in, and this is how long the
            // door stays open". It is Erase because that is literally what
            // the flow does to it — the redeem deletes the row, and every
            // new request sweeps expired ones — so a subject-access answer
            // or an erasure request finds, at most, links that could still
            // work. No token is stored: the row is keyed by the SHA-256 of
            // the 32 bytes in the URL, which cannot be turned back into
            // the bearer credential, and the mail itself is the only place
            // the link exists whole.
            PersonalDataSet {
                table: "magic_link",
                subject: "email",
                kind: DataKind::Contact,
                disposition: Disposition::Erase,
                description: "A sign-in link we mailed you: your address, held only until \
                              the link is used once or expires (minutes, not hours), then \
                              deleted. The link's secret itself is never stored — only a \
                              one-way hash of it, so this row cannot become a way into \
                              your account.",
                redacted: &[],
                subject_via: None,
            },
        ];
        SETS
    }

    fn migrations(&self) -> Migrations {
        // The console owns the tables its domain crates use: the allowlist +
        // audit (access), accounts + ventures, provisioning progress,
        // environments and their provisioning progress (#31), and the
        // magic-link tokens (access again — the login gate's own
        // ephemeral credential store). Re-id the six sub-schemas so they
        // are unique WITHIN this module: each crate's own MIGRATION is id
        // "0001", which would collide under one module and apply only one
        // table set. Same SQL, same transaction rule (copied, not
        // restated: a sub-schema that later needs to run outside a
        // transaction must not silently run inside one here), distinct
        // ids.
        const MIGRATIONS: [SqlMigration; 6] = [
            if cratefield_access::MIGRATION.transactional {
                SqlMigration::new("0001", "access", cratefield_access::MIGRATION.sql)
            } else {
                SqlMigration::new("0001", "access", cratefield_access::MIGRATION.sql)
                    .non_transactional()
            },
            if cratefield_accounts::MIGRATION.transactional {
                SqlMigration::new("0002", "accounts", cratefield_accounts::MIGRATION.sql)
            } else {
                SqlMigration::new("0002", "accounts", cratefield_accounts::MIGRATION.sql)
                    .non_transactional()
            },
            if cratefield_provisioning::MIGRATION.transactional {
                SqlMigration::new(
                    "0003",
                    "provisioning",
                    cratefield_provisioning::MIGRATION.sql,
                )
            } else {
                SqlMigration::new(
                    "0003",
                    "provisioning",
                    cratefield_provisioning::MIGRATION.sql,
                )
                .non_transactional()
            },
            if cratefield_accounts::ENVIRONMENTS_MIGRATION.transactional {
                SqlMigration::new(
                    "0004",
                    "environments",
                    cratefield_accounts::ENVIRONMENTS_MIGRATION.sql,
                )
            } else {
                SqlMigration::new(
                    "0004",
                    "environments",
                    cratefield_accounts::ENVIRONMENTS_MIGRATION.sql,
                )
                .non_transactional()
            },
            if cratefield_provisioning::ENVIRONMENT_PROGRESS_MIGRATION.transactional {
                SqlMigration::new(
                    "0005",
                    "environment-progress",
                    cratefield_provisioning::ENVIRONMENT_PROGRESS_MIGRATION.sql,
                )
            } else {
                SqlMigration::new(
                    "0005",
                    "environment-progress",
                    cratefield_provisioning::ENVIRONMENT_PROGRESS_MIGRATION.sql,
                )
                .non_transactional()
            },
            // The magic link's own store, last because it arrived last:
            // a set id is unique within the module, and two branches both
            // reaching for "0004" is what `assert_migration_set` exists
            // to refuse.
            if cratefield_access::MIGRATION_MAGIC_LINK.transactional {
                SqlMigration::new(
                    "0006",
                    "magic-link",
                    cratefield_access::MIGRATION_MAGIC_LINK.sql,
                )
            } else {
                SqlMigration::new(
                    "0006",
                    "magic-link",
                    cratefield_access::MIGRATION_MAGIC_LINK.sql,
                )
                .non_transactional()
            },
        ];
        // The array is the apply order; this refuses a gap, a duplicate
        // or an entry out of order at build time (issue #27).
        const _: () = cratefield_core::assert_migration_set(&MIGRATIONS);
        // Every one of the six is portable SQL (TEXT and BIGINT, no
        // dialect functions), so the Postgres set carries the same bytes
        // rather than copies that could drift (ADR 0004: the sets differ
        // only where the SQL truly differs, which here is nowhere).
        const MIGRATIONS_POSTGRES: [SqlMigration; 6] = MIGRATIONS;
        const _: () = cratefield_core::assert_migration_set(&MIGRATIONS_POSTGRES);
        Migrations {
            sqlite: &MIGRATIONS,
            postgres: &MIGRATIONS_POSTGRES,
        }
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
        // The magic-link TTL has to land between "survives a slow mail
        // queue" and "is not a password with a long tail" (the same range
        // auth-magic-link enforces); anything else is a deployment
        // mistake worth naming at boot rather than a link that surprises
        // somebody later.
        let module = ModuleConfig::new("console", cfg);
        if let Some(raw) = module.get_opt("MAGIC_LINK_TTL_SECS")
            && raw
                .trim()
                .parse::<i64>()
                .is_ok_and(|ttl| !(60..=86_400).contains(&ttl))
        {
            errors.push("CONSOLE_MAGIC_LINK_TTL_SECS must be between 60 and 86400 seconds");
        }
        errors.into_result()
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let state = Arc::new(ConsoleState {
            ctx: Arc::new(ctx),
            // Apple's minted client-secret cache: shared across requests
            // so the .p8 is parsed once per secret lifetime, exactly as it
            // is in auth-oidc. Untouched when Apple is not configured.
            apple: factory0_auth_oidc::apple::Minter::new(),
        });
        axum::Router::new()
            .route("/", get(home))
            .route("/login", get(login_page))
            .route("/dev-login", get(dev_login))
            .route("/auth/start", get(auth_start))
            .route("/auth/callback", get(callback))
            // Apple posts its authorization response (response_mode=
            // form_post), so its callback answers a form-encoded POST and
            // only that: a GET here is a 405, not a second way to deliver
            // an authorization response.
            .route("/auth/apple/start", get(apple_start))
            .route("/auth/apple/callback", post(apple_callback))
            .route("/auth/meta/start", get(meta_start))
            .route("/auth/meta/callback", get(meta_callback))
            .route("/magic-link/request", post(magic::magic_request))
            .route(
                "/magic-link/consume",
                get(magic::magic_consume_get).post(magic::magic_consume_post),
            )
            .route("/logout", get(logout))
            .route("/new", get(new_wizard).post(create_venture_handler))
            .route("/ventures/{id}", get(venture_detail))
            .route("/admin/allowlist", post(invite))
            .with_state(state)
    }
}

struct ConsoleState {
    ctx: Arc<ModuleContext>,
    apple: factory0_auth_oidc::apple::Minter,
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

/// The checkbox half of a module row: what you tick.
///
/// The `<label>` wraps the checkbox and the summary line and **stops
/// there**. The detail below it is a sibling, not a child: a `<summary>`
/// inside a label toggles the checkbox when it is clicked, so opening
/// "What it does" would have silently selected the module.
fn module_pick(module: &cratefield_catalog::CatalogModule) -> String {
    format!(
        "<label class=\"mod__pick\">\
         <input type=\"checkbox\" name=\"module\" value=\"{slug}\">\
         <span><span class=\"mod__name\">{name} <code>{slug}</code></span>\
         <span class=\"mod__sum\">{summary}</span></span></label>",
        slug = escape(&module.slug),
        name = escape(&module.name),
        summary = escape(&module.summary),
    )
}

/// The info pane: everything the catalog knows about a module, folded
/// away until somebody asks for it.
///
/// A native `<details>`, so it works with scripting off and needs no
/// stylesheet to hide anything — the one hiding mechanism an author rule
/// cannot accidentally override. A module with no detail (a catalog
/// deserialised from a document written before the field existed) renders
/// nothing rather than an empty pane promising an answer.
fn module_more(module: &cratefield_catalog::CatalogModule) -> String {
    use std::fmt::Write as _;

    let d = &module.detail;
    if d.what_it_is.is_empty() {
        return String::new();
    }
    let joined = |items: &[String]| {
        items
            .iter()
            .map(|i| escape(i))
            .collect::<Vec<_>>()
            .join(" &middot; ")
    };

    let mut facts = String::new();
    let version = module
        .releases
        .first()
        .map_or_else(String::new, |r| format!(" &middot; {}", escape(&r.version)));
    // `write!` into a String cannot fail; the results are discarded the
    // way the rest of this file's rendering does.
    let _ = write!(
        facts,
        "<dt>Crate</dt><dd><code>{}</code>{version}</dd>",
        escape(&d.crate_name)
    );
    if !d.needs.is_empty() {
        let _ = write!(facts, "<dt>Needs</dt><dd>{}</dd>", joined(&d.needs));
    }
    if !d.optional.is_empty() {
        let _ = write!(
            facts,
            "<dt>Uses if present</dt><dd>{}</dd>",
            joined(&d.optional)
        );
    }
    if d.tables.is_empty() {
        // Said out loud, because "no tables" is a fact a customer
        // weighing a module wants — not an omission.
        facts.push_str("<dt>Tables</dt><dd>None. It reads what other modules declare.</dd>");
    } else {
        facts.push_str("<dt>Tables</dt><dd><span class=\"mod__tables\">");
        for table in &d.tables {
            let _ = write!(facts, "<code>{}</code>", escape(table));
        }
        facts.push_str("</span></dd>");
    }
    if let Some(surface) = &d.surface {
        let _ = write!(facts, "<dt>Screens</dt><dd>{}</dd>", escape(surface));
    }

    let mut routes = String::new();
    for route in &d.routes {
        let _ = write!(
            routes,
            "<tr><td class=\"mod__m\">{method}</td>\
             <td><code>{path}</code></td><td>{note}</td></tr>",
            method = escape(&route.method),
            path = escape(&route.path),
            note = escape(&route.note),
        );
    }

    format!(
        "<details class=\"mod__more\"><summary>What it does</summary>\
         <div class=\"mod__detail\"><p class=\"mod__what\">{what}</p>\
         <dl class=\"mod__facts\">{facts}</dl>\
         <p class=\"mod__rh\">Endpoints</p>\
         <table class=\"mod__routes\"><tbody>{routes}</tbody></table>\
         </div></details>",
        what = escape(&d.what_it_is),
    )
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
            "<div class=\"mod\">{pick}{more}</div>",
            pick = module_pick(module),
            more = module_more(module),
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

pub(crate) fn now_rfc3339(ctx: &ModuleContext) -> String {
    ctx.ports
        .clock
        .as_ref()
        .and_then(|clock| clock.now().format(&Rfc3339).ok())
        .unwrap_or_default()
}

/// Parses an `application/x-www-form-urlencoded` body into ordered pairs,
/// keeping repeated keys (checkboxes) rather than collapsing them.
pub(crate) fn parse_form(body: &str) -> Vec<(String, String)> {
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

/// One way into the console, as the login page sees it: a label, whether
/// this deployment offers it, the route a rendered button would point at,
/// and — when it is absent — the settings it needs. The last field is the
/// honesty requirement: a provider whose configuration is missing does not
/// get a button that 503s, it gets named at the bottom of the page with
/// what it would take to turn on.
struct WayIn {
    label: &'static str,
    available: bool,
    /// `None` for the magic link even when available: it renders the
    /// address form below the buttons, not a button of its own.
    href: Option<String>,
    needs: &'static str,
}

/// The ways in this deployment can actually offer, resolved from config
/// and ports each time the page renders. Per-request resolution is
/// deliberate: it is what `google_client` already did, and a deployment
/// that fixes its configuration should not need a redeploy to stop being
/// told its providers are missing.
fn ways_in(ctx: &ModuleContext) -> Vec<WayIn> {
    vec![
        WayIn {
            label: "Sign in with Google",
            available: google_client(ctx).is_some(),
            href: Some(format!("{BASE}/auth/start")),
            needs: "CONSOLE_GOOGLE_CLIENT_ID, CONSOLE_GOOGLE_CLIENT_SECRET and \
                    CONSOLE_BASE_URL",
        },
        WayIn {
            label: "Sign in with Apple",
            available: apple_client(ctx).is_some(),
            href: Some(format!("{BASE}/auth/apple/start")),
            needs: "CONSOLE_APPLE_CLIENT_ID, CONSOLE_APPLE_TEAM_ID, \
                    CONSOLE_APPLE_KEY_ID, CONSOLE_APPLE_PRIVATE_KEY and \
                    CONSOLE_BASE_URL",
        },
        WayIn {
            label: "Sign in with Facebook",
            available: meta_client(ctx).is_some(),
            href: Some(format!("{BASE}/auth/meta/start")),
            needs: "CONSOLE_META_CLIENT_ID, CONSOLE_META_CLIENT_SECRET and \
                    CONSOLE_BASE_URL",
        },
        WayIn {
            label: "Email a sign-in link",
            available: magic::settings(ctx).is_some(),
            href: None,
            needs: "a mailer port, CONSOLE_MAGIC_LINK_FROM and CONSOLE_BASE_URL",
        },
    ]
}

/// The login page: the ways in this deployment can actually offer, and —
/// at the bottom, plainly — the ones that exist but are not configured
/// here. No button is rendered for a provider that cannot complete, which
/// is what replaces the old configured-looking Google button that 503'd
/// because no client was set.
#[allow(clippy::format_push_string)]
async fn login_page(State(state): State<Arc<ConsoleState>>) -> Response {
    let ctx = &state.ctx;
    let ways = ways_in(ctx);

    let mut buttons = String::new();
    let mut unconfigured = Vec::new();
    for way in &ways {
        if let Some(href) = &way.href
            && way.available
        {
            buttons.push_str(&format!(
                "<div class=\"dash__act\"><a class=\"btn btn--primary\" \
                 href=\"{href}\">{}</a></div>",
                way.label
            ));
        }
        if !way.available {
            unconfigured.push(format!("{} (needs {})", way.label, way.needs));
        }
    }
    // The magic-link form in place of a button, when this deployment can
    // mail. It is a form, not a link, because the address is the input.
    if magic::settings(ctx).is_some() {
        buttons.push_str(&format!(
            "<form method=\"post\" action=\"{BASE}/magic-link/request\">\
             <p class=\"field\"><label for=\"magic-email\">Or email a sign-in \
             link</label>\
             <input id=\"magic-email\" name=\"email\" type=\"email\" required \
             autocomplete=\"email\" placeholder=\"you@example.com\"></p>\
             <div class=\"dash__act\"><button class=\"btn\" type=\"submit\">Email \
             me a link</button></div></form>"
        ));
    }
    if dev_login_enabled(ctx) {
        buttons.push_str(&format!(
            "<div class=\"dash__act\"><a class=\"btn\" href=\"{BASE}/dev-login\">\
             Dev sign-in</a></div>"
        ));
    }

    let mut note = String::from(
        "Cratefield is invite-only: every way in below is checked against the \
         operator allowlist before a session is issued.",
    );
    if !unconfigured.is_empty() {
        note.push_str(&format!(
            " Not configured on this deployment: {}.",
            unconfigured.join("; ")
        ));
    }

    Html(page(
        "Sign in",
        &format!(
            "<div class=\"gate\"><div class=\"dash__card\">\
             <p class=\"dash__card-h\">Sign in</p>\
             <p class=\"dash__note\">{note}</p>{buttons}</div></div>",
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
        return provider_not_configured(
            "Google sign-in",
            "CONSOLE_GOOGLE_CLIENT_ID, CONSOLE_GOOGLE_CLIENT_SECRET and CONSOLE_BASE_URL",
        );
    };
    let token = fresh_state(ctx);
    (
        AppendHeaders([(
            header::SET_COOKIE,
            set_state_cookie(STATE_COOKIE, &token, SameSite::Lax),
        )]),
        Redirect::to(&client.authorize_url(&token)),
    )
        .into_response()
}

/// Begins Apple's flow. Identical shape to [`auth_start`] except the
/// cookie: Apple posts its response back cross-site, and only a
/// `SameSite=None` cookie survives that (see [`APPLE_STATE_COOKIE`]).
async fn apple_start(State(state): State<Arc<ConsoleState>>) -> Response {
    let ctx = &state.ctx;
    let Some(client) = apple_client(ctx) else {
        return provider_not_configured(
            "Apple sign-in",
            "CONSOLE_APPLE_CLIENT_ID, CONSOLE_APPLE_TEAM_ID, CONSOLE_APPLE_KEY_ID, \
             CONSOLE_APPLE_PRIVATE_KEY and CONSOLE_BASE_URL",
        );
    };
    let token = fresh_state(ctx);
    (
        AppendHeaders([(
            header::SET_COOKIE,
            set_state_cookie(APPLE_STATE_COOKIE, &token, SameSite::None),
        )]),
        Redirect::to(&client.authorize_url(&token)),
    )
        .into_response()
}

/// Begins Meta's flow. A redirect callback like Google's, so the same
/// `SameSite=Lax` state cookie.
async fn meta_start(State(state): State<Arc<ConsoleState>>) -> Response {
    let ctx = &state.ctx;
    let Some(client) = meta_client(ctx) else {
        return provider_not_configured(
            "Facebook sign-in",
            "CONSOLE_META_CLIENT_ID, CONSOLE_META_CLIENT_SECRET and CONSOLE_BASE_URL",
        );
    };
    let token = fresh_state(ctx);
    (
        AppendHeaders([(
            header::SET_COOKIE,
            set_state_cookie(META_STATE_COOKIE, &token, SameSite::Lax),
        )]),
        Redirect::to(&client.authorize_url(&token)),
    )
        .into_response()
}

/// A fresh CSRF state token from the id-gen port.
fn fresh_state(ctx: &ModuleContext) -> String {
    ctx.ports
        .id_gen
        .as_ref()
        .map_or_else(|| "state".to_owned(), |generator| generator.ulid())
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
        return provider_not_configured(
            "Google sign-in",
            "CONSOLE_GOOGLE_CLIENT_ID, CONSOLE_GOOGLE_CLIENT_SECRET and CONSOLE_BASE_URL",
        );
    };
    let (Some(code), Some(returned_state)) = (params.code, params.state) else {
        return (StatusCode::BAD_REQUEST, "missing code or state").into_response();
    };
    // CSRF: the state returned by Google must match the cookie we set.
    match state_from_cookies(&headers, STATE_COOKIE) {
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

    let now = now_unix(ctx);
    let allowlist = Allowlist::new(db);
    match complete_login(signer.as_ref(), &allowlist, &identity, now).await {
        Ok(LoginOutcome::Admitted { set_cookie }) => (
            AppendHeaders([
                (header::SET_COOKIE, set_cookie),
                (
                    header::SET_COOKIE,
                    clear_state_cookie(STATE_COOKIE, SameSite::Lax),
                ),
            ]),
            Redirect::to(BASE),
        )
            .into_response(),
        Ok(LoginOutcome::Refused) => refused_page(&identity.email),
        Err(err) => {
            tracing::error!(error = %err, "login failed");
            internal("login failed")
        }
    }
}

/// Apple's `form_post` callback: the authorization response arrives as a
/// cross-site, form-encoded `POST`, which is why this route exists
/// separately from [`callback`] and why the flow's state cookie was set
/// `SameSite=None`.
///
/// The body is parsed by hand rather than axum's `Form` extractor so a
/// malformed body gets the same answer as a missing `state` — a body that
/// will not parse is either a spoofed post or a provider change, and
/// neither is worth telling apart. The state cookie is deliberately not
/// cleared on a failed check: this route answers a cross-site POST that
/// carries a `SameSite=None` cookie, so anyone can make a browser send
/// one, and clearing on an unverified request would let a stranger abort
/// a sign-in in progress from any page the victim has open.
async fn apple_callback(
    State(app): State<Arc<ConsoleState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let ctx = &app.ctx;
    let Some(client) = apple_client(ctx) else {
        return provider_not_configured(
            "Apple sign-in",
            "CONSOLE_APPLE_CLIENT_ID, CONSOLE_APPLE_TEAM_ID, CONSOLE_APPLE_KEY_ID, \
             CONSOLE_APPLE_PRIVATE_KEY and CONSOLE_BASE_URL",
        );
    };
    let form = parse_form(&body);
    let field = |name: &str| {
        form.iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    let (Some(code), Some(returned_state)) = (field("code"), field("state")) else {
        return (StatusCode::BAD_REQUEST, "missing code or state").into_response();
    };
    match state_from_cookies(&headers, APPLE_STATE_COOKIE) {
        Some(cookie_state) if cookie_state == returned_state => {}
        _ => return (StatusCode::BAD_REQUEST, "state mismatch").into_response(),
    }

    let (Some(http), Some(db), Some(signer), Some(clock)) = (
        ctx.ports.http.clone(),
        ctx.ports.db.clone(),
        ctx.ports.signer.clone(),
        ctx.ports.clock.clone(),
    ) else {
        return internal("a required port is unavailable");
    };

    let identity = match client
        .exchange(
            &app.apple,
            http.as_ref(),
            clock.as_ref(),
            &code,
            field("user").as_deref(),
        )
        .await
    {
        Ok(identity) => identity,
        Err(err) => {
            tracing::error!(error = %err, "apple exchange failed");
            return (StatusCode::BAD_GATEWAY, "sign-in with Apple failed").into_response();
        }
    };

    let now = now_unix(ctx);
    let allowlist = Allowlist::new(db);
    match complete_login(signer.as_ref(), &allowlist, &identity, now).await {
        Ok(LoginOutcome::Admitted { set_cookie }) => (
            AppendHeaders([
                (header::SET_COOKIE, set_cookie),
                (
                    header::SET_COOKIE,
                    clear_state_cookie(APPLE_STATE_COOKIE, SameSite::None),
                ),
            ]),
            Redirect::to(BASE),
        )
            .into_response(),
        Ok(LoginOutcome::Refused) => refused_page(&identity.email),
        Err(err) => {
            tracing::error!(error = %err, "login failed");
            internal("login failed")
        }
    }
}

/// Meta's redirect callback: the same shape as Google's, over the Meta
/// client. The one case of its own: a profile with no email address —
/// the person declined the permission — cannot be matched against an
/// allowlist keyed on addresses, and is refused with a page that says
/// what to do about it rather than a generic failure.
async fn meta_callback(
    State(app): State<Arc<ConsoleState>>,
    headers: HeaderMap,
    Query(params): Query<CallbackParams>,
) -> Response {
    let ctx = &app.ctx;
    let Some(client) = meta_client(ctx) else {
        return provider_not_configured(
            "Facebook sign-in",
            "CONSOLE_META_CLIENT_ID, CONSOLE_META_CLIENT_SECRET and CONSOLE_BASE_URL",
        );
    };
    let (Some(code), Some(returned_state)) = (params.code, params.state) else {
        return (StatusCode::BAD_REQUEST, "missing code or state").into_response();
    };
    match state_from_cookies(&headers, META_STATE_COOKIE) {
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
        Err(crate::meta::MetaError::NoEmail) => {
            return meta_no_email_page();
        }
        Err(err) => {
            tracing::error!(error = %err, "meta exchange failed");
            return (StatusCode::BAD_GATEWAY, "sign-in with Facebook failed").into_response();
        }
    };

    let now = now_unix(ctx);
    let allowlist = Allowlist::new(db);
    match complete_login(signer.as_ref(), &allowlist, &identity, now).await {
        Ok(LoginOutcome::Admitted { set_cookie }) => (
            AppendHeaders([
                (header::SET_COOKIE, set_cookie),
                (
                    header::SET_COOKIE,
                    clear_state_cookie(META_STATE_COOKIE, SameSite::Lax),
                ),
            ]),
            Redirect::to(BASE),
        )
            .into_response(),
        Ok(LoginOutcome::Refused) => refused_page(&identity.email),
        Err(err) => {
            tracing::error!(error = %err, "login failed");
            internal("login failed")
        }
    }
}

/// The refusal every provider's callback shares: the identity is real, the
/// invite is not there. Named with the address so the person can tell an
/// operator exactly what to invite.
pub(crate) fn refused_page(email: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Html(page(
            "Invite-only",
            &format!(
                "<div class=\"gate\"><div class=\"dash__card\">\
                 <p class=\"dash__card-h\">Invite only</p>\
                 <p class=\"dash__note\"><strong>{}</strong> is not on the \
                 Cratefield allowlist. No account was created.</p>\
                 <div class=\"dash__act\"><a class=\"btn\" href=\"{BASE}/login\">Back \
                 to sign in</a></div></div></div>",
                escape(email)
            ),
        )),
    )
        .into_response()
}

/// A Meta identity with no address cannot be matched to an invite. The
/// page says what to do, because the person can act on this one: grant
/// the email permission and try again, or use another way in.
fn meta_no_email_page() -> Response {
    (
        StatusCode::FORBIDDEN,
        Html(page(
            "No email shared",
            "<div class=\"gate\"><div class=\"dash__card\">\
             <p class=\"dash__card-h\">Facebook did not share an email address</p>\
             <p class=\"dash__note\">Cratefield matches invitations to email \
             addresses, and Facebook sign-in needs the email permission to \
             show one. Grant it and try again, or sign in one of the other \
             ways.</p>\
             <div class=\"dash__act\"><a class=\"btn\" href=\"{BASE}/login\">Back \
             to sign in</a></div></div></div>",
        )),
    )
        .into_response()
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

/// The console's Apple client from config, or `None` when the four
/// `CONSOLE_APPLE_*` settings and `CONSOLE_BASE_URL` are not all present.
/// All five or none: a Services ID with no `.p8` cannot mint a client
/// secret, a key with no Services ID mints one Apple will refuse for
/// somebody else's client, and no base URL means a redirect URI that is
/// a relative path — the button would look configured and the flow could
/// never come back, which is the 503-shaped lie the login page replaces.
fn apple_client(ctx: &ModuleContext) -> Option<crate::apple::AppleClient> {
    let cfg = ModuleConfig::new("console", &*ctx.config);
    let get = |suffix: &str| {
        cfg.get_opt(&format!("APPLE_{suffix}"))
            .filter(|value| !value.trim().is_empty())
    };
    let base = cfg
        .get_opt("BASE_URL")
        .filter(|value| !value.trim().is_empty())?;
    Some(crate::apple::AppleClient {
        client_id: get("CLIENT_ID")?,
        team_id: get("TEAM_ID")?,
        key_id: get("KEY_ID")?,
        private_key: get("PRIVATE_KEY")?,
        redirect_uri: format!(
            "{}{BASE}/auth/apple/callback",
            base.trim().trim_end_matches('/')
        ),
    })
}

/// The console's Meta client from config, or `None` when
/// `CONSOLE_META_*` are not both present. The Graph version defaults to
/// the one the shared `auth-meta` call was written against — check it
/// before deploying, Meta retires versions.
fn meta_client(ctx: &ModuleContext) -> Option<crate::meta::MetaClient> {
    let cfg = ModuleConfig::new("console", &*ctx.config);
    let client_id = cfg.get_str("META_CLIENT_ID", "");
    let client_secret = cfg.get_str("META_CLIENT_SECRET", "");
    let base = cfg.get_str("BASE_URL", "");
    if client_id.is_empty() || client_secret.is_empty() || base.is_empty() {
        return None;
    }
    Some(crate::meta::MetaClient {
        client_id,
        client_secret,
        redirect_uri: format!("{}{BASE}/auth/meta/callback", base.trim_end_matches('/')),
        graph_version: cfg.get_str(
            "META_GRAPH_VERSION",
            factory0_auth_meta::graph::DEFAULT_GRAPH_VERSION,
        ),
    })
}

fn set_state_cookie(name: &str, state: &str, same_site: SameSite) -> String {
    format!(
        "{name}={state}; HttpOnly; Secure; SameSite={}; Path={BASE}; Max-Age={STATE_COOKIE_MAX_AGE}",
        same_site.as_str()
    )
}

fn clear_state_cookie(name: &str, same_site: SameSite) -> String {
    format!(
        "{name}=; HttpOnly; Secure; SameSite={}; Path={BASE}; Max-Age=0",
        same_site.as_str()
    )
}

fn state_from_cookies(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie.split(';').find_map(|pair| {
        let (cookie_name, value) = pair.trim().split_once('=')?;
        (cookie_name == name).then(|| value.to_owned())
    })
}

/// The one answer an unconfigured provider's route gives: which provider,
/// and the settings it needs. Named rather than hidden because the
/// operator reading it can act on exactly that.
pub(crate) fn provider_not_configured(provider: &str, needs: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Html(page(
            "Sign-in unavailable",
            &format!(
                "<div class=\"gate\"><div class=\"dash__card\">\
                 <p class=\"dash__card-h\">Sign-in unavailable</p>\
                 <p class=\"dash__note\">{provider} is not configured on this \
                 console: it needs {needs}.</p></div></div>",
            ),
        )),
    )
        .into_response()
}

/// Percent-encodes one query/form component (unreserved bytes pass
/// through). Shared by the Google, Apple and Meta flows so all three
/// encode identically.
pub(crate) fn enc(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &byte in input.as_bytes() {
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

/// Form-encodes ordered pairs for an `application/x-www-form-urlencoded`
/// body. Shared by the Google, Apple and Meta flows.
pub(crate) fn form_encode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&")
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

pub(crate) fn internal(detail: &str) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, detail.to_owned()).into_response()
}

// ---------------------------------------------------------------------------
// Minimal HTML (no template engine; escape all dynamic text)
// ---------------------------------------------------------------------------

/// A signed-out page: the sign-in gate and the two pages that replace it
/// when the console cannot let someone in.
pub(crate) fn page(title: &str, body_html: &str) -> String {
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
pub(crate) fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
// The fakes below (`AdvancingClock`, `ScriptedHttp`) hold
// `std::sync::Mutex` — the case the workspace clippy.toml calls out:
// interior mutability that is not request state, so ADR 0007 does not
// apply. Allowed on the whole tests module, the same annotation and the
// same reason `google.rs`'s own test module carries.
#[allow(clippy::disallowed_types)]
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
        // The module's own set, so the tests see exactly what a venture
        // applies — including the magic-link table.
        db.apply_migrations("console", Console.migrations().sqlite)
            .expect("console schema");
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

    #[test]
    fn opening_the_detail_cannot_tick_the_checkbox() {
        // A `<summary>` inside a `<label>` toggles that label's control,
        // so a pane nested in the label would select the module the
        // moment somebody read about it. The label has to close first.
        for module in cratefield_catalog::curated().modules {
            let row = format!("{}{}", module_pick(&module), module_more(&module));
            let label_end = row.find("</label>").expect("the pick is a label");
            let pane = row.find("<details").expect("the module has a pane");
            assert!(
                label_end < pane,
                "`{}` renders its pane inside the label, so opening it selects the module",
                module.slug
            );
        }
    }

    #[test]
    fn the_pane_carries_every_fact_the_catalog_holds() {
        for module in cratefield_catalog::curated().modules {
            let pane = module_more(&module);
            let d = &module.detail;
            assert!(
                pane.contains(&escape(&d.crate_name)),
                "`{}` does not name its crate",
                module.slug
            );
            for port in d.needs.iter().chain(d.optional.iter()) {
                assert!(
                    pane.contains(port.as_str()),
                    "`{}` does not show the `{port}` port",
                    module.slug
                );
            }
            for table in &d.tables {
                assert!(
                    pane.contains(table.as_str()),
                    "`{}` does not show the `{table}` table",
                    module.slug
                );
            }
            if d.tables.is_empty() {
                assert!(
                    pane.contains("None. It reads what other modules declare."),
                    "`{}` owns no tables and says nothing about it",
                    module.slug
                );
            }
            for route in &d.routes {
                assert!(
                    pane.contains(&escape(&route.path)),
                    "`{}` does not show `{}`",
                    module.slug,
                    route.path
                );
                assert!(
                    pane.contains(&escape(&route.note)),
                    "`{}` shows `{}` with no explanation",
                    module.slug,
                    route.path
                );
            }
        }
    }

    #[test]
    fn a_module_with_no_detail_renders_no_pane() {
        // A catalog deserialised from a document written before the field
        // existed. An empty `<details>` would promise an answer it does
        // not have.
        let mut module = cratefield_catalog::curated().modules.remove(0);
        module.detail = cratefield_catalog::ModuleDetail::default();
        assert_eq!(module_more(&module), "");
        assert!(module_pick(&module).contains("type=\"checkbox\""));
    }

    #[test]
    fn prose_from_the_catalog_is_escaped_into_the_pane() {
        let mut module = cratefield_catalog::curated().modules.remove(0);
        module.detail.what_it_is = "<script>alert(1)</script>".to_owned();
        let pane = module_more(&module);
        assert!(!pane.contains("<script>"), "{pane}");
        assert!(pane.contains("&lt;script&gt;"), "{pane}");
    }

    // -----------------------------------------------------------------------
    // The four ways in: router-level acceptance tests (issue #3)
    // -----------------------------------------------------------------------

    /// A clock the test moves, because "the link fails after its TTL" is a
    /// claim about time and `SystemClock` cannot be argued with.
    struct AdvancingClock(Arc<std::sync::Mutex<time::OffsetDateTime>>);

    impl AdvancingClock {
        fn at(moment: time::OffsetDateTime) -> Arc<Self> {
            Arc::new(Self(Arc::new(std::sync::Mutex::new(moment))))
        }
        fn advance(&self, secs: i64) {
            *self.0.lock().expect("clock") += time::Duration::seconds(secs);
        }
    }

    impl cratefield_core::Clock for AdvancingClock {
        fn now(&self) -> time::OffsetDateTime {
            *self.0.lock().expect("clock")
        }
    }

    /// The provider exchanges run against a queue of canned responses, the
    /// same fake `google.rs`'s own tests use, promoted here because the
    /// callbacks need it too.
    struct ScriptedHttp {
        responses: std::sync::Mutex<std::collections::VecDeque<(u16, String)>>,
    }

    impl ScriptedHttp {
        fn with(responses: &[(u16, String)]) -> Arc<Self> {
            Arc::new(Self {
                responses: std::sync::Mutex::new(responses.iter().cloned().collect()),
            })
        }
    }

    #[async_trait::async_trait]
    impl cratefield_core::HttpClient for ScriptedHttp {
        async fn send(
            &self,
            _request: http::Request<bytes::Bytes>,
        ) -> Result<http::Response<bytes::Bytes>, cratefield_core::HttpError> {
            let (status, body) = self
                .responses
                .lock()
                .expect("script")
                .pop_front()
                .expect("a scripted response");
            Ok(http::Response::builder()
                .status(status)
                .body(bytes::Bytes::from(body))
                .expect("response"))
        }
    }

    /// What a handler answered, distilled for asserting on.
    struct Reply {
        status: StatusCode,
        location: String,
        set_cookies: Vec<String>,
        body: String,
    }

    async fn call(router: &axum::Router, request: http::Request<axum::body::Body>) -> Reply {
        use tower::util::ServiceExt as _;
        let response = router
            .clone()
            .oneshot(request)
            .await
            .expect("the router answers");
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, 1024 * 1024).await.expect("body");
        Reply {
            status: parts.status,
            location: parts
                .headers
                .get(header::LOCATION)
                .map(|value| value.to_str().unwrap_or_default().to_owned())
                .unwrap_or_default(),
            set_cookies: parts
                .headers
                .get_all(header::SET_COOKIE)
                .iter()
                .map(|value| value.to_str().unwrap_or_default().to_owned())
                .collect(),
            body: String::from_utf8(bytes.to_vec()).expect("utf-8"),
        }
    }

    /// The module router serves its routes unprefixed; the harness is
    /// what mounts them under `/v1/console`. Tests ask with the public
    /// path — the same URL a rendered button carries — and this maps it
    /// onto the module route, so a request and the href it follows can
    /// never drift apart in the source.
    fn route(path: &str) -> String {
        path.strip_prefix(BASE).unwrap_or(path).to_owned()
    }

    fn get(uri: &str, headers: &[(&str, &str)]) -> http::Request<axum::body::Body> {
        let mut builder = http::Request::builder().method("GET").uri(route(uri));
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(axum::body::Body::empty()).expect("request")
    }

    fn post_form(
        uri: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> http::Request<axum::body::Body> {
        let mut builder = http::Request::builder()
            .method("POST")
            .uri(route(uri))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder
            .body(axum::body::Body::from(body.to_owned()))
            .expect("request")
    }

    /// The console over real config, real ports (faked at the edges) and
    /// the module's own migrations — the surface the acceptance tests
    /// drive, one `MapConfig` at a time.
    struct Kit {
        router: axum::Router,
        db: Arc<dyn Database>,
        mailer: cratefield_testing::FakeMailer,
        clock: Arc<AdvancingClock>,
    }

    fn kit(config: cratefield_core::MapConfig) -> Kit {
        kit_over(config, &ScriptedHttp::with(&[]))
    }

    fn kit_over(config: cratefield_core::MapConfig, http: &Arc<ScriptedHttp>) -> Kit {
        use cratefield_core::{EventBus, Ports, TemplateRegistry, Venture};
        let db = db();
        let mailer = cratefield_testing::FakeMailer::new(cratefield_testing::MailerMode::SendOk);
        let clock = AdvancingClock::at(
            time::OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("a fixed moment"),
        );
        // The one config the module reads: `Ports::with_config` owns it,
        // and `ModuleConfig::new` reads through `ports.config`.
        let config: Arc<dyn cratefield_core::Config> = Arc::new(config);
        let mut ports = Ports::with_config(Arc::clone(&config));
        ports.signer = Some(Arc::new(signer()));
        ports.db = Some(Arc::clone(&db));
        ports.id_gen = Some(Arc::new(cratefield_core::UlidIdGen));
        ports.clock = Some(Arc::clone(&clock) as Arc<dyn cratefield_core::Clock>);
        ports.http = Some(Arc::clone(http) as Arc<dyn cratefield_core::HttpClient>);
        ports.mailer = Some(Arc::new(mailer.clone()));
        let ctx = ModuleContext {
            ports,
            config,
            events: EventBus::default(),
            templates: Arc::new(TemplateRegistry::default()),
            venture: Arc::new(Venture::new("cratefield-control-plane", "cratefield.com")),
            unprotected_writes_accepted: false,
            personal_data: Arc::new(cratefield_core::PersonalDataCatalog::default()),
            ui_mounted: false,
        };
        Kit {
            router: Console.router(ctx),
            db,
            mailer,
            clock,
        }
    }

    /// Puts one address on the kit's allowlist, the way `POST
    /// /admin/allowlist` would.
    async fn invite(kit: &Kit, email: &str) {
        Allowlist::new(Arc::clone(&kit.db))
            .allow(
                email,
                EntryKind::Email,
                "test",
                "seed",
                &format!("id-{email}"),
                "2026-01-01T00:00:00Z",
            )
            .await
            .expect("seed the allowlist");
    }

    /// Takes `name=value` out of a `Set-Cookie` line, as a browser would
    /// store and resend it.
    fn cookie_pair(set_cookie: &str) -> String {
        set_cookie.split(';').next().expect("name=value").to_owned()
    }

    /// The `state` query parameter out of a redirect Location.
    fn state_from(location: &str) -> String {
        location
            .split("state=")
            .nth(1)
            .and_then(|rest| rest.split('&').next())
            .expect("a state parameter")
            .to_owned()
    }

    /// The mailed link's token, out of the fake mailer's recorded text.
    fn token_from(message: &cratefield_core::Message) -> String {
        message
            .text
            .split("token=")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .expect("a token in the mailed link")
            .to_owned()
    }

    const CLICK_HEADERS: &[(&str, &str)] = &[
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-dest", "document"),
    ];

    #[pollster::test]
    async fn the_login_page_with_nothing_configured_offers_dev_login_and_names_the_rest() {
        let kit = kit(cratefield_core::MapConfig::from_pairs([(
            "CONSOLE_DEV_LOGIN",
            "1",
        )]));
        let page = call(&kit.router, get("/v1/console/login", &[])).await;

        assert_eq!(page.status, StatusCode::OK);
        // Dev sign-in is offered — it always works.
        assert!(page.body.contains("/v1/console/dev-login"));
        // Every provider that exists is named as unconfigured, with what
        // it would take to turn it on.
        assert!(page.body.contains("Not configured on this deployment"));
        for label in [
            "Sign in with Google",
            "Sign in with Apple",
            "Sign in with Facebook",
            "Email a sign-in link",
        ] {
            assert!(page.body.contains(label), "missing {label}");
        }
        assert!(page.body.contains("CONSOLE_GOOGLE_CLIENT_ID"));
        assert!(page.body.contains("CONSOLE_APPLE_PRIVATE_KEY"));
        assert!(page.body.contains("CONSOLE_META_CLIENT_SECRET"));
        assert!(page.body.contains("CONSOLE_MAGIC_LINK_FROM"));
        // And no button that cannot work: none of the provider starts,
        // and no magic-link form taking an address there is no mailer for.
        assert!(!page.body.contains("/v1/console/auth/start"));
        assert!(!page.body.contains("/v1/console/auth/apple/start"));
        assert!(!page.body.contains("/v1/console/auth/meta/start"));
        assert!(!page.body.contains("/v1/console/magic-link/request"));
    }

    #[pollster::test]
    async fn every_configured_way_in_gets_its_button() {
        let kit = kit(cratefield_core::MapConfig::from_pairs([
            ("CONSOLE_GOOGLE_CLIENT_ID", "gid"),
            ("CONSOLE_GOOGLE_CLIENT_SECRET", "gsecret"),
            ("CONSOLE_APPLE_CLIENT_ID", "aid"),
            ("CONSOLE_APPLE_TEAM_ID", "team"),
            ("CONSOLE_APPLE_KEY_ID", "key"),
            ("CONSOLE_APPLE_PRIVATE_KEY", "not-a-real-p8-but-nonempty"),
            ("CONSOLE_META_CLIENT_ID", "mid"),
            ("CONSOLE_META_CLIENT_SECRET", "msecret"),
            ("CONSOLE_MAGIC_LINK_FROM", "noreply@cratefield.com"),
            ("CONSOLE_BASE_URL", "https://console.cratefield.com"),
        ]));
        let page = call(&kit.router, get("/v1/console/login", &[])).await;

        assert_eq!(page.status, StatusCode::OK);
        assert!(
            page.body.contains("/v1/console/auth/start"),
            "google button"
        );
        assert!(
            page.body.contains("/v1/console/auth/apple/start"),
            "apple button"
        );
        assert!(
            page.body.contains("/v1/console/auth/meta/start"),
            "meta button"
        );
        assert!(
            page.body.contains("/v1/console/magic-link/request"),
            "the email-link form"
        );
        assert!(
            !page.body.contains("Not configured on this deployment"),
            "everything is configured here"
        );
    }

    #[pollster::test]
    async fn apple_without_a_base_url_is_not_configured_either() {
        // The four signing settings alone used to light the button while
        // the redirect URI was a relative path — a configured-looking way
        // in that could never come back.
        let kit = kit(cratefield_core::MapConfig::from_pairs([
            ("CONSOLE_APPLE_CLIENT_ID", "aid"),
            ("CONSOLE_APPLE_TEAM_ID", "team"),
            ("CONSOLE_APPLE_KEY_ID", "key"),
            ("CONSOLE_APPLE_PRIVATE_KEY", "not-a-real-p8-but-nonempty"),
        ]));
        let page = call(&kit.router, get("/v1/console/login", &[])).await;
        assert!(!page.body.contains("/v1/console/auth/apple/start"));
        assert!(page.body.contains("CONSOLE_BASE_URL"));
    }

    #[pollster::test]
    async fn a_magic_link_lands_a_session_and_fails_the_second_time() {
        let kit = kit(cratefield_core::MapConfig::from_pairs([
            ("CONSOLE_MAGIC_LINK_FROM", "noreply@cratefield.com"),
            ("CONSOLE_BASE_URL", "https://console.cratefield.com"),
        ]));
        invite(&kit, "op@cratefield.com").await;

        let asked = call(
            &kit.router,
            post_form(
                "/v1/console/magic-link/request",
                &[],
                "email=op@cratefield.com",
            ),
        )
        .await;
        assert_eq!(asked.status, StatusCode::OK);
        assert!(asked.body.contains("Check your mail"));

        // The positive half: the mail really went out, to that address,
        // carrying a link.
        let sent = kit.mailer.sent();
        assert_eq!(sent.len(), 1, "exactly one mail");
        assert_eq!(sent[0].to, "op@cratefield.com");
        assert!(sent[0].text.contains("/magic-link/consume?token="));
        let token = token_from(&sent[0]);

        // Following the link as a person clicking would lands a session.
        let landed = call(
            &kit.router,
            get(
                &format!("/v1/console/magic-link/consume?token={token}"),
                CLICK_HEADERS,
            ),
        )
        .await;
        assert_eq!(landed.status, StatusCode::SEE_OTHER);
        assert_eq!(landed.location, "/v1/console");
        let session_cookie = landed
            .set_cookies
            .iter()
            .find(|cookie| cookie.starts_with("cf_session="))
            .expect("a session cookie");
        let token = session_token_from_cookie_header(session_cookie).unwrap();
        let session = read_session(&signer(), token).expect("a proven session");
        assert_eq!(session.account_id, "op@cratefield.com");

        // The same link again is dead: a mail archive is not an
        // authentication factor.
        let again = call(
            &kit.router,
            get(
                &format!("/v1/console/magic-link/consume?token={token}"),
                CLICK_HEADERS,
            ),
        )
        .await;
        assert_eq!(again.status, StatusCode::BAD_REQUEST);
        assert!(again.body.contains("no longer valid"));
    }

    #[pollster::test]
    async fn the_magic_link_form_does_not_disclose_who_is_invited() {
        // Both halves in one test on purpose: the endpoint could pass the
        // non-disclosure half by being broken (mailing nobody, answering
        // nothing), so the test also proves the invited address really
        // got a mail through the fake mailer.
        let kit = kit(cratefield_core::MapConfig::from_pairs([
            ("CONSOLE_MAGIC_LINK_FROM", "noreply@cratefield.com"),
            ("CONSOLE_BASE_URL", "https://console.cratefield.com"),
        ]));
        invite(&kit, "op@cratefield.com").await;

        let invited = call(
            &kit.router,
            post_form(
                "/v1/console/magic-link/request",
                &[],
                "email=op@cratefield.com",
            ),
        )
        .await;
        let uninvited = call(
            &kit.router,
            post_form(
                "/v1/console/magic-link/request",
                &[],
                "email=stranger@example.com",
            ),
        )
        .await;

        // Same page, byte for byte, same status.
        assert_eq!(invited.status, StatusCode::OK);
        assert_eq!(uninvited.status, StatusCode::OK);
        assert_eq!(
            invited.body, uninvited.body,
            "the form is an oracle for the invite list if these differ"
        );

        // And the page names neither address.
        assert!(!invited.body.contains("op@cratefield.com"));
        assert!(!uninvited.body.contains("stranger@example.com"));

        // The positive half: exactly the invited address was mailed.
        let sent = kit.mailer.sent();
        assert_eq!(sent.len(), 1, "the invited address, and nobody else");
        assert_eq!(sent[0].to, "op@cratefield.com");
    }

    #[pollster::test]
    async fn a_magic_link_dies_with_its_ttl() {
        let kit = kit(cratefield_core::MapConfig::from_pairs([
            ("CONSOLE_MAGIC_LINK_FROM", "noreply@cratefield.com"),
            ("CONSOLE_BASE_URL", "https://console.cratefield.com"),
            ("CONSOLE_MAGIC_LINK_TTL_SECS", "60"),
        ]));
        invite(&kit, "op@cratefield.com").await;

        call(
            &kit.router,
            post_form(
                "/v1/console/magic-link/request",
                &[],
                "email=op@cratefield.com",
            ),
        )
        .await;
        let token = token_from(&kit.mailer.last_message().expect("the mail"));

        kit.clock.advance(61);
        let late = call(
            &kit.router,
            get(
                &format!("/v1/console/magic-link/consume?token={token}"),
                CLICK_HEADERS,
            ),
        )
        .await;
        assert_eq!(late.status, StatusCode::BAD_REQUEST);
        assert!(late.body.contains("no longer valid"));
    }

    #[pollster::test]
    async fn a_prefetched_magic_link_is_not_spent_by_the_prefetch() {
        // Mail clients and scanners fetch every URL in a message. A naive
        // single-use token dies to the prefetch; here the metadata-less
        // GET lands on a confirm page and the token survives for the
        // person's click.
        let kit = kit(cratefield_core::MapConfig::from_pairs([
            ("CONSOLE_MAGIC_LINK_FROM", "noreply@cratefield.com"),
            ("CONSOLE_BASE_URL", "https://console.cratefield.com"),
        ]));
        invite(&kit, "op@cratefield.com").await;

        call(
            &kit.router,
            post_form(
                "/v1/console/magic-link/request",
                &[],
                "email=op@cratefield.com",
            ),
        )
        .await;
        let token = token_from(&kit.mailer.last_message().expect("the mail"));

        // No fetch metadata at all: an old browser, or a scanner.
        let prefetched = call(
            &kit.router,
            get(
                &format!("/v1/console/magic-link/consume?token={token}"),
                &[],
            ),
        )
        .await;
        assert_eq!(prefetched.status, StatusCode::OK);
        assert!(prefetched.body.contains("Sign in to Cratefield?"));
        assert!(
            prefetched.body.contains(&format!("value=\"{token}\"")),
            "the confirm form carries the token for the button"
        );
        assert!(
            !prefetched.body.contains("cf_session"),
            "the prefetch signed nobody in"
        );

        // The person's click — the confirm button — still works.
        let confirmed = call(
            &kit.router,
            post_form(
                "/v1/console/magic-link/consume",
                &[],
                &format!("token={token}"),
            ),
        )
        .await;
        assert_eq!(confirmed.status, StatusCode::SEE_OTHER);
        assert!(
            confirmed
                .set_cookies
                .iter()
                .any(|cookie| cookie.starts_with("cf_session="))
        );
    }

    #[pollster::test]
    async fn a_magic_link_for_an_address_revoked_since_it_was_mailed_is_refused() {
        // Admission is re-checked at redeem, so revoking the invite
        // between the mail and the click refuses the click — the link is
        // a credential for an address, not a promise the address stays
        // invited.
        let kit = kit(cratefield_core::MapConfig::from_pairs([
            ("CONSOLE_MAGIC_LINK_FROM", "noreply@cratefield.com"),
            ("CONSOLE_BASE_URL", "https://console.cratefield.com"),
        ]));
        invite(&kit, "op@cratefield.com").await;
        call(
            &kit.router,
            post_form(
                "/v1/console/magic-link/request",
                &[],
                "email=op@cratefield.com",
            ),
        )
        .await;
        let token = token_from(&kit.mailer.last_message().expect("the mail"));

        Allowlist::new(Arc::clone(&kit.db))
            .revoke(
                "op@cratefield.com",
                "operator",
                "rev-id",
                "2026-01-02T00:00:00Z",
            )
            .await
            .expect("revoke");

        let refused = call(
            &kit.router,
            get(
                &format!("/v1/console/magic-link/consume?token={token}"),
                CLICK_HEADERS,
            ),
        )
        .await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN);
        assert!(refused.body.contains("not on the Cratefield allowlist"));
    }

    // --- Apple ------------------------------------------------------------

    /// A real P-256 PKCS#8 key, because the minter parses the `.p8` for
    /// real — the whole point of sharing it rather than faking past it.
    fn dev_apple_key() -> String {
        use p256::pkcs8::EncodePrivateKey as _;
        let secret = p256::SecretKey::from_slice(&[0x42; 32]).expect("a valid scalar");
        let signing = p256::ecdsa::SigningKey::from(&secret);
        signing
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("a pem")
            .to_string()
    }

    fn apple_config() -> cratefield_core::MapConfig {
        cratefield_core::MapConfig::from_pairs([
            ("CONSOLE_APPLE_CLIENT_ID", "com.cratefield.console"),
            ("CONSOLE_APPLE_TEAM_ID", "TEAM000000"),
            ("CONSOLE_APPLE_KEY_ID", "KEY0000000"),
            ("CONSOLE_APPLE_PRIVATE_KEY", &dev_apple_key()),
            ("CONSOLE_BASE_URL", "https://console.cratefield.com"),
        ])
    }

    /// An `id_token` shaped like Apple's: three base64url segments, the
    /// middle one JSON. The signature segment is filler because the
    /// console does not verify it — it came from Apple over our own
    /// back-channel, which is the documented trust argument.
    fn apple_id_token(aud: &str, email: &str, verified: &serde_json::Value) -> String {
        use base64ct::{Base64UrlUnpadded, Encoding as _};
        let header = br#"{"alg":"RS256"}"#;
        let claims = serde_json::json!({
            "iss": "https://appleid.apple.com",
            "aud": aud,
            "email": email,
            "email_verified": verified,
        });
        format!(
            "{}.{}.not-a-signature",
            Base64UrlUnpadded::encode_string(header),
            Base64UrlUnpadded::encode_string(claims.to_string().as_bytes()),
        )
    }

    #[pollster::test]
    async fn apples_state_cookie_is_built_to_survive_the_cross_site_form_post() {
        let kit = kit(apple_config());
        let started = call(&kit.router, get("/v1/console/auth/apple/start", &[])).await;

        assert_eq!(started.status, StatusCode::SEE_OTHER);
        assert!(
            started
                .location
                .starts_with("https://appleid.apple.com/auth/authorize")
        );
        assert!(
            started.location.contains("response_mode=form_post"),
            "the flow asks for the form post it is built to answer"
        );
        let state_cookie = started
            .set_cookies
            .iter()
            .find(|cookie| cookie.starts_with(APPLE_STATE_COOKIE))
            .expect("a state cookie");
        assert!(
            state_cookie.contains("SameSite=None"),
            "a Lax cookie never arrives on Apple's cross-site POST: {state_cookie}"
        );
        assert!(state_cookie.contains("Secure"));
    }

    #[pollster::test]
    async fn apples_form_post_callback_signs_in_through_the_cross_site_post() {
        let http = ScriptedHttp::with(&[(
            200,
            format!(
                r#"{{"id_token":"{}","token_type":"Bearer"}}"#,
                apple_id_token(
                    "com.cratefield.console",
                    "op@cratefield.com",
                    &"true".into()
                )
            ),
        )]);
        let kit = kit_over(apple_config(), &http);
        invite(&kit, "op@cratefield.com").await;

        // A GET to the form_post callback is a 405, not a second way to
        // deliver an authorization response.
        let wrong_method = call(
            &kit.router,
            get("/v1/console/auth/apple/callback?code=c&state=s", &[]),
        )
        .await;
        assert_eq!(wrong_method.status, StatusCode::METHOD_NOT_ALLOWED);

        // The round trip: start, then answer the cross-site POST Apple
        // makes — form-encoded body, the state cookie the flow set.
        let started = call(&kit.router, get("/v1/console/auth/apple/start", &[])).await;
        let state = state_from(&started.location);
        let cookie = cookie_pair(
            started
                .set_cookies
                .iter()
                .find(|cookie| cookie.starts_with(APPLE_STATE_COOKIE))
                .expect("the state cookie"),
        );
        let user = r#"{"name":{"firstName":"Op","lastName":"Erator"}}"#;
        let landed = call(
            &kit.router,
            post_form(
                "/v1/console/auth/apple/callback",
                &[("cookie", &cookie)],
                &format!("code=the_code&state={}&user={}", state, crate::enc(user)),
            ),
        )
        .await;

        assert_eq!(landed.status, StatusCode::SEE_OTHER, "{}", landed.body);
        assert_eq!(landed.location, "/v1/console");
        let session_cookie = landed
            .set_cookies
            .iter()
            .find(|cookie| cookie.starts_with("cf_session="))
            .expect("a session cookie");
        let token = session_token_from_cookie_header(session_cookie).unwrap();
        let session = read_session(&signer(), token).expect("a proven session");
        assert_eq!(session.account_id, "op@cratefield.com");
        // The state cookie is cleared with the same attributes it was
        // set with, or the clear itself would not stick.
        assert!(landed.set_cookies.iter().any(|cookie| {
            cookie.starts_with(&format!("{APPLE_STATE_COOKIE}=;"))
                && cookie.contains("SameSite=None")
        }));
    }

    #[pollster::test]
    async fn apples_callback_refuses_a_mismatched_state() {
        let kit = kit(apple_config());
        let started = call(&kit.router, get("/v1/console/auth/apple/start", &[])).await;
        let cookie = cookie_pair(
            started
                .set_cookies
                .iter()
                .find(|cookie| cookie.starts_with(APPLE_STATE_COOKIE))
                .expect("the state cookie"),
        );
        let spoofed = call(
            &kit.router,
            post_form(
                "/v1/console/auth/apple/callback",
                &[("cookie", &cookie)],
                "code=the_code&state=not-the-state",
            ),
        )
        .await;
        assert_eq!(spoofed.status, StatusCode::BAD_REQUEST);
        assert_eq!(spoofed.body, "state mismatch");
    }

    // --- Every provider's refusal -----------------------------------------

    #[pollster::test]
    async fn a_non_allowlisted_identity_from_each_provider_is_refused() {
        // Google: the exchange succeeds and yields a stranger.
        let http = ScriptedHttp::with(&[
            (
                200,
                r#"{"access_token":"at","token_type":"Bearer"}"#.to_owned(),
            ),
            (
                200,
                r#"{"email":"stranger@example.com","email_verified":true,"name":"S"}"#.to_owned(),
            ),
        ]);
        let kit = kit_over(
            cratefield_core::MapConfig::from_pairs([
                ("CONSOLE_GOOGLE_CLIENT_ID", "gid"),
                ("CONSOLE_GOOGLE_CLIENT_SECRET", "gsecret"),
                ("CONSOLE_BASE_URL", "https://console.cratefield.com"),
            ]),
            &http,
        );
        let started = call(&kit.router, get("/v1/console/auth/start", &[])).await;
        let state = state_from(&started.location);
        let cookie = cookie_pair(
            started
                .set_cookies
                .iter()
                .find(|cookie| cookie.starts_with(STATE_COOKIE))
                .expect("the google state cookie"),
        );
        let refused = call(
            &kit.router,
            get(
                &format!("/v1/console/auth/callback?code=c&state={state}"),
                &[("cookie", &cookie)],
            ),
        )
        .await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN);
        assert!(refused.body.contains("stranger@example.com"));
        assert!(refused.body.contains("not on the Cratefield allowlist"));

        // Apple: same, through the form post.
        let http = ScriptedHttp::with(&[(
            200,
            format!(
                r#"{{"id_token":"{}"}}"#,
                apple_id_token(
                    "com.cratefield.console",
                    "stranger@example.com",
                    &true.into()
                )
            ),
        )]);
        let kit = kit_over(apple_config(), &http);
        let started = call(&kit.router, get("/v1/console/auth/apple/start", &[])).await;
        let state = state_from(&started.location);
        let cookie = cookie_pair(
            started
                .set_cookies
                .iter()
                .find(|cookie| cookie.starts_with(APPLE_STATE_COOKIE))
                .expect("the apple state cookie"),
        );
        let refused = call(
            &kit.router,
            post_form(
                "/v1/console/auth/apple/callback",
                &[("cookie", &cookie)],
                &format!("code=c&state={state}"),
            ),
        )
        .await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN);
        assert!(refused.body.contains("stranger@example.com"));

        // Meta: a profile with a stranger's address.
        let http = ScriptedHttp::with(&[
            (
                200,
                r#"{"access_token":"at","token_type":"bearer"}"#.to_owned(),
            ),
            (
                200,
                r#"{"id":"101","name":"S","email":"stranger@example.com"}"#.to_owned(),
            ),
        ]);
        let kit = kit_over(
            cratefield_core::MapConfig::from_pairs([
                ("CONSOLE_META_CLIENT_ID", "mid"),
                ("CONSOLE_META_CLIENT_SECRET", "msecret"),
                ("CONSOLE_BASE_URL", "https://console.cratefield.com"),
            ]),
            &http,
        );
        let started = call(&kit.router, get("/v1/console/auth/meta/start", &[])).await;
        let state = state_from(&started.location);
        let cookie = cookie_pair(
            started
                .set_cookies
                .iter()
                .find(|cookie| cookie.starts_with(META_STATE_COOKIE))
                .expect("the meta state cookie"),
        );
        let refused = call(
            &kit.router,
            get(
                &format!("/v1/console/auth/meta/callback?code=c&state={state}"),
                &[("cookie", &cookie)],
            ),
        )
        .await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN);
        assert!(refused.body.contains("stranger@example.com"));

        // The magic link's refusal is the revoked-after-mail case, proven
        // in its own test above: only allowlisted addresses are ever
        // mailed, and the redeem re-checks admission.
    }

    #[pollster::test]
    async fn a_meta_identity_without_an_email_is_refused_with_a_page_saying_what_to_do() {
        let http = ScriptedHttp::with(&[
            (
                200,
                r#"{"access_token":"at","token_type":"bearer"}"#.to_owned(),
            ),
            // The person declined the email permission: /me has no
            // address to match an invite against.
            (200, r#"{"id":"101","name":"No Address"}"#.to_owned()),
        ]);
        let kit = kit_over(
            cratefield_core::MapConfig::from_pairs([
                ("CONSOLE_META_CLIENT_ID", "mid"),
                ("CONSOLE_META_CLIENT_SECRET", "msecret"),
                ("CONSOLE_BASE_URL", "https://console.cratefield.com"),
            ]),
            &http,
        );
        let started = call(&kit.router, get("/v1/console/auth/meta/start", &[])).await;
        let state = state_from(&started.location);
        let cookie = cookie_pair(
            started
                .set_cookies
                .iter()
                .find(|cookie| cookie.starts_with(META_STATE_COOKIE))
                .expect("the meta state cookie"),
        );
        let refused = call(
            &kit.router,
            get(
                &format!("/v1/console/auth/meta/callback?code=c&state={state}"),
                &[("cookie", &cookie)],
            ),
        )
        .await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN);
        assert!(refused.body.contains("did not share an email address"));
        assert!(refused.body.contains("email permission"));
    }
}
