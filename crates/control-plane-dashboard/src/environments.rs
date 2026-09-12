//! The Environments screen (control-plane #31): production, staging
//! beside it, and a promotion that rehearses before it moves.
//!
//! Today a venture is one thing — one database, one set of secrets, one
//! module set, deployed once — so every schema change is tested in
//! production. This screen exists to end that. An environment belongs
//! to a venture and has its own database, its own secret store and its
//! own module set; production is the venture as it already exists
//! (derived, never mirrored — see the accounts crate for why a stored
//! copy was rejected), and staging is created alongside it.
//!
//! Creating staging runs the same provisioning engine as anything else,
//! against the environment's own tenant, and stops where every
//! provisioning run stops today: the [`Unwired`] deployer, honestly,
//! with the step and the reason recorded against the environment. The
//! venture itself is not touched — a staging run must never read as the
//! venture itself provisioning.
//!
//! **Promotion is the point**, and it is plan-then-confirm, the shape
//! the dashboard already uses for key rotation: the plan names the
//! module-set difference and the migrations that would apply, and the
//! operator confirms the plan, not the intention. One rule is enforced
//! rather than advised: **a promotion may only apply migrations staging
//! has already applied.** Staging rehearses its migrations when its own
//! provisioning run completes the schema step; a set change clears that
//! record (the same contract the venture's editor holds), so "staging
//! ran the schema step" always means "staging ran *this* set's
//! migrations". With no deployer wired, staging never completes the
//! artifact step, so every module-adding promotion is refused — which
//! is exactly right: nothing has been rehearsed, and this screen exists
//! so that cannot be done by accident.
//!
//! [`Unwired`]: cratefield_provisioning::Unwired

use std::sync::Arc;

use axum::extract::{Path, Query, RawForm, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use cratefield_accounts::{Environment, Venture};
use cratefield_chrome::{Page, escape, render};
use cratefield_console::current_session;
use cratefield_core::{Database, Statement};
use cratefield_provisioning::{Engine, Step, Unwired as UnwiredDeployer};
use http::{HeaderMap, StatusCode};

use crate::{
    BASE, DashboardState, Progress, account_nav, account_of, frame, guard, internal, now_rfc3339,
    progress_of, render_progress, same_set, status_chip, ulid,
};

/// Where the screen sits under the dashboard.
const PATH: &str = "/v1/dashboard/environments";

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/// An environment's provisioning progress, read from its own ledger the
/// way [`progress_of`] reads the venture's.
#[derive(Debug)]
struct EnvProgress {
    last_step: String,
    error: String,
    updated_at: String,
}

async fn env_progress_of(
    db: &dyn Database,
    environment_id: &str,
) -> Result<EnvProgress, cratefield_core::DbError> {
    let rows = db
        .query(&Statement::with_values(
            "SELECT last_step, error, updated_at FROM environment_progress \
             WHERE environment_id = ?",
            vec![text(environment_id)],
        ))
        .await?;
    let row = rows.first();
    Ok(EnvProgress {
        last_step: row.and_then(|row| row.get("last_step")).unwrap_or_default(),
        error: row.and_then(|row| row.get("error")).unwrap_or_default(),
        updated_at: row
            .and_then(|row| row.get("updated_at"))
            .unwrap_or_default(),
    })
}

/// Whether staging has rehearsed the migrations a promotion of its
/// current set would apply: its own run completed through the schema
/// step and is not sitting on a recorded failure. A set change clears
/// the ledger first ([`set_modules`]), so a `true` here cannot be a
/// record of an older set's run.
fn rehearsed(progress: &EnvProgress) -> bool {
    progress.error.is_empty() && Step::completed_through(&progress.last_step, Step::Schema)
}

/// The members of a module-set content key, sorted, without empties —
/// the comparison [`same_set`] makes, materialised for naming the
/// difference a promotion would move.
fn members_of(set: &str) -> Vec<String> {
    let mut parts: Vec<String> = set
        .split('+')
        .filter(|slug| !slug.is_empty())
        .map(str::to_owned)
        .collect();
    parts.sort_unstable();
    parts.dedup();
    parts
}

/// What a promotion from staging to production would move: modules
/// added (which bring migrations) and modules removed (which bring
/// none — the harness has no down-migrations to apply).
struct PromotionDiff {
    added: Vec<String>,
    removed: Vec<String>,
}

fn promotion_diff(production: &str, staging: &str) -> PromotionDiff {
    let production = members_of(production);
    let staging = members_of(staging);
    PromotionDiff {
        added: staging
            .iter()
            .filter(|slug| !production.contains(slug))
            .cloned()
            .collect(),
        removed: production
            .iter()
            .filter(|slug| !staging.contains(slug))
            .cloned()
            .collect(),
    }
}

fn text(value: &str) -> sea_query::Value {
    sea_query::Value::String(Some(Box::new(value.to_owned())))
}

/// The urlencoded fields of a raw form body, parsed the way the console
/// parses its wizard body: repeated keys stay repeated, because one
/// `module` field per ticked box is the shape the editor posts.
fn form_fields(body: &[u8]) -> Vec<(String, String)> {
    let raw = String::from_utf8_lossy(body);
    raw.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) => (urldecode(name), urldecode(value)),
            None => (urldecode(pair), String::new()),
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
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    index += 3;
                } else {
                    out.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// The screen
// ---------------------------------------------------------------------------

/// `/v1/dashboard/environments` — every venture with its production
/// environment (the venture itself) and any environments named
/// alongside it, each with its own module set, tenant and provisioning
/// state.
#[allow(clippy::too_many_lines)]
#[allow(clippy::format_push_string)] // the house idiom for HTML building
pub(super) async fn screen(state: State<Arc<DashboardState>>, headers: HeaderMap) -> Response {
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
    let ventures = match repo.ventures_for(&account.id).await {
        Ok(ventures) => ventures,
        Err(err) => {
            tracing::error!(error = %err, "venture list failed on the environments screen");
            return internal("could not load the ventures");
        }
    };

    let mut cards = String::new();
    for venture in &ventures {
        let environments = match repo.environments_for(&account.id, &venture.id).await {
            Ok(environments) => environments,
            Err(err) => {
                tracing::error!(error = %err, "environment list failed");
                return internal("could not load the environments");
            }
        };
        let production_progress = match progress_of(db.as_ref(), &venture.id).await {
            Ok(progress) => progress,
            Err(err) => {
                tracing::error!(error = %err, "venture progress read failed");
                return internal("could not load the provisioning progress");
            }
        };
        let mut named: Vec<(Environment, EnvProgress)> = Vec::with_capacity(environments.len());
        for environment in environments {
            let progress = match env_progress_of(db.as_ref(), &environment.id).await {
                Ok(progress) => progress,
                Err(err) => {
                    tracing::error!(error = %err, "environment progress read failed");
                    return internal("could not load the environment's progress");
                }
            };
            named.push((environment, progress));
        }
        cards.push_str(&venture_card(venture, &named, &production_progress));
    }

    let body = if ventures.is_empty() {
        String::from(
            "<p class=\"dash__empty\">No ventures yet. \
             <a href=\"/v1/console/new\">Create one in the console.</a></p>",
        )
    } else {
        cards
    };

    let crumb = format!(
        "{count} venture{s} · production is each one as it exists today",
        count = ventures.len(),
        s = if ventures.len() == 1 { "" } else { "s" },
    );

    Html(render(&Page {
        title: "Environments",
        signed_in_as: Some(&session.account_id),
        body: &format!(
            "<div class=\"page-h\"><h1>Environments</h1></div>\
             <p class=\"lede\">Every schema change is tested in production, because a \
             venture is one thing: one database, one set of secrets, one module set, \
             deployed once. This screen exists to end that — environments beside \
             production, and a promotion that rehearses before it moves.</p>{frame}",
            frame = frame(&account_nav("environments"), &crumb, &body),
        ),
    }))
    .into_response()
}

/// One venture's block: the production environment (derived, first),
/// every named environment after it, the staging button, and per named
/// environment the module-set rehearsal editor and the promotion link.
#[allow(clippy::too_many_lines)]
#[allow(clippy::format_push_string)]
fn venture_card(
    venture: &Venture,
    named: &[(Environment, EnvProgress)],
    production: &Progress,
) -> String {
    let production_env = Environment::production(venture);

    let mut rows = String::from(
        "<div class=\"dash__lrow dash__lrow--three dash__lrow--head\">\
         <span>Environment</span><span>Module set · tenant</span><span>Provisioning</span></div>",
    );
    rows.push_str(&environment_row(
        &production_env,
        &render_progress(production),
    ));
    for (environment, progress) in named {
        rows.push_str(&environment_row(
            environment,
            &render_env_progress(progress),
        ));
    }

    // Staging is the environment that matters (#31), so it gets the one
    // button; a second environment would need a name of its own and a
    // reason to exist first.
    let has_staging = named.iter().any(|(env, _)| env.name == "staging");
    let add_staging = if has_staging {
        String::new()
    } else {
        format!(
            "<form method=\"post\" action=\"{PATH}/{id}/staging\">\
             <button class=\"btn\" type=\"submit\">Add a staging environment</button>\
             <span class=\"dash__note\">Its own database, its own secret store, its \
             own module set — starting as a copy of production's. Provisioning runs \
             the same engine and stops where every run stops today: the unwired \
             deployer, recorded against the environment, never the venture.</span>\
             </form>",
            id = escape(&venture.id),
        )
    };

    let mut editors = String::new();
    for (environment, _) in named {
        editors.push_str(&environment_editor(venture, environment));
    }

    format!(
        "<div class=\"dash__card dash__card--wide\">\
         <p class=\"dash__card-h\"><a href=\"{BASE}/ventures/{id}\">{slug}</a> {status} \
         <span class=\"dash__tag\">{count} environment{e}</span></p>\
         <div class=\"dash__list\">{rows}</div>\
         <p class=\"dash__note\">Production is this venture as it exists today — the \
         same tenant, the same module set, the same subdomain — not a copy stored \
         beside it, which is why editing production's modules stays on the venture's \
         own screen.</p>{add_staging}{editors}</div>",
        id = escape(&venture.id),
        slug = escape(&venture.slug),
        status = status_chip(venture.status),
        count = named.len() + 1,
        e = if named.is_empty() { "" } else { "s" },
        rows = rows,
        add_staging = add_staging,
        editors = editors,
    )
}

/// One environment's row: its name (production styled as the live one),
/// its module set and tenant, and its provisioning state — the honest
/// rendering, with a stopped run's recorded reason spelled out.
#[allow(clippy::format_push_string)]
fn environment_row(environment: &Environment, progress_html: &str) -> String {
    let chip = if environment.is_production() {
        format!(
            "<span class=\"chip chip--live\">production</span> <em>{subdomain}</em>",
            subdomain = escape(&environment.subdomain),
        )
    } else {
        format!(
            "<span class=\"chip chip--working\">{name}</span> <em>{subdomain}</em>",
            name = escape(&environment.name),
            subdomain = escape(&environment.subdomain),
        )
    };
    format!(
        "<div class=\"dash__lrow dash__lrow--three\">\
         <span>{name}</span>\
         <span><code>{set}</code><br><em>{tenant}</em></span>\
         <span>{progress}</span></div>",
        name = chip,
        set = escape(&environment.module_set),
        tenant = escape(&environment.tenant_id),
        progress = progress_html,
    )
}

/// An environment's provisioning state, in the shape
/// [`crate::render_progress`] gives the venture's — same vocabulary, so
/// a stopped run reads the same wherever it stopped.
#[allow(clippy::format_push_string)]
fn render_env_progress(progress: &EnvProgress) -> String {
    if !progress.error.is_empty() {
        let after = if progress.last_step.is_empty() {
            String::from("on its first step")
        } else {
            format!("after <code>{}</code>", escape(&progress.last_step))
        };
        return format!(
            "<p class=\"dash__row\"><span class=\"dash__dot dash__dot--bad\"></span>\
             <strong>Provisioning stopped</strong> {after}</p>\
             <p class=\"dash__note\">{error}</p>",
            error = escape(&progress.error),
        );
    }
    if progress.last_step.is_empty() {
        return String::from(
            "<p class=\"dash__note\">No provisioning has run for this environment \
             yet.</p>",
        );
    }
    format!(
        "<p class=\"dash__row\"><span class=\"dash__dot dash__dot--live\"></span>\
         Last completed step <code>{}</code><span class=\"dash__meta\">{}</span></p>",
        escape(&progress.last_step),
        escape(&progress.updated_at),
    )
}

/// The rehearsal editor: the catalogue as checkboxes against the
/// environment's own set, posting to the environment's own module-set
/// route. The same shape the venture's editor has, so the two screens
/// teach one lesson, not two.
#[allow(clippy::format_push_string)]
fn environment_editor(venture: &Venture, environment: &Environment) -> String {
    let catalog = cratefield_catalog::curated();
    let on: Vec<&str> = environment
        .module_set
        .split('+')
        .filter(|slug| !slug.is_empty())
        .collect();

    let mut items = String::from("<div class=\"mods\">");
    for module in &catalog.modules {
        let is_on = on.contains(&module.slug.as_str());
        let core = module.tier == cratefield_catalog::Tier::Core;
        // A disabled checkbox submits nothing, so a core module needs a
        // hidden field or saving would silently remove it.
        let keep = if core && is_on {
            format!(
                "<input type=\"hidden\" name=\"module\" value=\"{}\">",
                escape(&module.slug)
            )
        } else {
            String::new()
        };
        items.push_str(&format!(
            "<label class=\"mod{on_class}\">{keep}\
             <input type=\"checkbox\" name=\"module\" value=\"{slug}\"{checked}{disabled}>\
             <span><span class=\"mod__name\">{name} <code>{slug}</code>{core_chip}</span>\
             <span class=\"mod__sum\">{summary}</span></span></label>",
            on_class = if is_on { " mod--on" } else { "" },
            keep = keep,
            slug = escape(&module.slug),
            name = escape(&module.name),
            checked = if is_on { " checked" } else { "" },
            disabled = if core { " disabled" } else { "" },
            core_chip = if core {
                "<span class=\"chip\">always on</span>"
            } else {
                ""
            },
            summary = escape(&module.summary),
        ));
    }
    for slug in &on {
        if !catalog.modules.iter().any(|m| m.slug == *slug) {
            items.push_str(&format!(
                "<label class=\"mod mod--on\"><input type=\"checkbox\" name=\"module\" \
                 value=\"{slug}\" checked><span>\
                 <span class=\"mod__name\"><code>{slug}</code> \
                 <span class=\"chip\">not in the catalogue</span></span>\
                 <span class=\"mod__sum\">This environment carries it, and the curated \
                 catalogue does not offer it. Unticking it removes it.</span></span></label>",
                slug = escape(slug),
            ));
        }
    }
    items.push_str("</div>");

    format!(
        "<p class=\"dash__card-h\" style=\"margin-top:18px\">Rehearse a change on \
         <span class=\"chip chip--working\">{name}</span></p>\
         <form method=\"post\" action=\"{PATH}/{venture}/{env}/modules\">{items}\
         <div class=\"dash__act\">\
         <button class=\"btn\" type=\"submit\">Save and re-provision {name}</button>\
         <a class=\"btn\" href=\"{PATH}/{venture}/promotion?environment={env}\">Plan a \
         promotion to production</a></div>\
         <span class=\"dash__note\">Saving records the set and re-provisions this \
         environment through the same engine — which stops at the unwired deployer \
         today, and that recorded stop is what gates promotion: a promotion is \
         refused until the environment's schema step has actually run.</span></form>",
        name = escape(&environment.name),
        venture = escape(&venture.id),
        env = escape(&environment.id),
    )
}

// ---------------------------------------------------------------------------
// Creating staging
// ---------------------------------------------------------------------------

/// Creates a venture's staging environment and provisions it: the same
/// engine, the environment's own tenant and ledger, the venture
/// untouched.
pub(super) async fn add_staging(
    state: State<Arc<DashboardState>>,
    headers: HeaderMap,
    Path(venture): Path<String>,
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
    let venture = match repo.venture_for(&account.id, &venture).await {
        Ok(Some(venture)) => venture,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such venture").into_response(),
        Err(err) => {
            tracing::error!(error = %err, "venture lookup failed");
            return internal("could not load the venture");
        }
    };

    let now = now_rfc3339(ctx);
    let environment = match repo
        .create_environment(
            &ulid(ctx),
            &account.id,
            &venture.id,
            "staging",
            &format!("ten_{}", ulid(ctx)),
            &now,
        )
        .await
    {
        Ok(environment) => environment,
        Err(cratefield_accounts::RepoError::Invalid(why)) => {
            return (StatusCode::CONFLICT, why).into_response();
        }
        Err(err) => {
            // The one expected case here is the unique (venture, name)
            // constraint: a staging environment already exists.
            tracing::error!(error = %err, "environment creation failed");
            return (
                StatusCode::CONFLICT,
                "a staging environment already exists for this venture",
            )
                .into_response();
        }
    };

    // The engine runs for real and stops at the unwired deployer, which
    // is a recorded outcome the screen shows — not an error to hide.
    let engine = Engine::new(db);
    match engine
        .provision_environment(&environment, &UnwiredDeployer, &now)
        .await
    {
        Ok(()) | Err(cratefield_provisioning::ProvisionError::Step { .. }) => {
            Redirect::to(PATH).into_response()
        }
        Err(err) => {
            tracing::error!(error = %err, "environment provisioning failed before it could run");
            internal("could not start provisioning the environment")
        }
    }
}

// ---------------------------------------------------------------------------
// Rehearsing: the environment's module set
// ---------------------------------------------------------------------------

/// Records an environment's module set and re-provisions it — the
/// rehearsal half. Mirrors the venture's module-set route exactly:
/// resolve through the catalogue, compare the sets rather than the
/// strings, and clear the recorded progress so the run cannot resume
/// past the step that builds the artifact — and so a completed schema
/// step always means *this* set's schema.
pub(super) async fn set_modules(
    state: State<Arc<DashboardState>>,
    headers: HeaderMap,
    Path((venture_id, environment_id)): Path<(String, String)>,
    RawForm(body): RawForm,
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
    let venture = match repo.venture_for(&account.id, &venture_id).await {
        Ok(Some(venture)) => venture,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such venture").into_response(),
        Err(err) => {
            tracing::error!(error = %err, "venture lookup failed");
            return internal("could not load the venture");
        }
    };
    let environment = match repo
        .environment_for(&account.id, &venture.id, &environment_id)
        .await
    {
        Ok(Some(environment)) => environment,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such environment").into_response(),
        Err(err) => {
            tracing::error!(error = %err, "environment lookup failed");
            return internal("could not load the environment");
        }
    };

    let chosen: Vec<String> = form_fields(&body)
        .into_iter()
        .filter(|(field, _)| field == "module")
        .map(|(_, slug)| slug)
        .collect();
    let catalog = cratefield_catalog::curated();
    let chosen: Vec<&str> = chosen.iter().map(String::as_str).collect();
    let resolved = match catalog.resolve(&chosen) {
        Ok(set) => set,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };
    let module_set = resolved.slugs().join("+");

    // Same selection, differently ordered: nothing to rehearse, and a
    // working environment is not torn down to rebuild the artifact it
    // already has.
    if same_set(&module_set, &environment.module_set) {
        return Redirect::to(PATH).into_response();
    }

    let now = now_rfc3339(ctx);
    let environment = match repo
        .set_environment_modules(&account.id, &venture.id, &environment.id, &module_set, &now)
        .await
    {
        Ok(environment) => environment,
        Err(err) => {
            tracing::error!(error = %err, "environment module set write failed");
            return internal("could not record the environment's module set");
        }
    };

    // The artifact is a function of the set, so the run restarts at the
    // first step — and the cleared ledger is what keeps the rehearsal
    // verdict honest.
    if let Err(err) = db
        .execute(&Statement::with_values(
            "DELETE FROM environment_progress WHERE environment_id = ?",
            vec![text(&environment.id)],
        ))
        .await
    {
        tracing::error!(error = %err, "could not clear the environment's progress");
        return internal("could not reset the environment's provisioning progress");
    }

    let engine = Engine::new(db);
    match engine
        .provision_environment(&environment, &UnwiredDeployer, &now)
        .await
    {
        Ok(()) | Err(cratefield_provisioning::ProvisionError::Step { .. }) => {
            Redirect::to(PATH).into_response()
        }
        Err(err) => {
            tracing::error!(error = %err, "environment re-provisioning failed before it could run");
            internal("could not start re-provisioning the environment")
        }
    }
}

// ---------------------------------------------------------------------------
// Promotion: plan, then confirm
// ---------------------------------------------------------------------------

/// Everything the promotion pages need, resolved once and shared by the
/// plan and the confirm so the two can never disagree about what would
/// move.
struct PromotionContext {
    venture: Venture,
    environment: Environment,
    diff: PromotionDiff,
    staging_progress: EnvProgress,
}

/// Resolves the venture and the environment named by `environment_id`,
/// computes the difference and the rehearsal verdict. Scoped to the
/// account: another account's ids are 404s, never context.
#[allow(clippy::result_large_err)]
async fn promotion_context(
    repo: &cratefield_accounts::Repository,
    db: &Arc<dyn Database>,
    account_id: &str,
    venture_id: &str,
    environment_id: &str,
) -> Result<PromotionContext, Response> {
    let venture = match repo.venture_for(account_id, venture_id).await {
        Ok(Some(venture)) => venture,
        Ok(None) => return Err((StatusCode::NOT_FOUND, "no such venture").into_response()),
        Err(err) => {
            tracing::error!(error = %err, "venture lookup failed");
            return Err(internal("could not load the venture"));
        }
    };
    let environment = match repo
        .environment_for(account_id, &venture.id, environment_id)
        .await
    {
        Ok(Some(environment)) => environment,
        Ok(None) => return Err((StatusCode::NOT_FOUND, "no such environment").into_response()),
        Err(err) => {
            tracing::error!(error = %err, "environment lookup failed");
            return Err(internal("could not load the environment"));
        }
    };
    let staging_progress = match env_progress_of(db.as_ref(), &environment.id).await {
        Ok(progress) => progress,
        Err(err) => {
            tracing::error!(error = %err, "environment progress read failed");
            return Err(internal("could not load the environment's progress"));
        }
    };
    let diff = promotion_diff(&venture.module_set, &environment.module_set);
    Ok(PromotionContext {
        venture,
        environment,
        diff,
        staging_progress,
    })
}

/// `GET /v1/dashboard/environments/{venture}/promotion?environment=…` —
/// the plan: what would move, what it would apply, whether it was
/// rehearsed, and where the run would stop. Nothing changes.
#[allow(clippy::too_many_lines)]
pub(super) async fn promotion_plan(
    state: State<Arc<DashboardState>>,
    headers: HeaderMap,
    Path(venture): Path<String>,
    Query(query): Query<Vec<(String, String)>>,
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
    let Some(environment) = query
        .iter()
        .find(|(key, _)| key == "environment")
        .map(|(_, value)| value.clone())
    else {
        return (
            StatusCode::BAD_REQUEST,
            "which environment? pass ?environment=<id>",
        )
            .into_response();
    };
    let context = match promotion_context(&repo, &db, &account.id, &venture, &environment).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    promotion_page(&session.account_id, &context, None)
}

/// `POST …/promotion` — the confirm. The first press (no `run`) renders
/// the plan again; only a press carrying `run` performs anything, and
/// even that is refused by the rehearsal rule before a single record
/// changes. Plan-then-confirm, the same two presses key rotation uses.
pub(super) async fn promotion_confirm(
    state: State<Arc<DashboardState>>,
    headers: HeaderMap,
    Path(venture): Path<String>,
    RawForm(body): RawForm,
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
    let fields = form_fields(&body);
    let Some(environment) = fields
        .iter()
        .find(|(name, _)| name == "environment")
        .map(|(_, value)| value.clone())
    else {
        return (
            StatusCode::BAD_REQUEST,
            "which environment? the form carries its id",
        )
            .into_response();
    };
    let context = match promotion_context(&repo, &db, &account.id, &venture, &environment).await {
        Ok(context) => context,
        Err(response) => return response,
    };

    // The first press plans; only `run` confirms.
    if !fields.iter().any(|(name, _)| name == "run") {
        return promotion_page(&session.account_id, &context, None);
    }

    // The rule, enforced before anything changes: a promotion that would
    // apply migrations staging has not applied is refused, with the rule
    // and the evidence on the page. Refused is refused — no partial
    // writes, no "best effort" — and the status says it too.
    if !context.diff.added.is_empty() && !rehearsed(&context.staging_progress) {
        let mut page = promotion_page(
            &session.account_id,
            &context,
            Some(
                "REFUSED: this promotion would apply migrations that have not run in \
                 staging. The environment's recorded progress shows its run has not \
                 completed the schema step, so nothing has been rehearsed. Nothing \
                 was changed.",
            ),
        );
        *page.status_mut() = StatusCode::CONFLICT;
        return page;
    }

    // An identical promotion is a no-op guard, the same one the venture's
    // module editor holds: production is not torn down to rebuild the
    // artifact it already runs.
    if same_set(&context.environment.module_set, &context.venture.module_set) {
        return Redirect::to(PATH).into_response();
    }

    let now = now_rfc3339(ctx);
    if let Err(err) = repo
        .set_venture_modules(
            &account.id,
            &context.venture.id,
            &context.environment.module_set,
            &now,
        )
        .await
    {
        tracing::error!(error = %err, "promotion module set write failed");
        return internal("could not record production's new module set");
    }
    // The artifact is a function of the set, so production's run starts
    // at the first step — the promotion is a re-provision, not a
    // resume.
    if let Err(err) = db
        .execute(&Statement::with_values(
            "DELETE FROM provision_progress WHERE venture_id = ?",
            vec![text(&context.venture.id)],
        ))
        .await
    {
        tracing::error!(error = %err, "could not clear the venture's progress");
        return internal("could not reset the provisioning progress");
    }
    let venture = Venture {
        module_set: context.environment.module_set.clone(),
        ..context.venture.clone()
    };
    let engine = Engine::new(db);
    match engine.provision(&venture, &UnwiredDeployer, &now).await {
        Ok(_) | Err(cratefield_provisioning::ProvisionError::Step { .. }) => {
            // A step failure is the recorded, visible outcome the
            // venture's own page renders — with no deployer wired it is
            // the expected one, and the operator is sent to it.
            Redirect::to(&format!("{BASE}/ventures/{}", venture.id)).into_response()
        }
        Err(err) => {
            tracing::error!(error = %err, "promotion failed before it could run");
            internal("could not start the promotion's re-provisioning")
        }
    }
}

/// Renders the promotion plan — the plan GET serves, the first POST
/// serves, and the refused confirm serves with a banner. `banner` is
/// the refusal sentence when there is one.
#[allow(clippy::too_many_lines)]
#[allow(clippy::format_push_string)]
fn promotion_page(identity: &str, context: &PromotionContext, banner: Option<&str>) -> Response {
    let venture = &context.venture;
    let environment = &context.environment;
    let diff = &context.diff;
    let is_rehearsed = rehearsed(&context.staging_progress);

    let banner_html = banner.map_or_else(String::new, |banner| {
        format!(
            "<p class=\"dash__banner dash__banner--bad\"><span class=\"chip \
             chip--degraded\">Refused</span>{banner}</p>",
            banner = escape(banner),
        )
    });

    // The difference, named module by module in both directions.
    let difference = if diff.added.is_empty() && diff.removed.is_empty() {
        String::from(
            "<p class=\"dash__note\">No module-set difference: staging and production \
             carry the same set. Promoting would re-provision production with the \
             artifact it already runs, which the confirm refuses as a no-op — a \
             working venture is not torn down for nothing.</p>",
        )
    } else {
        let mut lines = String::new();
        for slug in &diff.added {
            lines.push_str(&format!(
                "<p class=\"dash__note\"><strong>adds</strong> <code>{slug}</code> — \
                 a module production does not carry, so promoting builds a new \
                 artifact and applies the migrations it brings.</p>",
                slug = escape(slug),
            ));
        }
        for slug in &diff.removed {
            lines.push_str(&format!(
                "<p class=\"dash__note\"><strong>removes</strong> <code>{slug}</code> — \
                 the next artifact simply does not carry it. The harness has no \
                 down-migrations, so nothing applies on the way out.</p>",
                slug = escape(slug),
            ));
        }
        format!(
            "<p class=\"dash__note\">Production runs \
             <code>{production}</code>; staging rehearses \
             <code>{staging}</code>.</p>{lines}",
            production = escape(&venture.module_set),
            staging = escape(&environment.module_set),
            lines = lines,
        )
    };

    // The migrations that would apply — named per added module, with the
    // honest ceiling stated: the control plane does not link the
    // venture's modules, so it cannot enumerate the statements.
    let migrations = if diff.added.is_empty() {
        String::from(
            "<p class=\"dash__note\">No module migrations would apply: nothing is \
             being added.</p>",
        )
    } else {
        let mut lines = String::new();
        for slug in &diff.added {
            lines.push_str(&format!(
                "<p class=\"dash__note\">The migrations <code>{slug}</code> brings — \
                 its schema steps, applied to production's database by the \
                 promotion run.</p>",
                slug = escape(slug),
            ));
        }
        format!(
            "{lines}\
             <p class=\"dash__note\">The exact statements are the composed artifact's \
             to carry: the control plane does not link the venture's modules and \
             will not guess their SQL. What it can name — and does — is which \
             modules bring migrations, and whether staging has run them.</p>"
        )
    };

    // The rehearsal verdict, with the evidence.
    let rehearsal = if is_rehearsed {
        format!(
            "<p class=\"dash__note\"><span class=\"dash__dot dash__dot--live\"></span>\
             <strong>Rehearsed.</strong> {name}'s own run completed through the \
             schema step, so the migrations this promotion would apply have already \
             run against {name}'s database.</p>",
            name = escape(&environment.name),
        )
    } else {
        let evidence = if !context.staging_progress.error.is_empty() {
            format!(
                "Its recorded failure reads: <code>{error}</code>",
                error = escape(&context.staging_progress.error),
            )
        } else if context.staging_progress.last_step.is_empty() {
            String::from("No provisioning has run for it at all yet")
        } else {
            format!(
                "Its last completed step is <code>{step}</code>, which is before the \
                 schema step",
                step = escape(&context.staging_progress.last_step),
            )
        };
        format!(
            "<p class=\"dash__note\"><span class=\"dash__dot dash__dot--bad\"></span>\
             <strong>NOT rehearsed.</strong> {name}'s run has not completed the \
             schema step. {evidence}. Until it has, confirming this promotion is \
             refused — by the page and by the handler behind it.</p>",
            name = escape(&environment.name),
            evidence = evidence,
        )
    };

    // Where the run stops: the engine's own plan for the promoted set,
    // from the first step (the promotion clears production's progress —
    // the artifact is a function of the set).
    let mut steps = String::new();
    for planned in cratefield_provisioning::STEPS {
        steps.push_str(&format!(
            "<p class=\"dash__note\">{dot} {step}</p>",
            dot = "○",
            step = escape(planned.as_str()),
        ));
    }
    let run = format!(
        "<p class=\"dash__note\">Confirming records production's new module set, \
         clears its recorded progress — the artifact is a function of the set — and \
         re-provisions through the same engine, from the first step:</p>{steps}\
         <p class=\"dash__note\">Today the first step stops at the unwired deployer \
         and records that against the venture, exactly as the module-set editor \
         does. That recorded stop is what you will see on the venture's page after \
         confirming; it is the honest state of this control plane, not a failure \
         of the promotion.</p>"
    );

    // The confirm form exists only where confirming is allowed. A page
    // that offered the button and refused the press would be a lie with
    // better manners.
    // Nothing to promote is its own answer. `diff.added.is_empty()` is
    // true both when staging only *removes* a module — a real promotion
    // with no migration to rehearse — and when the two sets are already
    // the same, where the handler's no-op guard redirects without a word.
    // Offering the button there sent an operator back to the list with no
    // sign that the press had done nothing, which is the one outcome a
    // refusal must never look like.
    let nothing_to_promote = same_set(&environment.module_set, &venture.module_set);
    let confirm = if nothing_to_promote {
        format!(
            "<p class=\"dash__note\"><strong>There is no confirm button, on \
             purpose.</strong> {name} carries the module set production already \
             runs, so promoting it would tear down a working venture to rebuild \
             the artifact it already has. Change {name}'s set first; the plan \
             above will then have something to move.</p>",
            name = escape(&environment.name),
        )
    } else if diff.added.is_empty() || is_rehearsed {
        format!(
            "<form method=\"post\" action=\"{PATH}/{venture}/promotion\">\
             <input type=\"hidden\" name=\"environment\" value=\"{env}\">\
             <input type=\"hidden\" name=\"run\" value=\"1\">\
             <div class=\"dash__act\">\
             <button class=\"btn btn--primary\" type=\"submit\">Confirm the plan: \
             promote {name} to production</button>\
             <a class=\"btn\" href=\"{PATH}\">Back</a></div></form>",
            venture = escape(&venture.id),
            env = escape(&environment.id),
            name = escape(&environment.name),
        )
    } else {
        format!(
            "<p class=\"dash__note\"><strong>There is no confirm button, on \
             purpose.</strong> This promotion would apply migrations {name} has not \
             run, and the rule is enforced in the handler, not just withheld from \
             the page: a hand-made POST is refused the same way.</p>",
            name = escape(&environment.name),
        )
    };

    let body = format!(
        "{banner_html}\
         <div class=\"dash__card dash__card--wide\">\
         <p class=\"dash__card-h\">The module-set difference</p>{difference}</div>\
         <div class=\"dash__card dash__card--wide\">\
         <p class=\"dash__card-h\">The migrations that would apply</p>{migrations}\
         <p class=\"dash__note\"><strong>The rule:</strong> a promotion may only \
         apply migrations staging has already applied. Staging rehearses its \
         migrations when its own provisioning run completes the schema step, and \
         changing its module set clears that record — so a completed schema step \
         always means this set's schema, never an older one's.</p>{rehearsal}</div>\
         <div class=\"dash__card dash__card--wide\">\
         <p class=\"dash__card-h\">What confirming would run</p>{run}</div>\
         {confirm}\
         <p class=\"dash__note\">The operator confirms the plan, not the intention: \
         everything above is computed from the records at render time, and the \
         confirm recomputes it before anything changes.</p>",
    );

    Html(render(&Page {
        title: "Promotion",
        signed_in_as: Some(identity),
        body: &format!(
            "<p class=\"crumb\"><a href=\"{PATH}\">Environments</a> / \
             <a href=\"{BASE}/ventures/{vid}\">{slug}</a> / Promote {name}</p>\
             <div class=\"page-h\"><h1>Promote {name} to production</h1></div>\
             <p class=\"lede\">What would move, what it would apply, whether it was \
             rehearsed — as a plan, before anything happens.</p>{frame}",
            vid = escape(&venture.id),
            slug = escape(&venture.slug),
            name = escape(&environment.name),
            frame = frame(&account_nav("environments"), "promotion plan", &body),
        ),
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Dashboard;
    use cratefield_access::{DEFAULT_TTL_SECS, issue_session};
    use cratefield_testing::TestHarness;
    use http::{Method, Request as HttpRequest, header};
    use tower::util::ServiceExt;

    const EMAIL: &str = "op@cratefield.com";
    const NOW: u64 = 1_800_000_000;

    fn kit() -> TestHarness {
        TestHarness::new(vec![
            Box::new(cratefield_console::Console),
            Box::new(Dashboard::new(None)),
        ])
    }

    fn cookie(kit: &TestHarness) -> String {
        let token = issue_session(kit.signer.as_ref(), EMAIL, NOW, DEFAULT_TTL_SECS);
        format!("cf_session={token}")
    }

    /// A live venture, the state a real customer's production is in.
    async fn seeded(kit: &TestHarness) -> Venture {
        let repo = cratefield_accounts::Repository::new(kit.db.clone());
        repo.account_for_login(EMAIL, "Op", "acc_1", "t0")
            .await
            .expect("account");
        let venture = repo
            .create_venture(
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
        repo.set_venture_status(
            "acc_1",
            "v1",
            cratefield_accounts::VentureStatus::Provisioning,
            "t1",
        )
        .await
        .expect("provisioning");
        repo.set_venture_status(
            "acc_1",
            "v1",
            cratefield_accounts::VentureStatus::Live,
            "t2",
        )
        .await
        .expect("live");
        venture
    }

    async fn send(
        kit: &TestHarness,
        method: Method,
        uri: &str,
        cookie: Option<&str>,
        body: Option<&str>,
    ) -> (StatusCode, String, String) {
        let mut builder = HttpRequest::builder().method(method).uri(uri);
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        if body.is_some() {
            builder = builder.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        }
        let request = builder
            .body(axum::body::Body::from(body.unwrap_or("").to_owned()))
            .expect("request");
        let response = kit
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("router answers");
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, 4 * 1024 * 1024)
            .await
            .expect("body");
        (
            parts.status,
            String::from_utf8(bytes.to_vec()).expect("utf-8"),
            parts
                .headers
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned(),
        )
    }

    async fn add_staging(kit: &TestHarness) -> Environment {
        let reply = send(
            kit,
            Method::POST,
            &format!("{PATH}/v1/staging"),
            Some(&cookie(kit)),
            None,
        )
        .await;
        assert_eq!(reply.0, StatusCode::SEE_OTHER, "{}", reply.1);
        cratefield_accounts::Repository::new(kit.db.clone())
            .environments_for("acc_1", "v1")
            .await
            .expect("envs")
            .into_iter()
            .next()
            .expect("staging exists")
    }

    /// Posts a module selection for an environment, as its editor does.
    async fn post_env_modules(
        kit: &TestHarness,
        env: &str,
        modules: &[&str],
    ) -> (StatusCode, String) {
        let body = modules
            .iter()
            .map(|slug| format!("module={slug}"))
            .collect::<Vec<_>>()
            .join("&");
        let reply = send(
            kit,
            Method::POST,
            &format!("{PATH}/v1/{env}/modules"),
            Some(&cookie(kit)),
            Some(&body),
        )
        .await;
        (reply.0, reply.1)
    }

    async fn venture_of(kit: &TestHarness) -> Venture {
        cratefield_accounts::Repository::new(kit.db.clone())
            .venture_for("acc_1", "v1")
            .await
            .expect("read")
            .expect("venture")
    }

    #[pollster::test]
    async fn the_screen_shows_every_venture_with_its_production_environment() {
        let kit = kit();
        seeded(&kit).await;
        let (status, body, _) = send(&kit, Method::GET, PATH, Some(&cookie(&kit)), None).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // Production is named, with the venture's own facts — derived,
        // not stored — and staging can be added.
        assert!(body.contains("production"), "{body}");
        assert!(body.contains("cms+waitlist"), "{body}");
        assert!(body.contains("my-app.cratefield.app"), "{body}");
        assert!(body.contains("ten_1"), "{body}");
        assert!(body.contains("Add a staging environment"), "{body}");
        assert!(!body.contains("Not built."), "{body}");
    }

    #[pollster::test]
    async fn adding_staging_provisions_it_and_leaves_the_venture_untouched() {
        let kit = kit();
        seeded(&kit).await;
        let staging = add_staging(&kit).await;

        // Its own tenant, its own sibling subdomain, production's set.
        assert_eq!(staging.name, "staging");
        assert_eq!(staging.module_set, "cms+waitlist");
        assert_ne!(staging.tenant_id, "ten_1");
        assert_eq!(staging.subdomain, "my-app-staging.cratefield.app");

        // The engine ran for real and stopped at the unwired deployer,
        // recorded against the environment — not the venture.
        let progress = env_progress_of(kit.db.as_ref(), &staging.id)
            .await
            .expect("progress");
        assert!(
            progress.error.contains("no deployer is wired"),
            "the honest stop, recorded: {progress:?}"
        );
        let venture = venture_of(&kit).await;
        assert_eq!(
            venture.status,
            cratefield_accounts::VentureStatus::Live,
            "a staging run must never read as the venture provisioning"
        );
        let venture_progress = progress_of(kit.db.as_ref(), "v1")
            .await
            .expect("venture progress");
        assert_eq!(venture_progress.error, "", "the venture's ledger is clean");

        // And the screen shows the stop rather than a spinner.
        let (_, body, _) = send(&kit, Method::GET, PATH, Some(&cookie(&kit)), None).await;
        assert!(body.contains("staging"), "{body}");
        assert!(body.contains("no deployer is wired"), "{body}");
        // The button is gone: staging exists.
        assert!(!body.contains("Add a staging environment"), "{body}");
    }

    #[pollster::test]
    async fn a_venture_cannot_get_two_staging_environments() {
        let kit = kit();
        seeded(&kit).await;
        add_staging(&kit).await;
        let (status, body, _) = send(
            &kit,
            Method::POST,
            &format!("{PATH}/v1/staging"),
            Some(&cookie(&kit)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(
            body.contains("already exists"),
            "says what happened: {body}"
        );
    }

    #[pollster::test]
    async fn rehearsing_a_set_records_it_against_the_environment_only() {
        let kit = kit();
        seeded(&kit).await;
        let staging = add_staging(&kit).await;

        let (status, body) =
            post_env_modules(&kit, &staging.id, &["cms", "waitlist", "notifications"]).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{body}");

        let staging = cratefield_accounts::Repository::new(kit.db.clone())
            .environment_for("acc_1", "v1", &staging.id)
            .await
            .expect("read")
            .expect("still there");
        assert!(
            same_set(&staging.module_set, "cms+waitlist+notifications"),
            "got {}",
            staging.module_set
        );
        // The ledger was cleared and re-stopped: the recorded stop is for
        // THIS set, which is what the rehearsal verdict reads.
        let progress = env_progress_of(kit.db.as_ref(), &staging.id)
            .await
            .expect("progress");
        assert!(
            progress.error.contains("no deployer is wired"),
            "{progress:?}"
        );

        // The venture is exactly as it was.
        let venture = venture_of(&kit).await;
        assert_eq!(venture.module_set, "cms+waitlist");
        assert_eq!(venture.status, cratefield_accounts::VentureStatus::Live);
    }

    #[pollster::test]
    async fn the_promotion_plan_names_the_module_set_difference_and_the_rule() {
        let kit = kit();
        seeded(&kit).await;
        let staging = add_staging(&kit).await;
        post_env_modules(&kit, &staging.id, &["cms", "waitlist", "notifications"]).await;

        let (status, body, _) = send(
            &kit,
            Method::GET,
            &format!("{PATH}/v1/promotion?environment={}", staging.id),
            Some(&cookie(&kit)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // The difference, named.
        assert!(body.contains("adds"), "{body}");
        assert!(body.contains("notifications"), "{body}");
        // The migrations that would apply, with the honest ceiling.
        assert!(
            body.contains("The migrations <code>notifications</code> brings"),
            "{body}"
        );
        assert!(
            body.contains("does not link the venture's modules"),
            "{body}"
        );
        // The rule, stated.
        assert!(
            body.contains("a promotion may only apply migrations staging has already applied"),
            "{body}"
        );
        // The verdict: not rehearsed (the run stopped at the artifact
        // step), so there is no confirm button to press.
        assert!(body.contains("NOT rehearsed"), "{body}");
        assert!(body.contains("no confirm button, on purpose"), "{body}");
        assert!(
            !body.contains("name=\"run\" value=\"1\""),
            "no confirm form on an unrehearsed plan: {body}"
        );
        // And where the run stops today.
        assert!(body.contains("unwired deployer"), "{body}");
    }

    #[pollster::test]
    async fn a_promotion_that_would_apply_an_unrehearsed_migration_is_refused() {
        let kit = kit();
        seeded(&kit).await;
        let staging = add_staging(&kit).await;
        post_env_modules(&kit, &staging.id, &["cms", "waitlist", "notifications"]).await;

        // A hand-made confirm, exactly the POST a withheld button would
        // have sent: refused all the same, because the rule is in the
        // handler.
        let (status, body, _) = send(
            &kit,
            Method::POST,
            &format!("{PATH}/v1/promotion"),
            Some(&cookie(&kit)),
            Some(&format!("environment={}&run=1", staging.id)),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(body.contains("REFUSED"), "{body}");
        assert!(
            body.contains("migrations that have not run in staging"),
            "{body}"
        );

        // And nothing changed: no partial writes.
        let venture = venture_of(&kit).await;
        assert_eq!(
            venture.module_set, "cms+waitlist",
            "production kept its set"
        );
        assert_eq!(venture.status, cratefield_accounts::VentureStatus::Live);
        let progress = progress_of(kit.db.as_ref(), "v1")
            .await
            .expect("venture progress");
        assert_eq!(progress.error, "", "the venture's ledger is untouched");
    }

    #[pollster::test]
    async fn a_promotion_that_only_removes_modules_runs_to_the_unwired_deployer() {
        let kit = kit();
        seeded(&kit).await;
        let staging = add_staging(&kit).await;
        // Staging rehearses a removal: nothing added, so no migrations
        // would apply, so nothing needs rehearsing.
        post_env_modules(&kit, &staging.id, &["cms"]).await;

        let (status, body, location) = send(
            &kit,
            Method::POST,
            &format!("{PATH}/v1/promotion"),
            Some(&cookie(&kit)),
            Some(&format!("environment={}&run=1", staging.id)),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
        assert_eq!(location, format!("{BASE}/ventures/v1"));

        // Production now carries staging's set, and its re-provisioning
        // stopped at the unwired deployer, recorded — the acceptance
        // path: the promotion runs through the engine and stops at the
        // same port everything does.
        let venture = venture_of(&kit).await;
        assert_eq!(venture.module_set, "cms", "the promotion moved the set");
        let progress = progress_of(kit.db.as_ref(), "v1")
            .await
            .expect("venture progress");
        assert!(
            progress.error.contains("no deployer is wired"),
            "stopped at the port, honestly: {progress:?}"
        );
        assert_eq!(
            venture.status,
            cratefield_accounts::VentureStatus::Provisioning,
            "no longer claiming live with an artifact it does not run"
        );
    }

    #[pollster::test]
    async fn an_identical_promotion_is_refused_as_a_no_op_rather_than_tearing_down_production() {
        let kit = kit();
        seeded(&kit).await;
        let staging = add_staging(&kit).await;
        // Staging still carries production's set (nothing was rehearsed).

        let (status, body, location) = send(
            &kit,
            Method::POST,
            &format!("{PATH}/v1/promotion"),
            Some(&cookie(&kit)),
            Some(&format!("environment={}&run=1", staging.id)),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
        assert_eq!(location, PATH);

        // A live venture is not re-provisioned to rebuild the artifact
        // it already runs.
        let venture = venture_of(&kit).await;
        assert_eq!(venture.module_set, "cms+waitlist");
        assert_eq!(venture.status, cratefield_accounts::VentureStatus::Live);
    }

    #[pollster::test]
    async fn the_first_press_plans_and_only_the_second_runs() {
        let kit = kit();
        seeded(&kit).await;
        let staging = add_staging(&kit).await;
        post_env_modules(&kit, &staging.id, &["cms"]).await;

        // First press: the plan, nothing changed, 200.
        let (status, body, _) = send(
            &kit,
            Method::POST,
            &format!("{PATH}/v1/promotion"),
            Some(&cookie(&kit)),
            Some(&format!("environment={}", staging.id)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("Promote staging to production"), "{body}");
        assert_eq!(venture_of(&kit).await.module_set, "cms+waitlist");
    }

    #[pollster::test]
    async fn a_promotion_with_nothing_to_move_offers_no_confirm() {
        // The handler's no-op guard redirects to the list without a word,
        // so a button here would send an operator back to the list with
        // no sign that the press had done nothing. A refusal must never
        // look like a success; the page says the reason instead.
        let kit = kit();
        seeded(&kit).await;
        let env = add_staging(&kit).await.id;

        let (status, body, _) = send(
            &kit,
            Method::GET,
            &format!("{PATH}/v1/promotion?environment={env}"),
            Some(&cookie(&kit)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        // The positive half: this is the plan page for that environment,
        // and it says why there is nothing to do — so the absence below
        // cannot pass on an error page or an empty body.
        assert!(body.contains("Promote staging"), "{body}");
        assert!(
            body.contains(
                "production already
             runs"
            ) || body.contains("production already runs"),
            "the page says why there is nothing to promote: {body}"
        );
        assert!(
            !body.contains("Confirm the plan"),
            "no confirm button where confirming does nothing: {body}"
        );
    }

    #[pollster::test]
    async fn the_venture_screens_still_read_the_same_after_the_environments_migration() {
        // The migration introduced `environment` and
        // `environment_progress` and touched nothing about a venture;
        // this test is the promise that keeps. Every marker below is one
        // the pre-environments suite pinned first.
        let kit = kit();
        seeded(&kit).await;

        let (_, list, _) = send(&kit, Method::GET, BASE, Some(&cookie(&kit)), None).await;
        assert!(list.contains("my-app.cratefield.app"), "{list}");
        assert!(list.contains("live"), "{list}");

        let (_, detail, _) = send(
            &kit,
            Method::GET,
            &format!("{BASE}/ventures/v1"),
            Some(&cookie(&kit)),
            None,
        )
        .await;
        assert!(
            detail.contains("value=\"cms\" checked"),
            "the module set reads the same: {detail}"
        );
        assert!(detail.contains("value=\"waitlist\" checked"), "{detail}");
        assert!(
            !detail.contains("value=\"privacy\" checked"),
            "privacy is not installed and must not read as installed: {detail}"
        );
        assert!(detail.contains("my-app.cratefield.app"), "{detail}");
        assert!(detail.contains("ten_1"), "{detail}");

        // The composition applied both new tables; they exist and hold
        // nothing until somebody creates an environment.
        for table in ["environment", "environment_progress"] {
            kit.db
                .query(&Statement::new(format!("SELECT 1 FROM {table} LIMIT 1")))
                .await
                .unwrap_or_else(|err| panic!("{table} missing after migration: {err}"));
        }
    }

    #[pollster::test]
    async fn one_account_cannot_stage_or_promote_anothers_venture() {
        let kit = kit();
        seeded(&kit).await;
        let repo = cratefield_accounts::Repository::new(kit.db.clone());
        repo.account_for_login("b@x.co", "B", "acc_2", "t0")
            .await
            .expect("account");
        let token = issue_session(kit.signer.as_ref(), "b@x.co", NOW, DEFAULT_TTL_SECS);
        let stranger = format!("cf_session={token}");

        let (status, _, _) = send(
            &kit,
            Method::POST,
            &format!("{PATH}/v1/staging"),
            Some(&stranger),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _, _) = send(
            &kit,
            Method::GET,
            &format!("{PATH}/v1/promotion?environment=env_x"),
            Some(&stranger),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _, _) = send(
            &kit,
            Method::POST,
            &format!("{PATH}/v1/env_x/modules"),
            Some(&stranger),
            Some("module=cms"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[pollster::test]
    async fn an_unauthenticated_request_is_redirected_to_the_login_gate() {
        let kit = kit();
        let (status, _, _) = send(&kit, Method::GET, PATH, None, None).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
    }
}
