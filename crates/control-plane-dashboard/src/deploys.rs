//! The Deploys screen: the account-level view of provisioning runs.
//!
//! The planned copy said there was nothing to list because no Deployer
//! talks to Cloudflare, and that is true about Cloudflare. It was not
//! true about the control plane: the engine
//! (`cratefield-provisioning`) runs for real against
//! [`Unwired`](cratefield_provisioning::Unwired) and records every
//! pressed "Go" in `provision_progress` — which step a run reached,
//! where it stopped, and when. This screen is that table, read.
//!
//! The honest part is the banner: nothing has ever reached Cloudflare.
//! Every run stops at its first step refusing with "no deployer is
//! wired", which is a recorded fact rather than a missing feature (#26)
//! — so the rows here are called **runs**, never deploys, nothing is
//! "serving", and the page does not read as though deploys were
//! happening.
//!
//! Read-only over the engine's table: this screen never writes
//! `provision_progress` (changing the engine is out of scope), and the
//! step descriptions it renders come from [`Engine::plan`], not from a
//! list kept here that could drift from the engine's.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use cratefield_chrome::{Page, escape, render};
use cratefield_console::current_session;
use cratefield_core::scrub_text;
use cratefield_provisioning::{Engine, STEPS};

use crate::{DashboardState, account_nav, frame, guard, internal, progress_of, text};

/// Where the screen sits under the dashboard.
const PATH: &str = "/v1/dashboard/deploys";

/// One recorded run: a venture's row in `provision_progress`, joined to
/// the venture for the module set it carried. The engine keeps one row
/// per venture — the run in progress or the last one that stopped — so
/// "every venture's runs" is exactly this join.
struct RunRow {
    venture_id: String,
    slug: String,
    module_set: String,
    last_step: String,
    error: String,
    updated_at: String,
}

async fn runs_of(
    db: &dyn cratefield_core::Database,
    account_id: &str,
) -> Result<Vec<RunRow>, cratefield_core::DbError> {
    let rows = db
        .query(&cratefield_core::Statement::with_values(
            "SELECT v.id, v.slug, v.module_set, p.last_step, p.error, p.updated_at \
             FROM venture v JOIN provision_progress p ON p.venture_id = v.id \
             WHERE v.account_id = ? \
             ORDER BY p.updated_at DESC, v.slug ASC",
            vec![text(account_id)],
        ))
        .await?;
    Ok(rows
        .rows
        .iter()
        .map(|row| RunRow {
            venture_id: row.get("id").unwrap_or_default(),
            slug: row.get("slug").unwrap_or_default(),
            module_set: row.get("module_set").unwrap_or_default(),
            last_step: row.get("last_step").unwrap_or_default(),
            error: row.get("error").unwrap_or_default(),
            updated_at: row.get("updated_at").unwrap_or_default(),
        })
        .collect())
}

/// The final step's token: a run whose last completed step is this one
/// finished, whatever its venture's lifecycle status says separately.
fn is_final_step(token: &str) -> bool {
    STEPS.last().is_some_and(|step| step.as_str() == token)
}

/// The step a recorded error names, when it names a step the engine
/// knows. The engine writes `"<step>: <message>"`, but the table is
/// plain text a hand or a migration could have written anything into —
/// so the prefix is only believed when it matches a real step.
fn failed_step(error: &str) -> Option<&str> {
    let (head, _) = error.split_once(": ")?;
    STEPS
        .iter()
        .find(|step| step.as_str() == head)
        .map(|step| step.as_str())
}

/// The outcome column: where a run stands, in the engine's own
/// vocabulary. A run that recorded no failure and reached the last step
/// finished; anything else says what it did, never what it deployed.
fn outcome(run: &RunRow) -> String {
    if run.error.is_empty() {
        if is_final_step(&run.last_step) {
            return String::from("finished — every step done");
        }
        if run.last_step.is_empty() {
            return String::from("no steps recorded");
        }
        return format!(
            "reached <code>{}</code>, no failure recorded",
            escape(&run.last_step)
        );
    }
    match failed_step(&run.error) {
        Some(step) => format!("stopped at <code>{step}</code>"),
        None => String::from("stopped — the recorded error names no step the engine knows"),
    }
}

// ---------------------------------------------------------------------------
// The list
// ---------------------------------------------------------------------------

/// `/v1/dashboard/deploys` — every recorded run across the account's
/// ventures, newest first, with the banner that keeps the page from
/// reading as a list of deploys.
#[allow(clippy::format_push_string)] // the house idiom for HTML building
pub(super) async fn screen(state: State<Arc<DashboardState>>, headers: HeaderMap) -> Response {
    let ctx = &state.ctx;
    if let Err(redirect) = guard(ctx, &headers) {
        return redirect;
    }
    let session = current_session(ctx, &headers).expect("guard proved a session");
    let (account, repo) = match crate::account_of(ctx, &session.account_id).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let Some(db) = ctx.ports.db.clone() else {
        return internal("db port unavailable");
    };
    let runs = match runs_of(db.as_ref(), &account.id).await {
        Ok(runs) => runs,
        Err(err) => {
            tracing::error!(error = %err, "runs read failed");
            return internal("could not load the provisioning runs");
        }
    };
    let ventures = repo.ventures_for(&account.id).await.unwrap_or_default();
    let never_ran = ventures.len().saturating_sub(runs.len());

    let mut rows = String::from(
        "<div class=\"dash__lrow dash__lrow--runs dash__lrow--head\"><span>Venture</span>\
         <span>Module set</span><span>Reached</span><span>Outcome</span><span>When</span></div>",
    );
    if runs.is_empty() {
        rows.push_str(
            "<p class=\"dash__empty\">No provisioning has run for this account's ventures \
             yet. The engine writes a row the moment a run starts, so an empty list means \
             nobody has pressed Go — not that runs were lost.</p>",
        );
    } else {
        for run in &runs {
            rows.push_str(&format!(
                "<div class=\"dash__lrow dash__lrow--runs\">\
                 <span><a href=\"{PATH}/{id}\">{slug}</a></span> \
                 <span><code>{module_set}</code></span> \
                 <span>{reached}</span> \
                 <span>{outcome}</span> \
                 <span>{when}</span></div>",
                id = escape(&run.venture_id),
                slug = escape(&run.slug),
                module_set = escape(&run.module_set),
                reached = if run.last_step.is_empty() {
                    String::from("—")
                } else {
                    format!("<code>{}</code>", escape(&run.last_step))
                },
                outcome = outcome(run),
                when = escape(&run.updated_at),
            ));
        }
    }

    let body = format!(
        "{banner}\
         <div class=\"dash__card dash__card--wide\">\
         <p class=\"dash__card-h\">Runs <span class=\"dash__tag\">{n}</span></p>\
         <div class=\"dash__list\">{rows}</div>\
         <p class=\"dash__note\">These rows come from the provisioning engine's own \
         progress table — which step a run last completed, the error that stopped it, \
         and when it last changed. The engine keeps one row per venture, so this is \
         every run in flight or stopped, not a history of past runs.{never}</p></div>\
         <p class=\"dash__note\">What a run would do beyond its first step is the \
         engine's plan, not this screen's guess: open a run to see the seven steps, \
         where this one stopped, and the failure it recorded — scrubbed the way the \
         harness scrubs driver messages, because a step error is a driver message and \
         this repository has leaked credentials through exactly that seam before.</p>",
        banner = banner(&runs),
        n = runs.len(),
        rows = rows,
        never = if never_ran == 0 {
            String::new()
        } else {
            format!(
                " {never_ran} of this account's ventures {has} never run: no row, \
                 because there is nothing to record.",
                has = if never_ran == 1 { "has" } else { "have" },
            )
        },
    );

    let crumb = format!(
        "{n} run{s} · newest first",
        n = runs.len(),
        s = if runs.len() == 1 { "" } else { "s" },
    );
    Html(render(&Page {
        title: "Deploys",
        signed_in_as: Some(&session.account_id),
        body: &format!(
            "<div class=\"page-h\"><h1>Deploys</h1></div>\
             <p class=\"lede\">Every provisioning run the engine has recorded for this \
             account's ventures — what it carried, where it stopped, and when.</p>{frame}",
            frame = frame(&account_nav("deploys"), &crumb, &body),
        ),
    }))
    .into_response()
}

/// The banner, in the voice the planned screens use — plain statements,
/// each one checkable. It is decided by the rows, not fixed in the
/// source: the day a real deployer is wired and a run finishes, the
/// static claim would become the lie, so the claim is only made while
/// the data makes it true.
fn banner(runs: &[RunRow]) -> String {
    let finished = runs
        .iter()
        .filter(|run| run.error.is_empty() && is_final_step(&run.last_step))
        .count();
    if finished == 0 {
        return format!(
            "<p class=\"dash__banner\"><span class=\"chip\">Recorded fact</span>\
             <strong>No deploy has ever reached Cloudflare.</strong> The deployer is \
             <code>Unwired</code> — no adapter talks to Cloudflare yet \
             (<a href=\"{issue}\" rel=\"noopener\">#26</a>) — so every run recorded here \
             stopped at its first step, refusing with \u{201c}no deployer is wired\u{201d}. \
             These are provisioning runs, not deploys: nothing is serving because of \
             them, and the page will not say otherwise. The day a real deployer is \
             wired, a stopped run resumes from the step after its last completed one — \
             nothing here is lost, and nothing here was deployed.</p>",
            issue = "https://github.com/Cratefield/control-plane/issues/26",
        );
    }
    format!(
        "<p class=\"dash__banner\"><span class=\"chip\">Recorded fact</span>\
         <strong>{finished} run{s} finished.</strong> The rows below are what the \
         engine recorded, no more: a finished run means its seven steps completed, \
         and this page still does not call a run a deploy or invent a \
         \u{201c}serving now\u{201d} version of it.</p>",
        s = if finished == 1 { "" } else { "s" },
    )
}

// ---------------------------------------------------------------------------
// One run
// ---------------------------------------------------------------------------

/// `/v1/dashboard/deploys/{venture}` — the seven steps with their state,
/// the timing the engine actually records, and the scrubbed error text
/// of the step that failed.
#[allow(clippy::format_push_string)] // the house idiom for HTML building
pub(super) async fn run(
    state: State<Arc<DashboardState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let ctx = &state.ctx;
    if let Err(redirect) = guard(ctx, &headers) {
        return redirect;
    }
    let session = current_session(ctx, &headers).expect("guard proved a session");
    let (account, repo) = match crate::account_of(ctx, &session.account_id).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let Some(db) = ctx.ports.db.clone() else {
        return internal("db port unavailable");
    };
    let venture = match repo.venture_for(&account.id, &id).await {
        Ok(Some(venture)) => venture,
        Ok(None) => return (axum::http::StatusCode::NOT_FOUND, "no such venture").into_response(),
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
    // The plan is the engine's own: the same source the retry button
    // uses, so the step list cannot drift from what a resume would run.
    let plan = match Engine::new(Arc::clone(&db)).plan(&venture).await {
        Ok(plan) => plan,
        Err(err) => {
            tracing::error!(error = %err, "plan read failed");
            return internal("could not load the provisioning plan");
        }
    };

    let failed = failed_step(&progress.error);
    let steps = steps_ladder(&plan, failed);
    let failure = failure_card(&progress, failed);

    let body = format!(
        "<div class=\"dash__grid\">\
         <div class=\"dash__card\">\
         <p class=\"dash__card-h\">The run</p>\
         <dl class=\"kv\">\
         <div><dt>Venture</dt><dd><a href=\"/v1/dashboard/ventures/{id}\">{slug}</a></dd></div>\
         <div><dt>Module set</dt><dd><code>{module_set}</code></dd></div>\
         <div><dt>Last changed</dt><dd>{when}</dd></div>\
         <div><dt>Outcome</dt><dd>{outcome}</dd></div>\
         </dl></div>\
         <div class=\"dash__card dash__card--wide\">\
         <p class=\"dash__card-h\">Steps <span class=\"dash__tag\">{count}</span></p>\
         <div class=\"dash__list\">{steps}</div>\
         <p class=\"dash__note\">Each step's own start and duration are not recorded: \
         the engine keeps one row per venture — the last completed step, the failure, \
         and when it last changed — rather than one row per step, so the timing above \
         is the run's, not the step's. A retry resumes from the step after the last \
         one shown done.</p></div>\
         <div class=\"dash__card dash__card--wide\">\
         <p class=\"dash__card-h\">The failure</p>{failure}</div></div>",
        id = escape(&venture.id),
        slug = escape(&venture.slug),
        module_set = escape(&venture.module_set),
        when = escape(&progress.updated_at),
        outcome = outcome(&RunRow {
            venture_id: venture.id.clone(),
            slug: venture.slug.clone(),
            module_set: venture.module_set.clone(),
            last_step: progress.last_step.clone(),
            error: progress.error.clone(),
            updated_at: progress.updated_at.clone(),
        }),
        count = plan.len(),
        steps = steps,
        failure = failure,
    );

    let crumb = format!(
        "<a href=\"{PATH}\">Deploys</a> / {slug}",
        slug = escape(&venture.slug),
    );
    Html(render(&Page {
        title: &venture.slug,
        signed_in_as: Some(&session.account_id),
        body: &format!(
            "<p class=\"crumb\">{crumb}</p>\
             <div class=\"page-h\"><h1>{slug}</h1></div>\
             <p class=\"lede\">One provisioning run: the seven steps the engine runs, \
             where this one stopped, and the failure it recorded.</p>{frame}",
            slug = escape(&venture.slug),
            frame = frame(&account_nav("deploys"), &venture.slug, &body),
        ),
    }))
    .into_response()
}

/// The step ladder: every step the engine runs, its state, and the
/// engine's own description of what it does — generated from
/// [`Engine::plan`], never a list kept here that could drift.
#[allow(clippy::format_push_string)] // the house idiom for HTML building
fn steps_ladder(plan: &[cratefield_provisioning::PlannedStep], failed: Option<&str>) -> String {
    let mut steps = String::from(
        "<div class=\"dash__lrow dash__lrow--steps dash__lrow--head\"><span></span>\
         <span>Step</span><span>State</span><span>What it does</span></div>",
    );
    for planned in plan {
        let token = planned.step.as_str();
        let (dot, state) = if Some(token) == failed {
            ("<span class=\"dash__dot dash__dot--bad\"></span>", "failed")
        } else if planned.done {
            ("<span class=\"dash__dot dash__dot--live\"></span>", "done")
        } else {
            ("<span class=\"dash__dot\"></span>", "pending")
        };
        steps.push_str(&format!(
            "<div class=\"dash__lrow dash__lrow--steps\">\
             <span>{dot}</span><span><code>{token}</code></span><span>{state}</span> \
             <span class=\"dash__meta\">{description}</span></div>",
            token = escape(token),
            description = escape(&planned.description),
        ));
    }
    steps
}

/// The failure card: the recorded error, scrubbed the way `DbError`'s
/// `Display` scrubs — emails, signed tokens, URL queries, URL
/// credentials and bearer values are rewritten before the text reaches
/// the page, because a step error is a driver message and that is the
/// seam credentials leak through.
fn failure_card(progress: &crate::Progress, failed: Option<&str>) -> String {
    if progress.error.is_empty() {
        return String::from(
            "<p class=\"dash__note\">No failure is recorded for this run. A run with no \
             error and an unfinished ladder is one that has not been run to the end — \
             the engine records no \u{201c}in flight\u{201d} state of its own.</p>",
        );
    }
    format!(
        "<p class=\"dash__row\"><span class=\"dash__dot dash__dot--bad\"></span>\
         <strong>Recorded failure</strong>{where_}</p>\
         <p class=\"dash__note\">{error}</p>\
         <p class=\"dash__note\">Shown as recorded, scrubbed the way \
         <code>DbError</code>'s <code>Display</code> scrubs, for the reason above.</p>",
        where_ = match failed {
            Some(step) => format!(" at <code>{step}</code>"),
            None => String::from(
                " — the recorded error names no step the engine knows, so it is \
                 shown unpinned rather than guessed at",
            ),
        },
        error = escape(&scrub_text(&progress.error)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Dashboard;
    use cratefield_access::{DEFAULT_TTL_SECS, issue_session};
    use cratefield_accounts::Repository;
    use cratefield_core::Statement;
    use cratefield_testing::TestHarness;
    use http::{Method, Request as HttpRequest, StatusCode, header};
    use tower::util::ServiceExt;

    const EMAIL: &str = "op@cratefield.com";
    const NOW: u64 = 1_800_000_000;
    const REFUSAL: &str = "artifact: no deployer is wired: building the composed artifact \
         needs an adapter that talks to Cloudflare, and the control plane has none yet. \
         Nothing was changed.";

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

    async fn get(kit: &TestHarness, uri: &str, cookie: Option<&str>) -> (StatusCode, String) {
        let mut builder = HttpRequest::builder().method(Method::GET).uri(uri);
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
        let bytes = axum::body::to_bytes(body, 4 * 1024 * 1024)
            .await
            .expect("body");
        (
            parts.status,
            String::from_utf8(bytes.to_vec()).expect("utf-8"),
        )
    }

    async fn seed_venture(kit: &TestHarness, id: &str, slug: &str, modules: &str) {
        let repo = Repository::new(kit.db.clone());
        repo.account_for_login(EMAIL, "Op", "acc_1", "t0")
            .await
            .expect("account");
        repo.create_venture(
            id,
            "acc_1",
            slug,
            &format!("{slug}.cratefield.app"),
            modules,
            "ten_1",
            "t0",
        )
        .await
        .expect("venture");
    }

    /// The row the engine writes, exactly as it writes it.
    async fn record_run(kit: &TestHarness, venture: &str, last_step: &str, error: &str, at: &str) {
        kit.db
            .execute(&Statement::with_values(
                "INSERT INTO provision_progress (venture_id, last_step, error, updated_at) \
                 VALUES (?, ?, ?, ?)",
                vec![text(venture), text(last_step), text(error), text(at)],
            ))
            .await
            .expect("progress row");
    }

    #[pollster::test]
    async fn the_deploys_screen_lists_runs_newest_first_and_says_none_reached_cloudflare() {
        let kit = kit();
        seed_venture(&kit, "v1", "my-app", "cms+waitlist").await;
        seed_venture(&kit, "v2", "other-app", "cms").await;
        record_run(&kit, "v1", "", REFUSAL, "2026-02-01T00:00:00Z").await;
        record_run(&kit, "v2", "", REFUSAL, "2026-03-01T00:00:00Z").await;

        let (status, body) = get(&kit, PATH, Some(&cookie(&kit))).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // Newest first: other-app's run (March) above my-app's (February).
        let newer = body.find("other-app").expect("the newer run is listed");
        let older = body.find("my-app").expect("the older run is listed");
        assert!(newer < older, "runs must list newest first: {body}");

        // The banner keeps the page from reading as a list of deploys.
        assert!(
            body.contains("No deploy has ever reached Cloudflare"),
            "{body}"
        );
        assert!(body.contains("issues/26"), "{body}");
        assert!(body.contains("<code>Unwired</code>"), "{body}");
        // A run is a run.
        assert!(body.contains("stopped at <code>artifact</code>"), "{body}");
        assert!(body.contains("<code>cms+waitlist</code>"), "{body}");
        // The module set it carried, and the click-in.
        assert!(body.contains("href=\"/v1/dashboard/deploys/v2\""), "{body}");
        // The planned page is gone.
        assert!(!body.contains("Not built."), "{body}");
        // And no invented serving state.
        assert!(!body.contains("serving now"), "{body}");
    }

    #[pollster::test]
    async fn a_finished_run_changes_the_banner_rather_than_letting_it_lie() {
        let kit = kit();
        seed_venture(&kit, "v1", "my-app", "cms").await;
        record_run(&kit, "v1", "health", "", "2026-03-01T00:00:00Z").await;

        let (status, body) = get(&kit, PATH, Some(&cookie(&kit))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        // The static claim is only made while the data makes it true.
        assert!(
            !body.contains("No deploy has ever reached Cloudflare"),
            "a finished run must retire the static banner: {body}"
        );
        assert!(body.contains("1 run finished"), "{body}");
        assert!(body.contains("finished — every step done"), "{body}");
    }

    #[pollster::test]
    async fn a_step_error_cannot_carry_a_credential_to_the_page() {
        let kit = kit();
        seed_venture(&kit, "v1", "my-app", "cms").await;
        // A driver-shaped failure: the URL credentials are exactly the
        // seam this test exists for — the error column is plain text a
        // driver fills, and `DbError`'s Display scrubs for that reason.
        record_run(
            &kit,
            "v1",
            "schema",
            "schema: apply failed: could not connect to \
             postgres://venture:sup3r-s3cret-pw@db.internal:5432/app: password rejected",
            "2026-03-01T00:00:00Z",
        )
        .await;

        let (status, body) = get(&kit, &format!("{PATH}/v1"), Some(&cookie(&kit))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(!body.contains("sup3r-s3cret-pw"), "{body}");
        assert!(!body.contains("postgres://venture:"), "{body}");
        // The scrubber's marker, and the diagnostic that survives it.
        assert!(body.contains("[redacted]"), "{body}");
        assert!(body.contains("password rejected"), "{body}");

        // The list renders the outcome, not the error — but it is held to
        // the same standard anyway.
        let (_, list) = get(&kit, PATH, Some(&cookie(&kit))).await;
        assert!(!list.contains("sup3r-s3cret-pw"), "{list}");
    }

    #[pollster::test]
    async fn the_run_page_shows_every_step_and_where_it_stopped() {
        let kit = kit();
        seed_venture(&kit, "v1", "my-app", "cms").await;
        record_run(&kit, "v1", "worker", "", "2026-03-01T00:00:00Z").await;

        let (status, body) = get(&kit, &format!("{PATH}/v1"), Some(&cookie(&kit))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        for token in [
            "artifact", "database", "worker", "schema", "secrets", "route", "health",
        ] {
            assert!(body.contains(&format!("<code>{token}</code>")), "{body}");
        }
        assert!(
            body.contains("reached <code>worker</code>, no failure recorded"),
            "{body}"
        );
        // Timing honesty: the note says the run's, not the step's.
        assert!(
            body.contains("Each step's own start and duration are not recorded"),
            "{body}"
        );
        // And the plan is the engine's, not a list kept here.
        assert!(
            body.contains("create the D1 database for tenant"),
            "the step descriptions must come from the engine's plan: {body}"
        );
    }

    #[pollster::test]
    async fn one_account_cannot_read_anothers_runs() {
        let kit = kit();
        seed_venture(&kit, "v1", "my-app", "cms").await;
        record_run(&kit, "v1", "", REFUSAL, "2026-03-01T00:00:00Z").await;

        let repo = Repository::new(kit.db.clone());
        repo.account_for_login("b@x.co", "B", "acc_2", "t0")
            .await
            .expect("account");
        let token = issue_session(kit.signer.as_ref(), "b@x.co", NOW, DEFAULT_TTL_SECS);

        let (status, body) = get(&kit, PATH, Some(&format!("cf_session={token}"))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            !body.contains("my-app"),
            "another account's runs must not list: {body}"
        );

        let (status, _) = get(
            &kit,
            &format!("{PATH}/v1"),
            Some(&format!("cf_session={token}")),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[pollster::test]
    async fn a_venture_that_never_ran_is_a_note_not_a_row() {
        let kit = kit();
        seed_venture(&kit, "v1", "my-app", "cms").await;

        let (status, body) = get(&kit, PATH, Some(&cookie(&kit))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.contains("1 of this account's ventures has never run"),
            "{body}"
        );
        assert!(
            !body.contains("href=\"/v1/dashboard/deploys/v1\""),
            "a venture with no run must not render a run link: {body}"
        );
    }
}
