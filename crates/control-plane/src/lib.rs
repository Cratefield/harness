//! The Cratefield control plane, as a harness venture.
//!
//! "The same Rust backend as we do now" (the ADR, `docs/ARCHITECTURE.md`)
//! is meant literally: the control plane is one more Worker + D1 built on
//! `Cratefield/harness`, and it dogfoods the same runtime, secrets layer
//! and UI surface it provisions for customers.
//!
//! This crate is the wasm entry point and the composition root. The
//! control-plane logic lives in its module crates (`accounts`, `catalog`,
//! `connections`, `provisioning`, `cms`), added as the epic's children
//! land; today it is the smallest thing that answers `/__health`.

#![forbid(unsafe_code)]

use std::sync::{Arc, OnceLock};

use cratefield_adapter_resend::Resend;
use cratefield_core::{Config as _, Harness, Venture};
use cratefield_runtime_cloudflare::{
    Cloudflare, EnvConfig, FetchClient, WorkersClock, serve, serve_scheduled,
};
use worker::{Context, Env, Request, Response, event};

static INSTANCE: OnceLock<(Harness, Cloudflare)> = OnceLock::new();

/// The Workers Rate Limiting binding (`[[ratelimits]]` in `wrangler.toml`).
/// Readiness refuses every `/v1` route of a production deployment with
/// admin routes or public writes unless a limiter resolves (issue #437),
/// and the console has both — so without this the deployed console would
/// answer `not-production-ready` to everything but the probes.
const RATE_LIMITER_BINDING: &str = "RATE_LIMITER";

/// The Worker secret holding the Resend API key that carries the console's
/// magic link. Absent, no mailer is wired and the login page hides the
/// magic-link option rather than offering a form that cannot send.
const RESEND_API_KEY: &str = "RESEND_API_KEY";

/// The runtime this deployment serves with: D1, the rate limiter, and the
/// mailer when its key is set. Built once and handed to both the harness
/// (whose `build` checks module requirements against it) and `serve`, so
/// the two can never disagree about what ports exist.
fn runtime_for(env: &Env) -> Cloudflare {
    let runtime = Cloudflare::new()
        .db("DB")
        .rate_limiter(RATE_LIMITER_BINDING);
    let config = EnvConfig(env.clone());
    match config
        .get(RESEND_API_KEY)
        .filter(|key| !key.trim().is_empty())
    {
        // The console sets the sender on every message
        // (`CONSOLE_MAGIC_LINK_FROM`), so the adapter's own default sender
        // is only a fallback and stays empty here.
        Some(key) => runtime.mailer(Resend::new(
            Arc::new(FetchClient),
            Arc::new(WorkersClock),
            Some(key),
            String::new(),
            None,
        )),
        None => runtime,
    }
}

/// The composed control plane. One instance per isolate; the harness is
/// built once and reused (ADR 0007: no ambient request state, the scope
/// travels with the request). The `Env` is read only on the first event,
/// for the mailer key; a rotated key reaches a fresh isolate, which every
/// `wrangler secret put` starts.
fn instance(env: &Env) -> &'static (Harness, Cloudflare) {
    INSTANCE.get_or_init(|| {
        let runtime = runtime_for(env);
        let harness = Harness::builder()
            .venture(
                Venture::new("cratefield-control-plane", "cratefield.com")
                    .public_url("https://app.cratefield.com")
                    .cors_origins(["https://app.cratefield.com"]),
            )
            // The console (#3): session guard, login skeleton, operator
            // allowlist. More modules land with the wizard (#8) and dashboard
            // (#11).
            // The shared page chrome (the stylesheet every screen links).
            // Mounted first so it is obvious that it is the frame, not a
            // feature.
            .module(cratefield_chrome::Chrome)
            .module(cratefield_console::Console)
            // The account dashboard (#11): ventures, health verdicts,
            // connections, archiving. Read-only except archiving; see
            // docs/DASHBOARD.md for the half that is not built.
            //
            // No KMS is wired here on purpose: the Workers runtime has no
            // filesystem for `LocalFileKms` and no managed KMS adapter
            // exists yet (its own issue, deliberately not invented in the
            // pass that added the secrets screen). The dashboard carries
            // `None` and the secrets screen renders that state honestly
            // rather than failing — `Some(kms)` arrives with the adapter.
            .module(cratefield_dashboard::Dashboard::default())
            .runtime(runtime.clone())
            .build()
            .expect("the control-plane harness is valid");
        (harness, runtime)
    })
}

#[event(fetch)]
/// Worker fetch entry point.
///
/// # Errors
///
/// Propagates `worker::Error` from the harness router.
pub async fn fetch(req: Request, env: Env, ctx: Context) -> worker::Result<Response> {
    let (harness, runtime) = instance(&env);
    serve(harness, runtime, req, env, ctx).await
}

#[event(scheduled)]
pub async fn scheduled(event: worker::ScheduledEvent, env: Env, ctx: worker::ScheduleContext) {
    let (harness, runtime) = instance(&env);
    serve_scheduled(harness, runtime, event, env, ctx).await;
}

#[cfg(test)]
mod tests {
    /// The secrets screen tells an operator the date of the next
    /// automatic key rotation. `serve_scheduled` is the only thing that
    /// runs that pass, and a cron trigger is the only thing that calls
    /// `serve_scheduled` on a Worker — so if this Worker's config loses
    /// its trigger, the screen keeps naming a date and nothing ever acts
    /// on it. A promise a deployment cannot keep is worse than a screen
    /// that admits it does nothing, so the trigger is pinned here rather
    /// than left to a reviewer to notice.
    #[test]
    fn the_worker_registers_the_cron_its_scheduled_work_depends_on() {
        let config = include_str!("../wrangler.toml");
        assert!(
            config.contains("[triggers]"),
            "the control plane declares scheduled work and must register a trigger for it"
        );
        let crons = config
            .split("crons = [")
            .nth(1)
            .and_then(|rest| rest.split(']').next())
            .expect("a triggers section names its cron expressions");
        assert!(
            crons.contains('*'),
            "a cron expression, not an empty list: {crons}"
        );
    }

    /// `wrangler d1 migrations apply` reads `migrations/`, not the modules,
    /// so every migration a mounted module declares has to be collected
    /// there (`fz migrations collect`, pinned by `.harness-lock.json`) with
    /// exactly the module's SQL. Without this the directory silently fell
    /// eleven migrations behind the console and the dashboard (#688): a
    /// deploy would have served the magic link, environments and the
    /// secrets screen against tables that did not exist.
    #[test]
    fn every_module_migration_is_collected_for_wrangler() {
        use cratefield_core::Module;

        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let lock: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join(".harness-lock.json")).expect("the lockfile"),
        )
        .expect("the lockfile parses");
        let modules: [&dyn Module; 3] = [
            &cratefield_chrome::Chrome,
            &cratefield_console::Console,
            &cratefield_dashboard::Dashboard::default(),
        ];
        for module in modules {
            for migration in module.migrations().sqlite {
                let key = format!("{}/{}", module.name(), migration.id);
                let file = lock[&key]["file"].as_str().unwrap_or_else(|| {
                    panic!("{key} is not collected into migrations/ (docs/control-plane/DEPLOY.md, \"Migrations\")")
                });
                let collected =
                    std::fs::read_to_string(dir.join(file)).expect("the collected file");
                assert_eq!(
                    collected,
                    migration.sql.trim_end().to_owned() + "\n",
                    "{file} differs from {key}'s SQL"
                );
            }
        }
    }

    /// The runtime names a limiter binding, and a named binding that does
    /// not resolve fails every `/v1` route closed (issue #562). Wrangler
    /// does not inherit bindings into an environment, so the binding has to
    /// be declared twice — once for `wrangler dev`, once for the production
    /// deploy — and losing either copy takes that shape of the console
    /// down. The production section also has to keep its Custom Domain and
    /// its `ENV`, or the deploy lands somewhere nobody looks, in a mode
    /// that skips the production rules.
    #[test]
    fn both_worker_shapes_declare_the_limiter_and_production_its_domain() {
        let config = include_str!("../wrangler.toml");
        let binding = format!("name = \"{}\"", super::RATE_LIMITER_BINDING);
        let (local, production) = config
            .split_once("\n[env.production]\n")
            .expect("a production environment");
        assert!(
            local.contains("[[ratelimits]]") && local.contains(&binding),
            "local dev declares the limiter"
        );
        assert!(
            production.contains("[[env.production.ratelimits]]") && production.contains(&binding),
            "production declares the limiter"
        );
        assert!(
            production.contains(
                "routes = [{ pattern = \"console.cratefield.com\", custom_domain = true }]"
            )
        );
        assert!(production.contains("ENV = \"production\""));
        assert!(production.contains("CONSOLE_BASE_URL = \"https://console.cratefield.com\""));
    }
}
