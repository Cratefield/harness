//! Production limiter readiness on the native runtime (issue #562): a
//! module that declares `Port::RateLimiter` — required or optional — holds
//! a production venture to a mounted limiter. `Native` provides the port
//! only when `.rate_limiter(..)` was called, so there is no
//! named-but-unresolved middle state here: the refusal is a **build
//! error**, naming the module and the routes that would run unlimited.

use std::sync::Arc;

use cratefield_core::{
    Action, Audience, Config, ConfigError, Decision, Harness, Migrations, Module, ModuleContext,
    Port, RateLimitError, RateLimiter, Surface, Venture, VentureEnv,
};
use cratefield_runtime_native::Native;

/// A public read published by a module that declares the limiter port —
/// no captcha form, no public write, no admin plane, so the issue #437
/// triggers stay silent and what the gate reads is the declaration.
struct SearchModule;

impl Module for SearchModule {
    fn name(&self) -> &'static str {
        "search"
    }

    fn version(&self) -> &'static str {
        "0.0.0-test"
    }

    fn requires(&self) -> &'static [Port] {
        &[]
    }

    fn optional(&self) -> &'static [Port] {
        &[Port::RateLimiter]
    }

    fn migrations(&self) -> Migrations {
        Migrations::default()
    }

    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }

    fn surface(&self) -> Surface {
        Surface::new().action(Action::get("search", "/search").audience(Audience::Public))
    }

    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        axum::Router::new()
    }
}

/// The cheapest limiter that satisfies the port; the build gate only asks
/// that one is mounted.
struct NoopLimiter;

#[async_trait::async_trait]
impl RateLimiter for NoopLimiter {
    async fn limit(&self, _key: &str) -> Result<Decision, RateLimitError> {
        Ok(Decision {
            ok: true,
            retry_after: None,
            quota: None,
        })
    }
}

fn venture(env: VentureEnv) -> Venture {
    Venture::new("venture", "test.example")
        .cors_origins(["https://test.example"])
        .env(env)
}

#[test]
fn a_production_venture_with_a_declaring_module_needs_a_limiter_mounted() {
    let error = Harness::builder()
        .venture(venture(VentureEnv::Production))
        .module(SearchModule)
        .runtime(Native::new())
        .build()
        .expect_err("no limiter mounted: the build refuses");
    let message = error.problems.join("\n");
    assert!(message.contains("search"), "{message}");
    assert!(message.contains("GET /v1/search/search"), "{message}");
    assert!(
        message.contains("HARNESS_ALLOW_UNLIMITED_PUBLIC_ROUTES"),
        "the hatch is named the way the boot gate names it: {message}"
    );

    // The same composition with the limiter mounted builds.
    Harness::builder()
        .venture(venture(VentureEnv::Production))
        .module(SearchModule)
        .runtime(Native::new().rate_limiter_arc(Arc::new(NoopLimiter)))
        .build()
        .expect("a mounted limiter satisfies the declaration");

    // Below production nothing is owed.
    Harness::builder()
        .venture(venture(VentureEnv::Development))
        .module(SearchModule)
        .runtime(Native::new())
        .build()
        .expect("a development venture builds without a limiter");
}
