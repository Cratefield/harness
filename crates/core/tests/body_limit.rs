//! The pre-buffer body ceiling (issue #440): `Harness::max_body_bytes`
//! maps a request path to the largest body a runtime may buffer for it,
//! so a fixed-memory runtime (a Workers isolate) can refuse an oversize
//! body before the router's `DefaultBodyLimit` — which only fires once
//! the bytes are resident — ever sees it.

mod common;

use std::sync::Arc;

use axum::Router;
use common::*;
use cratefield_core::{
    Config, ConfigError, Harness, MAX_BODY_BYTES, MapConfig, Migrations, Module, ModuleContext,
    Port,
};

/// A module that declares its own body ceiling, the way LinkedIn's image
/// upload does. `ceiling` is returned verbatim — smaller than
/// `MAX_BODY_BYTES` included — so the tests can see the harness's floor
/// applied on top of it.
struct CeilingModule {
    name: &'static str,
    ceiling: usize,
}

impl Module for CeilingModule {
    fn name(&self) -> &'static str {
        self.name
    }
    fn version(&self) -> &'static str {
        "0.0.0-test"
    }
    fn requires(&self) -> &'static [Port] {
        &[]
    }
    fn migrations(&self) -> Migrations {
        Migrations::default()
    }
    fn validate_config(&self, _: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, _: ModuleContext) -> Router {
        Router::new()
    }
    fn max_body_bytes(&self, _: &dyn Config) -> usize {
        self.ceiling
    }
}

fn harness_with(module: CeilingModule) -> Harness {
    Harness::builder()
        .venture(base_venture())
        .module(module)
        .runtime(FakeRuntime(all_ports()))
        .build()
        .expect("a ceiling module builds")
}

fn empty_config() -> Arc<dyn Config> {
    Arc::new(MapConfig::default())
}

/// The ceiling is consulted with the raw path the runtime has —
/// `url.path()` — so that exact shape must work first.
#[test]
fn a_module_route_picks_up_the_module_ceiling() {
    let harness = harness_with(CeilingModule {
        name: "greedy",
        ceiling: 8 * 1024 * 1024,
    });
    let cfg = empty_config();
    assert_eq!(
        harness.max_body_bytes("/v1/greedy/admin/images", cfg.as_ref()),
        8 * 1024 * 1024
    );
    // The mount root itself, `/v1/<name>`, is a route too.
    assert_eq!(
        harness.max_body_bytes("/v1/greedy", cfg.as_ref()),
        8 * 1024 * 1024
    );
}

#[test]
fn a_module_ceiling_cannot_sink_below_the_router_default() {
    // The guard sits in front of the router: a module returning less than
    // `MAX_BODY_BYTES` would 413 requests the router itself accepts.
    let harness = harness_with(CeilingModule {
        name: "tight",
        ceiling: 16,
    });
    assert_eq!(
        harness.max_body_bytes("/v1/tight/join", empty_config().as_ref()),
        MAX_BODY_BYTES
    );
}

#[test]
fn a_module_ceiling_is_never_pulled_down_by_the_floor() {
    // Above the default, the module's word wins: that is the whole point
    // (the image upload).
    let harness = harness_with(CeilingModule {
        name: "greedy",
        ceiling: MAX_BODY_BYTES * 2,
    });
    assert_eq!(
        harness.max_body_bytes("/v1/greedy", empty_config().as_ref()),
        MAX_BODY_BYTES * 2
    );
}

#[test]
fn an_unknown_module_gets_the_default_ceiling() {
    let harness = harness_with(CeilingModule {
        name: "greedy",
        ceiling: 8 * 1024 * 1024,
    });
    assert_eq!(
        harness.max_body_bytes("/v1/nowhere/join", empty_config().as_ref()),
        MAX_BODY_BYTES
    );
}

#[test]
fn every_path_outside_a_module_mount_gets_the_default_ceiling() {
    let harness = harness_with(CeilingModule {
        name: "greedy",
        ceiling: 8 * 1024 * 1024,
    });
    let cfg = empty_config();
    for path in [
        "/",
        "/ui/waitlist/status",
        "/__events",
        "/__health",
        "/.well-known/jwks.json",
        "/v2/greedy/anything",
        "/greedy/anything",
        // `/v1` with no module segment names no module.
        "/v1",
        "/v1/",
    ] {
        assert_eq!(
            harness.max_body_bytes(path, cfg.as_ref()),
            MAX_BODY_BYTES,
            "default ceiling for {path}"
        );
    }
}

#[test]
fn the_ceiling_lookup_survives_query_strings_and_stray_slashes() {
    let harness = harness_with(CeilingModule {
        name: "greedy",
        ceiling: 8 * 1024 * 1024,
    });
    let cfg = empty_config();
    // `url.path()` never carries a query, but a caller passing the whole
    // URL must not have the module misidentified for it.
    assert_eq!(
        harness.max_body_bytes("/v1/greedy/admin/images?size=2", cfg.as_ref()),
        8 * 1024 * 1024
    );
    assert_eq!(
        harness.max_body_bytes("/v1/greedy/", cfg.as_ref()),
        8 * 1024 * 1024
    );
    assert_eq!(
        harness.max_body_bytes("//v1//greedy//images", cfg.as_ref()),
        8 * 1024 * 1024
    );
    assert_eq!(
        harness.max_body_bytes("/v1/nowhere?x=1", cfg.as_ref()),
        MAX_BODY_BYTES
    );
}

/// A module that declares nothing — the default — keeps the harness
/// default on its own mount.
#[test]
fn the_default_module_ceiling_is_the_harness_default() {
    let harness = harness_with_sample();
    assert_eq!(
        harness.max_body_bytes("/v1/sample/hello", empty_config().as_ref()),
        MAX_BODY_BYTES
    );
}
