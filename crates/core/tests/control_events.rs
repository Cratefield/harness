//! Boot-time control events reaching the process-wide error forwarder
//! (issue #441).
//!
//! On Cloudflare/wasm32 no `tracing` dispatcher can be installed (it hangs
//! the workerd isolate), so every `tracing::*` event is dropped and the only
//! path to Workers Logs is the process-wide forwarder
//! `cratefield_core::set_error_forwarder` installs. The production-readiness
//! gate — an operator's `HARNESS_ALLOW_UNPROTECTED_WRITES` acceptance, and
//! the refusal when no acceptance is configured — therefore forwards each
//! record through that sink *in addition to* its `tracing` event.
//!
//! The unit tests in `src/logging.rs` cover the forwarder API in isolation.
//! These tests close the loop end to end: they drive the real boot path
//! (`Harness::router`, which is where the private `production_readiness_now`
//! runs) the way a production deployment boots — a venture compiled as
//! development, deployed with `ENV=production`, a captcha-guarded public
//! write, and no effectively configured Captcha port — and assert the
//! installed sink captured what an auditor would look for, at the level the
//! record claims to carry.

// The capture sink below is a `std::sync::Mutex` on purpose (see the comment
// above `INSTALL`); clippy.toml bans the type workspace-wide, so the allow is
// scoped to this file.
#![allow(clippy::disallowed_types)]

mod common;

use std::sync::Arc;

use axum::http::{Method, StatusCode};
use common::{base_venture, body_json, request};
use cratefield_core::{
    ALLOW_UNLIMITED_PUBLIC_ROUTES, ALLOW_UNPROTECTED_WRITES, Config, ConfigError, Harness,
    MapConfig, Migrations, Module, ModuleContext, Port, Ports, Runtime,
};

// ---------------------------------------------------------- the capture sink
//
// **Process-global on purpose.** A thread-local `tracing` capture through
// `with_default` will not do: it held locally in an earlier suite and missed
// every line emitted off the asserting thread. The sink
// `set_error_forwarder` installs is global and `Mutex`-guarded, so it cannot
// miss a line for scheduling reasons.
//
// Being global means a single test binary may install exactly one sink
// (first install wins, later ones are dropped by contract) and every test in
// this file shares one buffer. So an assertion must name a needle only its
// own test produces, and the buffer is never asserted empty: another boot
// may have filled it first.

static CAPTURED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
static INSTALL: std::sync::Once = std::sync::Once::new();

fn record(line: &str) {
    CAPTURED.lock().expect("capture lock").push(line.to_owned());
}

/// Installs the sink once per test binary — `set_error_forwarder` keeps the
/// first installation and ignores later ones, so this must not race — and
/// returns the lookup. Call it **before** the boot: the control events are
/// forwarded while `Harness::router` runs, and a sink installed afterwards
/// would have missed them.
fn capture() -> impl Fn(&str) -> Option<String> {
    INSTALL.call_once(|| cratefield_core::set_error_forwarder(record));
    move |needle: &str| {
        CAPTURED
            .lock()
            .expect("capture lock")
            .iter()
            .find(|line| line.contains(needle))
            .cloned()
    }
}

// ------------------------------------------------------------------ fixtures

/// Provides every port but can usefully back none of them — the Captcha
/// binding is the shape of a deployment whose Turnstile secret never
/// arrived, which is exactly the gap `production_readiness` reports.
struct UnusableCaptcha;

impl Runtime for UnusableCaptcha {
    fn provides(&self) -> Vec<Port> {
        Port::ALL.to_vec()
    }
    fn effectively_configured(&self, port: Port) -> bool {
        port != Port::Captcha
    }
}

/// A public writer with no declared surface: the undeclared-public-writer
/// fallback files it under `needs_captcha`, so a production boot with no
/// effective Captcha port has a problem to record. Its name appears in that
/// problem text, which doubles as a needle no other test produces.
struct PublicWriter;

impl Module for PublicWriter {
    fn name(&self) -> &'static str {
        "control-events-writer"
    }
    fn version(&self) -> &'static str {
        "0.0.0-test"
    }
    fn requires(&self) -> &'static [Port] {
        &[]
    }
    fn public_writes(&self) -> bool {
        true
    }
    fn migrations(&self) -> Migrations {
        Migrations::default()
    }
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        axum::Router::new().route("/join", axum::routing::post(|| async { "ok" }))
    }
}

/// The operator's reason, unique to this file so the shared sink's other
/// traffic can never satisfy the acceptance assertion.
const ACCEPTANCE_REASON: &str =
    "control-events-441: Turnstile is pending on the Cloudflare account";

/// A harness the way a production deployment builds one: the compiled env
/// is development (so `Harness::build`'s own gate passes), and the
/// deployment's stricter `ENV=production` is what turns the readiness
/// re-check inside `Harness::router` into a boot-time control event.
fn production_writer_harness() -> Harness {
    Harness::builder()
        .venture(base_venture())
        .module(PublicWriter)
        .runtime(UnusableCaptcha)
        .build()
        .expect("the compiled env is development, so the build-time gate passes")
}

/// The deployment's config: `ENV=production`, plus the operator's recorded
/// reason when one is configured. The reason rides the `Config` map —
/// `unprotected_writes_override` reads it through `Config::get` — never the
/// process environment, which no test here touches.
fn production_ports(acceptance: Option<&str>) -> Ports {
    let mut pairs = vec![("ENV", "production")];
    if let Some(reason) = acceptance {
        pairs.push((ALLOW_UNPROTECTED_WRITES, reason));
        // These ports wire no `RateLimiter`, and readiness refuses a
        // production venture with public writes that has none — a waiver
        // covers only the control it names, so the unprotected-writes
        // acceptance does not excuse the limiter leg. What this test is
        // about is the forwarded record, so both legs are accepted and the
        // boot gets far enough to produce one.
        pairs.push((ALLOW_UNLIMITED_PUBLIC_ROUTES, reason));
    }
    Ports::with_config(Arc::new(MapConfig::from_pairs(pairs)))
}

// ----------------------------------------------------------------- the boots

/// Issue #441's first acceptance criterion, end to end: booting on an
/// operator's recorded acceptance must leave an observable record carrying
/// the acceptance, the reason and the problems accepted, prefixed `[warn] ` —
/// the record an auditor looks for, readable on wasm where the `tracing`
/// event goes nowhere.
#[pollster::test]
async fn a_boot_on_a_recorded_acceptance_forwards_the_acceptance_its_reason_and_its_problems() {
    let capture = capture();
    let router = production_writer_harness().router(production_ports(Some(ACCEPTANCE_REASON)));

    // The acceptance serves: the record, not the gate, is the accountability.
    let served = request(
        &router,
        Method::POST,
        "/v1/control-events-writer/join",
        &[],
        Some(b"{}".to_vec()),
    )
    .await;
    assert_eq!(
        served.status(),
        StatusCode::OK,
        "an operator's acceptance serves the guarded route"
    );

    let line = capture(ACCEPTANCE_REASON)
        .expect("the boot should have forwarded the acceptance to the installed sink");
    assert!(
        line.starts_with("[warn] "),
        "an acceptance is recorded as a warning: {line}"
    );
    assert!(
        line.contains("serving guarded routes unprotected on an operator's recorded acceptance"),
        "the record should say what happened: {line}"
    );
    assert!(
        line.contains("captcha-guarded public writes from [control-events-writer]"),
        "the problems the operator accepted ride the same line: {line}"
    );
}

/// The other half (issue #441): the same boot with no acceptance configured
/// forwards the refusal at `[error] `, and the boot fails closed — the
/// guarded route answers 503 `not-production-ready` while the probes stay up
/// to say why.
#[pollster::test]
async fn a_readiness_refusal_is_forwarded_at_error_level_and_the_guarded_route_answers_503() {
    let capture = capture();
    let router = production_writer_harness().router(production_ports(None));

    let refused = request(
        &router,
        Method::POST,
        "/v1/control-events-writer/join",
        &[],
        Some(b"{}".to_vec()),
    )
    .await;
    assert_eq!(
        refused.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "no acceptance, no serving"
    );
    let body = body_json(refused).await;
    assert_eq!(
        body["type"].as_str().unwrap().rsplit('/').next().unwrap(),
        "not-production-ready"
    );

    // The probes stay up: an outage with no diagnosis is worse than one
    // someone can read.
    let health = request(&router, Method::GET, "/__health", &[], None).await;
    assert_eq!(health.status(), StatusCode::OK);

    let line = capture(
        "refusing guarded routes: production venture has captcha-guarded public writes \
         from [control-events-writer]",
    )
    .expect("the boot should have forwarded the refusal to the installed sink");
    assert!(
        line.starts_with("[error] "),
        "a refusal is recorded as an error: {line}"
    );
    assert!(
        line.contains(ALLOW_UNPROTECTED_WRITES),
        "the refusal tells the operator the key that would accept it: {line}"
    );
}
