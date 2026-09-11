//! The double's module: one event subscription and one evidence route
//! (issue #258). Its job is to make the two halves of the sidecar-forward
//! contract separately observable from CI:
//!
//! - `/v1/probe/delivered` reports that the host's forward actually
//!   **arrived and was heard** — the half a timing assertion alone would
//!   pass on a broken forward. A module's `tracing` output is dropped on
//!   wasm32 (issue #107), so an in-memory endpoint is the evidence
//!   channel, read back over HTTP within the same dev session.
//! - The subscription is a real subscriber through the real
//!   `deliver_inbound` path, so the event must clear the gateway stamp,
//!   the envelope parse and the bus — not merely reach the Worker.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::extract::State;
use axum::routing::get;
use cratefield_core::{AnyError, EventHandler, EventName, Module, ModuleContext, Scope};
use serde_json::Value;

/// The event the venture's sample module emits from
/// `/v1/sample/sidecar-probe` (issue #258). One name, pinned on both ends;
/// a typo on either side is exactly the silently-undelivered forward this
/// whole check exists to catch, and the evidence endpoint goes red for it.
pub const SUBSCRIBED_EVENT: &str = "sample.probe";

/// What the subscription has observed. `AtomicUsize` alone would answer
/// "something arrived"; the last request id answers "*this* run's request
/// arrived", which is what keeps the check honest across a job that fires
/// the probe more than once while iterating.
#[derive(Default)]
pub struct Deliveries {
    count: AtomicUsize,
    // Delivery evidence recorded by the subscription, read back by the
    // evidence route — the same recording-fake shape as `cratefield-testing`'s,
    // not request state (ADR 0007); scoped allow per the clippy.toml policy.
    #[allow(clippy::disallowed_types)]
    last_request_id: std::sync::Mutex<Option<String>>,
}

impl Deliveries {
    fn record(&self, request_id: &str) {
        self.count.fetch_add(1, Ordering::SeqCst);
        *self.last_request_id.lock().expect("deliveries lock") = Some(request_id.to_owned());
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    fn last_request_id(&self) -> Option<String> {
        self.last_request_id
            .lock()
            .expect("deliveries lock")
            .clone()
    }
}

/// The sidecar's module. `Arc<Deliveries>` is shared fixture state between
/// the event handler and the evidence route — not request state (ADR 0007),
/// and the scoped allow follows the same workspace clippy.toml policy the
/// test fixtures do.
pub struct Probe {
    deliveries: Arc<Deliveries>,
}

impl Default for Probe {
    fn default() -> Self {
        Self::new()
    }
}

impl Probe {
    #[must_use]
    pub fn new() -> Self {
        Self {
            deliveries: Arc::new(Deliveries::default()),
        }
    }
}

impl Module for Probe {
    fn name(&self) -> &'static str {
        "probe"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [cratefield_core::Port] {
        &[]
    }

    fn tables(&self) -> &'static [&'static str] {
        &[]
    }

    fn migrations(&self) -> cratefield_core::Migrations {
        cratefield_core::Migrations::EMPTY
    }

    fn validate_config(
        &self,
        _cfg: &dyn cratefield_core::Config,
    ) -> Result<(), cratefield_core::ConfigError> {
        Ok(())
    }

    fn events(&self) -> Vec<(EventName, EventHandler)> {
        let deliveries = Arc::clone(&self.deliveries);
        let handler: EventHandler = Arc::new(move |scope: &Scope, _payload: Value| {
            let deliveries = Arc::clone(&deliveries);
            let request_id = scope.request_id.clone();
            Box::pin(async move {
                deliveries.record(&request_id);
                Ok::<(), AnyError>(())
            })
        });
        vec![(SUBSCRIBED_EVENT.to_owned(), handler)]
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let _ = ctx;
        let state = Arc::clone(&self.deliveries);
        axum::Router::new().route("/delivered", get(evidence).with_state(state))
    }
}

/// The check reads this back until a delivery shows up (issue #258). A
/// count of zero after the host has long answered is the red half of the
/// check: a forward that is never delivered also returns promptly, so
/// this — not the timing assertion — is what pins the forward itself.
async fn evidence(State(deliveries): State<Arc<Deliveries>>) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "delivered": deliveries.count(),
        "last_request_id": deliveries.last_request_id(),
    }))
}
