//! The `Tracker` port is an adapter-injected one on the native runtime
//! (issue #431): like `Payments`, the venture constructs the adapter and
//! passes it to the builder, so the port is provided exactly when an
//! adapter was wired — there is no env assembly to fall back to.

use std::sync::Arc;

use cratefield_core::{
    Credential, Destination, Filed, Port, Runtime, TicketDraft, TicketState, TicketStatus, Tracker,
    TrackerError,
};
use cratefield_runtime_native::Native;

/// Stands in for an adapter the venture passed itself. Answers the
/// cheapest thing that satisfies the trait; what these tests assert is
/// wiring, not adapter behaviour.
struct StubTracker;

#[async_trait::async_trait]
impl Tracker for StubTracker {
    async fn file(
        &self,
        _dest: &Destination,
        _cred: &Credential,
        _draft: &TicketDraft,
    ) -> Result<Filed, TrackerError> {
        Err(TrackerError::NotConfigured)
    }

    async fn status(
        &self,
        _dest: &Destination,
        _cred: &Credential,
        external_id: &str,
    ) -> Result<TicketStatus, TrackerError> {
        Ok(TicketStatus {
            external_id: external_id.to_owned(),
            state: TicketState::Open,
            url: None,
        })
    }
}

#[test]
fn a_venture_that_wires_no_tracker_provides_no_tracker_port() {
    let runtime = Native::new();
    assert!(!runtime.provides().contains(&Port::Tracker));
}

#[test]
fn a_wired_tracker_is_provided_and_reaches_the_port_bundle() {
    let tracker: Arc<dyn Tracker> = Arc::new(StubTracker);
    let runtime = Native::new().tracker_arc(Arc::clone(&tracker));
    assert!(runtime.provides().contains(&Port::Tracker));

    // The adapter the builder took is the one `ports()` hands back, by
    // identity — a second wrapper here would be a second tracker that
    // never saw the venture's configuration.
    let ports = runtime.ports();
    assert!(ports.has(Port::Tracker));
    let handed_back = ports.tracker.expect("the tracker port is wired");
    assert!(Arc::ptr_eq(&handed_back, &tracker));
}
