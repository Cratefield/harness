//! The crate-root re-export list is where the Tracker additions of issue
//! #559 (`TicketComment`, `StatusWebhook`, `StatusUpdate`,
//! `InboundStatusError`, `receive_status`) met the `VectorIndex` and
//! `Embedder` ports of issue #561: both edited the same `pub use` block.
//! A resolution that keeps one side and drops the other still compiles
//! everything *inside* core, so this test names both sets from outside,
//! the way a venture does, and uses them together.

use std::sync::Arc;

use cratefield_core::{
    Credential, Destination, Embedder, ExactVectorIndex, InboundStatusError, RoutingTracker,
    StatusUpdate, StatusWebhook, TicketComment, TicketState, Tracker, TrackerError, VectorIndex,
    WebhookVerifier, receive_status,
};
use cratefield_core::{ProviderScheme, SignatureEncoding};
use http::HeaderMap;

struct NoStatus;

impl StatusWebhook for NoStatus {
    fn kind(&self) -> &'static str {
        "jira"
    }

    fn verifier(&self) -> WebhookVerifier {
        WebhookVerifier::new(ProviderScheme {
            signature: "X-Hub-Signature",
            encoding: SignatureEncoding::Hex,
            prefix: Some("sha256="),
            timestamp: None,
        })
    }

    fn parse(&self, _body: &[u8]) -> Result<Option<StatusUpdate>, InboundStatusError> {
        Ok(Some(StatusUpdate {
            external_id: "PROJ-7".to_owned(),
            state: TicketState::Closed,
            url: None,
        }))
    }
}

/// Names the vector ports as trait objects, so a dropped re-export is a
/// compile error here rather than in the next venture to import it.
fn vector_ports(index: &dyn VectorIndex, embedder: Option<&dyn Embedder>) -> bool {
    let _ = index;
    embedder.is_none()
}

#[test]
fn both_sides_of_the_reexport_block_are_reachable_from_the_crate_root() {
    // #561: the vector ports.
    let index = ExactVectorIndex::new(3);
    assert!(vector_ports(&index, None));

    // #559: an unsigned delivery is refused before parsing.
    let refused = receive_status(&NoStatus, "secret", &HeaderMap::new(), b"{}", 0);
    assert_eq!(refused.unwrap_err(), InboundStatusError::Signature);

    // #559: a router with nothing wired refuses a comment as NotConfigured.
    let router: Arc<dyn Tracker> = Arc::new(RoutingTracker::new());
    let note = TicketComment::new("k", "dup").with_link("https://example.test/1");
    let dest = Destination::Freshdesk {
        domain: "acme.freshdesk.com".to_owned(),
    };
    let error =
        pollster::block_on(router.comment(&dest, &Credential::new("t"), "1", &note)).unwrap_err();
    assert_eq!(error, TrackerError::NotConfigured);
}
