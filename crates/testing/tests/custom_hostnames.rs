//! `FakeCustomHostnames` (issue #590): a claim walks from pending to live,
//! and a hostname this port would never send is refused before any
//! provider call.

use cratefield_core::{
    CertificateStatus, CustomHostnameError, CustomHostnames, HostnameClaim, HostnameRefusal,
    ProviderStatus,
};
use cratefield_testing::FakeCustomHostnames;

#[test]
fn a_claim_walks_pending_to_live() {
    let api = FakeCustomHostnames::new("cratefield.app");
    let claim = HostnameClaim::new("Share.Acme.COM.");

    let created = pollster::block_on(api.create(&claim)).expect("claims");
    assert_eq!(created.id, "fake-0");
    assert_eq!(created.hostname, "share.acme.com", "the name is normalised");
    assert_eq!(created.status, ProviderStatus::Pending);
    assert_eq!(created.certificate, CertificateStatus::Pending);
    assert_eq!(created.validation.len(), 1, "one TXT record to publish");
    assert!(!created.is_live());

    api.activate("share.acme.com");
    let live = pollster::block_on(api.refresh("share.acme.com")).expect("refreshes");
    assert!(live.is_live());
    assert_eq!(live.certificate, CertificateStatus::Active);
    assert!(live.validation.is_empty(), "nothing left to publish");

    assert_eq!(
        api.calls(),
        vec!["create Share.Acme.COM.", "refresh share.acme.com"]
    );
}

#[test]
fn a_hostname_this_port_would_never_send_is_refused() {
    let api = FakeCustomHostnames::new("cratefield.app");
    // An apex never reaches the provider: `create` runs `check_hostname`
    // first, the way a real adapter must.
    let refused = pollster::block_on(api.create(&HostnameClaim::new("acme.com"))).unwrap_err();
    assert_eq!(refused, CustomHostnameError::Refused(HostnameRefusal::Apex));
    assert!(
        pollster::block_on(api.get("acme.com"))
            .expect("reads")
            .is_none(),
        "nothing was stored"
    );
}

#[test]
fn a_scripted_refusal_answers_the_next_call() {
    let api = FakeCustomHostnames::new("cratefield.app");
    api.refuse_next(CustomHostnameError::RateLimited);
    assert_eq!(
        pollster::block_on(api.create(&HostnameClaim::new("share.acme.com"))).unwrap_err(),
        CustomHostnameError::RateLimited
    );
    // The next call is unscripted and succeeds.
    assert!(
        pollster::block_on(api.create(&HostnameClaim::new("share.acme.com"))).is_ok(),
        "the queue is drained"
    );
}

#[test]
fn delete_is_idempotent() {
    let api = FakeCustomHostnames::new("cratefield.app");
    pollster::block_on(api.create(&HostnameClaim::new("share.acme.com"))).expect("claims");
    pollster::block_on(api.delete("share.acme.com")).expect("deletes");
    pollster::block_on(api.delete("share.acme.com")).expect("deleting again is Ok");
    assert!(
        pollster::block_on(api.refresh("share.acme.com")).is_err(),
        "gone after delete"
    );
}
