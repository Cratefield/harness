//! `FakeTracker` (issue #431): a scripted `Tracker` whose recordings prove
//! a credential reached the port without the fake ever holding the secret
//! itself.

use std::time::Duration;

use cratefield_core::{
    Credential, Destination, Severity, TicketDraft, TicketState, TicketStatus, Tracker,
    TrackerError,
};
use cratefield_testing::{FakeTracker, TrackerMode};

fn github() -> Destination {
    Destination::GitHub {
        owner: "acme".to_owned(),
        repo: "api".to_owned(),
    }
}

fn slack() -> Destination {
    Destination::Slack {
        channel: "C0123456789".to_owned(),
    }
}

fn draft() -> TicketDraft {
    TicketDraft::new(
        "outbox-42",
        "Checkout failing",
        "Stripe 500s on `/v1/charges`.",
        Severity::Error,
    )
    .environment("production")
}

/// A distinctive stand-in for a decrypted per-tenant token. The acceptance
/// criterion it drives: this string appears nowhere in anything the fake
/// returns or prints.
fn the_secret() -> Credential {
    Credential::new("ghp_supersecrettokenvalue")
}

#[test]
fn a_filed_ticket_records_its_destination_and_draft() {
    let tracker = FakeTracker::new(TrackerMode::FileOk);
    pollster::block_on(tracker.file(&github(), &the_secret(), &draft())).expect("files");
    pollster::block_on(tracker.file(&slack(), &the_secret(), &draft())).expect("files");

    let filed = tracker.filed();
    assert_eq!(filed.len(), 2);
    assert_eq!(filed[0].dest, github());
    assert_eq!(filed[1].dest, slack());

    let last = tracker.last_filed().expect("a call was recorded");
    assert_eq!(last.dest, slack());
    assert_eq!(last.draft, draft());
    assert_eq!(last.draft.idempotency_key, "outbox-42");
    assert_eq!(last.draft.severity, Severity::Error);
    assert_eq!(last.draft.environment.as_deref(), Some("production"));
}

/// Every fixed mode scripts its `TrackerError`, and `Error` makes any
/// error value reachable — text and delay included (issue #236's rule).
#[test]
fn the_mode_scripts_every_tracker_error() {
    let tracker = FakeTracker::new(TrackerMode::NotConfigured);
    assert_eq!(
        pollster::block_on(tracker.file(&github(), &the_secret(), &draft())).unwrap_err(),
        TrackerError::NotConfigured
    );

    tracker.set_mode(TrackerMode::Unauthorized);
    assert_eq!(
        pollster::block_on(tracker.file(&github(), &the_secret(), &draft())).unwrap_err(),
        TrackerError::Unauthorized
    );

    tracker.set_mode(TrackerMode::Rejected);
    let error = pollster::block_on(tracker.file(&github(), &the_secret(), &draft())).unwrap_err();
    assert!(
        matches!(&error, TrackerError::Rejected(text) if text.contains("fake tracker rejection")),
        "{error:?}"
    );

    tracker.set_mode(TrackerMode::Transient);
    assert_eq!(
        pollster::block_on(tracker.file(&github(), &the_secret(), &draft())).unwrap_err(),
        TrackerError::Transient { retry_after: None }
    );

    tracker.set_mode(TrackerMode::Error(TrackerError::Transient {
        retry_after: Some(Duration::from_secs(30)),
    }));
    let error = pollster::block_on(tracker.file(&github(), &the_secret(), &draft())).unwrap_err();
    assert_eq!(error.retry_after(), Some(Duration::from_secs(30)));

    // A call the mode answered with an error recorded nothing.
    assert!(tracker.filed().is_empty());
}

/// `status` answers from the same mode, and the state it reports when it
/// answers well is its own script: "the file succeeded" and "the ticket
/// has moved on since" are set independently.
#[test]
fn status_answers_from_the_mode_and_the_scripted_state() {
    let tracker = FakeTracker::new(TrackerMode::FileOk);
    assert_eq!(tracker.state(), TicketState::Open, "a fresh ticket is open");
    tracker.set_state(TicketState::InProgress);

    let status = pollster::block_on(tracker.status(&github(), &the_secret(), "fake-0"))
        .expect("status answers");
    assert_eq!(
        status,
        TicketStatus {
            external_id: "fake-0".to_owned(),
            state: TicketState::InProgress,
            url: None,
        }
    );
    assert_eq!(tracker.statused().len(), 1);
    assert_eq!(tracker.statused()[0].external_id, "fake-0");

    tracker.set_mode(TrackerMode::Unauthorized);
    assert_eq!(
        pollster::block_on(tracker.status(&github(), &the_secret(), "fake-0")).unwrap_err(),
        TrackerError::Unauthorized
    );
    assert_eq!(
        tracker.statused().len(),
        1,
        "a status the mode answered with an error is not recorded"
    );
}

/// The acceptance criterion behind the port: the credential is used once,
/// to prove it was passed, and then gone. No accessor returns it and no
/// `Debug` prints it — not the whole string, not a recognisable piece.
#[test]
fn the_credential_is_never_stored_or_printed() {
    let tracker = FakeTracker::new(TrackerMode::FileOk);
    pollster::block_on(tracker.file(&github(), &the_secret(), &draft())).expect("files");
    pollster::block_on(tracker.status(&github(), &the_secret(), "fake-0")).expect("statuses");

    let secret = "ghp_supersecrettokenvalue";
    let fragments = [secret, "supersecret", "secrettoken", "tokenvalue", "ghp_"];

    // Everything the fake hands back, formatted — recorded calls, the
    // handle's own Debug — must be free of the secret.
    let printed = format!(
        "{:?}{:?}{:?}{:?}",
        tracker.filed(),
        tracker.last_filed(),
        tracker.statused(),
        tracker
    );
    for fragment in fragments {
        assert!(
            !printed.contains(fragment),
            "leaked {fragment} through {printed}"
        );
    }

    // What *is* stored is a fingerprint: it proves the credential was
    // passed, distinguishes one from another, and is not the text.
    let two_callers = FakeTracker::new(TrackerMode::FileOk);
    pollster::block_on(two_callers.file(&github(), &the_secret(), &draft())).expect("files");
    pollster::block_on(two_callers.file(&github(), &Credential::new("slack-xoxb-other"), &draft()))
        .expect("files");
    let filed = two_callers.filed();
    assert_ne!(
        filed[0].credential_fingerprint, filed[1].credential_fingerprint,
        "two credentials must not share a fingerprint"
    );

    let once_more = FakeTracker::new(TrackerMode::FileOk);
    pollster::block_on(once_more.file(&github(), &the_secret(), &draft())).expect("files");
    assert_eq!(
        once_more.filed()[0].credential_fingerprint,
        tracker.filed()[0].credential_fingerprint,
        "the same credential fingerprints the same way"
    );
    assert!(tracker.filed()[0].credential_fingerprint.starts_with("fp:"));
}

/// The point of the per-destination modes: exactly one tenant's credential
/// is dead, and the rest file on.
#[test]
fn one_unauthorized_destination_among_filing_ones() {
    let tracker = FakeTracker::new(TrackerMode::FileOk);
    tracker.set_mode_for(&slack(), TrackerMode::Unauthorized);
    assert_eq!(tracker.mode_for(&slack()), TrackerMode::Unauthorized);
    assert_eq!(tracker.mode_for(&github()), TrackerMode::FileOk);

    assert_eq!(
        pollster::block_on(tracker.file(&slack(), &the_secret(), &draft())).unwrap_err(),
        TrackerError::Unauthorized
    );
    pollster::block_on(tracker.file(&github(), &the_secret(), &draft())).expect("files");
    assert_eq!(
        tracker.filed().len(),
        1,
        "only the live destination recorded a call"
    );

    tracker.clear_mode_for(&slack());
    assert_eq!(tracker.mode_for(&slack()), TrackerMode::FileOk);
}
