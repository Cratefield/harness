//! `FakePush` and the push recipient conformance check (issue #177).

use std::sync::Arc;

use cratefield_core::{
    Notification, Platform, Push, PushError, PushOutcome, Recipient, RoutingPush,
};
use cratefield_testing::{FakePush, PushMode, push_recipient_conformance};

fn phone() -> Recipient {
    Recipient::apns("device-a")
}
fn tablet() -> Recipient {
    Recipient::apns("device-b")
}
fn browser() -> Recipient {
    Recipient::web_push("https://push.example.test/sub", "p256dh", "auth")
}

#[test]
fn records_the_recipient_alongside_the_notification() {
    let push = FakePush::default();
    pollster::block_on(push.send(&phone(), &Notification::new("a", "b"))).unwrap();
    pollster::block_on(push.send(&browser(), &Notification::new("c", "d"))).unwrap();

    let sent = push.sent();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].0, phone());
    assert_eq!(sent[1].0, browser());
    assert_eq!(push.last().unwrap().1.title, "c");
    assert_eq!(push.sent_to(&phone()).len(), 1);
    assert!(push.sent_to(&tablet()).is_empty());
}

/// The point of the per-recipient modes: a fan-out where exactly one device
/// is dead, so a prune test can assert it pruned *that* one.
#[test]
fn one_dead_recipient_among_live_ones() {
    let push = FakePush::new(PushMode::DeliverOk);
    push.set_mode_for(&tablet(), PushMode::Unregistered);

    let notification = Notification::new("Room starting", "Yoga in 10 min");
    let mut dead = Vec::new();
    for recipient in [phone(), tablet(), browser()] {
        match pollster::block_on(push.send(&recipient, &notification)) {
            Err(PushError::Unregistered) => dead.push(recipient),
            Ok(PushOutcome::Delivered { .. }) => {}
            other => panic!("unexpected answer for a live recipient: {other:?}"),
        }
    }

    assert_eq!(dead, vec![tablet()], "only the dead token is pruned");
    let delivered: Vec<Recipient> = push.sent().into_iter().map(|(to, _)| to).collect();
    assert_eq!(delivered, vec![phone(), browser()]);
}

#[test]
fn an_override_wins_over_the_global_mode_and_can_be_cleared() {
    let push = FakePush::new(PushMode::DeliverOk);
    push.set_mode_for(&phone(), PushMode::Transient);
    assert_eq!(push.mode_for(&phone()), PushMode::Transient);
    assert_eq!(push.mode_for(&browser()), PushMode::DeliverOk);

    let error = pollster::block_on(push.send(&phone(), &Notification::new("a", "b"))).unwrap_err();
    assert!(matches!(error, PushError::Transient { .. }));

    // The global mode moves under the override without disturbing it.
    push.set_mode(PushMode::NotConfigured);
    assert_eq!(push.mode_for(&phone()), PushMode::Transient);
    assert_eq!(
        pollster::block_on(push.send(&browser(), &Notification::new("a", "b"))).unwrap(),
        PushOutcome::NotConfigured
    );

    push.clear_mode_for(&phone());
    assert_eq!(push.mode_for(&phone()), PushMode::NotConfigured);
}

#[test]
fn the_fake_serves_every_transport() {
    let push = FakePush::default();
    pollster::block_on(push_recipient_conformance(
        &push,
        &[Platform::Ios, Platform::Android, Platform::Web],
    ));
    assert_eq!(push.sent().len(), 3, "one per transport");
}

/// A router in front of a single-transport adapter is what a venture wires;
/// the transports it has no adapter for are `NotConfigured`, which the
/// conformance check accepts as "served" — the recipient is fine, the
/// venture simply did not wire that leg.
#[test]
fn a_router_over_one_adapter_answers_every_transport() {
    let ios = FakePush::default();
    let router = RoutingPush::new().apns(Arc::new(ios.clone()));

    assert_eq!(
        pollster::block_on(router.send(&phone(), &Notification::new("a", "b"))).unwrap(),
        PushOutcome::Delivered {
            id: Some("fake-push-0".to_owned())
        }
    );
    assert_eq!(
        pollster::block_on(router.send(&browser(), &Notification::new("a", "b"))).unwrap(),
        PushOutcome::NotConfigured
    );
    assert_eq!(ios.sent().len(), 1, "only the APNs leg was called");
}

/// The negative case: an adapter that rejects a transport it *does* serve
/// must fail the check, or the check proves nothing.
#[test]
#[should_panic(expected = "claims to serve web")]
fn the_check_catches_an_adapter_that_rejects_a_transport_it_claims() {
    struct IosOnly;
    #[async_trait::async_trait]
    impl Push for IosOnly {
        async fn send(
            &self,
            to: &Recipient,
            _notification: &Notification,
        ) -> Result<PushOutcome, PushError> {
            match to {
                Recipient::Apns { .. } => Ok(PushOutcome::Delivered { id: None }),
                other => Err(PushError::unsupported_recipient(other)),
            }
        }
    }
    // Claims Web Push, does not serve it.
    pollster::block_on(push_recipient_conformance(
        &IosOnly,
        &[Platform::Ios, Platform::Web],
    ));
}
