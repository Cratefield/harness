//! The two concurrency properties the module's at-most-once story rests
//! on (issue #587): the guarded `approved` → `consumed` update mints one
//! credential when two polls race, and the interval gate lets exactly one
//! poller per interval through. Both are the `UPDATE` row count doing the
//! work, so both are tested with real concurrent requests, not a mock of
//! concurrency.

mod support;

use axum::http::StatusCode;

use support::{CLIENT_A, Spec, approve, fixture, issue, poll, poll_thread};

/// Two polls of an approved code race: exactly one receives the credential
/// and the other is told `expired_token`, and the issuer is called exactly
/// once.
#[pollster::test]
async fn two_polls_of_an_approved_code_mint_exactly_one_credential() {
    for kit in fixture(&Spec::default(), |_| {}).kits {
        kit.issuer.reset();
        let codes = issue(&kit.harness, CLIENT_A, "read write", None).await;
        let approved = approve(&kit.harness, &codes.user_code).await;
        assert_eq!(approved.status, StatusCode::OK, "{}", approved.text());

        let device = codes.device_code.clone();
        let first = poll_thread(
            kit.harness.router.clone(),
            device.clone(),
            CLIENT_A.to_owned(),
        );
        let second = poll_thread(kit.harness.router.clone(), device, CLIENT_A.to_owned());
        let first = first.join().expect("the first poll completes");
        let second = second.join().expect("the second poll completes");

        let mut issued = 0;
        let mut expired = 0;
        for response in [first, second] {
            if response.status == StatusCode::OK {
                issued += 1;
                assert_eq!(response.json()["subject"], serde_json::json!("alice"));
            } else {
                assert_eq!(
                    response.status,
                    StatusCode::BAD_REQUEST,
                    "{}",
                    response.text()
                );
                assert_eq!(response.oauth_error(), "expired_token");
                expired += 1;
            }
        }
        assert_eq!(issued, 1, "exactly one poll minted a credential");
        assert_eq!(expired, 1, "the loser is told the code is spent");
        assert_eq!(kit.issuer.calls(), 1, "the issuer is called at most once");
    }
}

/// The interval gate is the same kind of guard: two polls of a pending
/// code race, one wins the interval and is `authorization_pending`, and
/// the other widens the interval and is `slow_down`.
#[pollster::test]
async fn two_polls_in_one_interval_let_exactly_one_through() {
    for kit in fixture(&Spec::default(), |_| {}).kits {
        kit.clock.reset();
        let codes = issue(&kit.harness, CLIENT_A, "read", None).await;

        // A first poll takes the interval, then the clock moves past it, so
        // the two racing polls are both eligible and the guarded update —
        // not the clock — is what decides between them.
        assert_eq!(
            poll(&kit.harness, &codes.device_code, CLIENT_A)
                .await
                .oauth_error(),
            "authorization_pending"
        );
        kit.clock.advance_secs(6);

        let device = codes.device_code.clone();
        let first = poll_thread(
            kit.harness.router.clone(),
            device.clone(),
            CLIENT_A.to_owned(),
        );
        let second = poll_thread(kit.harness.router.clone(), device, CLIENT_A.to_owned());
        let first = first.join().expect("the first poll completes");
        let second = second.join().expect("the second poll completes");

        let mut pending = 0;
        let mut slow = 0;
        for response in [first, second] {
            match response.oauth_error().as_str() {
                "authorization_pending" => pending += 1,
                "slow_down" => slow += 1,
                other => panic!("unexpected poll answer: {other}"),
            }
        }
        assert_eq!(pending, 1, "exactly one poller wins the interval");
        assert_eq!(slow, 1, "the other is paced");
    }
}

/// A poll that arrives after the clock has passed the interval is answered
/// normally even though a `slow_down` preceded it — the widened interval
/// is honoured, not permanent.
#[pollster::test]
async fn a_widened_interval_is_still_waitable() {
    for kit in fixture(&Spec::default(), |_| {}).kits {
        kit.clock.reset();
        let codes = issue(&kit.harness, CLIENT_A, "read", None).await;
        let _ = poll(&kit.harness, &codes.device_code, CLIENT_A).await;
        assert_eq!(
            poll(&kit.harness, &codes.device_code, CLIENT_A)
                .await
                .oauth_error(),
            "slow_down"
        );

        kit.clock.advance_secs(15);
        assert_eq!(
            poll(&kit.harness, &codes.device_code, CLIENT_A)
                .await
                .oauth_error(),
            "authorization_pending"
        );
    }
}
