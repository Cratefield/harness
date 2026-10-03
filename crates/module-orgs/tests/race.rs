//! Concurrency, where a read-then-write would be wrong (issue #652).
//!
//! Two owners leaving at the same instant is the case a plain "count the other
//! owners, then delete" gets wrong under Postgres `READ COMMITTED`: each counts
//! two, both delete, and the organization is left with nobody who can
//! administer it. The guard here rides the same transaction as the write, so
//! one of the two is always held back. Two accepts of one invitation is the
//! same shape for the single-use spend: the membership rides the spend.
//!
//! Postgres is where the interleaving this asserts is possible; SQLite
//! serializes its writers behind one lock, and the invariant holds there for
//! free — so the legs run both, with the dialect named in every failure.

mod support;

use std::sync::{Arc, Barrier};

use axum::http::{Method, StatusCode};

use support::{Spec, fixture, race_send};

/// Two owners leave together, over and over: exactly one is let go and one is
/// held back, so at least one owner always remains.
#[pollster::test]
async fn two_owners_leaving_at_once_always_leave_one() {
    for kit in fixture(&Spec::default()).kits {
        for round in 0..20 {
            let id = kit.create_org("alice", "Acme").await;
            let added = kit.add_member(&id, "alice", "bob", "owner").await;
            assert_eq!(added.status, StatusCode::CREATED, "{}", kit.harness.dialect);

            let gate = Arc::new(Barrier::new(2));
            let path = format!("/v1/orgs/{id}/leave");
            let racers: Vec<_> = ["alice", "bob"]
                .into_iter()
                .map(|sub| {
                    let router = kit.harness.router.clone();
                    let gate = Arc::clone(&gate);
                    let path = path.clone();
                    std::thread::spawn(move || {
                        gate.wait();
                        race_send(router, Method::POST, &path, sub, None)
                    })
                })
                .collect();

            let mut released = 0;
            let mut held = 0;
            for racer in racers {
                let res = racer.join().expect("race thread");
                match res.status {
                    StatusCode::OK => released += 1,
                    StatusCode::CONFLICT => {
                        assert_eq!(res.problem_slug(), "orgs-last-owner");
                        held += 1;
                    }
                    other => panic!(
                        "{}: round {round}: a leave answered {other}: {}",
                        kit.harness.dialect,
                        res.text()
                    ),
                }
            }

            assert_eq!(
                released, 1,
                "{}: round {round}: exactly one owner left",
                kit.harness.dialect
            );
            assert_eq!(
                held, 1,
                "{}: round {round}: the guard held one back",
                kit.harness.dialect
            );
            assert_eq!(
                kit.owners_in(&id).await,
                1,
                "{}: round {round}: an owner must remain",
                kit.harness.dialect
            );
            assert_eq!(
                kit.rows_for("org_members", "org_id", &id).await,
                1,
                "{}: round {round}: one membership must remain",
                kit.harness.dialect
            );
        }
    }
}

/// One invitation, two accepts at the same instant: the token is spent once,
/// the membership is added once, and the caller whose accept lost the race
/// gets the same 410 a replay gets.
#[pollster::test]
async fn two_accepts_of_one_invitation_add_one_member() {
    for kit in fixture(&Spec::default()).kits {
        for round in 0..10 {
            kit.clock.reset();
            let id = kit.create_org("alice", "Acme").await;
            let invited = kit
                .post(
                    &format!("/v1/orgs/{id}/invitations"),
                    "alice",
                    r#"{"email":"bob@example.test","role":"staff"}"#,
                )
                .await;
            assert_eq!(
                invited.status,
                StatusCode::ACCEPTED,
                "{}",
                kit.harness.dialect
            );
            let token = kit.invitation_token();

            let gate = Arc::new(Barrier::new(2));
            let path = "/v1/orgs/invitations/accept".to_owned();
            let racers: Vec<_> = (0..2)
                .map(|_| {
                    let router = kit.harness.router.clone();
                    let gate = Arc::clone(&gate);
                    let path = path.clone();
                    let body = format!(r#"{{"token":"{token}"}}"#);
                    std::thread::spawn(move || {
                        gate.wait();
                        race_send(
                            router,
                            Method::POST,
                            &path,
                            "bob|bob@example.test",
                            Some(&body),
                        )
                    })
                })
                .collect();

            let mut accepted = 0;
            let mut gone = 0;
            for racer in racers {
                let res = racer.join().expect("race thread");
                match res.status {
                    StatusCode::OK => accepted += 1,
                    StatusCode::GONE => {
                        assert_eq!(res.problem_slug(), "orgs-invitation-gone");
                        gone += 1;
                    }
                    other => panic!(
                        "{}: round {round}: an accept answered {other}: {}",
                        kit.harness.dialect,
                        res.text()
                    ),
                }
            }

            assert_eq!(
                accepted, 1,
                "{}: round {round}: exactly one accept spends the invitation",
                kit.harness.dialect
            );
            assert_eq!(
                gone, 1,
                "{}: round {round}: one accept loses",
                kit.harness.dialect
            );
            assert_eq!(
                kit.rows_for("org_members", "org_id", &id).await,
                2,
                "{}: round {round}: the owner plus bob, and nobody twice",
                kit.harness.dialect
            );
        }
    }
}
