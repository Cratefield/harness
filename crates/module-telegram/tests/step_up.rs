//! The step-up seam (issue #764): the confirm route asks the injected
//! [`StepUp`] to prove a fresh passkey ceremony, handing it the request's
//! own headers and the owning subject; with none configured it answers
//! `403` and nothing moves.
//!
//! There is deliberately **no stock implementation** in this crate. A
//! bearer token's `amr` and `iat` cannot prove a fresh ceremony: the auth
//! service copies the session's login-time `amr` into every token it
//! mints and stamps a fresh `iat` on each mint — the refresh grant
//! included — so a token refreshed hours after a passkey login carries
//! `passkey` and a recent `iat` while proving nothing about the last
//! minutes. An implementation must verify a passkey assertion for this
//! subject within this request or within its own freshness window; see
//! the trait's documentation.

use std::sync::{Arc, RwLock};

use axum::http::StatusCode;
use cratefield_module_telegram::{StepUp, TelegramEvents};
use http::HeaderMap;
use serde_json::json;

mod support;

use support::{ALICE, BOB, insert_action, kit_with, post};

/// A [`StepUp`] that records what the route asked it, and answers by
/// switch — the contract under test is *what is asked*, not what answers.
struct Recording {
    ok: std::sync::atomic::AtomicBool,
    asked: RwLock<Vec<(Option<String>, String)>>,
}

impl Recording {
    fn refusing() -> Arc<Self> {
        Arc::new(Self {
            ok: std::sync::atomic::AtomicBool::new(false),
            asked: RwLock::default(),
        })
    }

    fn accepting() -> Arc<Self> {
        Arc::new(Self {
            ok: std::sync::atomic::AtomicBool::new(true),
            asked: RwLock::default(),
        })
    }
}

#[async_trait::async_trait]
impl StepUp for Recording {
    async fn passkey_verified(&self, headers: &HeaderMap, subject: &str) -> bool {
        self.asked.write().expect("asked lock").push((
            headers
                .get(http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
            subject.to_owned(),
        ));
        self.ok.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// The kit with the recording verifier injected.
fn kit(step_up: Arc<Recording>) -> cratefield_testing::TestHarness {
    let (kit, _bot) = kit_with(
        TelegramEvents::new(),
        support::config(vec![]),
        Some(step_up as _),
    );
    kit
}

#[pollster::test]
async fn the_route_asks_step_up_with_the_requests_headers_and_the_owner() {
    let verifier = Recording::refusing();
    let kit = kit(verifier.clone());
    insert_action(&kit, "armed-action", ALICE, "awaiting_passkey", true, 600);

    let (status, body) = post(
        &kit,
        "/actions/armed-action/confirm",
        Some(ALICE),
        json!({}),
    )
    .await;

    // A no from the verifier is a `403`, and the action stays armed.
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        support::action_status(&kit, "armed-action").as_deref(),
        Some("awaiting_passkey")
    );

    // What was asked: this request's bearer header, and the subject that
    // owns the action — nobody else's ceremony could stand in.
    let asked = verifier.asked.read().expect("asked lock");
    assert_eq!(asked.len(), 1, "asked once per attempt");
    assert_eq!(
        asked[0].0.as_deref(),
        Some(&format!("Bearer {ALICE}")[..]),
        "the confirm request's own Authorization header"
    );
    assert_eq!(asked[0].1, ALICE, "the owning subject");
}

#[pollster::test]
async fn a_foreign_subjects_attempt_never_reaches_step_up() {
    let verifier = Recording::refusing();
    let kit = kit(verifier.clone());
    insert_action(&kit, "armed-action", ALICE, "awaiting_passkey", true, 600);

    let (status, body) = post(&kit, "/actions/armed-action/confirm", Some(BOB), json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["title"], "Not your action");

    // The ownership check runs first: the verifier is asked nothing about
    // an action that is not the caller's.
    assert!(verifier.asked.read().expect("asked lock").is_empty());
}

#[pollster::test]
async fn the_verifiers_yes_is_the_only_thing_that_commits() {
    let verifier = Recording::accepting();
    let kit = kit(verifier);
    insert_action(&kit, "armed-action", ALICE, "awaiting_passkey", true, 600);

    let (status, body) = post(
        &kit,
        "/actions/armed-action/confirm",
        Some(ALICE),
        json!({}),
    )
    .await;

    assert!(status.is_success(), "{status}: {body}");
    assert_eq!(
        support::action_status(&kit, "armed-action").as_deref(),
        Some("approved"),
        "a proved ceremony commits the confirmation"
    );
}
