//! The kit's own tests plus a demo module passing conformance (issue #9).

use cratefield_core::{
    Config, ConfigError, Database, Migrations, Module, ModuleContext, Port, SqlMigration,
};
use cratefield_testing::{
    FakeCaptcha, FakeDefer, FakeHttpClient, FakeMailer, FakeRateLimiter, MailerMode,
    MemoryKeyValue, TestHarness, assert_wasm_safe_deps, conformance, request,
};
use std::sync::Arc;
use std::time::Duration;

const DEMO_INIT: SqlMigration = SqlMigration {
    id: "0001",
    name: "init",
    sql: "CREATE TABLE IF NOT EXISTS demo_notes (
        id TEXT PRIMARY KEY,
        body TEXT NOT NULL
    );",
};

pub struct DemoModule;

impl Module for DemoModule {
    fn name(&self) -> &'static str {
        "demo"
    }
    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }
    fn requires(&self) -> &'static [Port] {
        &[Port::Db]
    }
    fn tables(&self) -> &'static [&'static str] {
        &["demo_notes"]
    }
    fn migrations(&self) -> Migrations {
        const MIGRATIONS: [SqlMigration; 1] = [DEMO_INIT];
        Migrations {
            sqlite: &MIGRATIONS,
            postgres: &[],
        }
    }
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let db = ctx.ports.db.expect("demo requires Db");
        axum::Router::new().route(
            "/notes",
            axum::routing::get(move || async move {
                let rows = db
                    .query(&cratefield_core::Statement::new(
                        "SELECT id FROM demo_notes",
                    ))
                    .await
                    .expect("select");
                cratefield_core::Json(serde_json::json!({ "count": rows.len() }))
            }),
        )
    }
}

#[test]
fn demo_module_passes_conformance() {
    conformance(Box::new(DemoModule));
}

/// The issue #46 fixture: a module whose `well_known` router serves one
/// discovery document, checked by the kit's sixth conformance rule.
pub struct DiscoveryModule;

impl Module for DiscoveryModule {
    fn name(&self) -> &'static str {
        "discovery"
    }
    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }
    fn requires(&self) -> &'static [Port] {
        &[]
    }
    fn migrations(&self) -> Migrations {
        Migrations::default()
    }
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        axum::Router::new()
    }
    fn well_known(&self) -> Option<axum::Router> {
        Some(axum::Router::new().route(
            "/jwks.json",
            axum::routing::get(|| async {
                cratefield_core::Json(serde_json::json!({ "keys": [] }))
            }),
        ))
    }
}

#[test]
fn discovery_module_passes_conformance() {
    conformance(Box::new(DiscoveryModule));
}

#[pollster::test]
async fn discovery_document_serves_at_root() {
    let kit = TestHarness::new(vec![Box::new(DiscoveryModule)]);
    let response = request(
        &kit.router,
        axum::http::Method::GET,
        "/.well-known/jwks.json",
        None,
    )
    .await;
    assert_eq!(response.status, axum::http::StatusCode::OK);
    assert_eq!(response.json()["keys"], serde_json::json!([]));
}

#[test]
fn testing_crate_deps_are_wasm_safe() {
    assert_wasm_safe_deps("cratefield-testing");
}

#[pollster::test]
async fn test_harness_applies_migrations_and_serves_module_routes() {
    let kit = TestHarness::new(vec![Box::new(DemoModule)]);
    let response = request(&kit.router, axum::http::Method::GET, "/v1/demo/notes", None).await;
    assert_eq!(response.status, axum::http::StatusCode::OK);
    assert_eq!(response.json()["count"], 0);

    // Module writes land in the shared db handle.
    kit.db
        .execute(&cratefield_core::Statement::new(
            "INSERT INTO demo_notes (id, body) VALUES ('n1', 'hello')",
        ))
        .await
        .expect("insert");
    let response = request(&kit.router, axum::http::Method::GET, "/v1/demo/notes", None).await;
    assert_eq!(response.json()["count"], 1);
}

#[pollster::test]
async fn fake_mailer_records_and_switches_modes() {
    use cratefield_core::{Mailer, Message, SendOutcome};
    let mailer = FakeMailer::new(MailerMode::SendOk);
    let message = Message::new(
        "nick@example.com",
        "no-reply@test.example",
        "hi",
        "hi",
        "<p>hi</p>",
    );
    let outcome = mailer.send(message.clone()).await.expect("send");
    assert!(matches!(outcome, SendOutcome::Sent { .. }));
    assert_eq!(mailer.sent().len(), 1);
    assert_eq!(mailer.last_message().expect("recorded").to, message.to);

    mailer.set_mode(MailerMode::NotConfigured);
    assert_eq!(
        mailer.send(message).await.expect("send"),
        SendOutcome::NotConfigured
    );
    assert_eq!(mailer.sent().len(), 1, "NotConfigured records nothing");

    mailer.set_mode(MailerMode::Fail);
    assert!(
        mailer
            .send(Message::new("x@y.dev", "", "", "", ""))
            .await
            .is_err()
    );
}

#[pollster::test]
async fn fake_mailer_emits_any_error_variant_with_the_callers_own_text() {
    // Issue #236. With only `Fail` the fake could produce exactly one
    // error — `Upstream("fake mailer failure")` — so the two variants
    // that carry provider text, and therefore the two that can carry a
    // recipient address, were unreachable from any test. Every arm of a
    // caller's outcome mapping has to be drivable, with the text the
    // caller chooses, or the mapping is only ever read.
    use cratefield_core::{MailError, Mailer, Message};

    for error in [
        MailError::Unauthorized,
        MailError::DomainNotVerified {
            domain: "send.example.test".to_owned(),
        },
        MailError::Invalid {
            detail: "to: nick@example.com is suppressed".to_owned(),
        },
        MailError::RateLimited {
            retry_after: Some(std::time::Duration::from_mins(15)),
        },
        MailError::Upstream("resend 503".to_owned()),
        MailError::Transport("connection reset".to_owned()),
    ] {
        let mailer = FakeMailer::new(MailerMode::Error(error.clone()));
        let answer = mailer
            .send(Message::new("x@y.dev", "", "", "", ""))
            .await
            .expect_err("the mode is an error");
        assert_eq!(answer, error, "the fake emits exactly what it was given");
        assert!(mailer.sent().is_empty(), "a failure records nothing");
    }
}

#[pollster::test]
async fn fake_push_emits_any_error_variant_with_the_callers_own_text() {
    // The same hole on the push side (issue #236): the fixed modes only
    // ever produce clean strings, so nothing could show a device token or
    // a push endpoint arriving somewhere it should not.
    use cratefield_core::{Notification, Push, PushError, Recipient};
    use cratefield_testing::{FakePush, PushMode};

    for error in [
        PushError::Unregistered,
        PushError::Rejected("web push 400 for https://push.example.test/wp/x?auth=cap".to_owned()),
        PushError::transient_after("apns 429", Some(std::time::Duration::from_mins(15))),
    ] {
        let push = FakePush::new(PushMode::Error(error.clone()));
        let answer = push
            .send(&Recipient::apns("device-a"), &Notification::new("a", "b"))
            .await
            .expect_err("the mode is an error");
        assert_eq!(answer, error);
        assert!(push.sent().is_empty());
    }
}

#[pollster::test]
async fn fake_captcha_allow_all_and_token_lists() {
    use cratefield_core::Captcha;
    let allow_all = FakeCaptcha::allow_all();
    assert!(allow_all.verify("anything", None).await.expect("v").ok);

    let listed = FakeCaptcha::with_tokens(["good-token"]);
    assert!(listed.verify("good-token", None).await.expect("v").ok);
    let bad = listed.verify("bad-token", None).await.expect("v");
    assert!(!bad.ok);
    assert_eq!(bad.reason.as_deref(), Some("token not allowed"));
}

#[pollster::test]
async fn fake_rate_limiter_is_scripted() {
    use cratefield_core::{Decision, RateLimiter};
    let limiter = FakeRateLimiter::scripted(
        vec![Decision {
            ok: false,
            retry_after: Some(Duration::from_secs(3)),
        }],
        Decision {
            ok: true,
            retry_after: None,
        },
    );
    let first = limiter.limit("k").await.expect("l");
    assert!(!first.ok);
    assert_eq!(first.retry_after, Some(Duration::from_secs(3)));
    assert!(limiter.limit("k").await.expect("l").ok);
    assert!(limiter.limit("k").await.expect("l").ok);
    assert_eq!(limiter.calls(), 3);
}

#[pollster::test]
async fn memory_key_value_round_trips() {
    use cratefield_core::KeyValue;
    let kv = MemoryKeyValue::new();
    assert_eq!(kv.get("k").await.expect("g"), None);
    kv.put("k", "v", None).await.expect("p");
    assert_eq!(kv.get("k").await.expect("g"), Some("v".into()));
    kv.delete("k").await.expect("d");
    assert_eq!(kv.get("k").await.expect("g"), None);
}

#[pollster::test]
async fn fake_http_client_is_scripted_and_captures() {
    use cratefield_core::HttpClient;
    let http = FakeHttpClient::ok_json(r#"{"ok":true}"#);
    let request = http::Request::builder()
        .method("POST")
        .uri("https://example.test/x")
        .body(bytes::Bytes::from("payload"))
        .expect("request");
    let response = http.send(request).await.expect("send");
    assert_eq!(response.status(), 200);
    let captured = http.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].0, "POST");
    assert_eq!(captured[0].1, "https://example.test/x");
    assert_eq!(captured[0].2, "payload");
}

#[pollster::test]
async fn fake_defer_collects_and_drains() {
    use cratefield_core::Defer;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let defer = FakeDefer::new();
    let ran = Arc::new(AtomicUsize::new(0));
    for _ in 0..3 {
        let ran = Arc::clone(&ran);
        defer.wait_until(Box::pin(async move {
            ran.fetch_add(1, Ordering::SeqCst);
        }));
    }
    assert_eq!(defer.deferred_count(), 3);
    assert_eq!(ran.load(Ordering::SeqCst), 0, "nothing runs before drain");
    defer.drain().await;
    assert_eq!(ran.load(Ordering::SeqCst), 3);
}

#[pollster::test]
async fn signer_round_trips_with_test_secret() {
    use cratefield_core::{Kid, Payload, Signer};
    let kit = TestHarness::new(vec![Box::new(DemoModule)]);
    let payload = Payload {
        purpose: "confirm".into(),
        subject: "nick@example.com".into(),
        exp: None,
        kid: Kid::Cur,
    };
    let token = kit.signer.sign(&payload);
    let verified = kit.signer.verify(&token, "confirm").expect("verifies");
    assert_eq!(verified.subject, "nick@example.com");
}

#[test]
fn empty_database_answers_readiness_probe() {
    let db = cratefield_testing::EmptyDatabase;
    let rows = pollster::block_on(db.query(&cratefield_core::Statement::new("SELECT 1")))
        .expect("select 1");
    assert_eq!(rows.len(), 1);
}
