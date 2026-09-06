//! Turnstile adapter acceptance tests (issue #7): success, invalid token,
//! timeout, hostname mismatch, fail-open. All through a fake `HttpClient`
//! and a controllable `Clock`.

use async_trait::async_trait;
use bytes::Bytes;
use factory0_adapter_turnstile::Turnstile;
use factory0_core::{Captcha, Clock, HttpClient, HttpError, Verdict};
use http::{Request, Response, StatusCode};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

// Obvious dummy secret, never real.
const DUMMY_SECRET: &str = "0x4AAAAAAA_dummy_secret_000000";

type BodyFactory = Box<dyn Fn() -> Result<Response<Bytes>, HttpError> + Send + Sync>;

struct FakeHttp {
    responder: BodyFactory,
}

#[async_trait]
impl HttpClient for FakeHttp {
    async fn send(&self, _request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        (self.responder)()
    }
}

struct CapturingHttp {
    tx: mpsc::Sender<String>,
}

#[async_trait]
impl HttpClient for CapturingHttp {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let body = String::from_utf8_lossy(request.body()).to_string();
        self.tx.send(body).expect("channel open");
        Response::builder()
            .status(StatusCode::OK)
            .body(Bytes::from(r#"{"success":true}"#))
            .map_err(|err| HttpError::Transport(err.to_string()))
    }
}

fn ok_json(body: &'static str) -> BodyFactory {
    Box::new(move || {
        Response::builder()
            .status(StatusCode::OK)
            .body(Bytes::from(body))
            .map_err(|err| HttpError::Transport(err.to_string()))
    })
}

fn failing() -> BodyFactory {
    Box::new(|| Err(HttpError::Transport("network down".to_string())))
}

/// A clock whose timeout runs the future to completion (system default
/// behavior; tests use this unless exercising the timeout path).
struct RunToCompletionClock;

#[async_trait]
impl Clock for RunToCompletionClock {
    fn now(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::now_utc()
    }
}

/// A clock whose timeout always abandons the future.
struct NeverClock;

#[async_trait]
impl Clock for NeverClock {
    fn now(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::now_utc()
    }

    async fn timeout_any(
        &self,
        _fut: futures_core::future::BoxFuture<'static, Box<dyn std::any::Any + Send>>,
        _after: Duration,
    ) -> Option<Box<dyn std::any::Any + Send>> {
        None
    }
}

fn turnstile(responder: BodyFactory) -> Turnstile {
    Turnstile::new(
        Arc::new(FakeHttp { responder }),
        Arc::new(RunToCompletionClock),
        DUMMY_SECRET,
    )
}

#[pollster::test]
async fn success_verifies_ok() {
    let captcha = turnstile(ok_json(
        r#"{"success":true,"error-codes":[],"hostname":"example.com"}"#,
    ));
    let verdict = captcha
        .verify("tok", Some("203.0.113.7"))
        .await
        .expect("no transport error");
    assert_eq!(
        verdict,
        Verdict {
            ok: true,
            reason: None
        }
    );
}

#[pollster::test]
async fn invalid_token_fails_with_first_error_code() {
    let captcha = turnstile(ok_json(
        r#"{"success":false,"error-codes":["invalid-input-response","bad-loser"]}"#,
    ));
    let verdict = captcha.verify("tok", None).await.expect("ok");
    assert_eq!(
        verdict,
        Verdict {
            ok: false,
            reason: Some("invalid-input-response".to_string()),
        }
    );
}

#[pollster::test]
async fn timeout_is_fail_closed_unavailable() {
    let captcha = Turnstile::new(
        Arc::new(FakeHttp {
            responder: ok_json(r#"{"success":true}"#),
        }),
        Arc::new(NeverClock),
        DUMMY_SECRET,
    );
    let verdict = captcha.verify("tok", None).await.expect("ok");
    assert_eq!(
        verdict,
        Verdict {
            ok: false,
            reason: Some("unavailable".to_string()),
        }
    );
}

#[pollster::test]
async fn transport_failure_is_fail_closed_unavailable() {
    let captcha = turnstile(failing());
    let verdict = captcha.verify("tok", None).await.expect("ok");
    assert_eq!(
        verdict,
        Verdict {
            ok: false,
            reason: Some("unavailable".to_string()),
        }
    );
}

#[pollster::test]
async fn fail_open_lets_transport_failure_pass() {
    let captcha = turnstile(failing()).fail_open(true);
    let verdict = captcha.verify("tok", None).await.expect("ok");
    assert_eq!(
        verdict,
        Verdict {
            ok: true,
            reason: None
        }
    );
}

#[pollster::test]
async fn hostname_mismatch_fails() {
    let captcha = turnstile(ok_json(
        r#"{"success":true,"error-codes":[],"hostname":"evil.example"}"#,
    ))
    .expected_hostname("example.com");
    let verdict = captcha.verify("tok", None).await.expect("ok");
    assert_eq!(
        verdict,
        Verdict {
            ok: false,
            reason: Some("hostname-mismatch".to_string()),
        }
    );
}

#[pollster::test]
async fn hostname_match_passes() {
    let captcha = turnstile(ok_json(
        r#"{"success":true,"error-codes":[],"hostname":"example.com"}"#,
    ))
    .expected_hostname("example.com");
    let verdict = captcha.verify("tok", None).await.expect("ok");
    assert_eq!(
        verdict,
        Verdict {
            ok: true,
            reason: None
        }
    );
}

#[pollster::test]
async fn from_env_none_without_secret() {
    // Env mutation is unsafe in edition 2024; the var is absent in clean
    // environments (CI). Skip only when a developer machine has it set.
    if std::env::var("TURNSTILE_SECRET").is_ok() {
        return;
    }
    assert!(
        Turnstile::from_env(
            Arc::new(FakeHttp {
                responder: ok_json("{}"),
            }),
            Arc::new(RunToCompletionClock),
        )
        .is_none()
    );
}

#[pollster::test]
async fn request_carries_secret_and_token() {
    let (tx, rx) = mpsc::channel::<String>();
    let captcha = Turnstile::new(
        Arc::new(CapturingHttp { tx }),
        Arc::new(RunToCompletionClock),
        DUMMY_SECRET,
    );
    captcha.verify("the-token", None).await.expect("ok");
    let body = rx.try_recv().expect("captured");
    assert!(body.contains(&format!("secret={DUMMY_SECRET}")));
    assert!(body.contains("response=the-token"));
}
