//! Turnstile adapter acceptance tests (issue #7): success, invalid token,
//! timeout, hostname mismatch, fail-open. All through a fake `HttpClient`
//! and a controllable `Clock`. Issue #436 adds form-encoding, token
//! shape-checking, and secret-never-logged acceptance on top.

// Test-side recording fixture, not request state — the same category
// and allowance as the fakes in `cratefield-testing` (ADR 0007 policy).
#![allow(clippy::disallowed_types)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_adapter_turnstile::Turnstile;
use cratefield_core::{Captcha, CaptchaBinding, Clock, HttpClient, HttpError, Verdict};
use http::{Request, Response, StatusCode};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
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

fn server_error() -> BodyFactory {
    Box::new(|| {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Bytes::from("server exploded"))
            .map_err(|err| HttpError::Transport(err.to_string()))
    })
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
    turnstile_with_secret(responder, DUMMY_SECRET)
}

fn turnstile_with_secret(responder: BodyFactory, secret: &str) -> Turnstile {
    Turnstile::new(
        Arc::new(FakeHttp { responder }),
        Arc::new(RunToCompletionClock),
        secret,
    )
}

/// A `Turnstile` over `CapturingHttp`, plus the receiver for the bodies
/// it was sent — for tests that assert what reached the wire (or that
/// nothing did).
fn capturing_turnstile(secret: &str) -> (Turnstile, mpsc::Receiver<String>) {
    let (tx, rx) = mpsc::channel::<String>();
    let captcha = Turnstile::new(
        Arc::new(CapturingHttp { tx }),
        Arc::new(RunToCompletionClock),
        secret,
    );
    (captcha, rx)
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

// --- issue #133: bound checks fail closed, and the adapter reports ---

#[pollster::test]
async fn bound_hostname_rejects_response_without_hostname() {
    // Provider says success but returns no hostname: the widget was not
    // bound the way this deployment expects — absent is not "passed".
    let captcha =
        turnstile(ok_json(r#"{"success":true,"error-codes":[]}"#)).expected_hostname("example.com");
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
async fn action_mismatch_fails() {
    let captcha = turnstile(ok_json(
        r#"{"success":true,"hostname":"example.com","action":"login"}"#,
    ))
    .expected_action("signup");
    let verdict = captcha.verify("tok", None).await.expect("ok");
    assert_eq!(
        verdict,
        Verdict {
            ok: false,
            reason: Some("action-mismatch".to_string()),
        }
    );
}

#[pollster::test]
async fn action_match_passes() {
    let captcha = turnstile(ok_json(
        r#"{"success":true,"hostname":"example.com","action":"signup"}"#,
    ))
    .expected_action("signup");
    let verdict = captcha.verify("tok", None).await.expect("ok");
    assert!(verdict.ok, "{verdict:?}");
}

#[pollster::test]
async fn binding_reports_configured_checks() {
    let unbound = turnstile(ok_json(r#"{"success":true}"#));
    assert_eq!(
        unbound.binding(),
        Some(CaptchaBinding {
            hostname_bound: false,
            action_bound: false,
            fail_open: false,
        })
    );

    let bound = turnstile(ok_json(r#"{"success":true}"#))
        .expected_hostname("example.com")
        .expected_action("signup");
    assert_eq!(
        bound.binding(),
        Some(CaptchaBinding {
            hostname_bound: true,
            action_bound: true,
            fail_open: false,
        })
    );

    let staging = turnstile(ok_json(r#"{"success":true}"#))
        .expected_hostname("example.com")
        .fail_open(true);
    assert_eq!(
        staging.binding(),
        Some(CaptchaBinding {
            hostname_bound: true,
            action_bound: false,
            fail_open: true,
        })
    );
}

// --- issue #436: a malformed token is refused before any network call ---

#[pollster::test]
async fn malformed_token_is_refused_before_any_network_call() {
    let (captcha, rx) = capturing_turnstile(DUMMY_SECRET);
    let verdict = captcha
        .verify("bad&token", Some("203.0.113.9"))
        .await
        .expect("no transport error");
    assert_eq!(
        verdict,
        Verdict {
            ok: false,
            reason: Some("invalid-input-response".to_string()),
        }
    );
    assert!(
        rx.try_recv().is_err(),
        "a malformed token must never reach siteverify"
    );
}

#[pollster::test]
async fn fail_open_does_not_soften_the_malformed_token_refusal() {
    // `fail_open` is for transport and availability failures. A token
    // that is not a token is an input error: it stays refused.
    let (captcha, rx) = capturing_turnstile(DUMMY_SECRET);
    let captcha = captcha.fail_open(true);
    let verdict = captcha
        .verify("bad&token", None)
        .await
        .expect("no transport error");
    assert_eq!(
        verdict,
        Verdict {
            ok: false,
            reason: Some("invalid-input-response".to_string()),
        }
    );
    assert!(
        rx.try_recv().is_err(),
        "fail_open must not soften the refusal"
    );
}

#[pollster::test]
async fn empty_and_oversized_tokens_are_refused_before_any_network_call() {
    let (captcha, rx) = capturing_turnstile(DUMMY_SECRET);
    // One byte past the 2048-byte ceiling the adapter accepts.
    let oversized = "a".repeat(2049);
    for token in ["", oversized.as_str()] {
        let verdict = captcha
            .verify(token, None)
            .await
            .expect("no transport error");
        assert_eq!(
            verdict,
            Verdict {
                ok: false,
                reason: Some("invalid-input-response".to_string()),
            },
            "token length: {}",
            token.len()
        );
    }
    assert!(
        rx.try_recv().is_err(),
        "neither refused token reached siteverify"
    );
}

#[pollster::test]
async fn a_well_formed_token_still_reaches_siteverify() {
    let (captcha, rx) = capturing_turnstile(DUMMY_SECRET);
    let token = "0.z8xQa_7-bBcCdDeE";
    let verdict = captcha
        .verify(token, Some("203.0.113.9"))
        .await
        .expect("captured");
    assert!(verdict.ok, "{verdict:?}");
    let body = rx.try_recv().expect("captured");
    assert!(body.contains(&format!("response={token}")));

    // A token exactly at the length ceiling is still well formed and
    // still goes out.
    let (captcha, rx) = capturing_turnstile(DUMMY_SECRET);
    let ceiling = "a".repeat(2048);
    let verdict = captcha.verify(&ceiling, None).await.expect("captured");
    assert!(verdict.ok, "{verdict:?}");
    let body = rx.try_recv().expect("captured");
    assert!(body.contains(&format!("response={ceiling}")));
}

// --- issue #436: the secret never reaches a log line, verdict or error ---

/// A distinctive stand-in secret whose literal presence is easy to assert
/// against. Never a real secret.
const SECRET_PROBE: &str = "SUPER_SECRET_VALUE_9x8y7z";

/// Test-side recording subscriber: turns every emitted event into one
/// plain line (message plus `name=value` fields), so tests can assert
/// over exactly what was logged.
struct CapturingSubscriber {
    lines: Arc<Mutex<Vec<String>>>,
}

impl tracing::Subscriber for CapturingSubscriber {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = LineVisitor(String::new());
        event.record(&mut visitor);
        self.lines.lock().expect("log lock").push(visitor.0);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

struct LineVisitor(String);

impl tracing::field::Visit for LineVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.push(field.name(), value);
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.push(field.name(), &format!("{value:?}"));
    }
}

impl LineVisitor {
    fn push(&mut self, name: &str, rendered: &str) {
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        if name == "message" {
            self.0.push_str(rendered);
        } else {
            self.0.push_str(name);
            self.0.push('=');
            self.0.push_str(rendered);
        }
    }
}

/// Runs `run` under the capturing subscriber, returning the emitted lines
/// and whatever `run` produced.
///
/// Tests run in parallel, and tracing caches each callsite's interest
/// globally. While at most one dispatcher is registered, tracing computes
/// that interest from whichever thread registers the callsite first, so a
/// parallel test with no subscriber could cache `never` for the warn this
/// test waits on, and the line would never arrive (a flake, about one run
/// in three). Keeping a second dispatcher alive for the whole process makes
/// tracing consult every registered dispatcher instead, and rebuilding the
/// cache under the scoped default clears a `never` cached before either
/// existed.
fn captured<T>(run: impl FnOnce() -> T) -> (Vec<String>, T) {
    static KEEP_MULTI_DISPATCH: std::sync::OnceLock<tracing::dispatcher::Dispatch> =
        std::sync::OnceLock::new();
    KEEP_MULTI_DISPATCH.get_or_init(|| {
        tracing::dispatcher::Dispatch::new(CapturingSubscriber {
            lines: Arc::new(Mutex::new(Vec::new())),
        })
    });
    let lines = Arc::new(Mutex::new(Vec::new()));
    let dispatch = tracing::dispatcher::Dispatch::new(CapturingSubscriber {
        lines: Arc::clone(&lines),
    });
    let value = tracing::dispatcher::with_default(&dispatch, || {
        tracing::callsite::rebuild_interest_cache();
        run()
    });
    let lines = lines.lock().expect("log lock").clone();
    (lines, value)
}

/// Nothing on the returned log lines, and nothing in the rendered
/// verdict/error, may carry the secret.
fn assert_secret_absent(lines: &[String], rendered: &str) {
    assert!(
        !rendered.contains(SECRET_PROBE),
        "secret leaked into a value: {rendered}"
    );
    for line in lines {
        assert!(
            !line.contains(SECRET_PROBE),
            "secret leaked into a log line: {line}"
        );
    }
}

#[test]
fn transport_failure_never_logs_or_returns_the_secret() {
    let (lines, verdict) = captured(|| {
        pollster::block_on(async {
            turnstile_with_secret(failing(), SECRET_PROBE)
                .verify("tok", None)
                .await
                .expect("ok")
        })
    });
    assert!(
        lines
            .iter()
            .any(|line| line.contains("siteverify transport failure")),
        "expected the transport warn, got: {lines:?}"
    );
    assert!(!verdict.ok, "{verdict:?}");
    assert_secret_absent(&lines, &format!("{verdict:?}"));
}

#[test]
fn non_success_status_never_logs_or_returns_the_secret() {
    let (lines, verdict) = captured(|| {
        pollster::block_on(async {
            turnstile_with_secret(server_error(), SECRET_PROBE)
                .verify("tok", None)
                .await
                .expect("ok")
        })
    });
    assert!(
        lines
            .iter()
            .any(|line| line.contains("siteverify returned non-success")),
        "expected the non-success warn, got: {lines:?}"
    );
    assert!(!verdict.ok, "{verdict:?}");
    assert_secret_absent(&lines, &format!("{verdict:?}"));
}

#[test]
fn unparseable_body_never_returns_the_secret_in_the_error() {
    let (lines, error) = captured(|| {
        pollster::block_on(async {
            turnstile_with_secret(ok_json("this is not json"), SECRET_PROBE)
                .verify("tok", None)
                .await
                .expect_err("a non-JSON body is a transport error")
        })
    });
    assert_secret_absent(&lines, &error.to_string());
}

#[test]
fn malformed_token_refusal_never_logs_or_returns_the_secret_or_token() {
    let hostile_token = "bad&token=probe";
    let (lines, verdict) = captured(|| {
        pollster::block_on(async {
            turnstile_with_secret(ok_json(r#"{"success":true}"#), SECRET_PROBE)
                .verify(hostile_token, None)
                .await
                .expect("ok")
        })
    });
    assert!(
        lines
            .iter()
            .any(|line| line.contains("refusing malformed turnstile token")),
        "expected the malformed-token warn, got: {lines:?}"
    );
    assert_eq!(
        verdict,
        Verdict {
            ok: false,
            reason: Some("invalid-input-response".to_string()),
        }
    );
    assert_secret_absent(&lines, &format!("{verdict:?}"));
    // The rejected token itself is not echoed into the log either.
    for line in &lines {
        assert!(
            !line.contains(hostile_token),
            "token leaked into a log line: {line}"
        );
    }
}
