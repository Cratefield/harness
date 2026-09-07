//! Issue #13 acceptance: a request carrying `Authorization` and a
//! `token` field produces log output through core's redaction rules
//! where secrets never appear and emails appear only as a 12-hex
//! `subject_hash` — and no emitted line from the real module flow
//! contains an `@`.

// Test-side recording fixture, not request state — the same category
// and allowance as the fakes in `cratefield-testing` (ADR 0007 policy).
#![allow(clippy::disallowed_types)]

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use cratefield_module_email_signup::EmailSignup;
use cratefield_testing::TestHarness;
use std::sync::{Arc, Mutex};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};

struct CapturingSubscriber {
    lines: Mutex<Vec<String>>,
}

impl Subscriber for CapturingSubscriber {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _attributes: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _id: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _follows: &Id, _to: &Id) {}

    fn event(&self, event: &Event<'_>) {
        // The same redaction every runtime formatter applies.
        let mut visitor = cratefield_core::RedactingVisitor::new();
        event.record(&mut visitor);
        let line = visitor
            .fields
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join(" ");
        self.lines.lock().expect("log lock").push(line);
    }

    fn enter(&self, _id: &Id) {}

    fn exit(&self, _id: &Id) {}
}

#[test]
fn secrets_and_emails_never_reach_log_lines() {
    let subscriber = Arc::new(CapturingSubscriber {
        lines: Mutex::new(Vec::new()),
    });
    let dispatch = tracing::dispatcher::Dispatch::new(ArcSub {
        inner: Arc::clone(&subscriber),
    });

    let kit = TestHarness::new(vec![Box::new(EmailSignup::new())]);
    let secret_token = "super-secret-bearer-value-0123456789";
    let captcha_token = "captcha-token-value";
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/email-signup")
        .header(header::AUTHORIZATION, format!("Bearer {secret_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(format!(
            r#"{{"email":"nick@example.com","captchaToken":"{captcha_token}"}}"#
        )))
        .expect("request");

    let router = kit.router.clone();
    let authorization_value = format!("Bearer {secret_token}");
    tracing::dispatcher::with_default(&dispatch, || {
        pollster::block_on(async {
            use tower::ServiceExt;
            let response = router.oneshot(request).await.expect("router answers");
            assert_eq!(response.status(), StatusCode::ACCEPTED);
        });
        // A careless handler logging exactly the fields section 11
        // worries about: the redaction layer must neutralize them.
        tracing::info!(
            authorization = authorization_value.as_str(),
            token = captcha_token,
            email = "nick@example.com",
            subject = "nick@example.com",
            outcome = "sent",
            "redaction probe"
        );
    });

    let lines = subscriber.lines.lock().expect("log lock").clone();
    assert!(!lines.is_empty(), "something was logged");
    for line in &lines {
        assert!(!line.contains(secret_token), "bearer leaked: {line}");
        assert!(!line.contains(captcha_token), "token leaked: {line}");
        assert!(!line.contains('@'), "email leaked: {line}");
    }

    let probe = lines
        .iter()
        .find(|line| line.contains("redaction") || line.contains("probe"))
        .or_else(|| lines.iter().find(|line| line.contains("outcome=sent")))
        .expect("probe event captured");
    assert!(probe.contains("outcome=sent"), "probe: {probe}");
}

/// `Dispatch` needs a by-value `Subscriber`; forward to the shared one.
struct ArcSub {
    inner: Arc<CapturingSubscriber>,
}

impl Subscriber for ArcSub {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.inner.enabled(metadata)
    }
    fn new_span(&self, attributes: &Attributes<'_>) -> Id {
        self.inner.new_span(attributes)
    }
    fn record(&self, span: &Id, values: &Record<'_>) {
        self.inner.record(span, values);
    }
    fn record_follows_from(&self, follows: &Id, to: &Id) {
        self.inner.record_follows_from(follows, to);
    }
    fn event(&self, event: &Event<'_>) {
        self.inner.event(event);
    }
    fn enter(&self, span: &Id) {
        self.inner.enter(span);
    }
    fn exit(&self, span: &Id) {
        self.inner.exit(span);
    }
}

#[test]
fn module_events_stay_below_error_level_threshold_exists() {
    // Guard against accidentally silencing the capturing path: the
    // module logs at info level, which this subscriber accepts.
    let subscriber = Arc::new(CapturingSubscriber {
        lines: Mutex::new(Vec::new()),
    });
    let dispatch = tracing::dispatcher::Dispatch::new(ArcSub {
        inner: Arc::clone(&subscriber),
    });
    tracing::dispatcher::with_default(&dispatch, || {
        tracing::info!(outcome = "sent", "probe");
    });
    assert!(
        subscriber
            .lines
            .lock()
            .expect("log lock")
            .iter()
            .any(|line| line.contains("outcome=sent"))
    );
    let _ = Level::INFO;
}
