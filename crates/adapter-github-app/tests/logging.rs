//! Issue #623 acceptance: no secret the GitHub App client handles ever
//! reaches a log line, and none is reachable through a `Debug` print or an
//! error's `Display`.
// Test-side recording fixture, not request state — the same category and
// allowance as the fakes in `cratefield-testing` (ADR 0007 policy).
#![allow(clippy::disallowed_types)]

mod common;

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use common::{RecordingHttp, StepClock, TEST_KEY, ok_json, response, token_body};
use cratefield_adapter_github_app::{GithubApp, GithubAppError};
use http::Request;
use tracing::dispatcher::Dispatch;
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

/// A subscriber that keeps every event, after the same redaction every
/// runtime formatter applies (copied from
/// `crates/module-email-signup/tests/logging.rs`).
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

const CLIENT_SECRET: &str = "client-secret-value-0123456789";
const GHS_STALE: &str = "ghs_STALE000000000000000000000000000000000";
const GHS_FRESH: &str = "ghs_FRESH000000000000000000000000000000000";
const GHU_TOKEN: &str = "ghu_FIXTURE000000000000000000000000000000";

fn get(uri: &str) -> Request<Bytes> {
    Request::get(uri).body(Bytes::new()).expect("request")
}

/// Every string that must never surface: both installation tokens, the user
/// token, the client secret, the JWT, and every line of the private key.
struct Secrets(Vec<String>);

impl Secrets {
    fn new(jwt: &str) -> Self {
        let mut secrets = vec![jwt.to_owned()];
        secrets.extend([CLIENT_SECRET, GHS_STALE, GHS_FRESH, GHU_TOKEN].map(str::to_owned));
        // Every PEM line, not just the markers.
        secrets.extend(
            TEST_KEY
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_owned),
        );
        Self(secrets)
    }

    fn assert_absent(&self, haystack: &str, what: &str) {
        for secret in &self.0 {
            assert!(!haystack.contains(secret), "{what} leaked: {haystack}");
        }
    }
}

/// Drives a cold exchange, a `401` re-mint and replay, an exchange GitHub
/// refuses, and both OAuth outcomes, so every logging site is exercised.
fn drive(app: &GithubApp, dispatch: &Dispatch) -> (String, GithubAppError, GithubAppError) {
    tracing::dispatcher::with_default(dispatch, || {
        let jwt = app.app_jwt().expect("a JWT");
        let (error, user_error) = pollster::block_on(async {
            app.installation_token(7, None, None).await.expect("minted");
            app.request(7, get("/repos/acme/widgets"))
                .await
                .expect("answered");
            // A second installation whose exchange GitHub refuses.
            let error = app
                .installation_token(8, None, None)
                .await
                .expect_err("500");
            app.exchange_user_code("client-id", CLIENT_SECRET, "good-code", None)
                .await
                .expect("exchanged");
            let user_error = app
                .exchange_user_code("client-id", CLIENT_SECRET, "bad-code", None)
                .await
                .expect_err("oauth error");
            (error, user_error)
        });
        (jwt, error, user_error)
    })
}

#[test]
fn no_token_key_or_secret_ever_reaches_a_log_line() {
    let subscriber = Arc::new(CapturingSubscriber {
        lines: Mutex::new(Vec::new()),
    });
    let dispatch = Dispatch::new(ArcSub {
        inner: Arc::clone(&subscriber),
    });
    let app = GithubApp::new(
        123_456,
        Some(TEST_KEY.to_owned()),
        RecordingHttp::scripted(vec![
            ok_json(token_body(GHS_STALE)), // 1. initial exchange (info)
            response(401, "", &[]),         // 2. request refused
            ok_json(token_body(GHS_FRESH)), // 3. re-mint (warn)
            response(200, "{}", &[]),       // 4. replay
            response(500, "", &[]),         // 5. an exchange GitHub refuses (warn)
            ok_json(include_str!("fixtures/user-token.json")), // 6. oauth ok
            ok_json(include_str!("fixtures/oauth-error.json")), // 7. oauth error (warn)
        ]),
        Arc::new(StepClock::at(1_700_000_000)),
        "https://api.github.test",
    );

    let (jwt, error, user_error) = drive(&app, &dispatch);

    let lines = subscriber.lines.lock().expect("log lock").clone();
    assert!(
        lines.iter().any(|line| line.contains("token-minted")),
        "the success path logged: {lines:?}"
    );
    assert!(
        lines.iter().any(|line| line.contains("token-refreshed")),
        "the 401 replay logged: {lines:?}"
    );

    // The log lines, and the Debug / Display surfaces, are all just as tight.
    let secrets = Secrets::new(&jwt);
    for line in &lines {
        secrets.assert_absent(line, "a log line");
    }
    for printed in [
        format!("{app:?}"),
        format!("{error}"),
        format!("{user_error}"),
    ] {
        secrets.assert_absent(&printed, "a Debug/Display print");
    }
    assert!(matches!(&error, GithubAppError::Status { .. }), "{error:?}");
    assert!(
        matches!(&user_error, GithubAppError::OAuth(_)),
        "{user_error:?}"
    );

    // The token's own Debug redacts its field.
    let token = pollster::block_on(app.installation_token(7, None, None)).expect("cached");
    let printed = format!("{token:?}");
    secrets.assert_absent(&printed, "the installation token's Debug");
    assert!(printed.contains("redacted"), "{printed}");
}
