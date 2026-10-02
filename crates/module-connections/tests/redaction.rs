//! Tokens never reach a log line, a response body or a header (issue #624).
//!
//! The whole flow runs under a capturing subscriber and then every captured
//! line is searched for the fixture's access tokens, refresh tokens and
//! client secret. A deliberate probe logs those same values as named fields,
//! the way a careless handler would, and the redaction layer must neutralise
//! it — so the test fails if either the module leaks a token or the redaction
//! that is supposed to catch it stops working.
//!
//! The subscriber is installed with `tracing::dispatcher::with_default`, the
//! same thread-scoped idiom `module-email-signup`'s logging test uses:
//! `pollster::block_on` runs the futures on this thread, and none of the
//! doubles spawn a task, so nothing escapes the capturing dispatcher.

// Test-side recording fixture, not request state — the same category and
// allowance as the fakes in `cratefield-testing` (ADR 0007 policy).
#![allow(clippy::disallowed_types)]

mod support;

use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

use support::{
    CLIENT_SECRET, REFRESHED_BODY, RETURN_TO, Spec, begin, callback_url, connect, fixture, query_of,
};

/// Every fixture string that must never appear in a log line, a body or a
/// header.
const SECRETS: &[&str] = &[
    "AT-connected-1",
    "AT-refreshed-2",
    "RT-connected-1",
    "RT-refreshed-2",
    CLIENT_SECRET,
    "test-authorization-code",
];

/// A 400 whose `error_description` echoes the token the endpoint was just
/// sent — what a careless provider returns, and what must never be kept.
const ECHOING_400: &str = r#"{"error":"invalid_request",
    "error_description":"AT-connected-1 / RT-connected-1 is not acceptable"}"#;

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

/// Runs `body` under the capturing subscriber and returns the log lines it
/// saw alongside its own result.
fn captured<F: std::future::Future>(body: F) -> (Vec<String>, F::Output) {
    let subscriber = Arc::new(CapturingSubscriber {
        lines: Mutex::new(Vec::new()),
    });
    let dispatch = tracing::dispatcher::Dispatch::new(ArcSub {
        inner: Arc::clone(&subscriber),
    });
    let output = tracing::dispatcher::with_default(&dispatch, || pollster::block_on(body));
    let lines = subscriber.lines.lock().expect("log lock").clone();
    (lines, output)
}

/// No secret appears in any of these lines.
fn assert_no_secret(lines: &[String], secrets: &[&str]) {
    for line in lines {
        for secret in secrets {
            assert!(
                !line.contains(secret),
                "a secret reached a log line: {line}"
            );
        }
    }
}

#[pollster::test]
async fn no_token_reaches_a_log_a_body_or_a_header() {
    let (lines, ()) = captured(async {
        for kit in fixture(&Spec::default()).kits {
            kit.fresh();

            let (authorize, state) = begin(&kit, "alice", "x", RETURN_TO).await;
            assert!(
                !authorize.url.contains(CLIENT_SECRET),
                "the authorize URL carries the client secret"
            );

            // The provider's own refusal (`a_provider_error_is_never_echoed`
            // moved here): it logs a warning naming the error code, the body
            // carries no provider text, and the description — where an
            // attacker's text goes — must not reach the log either.
            let refused = kit
                .get(
                    "/v1/connections/callback/x?error=access_denied\
                     &error_description=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
                )
                .await;
            assert_eq!(refused.status, StatusCode::BAD_REQUEST);
            assert_eq!(refused.problem_slug(), "connections-oauth-denied");
            assert!(
                !refused.text().contains("script"),
                "the provider's text must not be reflected: {}",
                refused.text()
            );

            // The callback route: the redirect stays on the return_to and
            // its Location and body carry no token.
            let response = kit
                .get(&callback_url("x", &state, "test-authorization-code"))
                .await;
            assert_eq!(response.status, StatusCode::SEE_OTHER);
            let location = response.location().expect("a redirect carries Location");
            assert!(
                location.starts_with(RETURN_TO),
                "off the return_to: {location}"
            );
            let id = query_of(&location, "connection").expect("the id is on the redirect");
            let rendered = format!(
                "{location} {} {}",
                response.text(),
                response
                    .headers
                    .iter()
                    .map(|(name, value)| format!("{name}: {:?}", value.to_str()))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            for secret in SECRETS {
                assert!(
                    !rendered.contains(secret),
                    "a token reached a response header or body: {secret}"
                );
            }

            // A refresh, and a revoke.
            kit.clock.advance_secs(3600);
            kit.http.set_response(200, REFRESHED_BODY);
            kit.api
                .access_token(&id)
                .await
                .expect("the refresh succeeds");
            kit.api.revoke(&id).await.expect("revokes");

            // What a careless handler would log: named token fields. The
            // redaction layer must turn each into `[redacted]`.
            tracing::info!(
                access_token = "AT-refreshed-2",
                refresh_token = "RT-refreshed-2",
                client_secret = CLIENT_SECRET,
                "redaction probe"
            );
        }
    });

    assert!(
        !lines.is_empty(),
        "nothing was logged, so nothing was proven"
    );
    assert!(
        lines.iter().any(|line| line.contains("redaction probe")),
        "the probe was not captured: {lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.contains("the provider refused the authorization")),
        "the module's own warn line was not captured: {lines:?}"
    );
    assert_no_secret(&lines, SECRETS);
}

/// A scheduled refresh the provider refuses with a non-`invalid_grant` 400
/// whose description echoes the token: the token reaches neither a log line
/// nor the row's `last_error`.
#[pollster::test]
async fn a_refused_refresh_echoing_the_token_keeps_it_out_of_the_log() {
    let (lines, ()) = captured(async {
        for kit in fixture(&Spec::default()).kits {
            kit.fresh();
            let connection = connect(&kit, "alice", "x").await;
            kit.fresh();

            kit.clock.advance_secs(3600);
            kit.http.set_response(400, ECHOING_400);
            kit.run_scheduled().await;

            assert_eq!(
                kit.connection_column(&connection.id, "last_error").await,
                None,
                "a provider failure is not recorded as the connection's own error"
            );
        }
    });
    // The pass's warn line is present, so the search below has a haystack.
    assert!(
        lines
            .iter()
            .any(|line| line.contains("a scheduled refresh did not complete")),
        "the scheduled warn line was not captured: {lines:?}"
    );
    assert_no_secret(&lines, &["AT-connected-1", "RT-connected-1"]);
}

/// The same 400 on the revoke leg: the provider cannot be reached or
/// confirms nothing, the local revoke still happens, and the echoed token
/// reaches neither a log line nor `last_error`.
#[pollster::test]
async fn a_refused_revoke_echoing_the_token_keeps_it_out_of_the_log() {
    let (lines, ()) = captured(async {
        for kit in fixture(&Spec::default()).kits {
            kit.fresh();
            let connection = connect(&kit, "alice", "x").await;
            kit.fresh();

            kit.http.set_response(400, ECHOING_400);
            kit.api
                .revoke(&connection.id)
                .await
                .expect("the local revoke happens whatever the provider says");
            assert_eq!(
                kit.connection_column(&connection.id, "last_error").await,
                None,
                "a refused revoke must not record the provider's prose"
            );
        }
    });
    assert!(
        lines
            .iter()
            .any(|line| line.contains("did not confirm the revocation")),
        "the revoke warn line was not captured: {lines:?}"
    );
    assert_no_secret(&lines, &["AT-connected-1", "RT-connected-1"]);
}
