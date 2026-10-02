//! The RFC 8628 client against the real `device-auth` module (issue #587):
//! no network, no second implementation. The client's `HttpClient` is an
//! adapter onto [`TestHarness`]'s router, so the code it requests, the poll
//! it paces and the credential it receives are all the module's own bytes.
//!
//! The approval happens between the first and second poll — the adapter
//! posts the module's own `/approve` route as a signed-in approver — which
//! is the shape of a real flow: a poll answers `authorization_pending`
//! until a person approves, and then the next poll gets the credential.

use std::any::Any;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{Clock, HttpClient, HttpError, RandomBytes, RandomError};
use cratefield_module_device_auth::{
    Approval, Approver, ApproverError, DeviceAuth, DeviceClient, IssueRequest, Issuer, IssuerError,
};
use cratefield_testing::TestHarness;
use futures_core::future::BoxFuture;
use http::{Method, Request, StatusCode, header};
use time::OffsetDateTime;
use tower::ServiceExt;

use cratefield_oauth_client::device::{DeviceFlowError, poll, request_code};

// ---------------------------------------------------------------------------
// The module's hooks

/// Mints one recognizable credential and names the approver, so the test
/// can prove the credential came from this issuer and for this subject.
struct TestIssuer;

#[async_trait]
impl Issuer for TestIssuer {
    async fn issue(&self, request: IssueRequest) -> Result<serde_json::Value, IssuerError> {
        Ok(serde_json::json!({
            "access_token": "issued-once",
            "token_type": "Bearer",
            "subject": request.subject,
            "client_id": request.client_id,
        }))
    }
}

/// A deterministic entropy source: the module needs a `RandomBytes`, and
/// the test needs the same codes every run.
#[derive(Default)]
struct TestRandom(AtomicU32);

impl RandomBytes for TestRandom {
    fn fill(&self, dest: &mut [u8]) -> Result<(), RandomError> {
        let mut state = self
            .0
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(0x9e37_79b9);
        for byte in dest.iter_mut() {
            // A linear congruential step; the values only need to vary.
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *byte = u8::try_from(state >> 24).expect("top byte fits");
        }
        Ok(())
    }
}

/// Every browser is "alice" here: the approver hook is where a venture
/// would consult its session, and the module never looks at the body.
struct TestApprover;

#[async_trait]
impl Approver for TestApprover {
    async fn approve(
        &self,
        _headers: &http::HeaderMap,
        _return_to: &str,
    ) -> Result<Approval, ApproverError> {
        Ok(Approval::Subject("alice".to_owned()))
    }
}

// ---------------------------------------------------------------------------
// The clock

/// A clock the test drives: `now` is read by the module (for expiry and the
/// poll interval) and advanced by the client's own sleeps, so the flow runs
/// to completion without a real second passing.
#[derive(Clone)]
struct TestClock {
    now: Arc<RwLock<OffsetDateTime>>,
}

impl Default for TestClock {
    fn default() -> Self {
        Self {
            now: Arc::new(RwLock::new(OffsetDateTime::UNIX_EPOCH)),
        }
    }
}

#[async_trait]
impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        *self.now.read().expect("clock lock")
    }

    async fn timeout_any(
        &self,
        _fut: BoxFuture<'static, Box<dyn Any + Send>>,
        after: std::time::Duration,
    ) -> Option<Box<dyn Any + Send>> {
        let seconds = i64::try_from(after.as_secs()).unwrap_or(i64::MAX);
        *self.now.write().expect("clock lock") += time::Duration::seconds(seconds);
        None
    }
}

// ---------------------------------------------------------------------------
// HttpClient over the harness router

/// Turns the client's outbound requests into in-process calls on the
/// harness router. It remembers the `user_code` so that, between the first
/// and second poll, it can approve the device through the module's own
/// `/approve` route.
struct HarnessHttp {
    router: axum::Router,
    token_calls: AtomicUsize,
    user_code: RwLock<Option<String>>,
}

impl HarnessHttp {
    fn new(router: axum::Router) -> Self {
        Self {
            router,
            token_calls: AtomicUsize::new(0),
            user_code: RwLock::new(None),
        }
    }

    async fn dispatch(&self, request: Request<Bytes>) -> http::Response<Bytes> {
        let (parts, body) = request.into_parts();
        let request = axum::http::Request::from_parts(parts, axum::body::Body::from(body));
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("the router answers");
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("the body reads");
        let mut builder = http::Response::builder().status(status);
        for (name, value) in &headers {
            builder = builder.header(name, value);
        }
        builder.body(body).expect("the response builds")
    }

    /// Approves the pending code as a signed-in approver. The `user_code`
    /// alphabet is letters and a hyphen, so it needs no escaping; the
    /// same-origin header is what the module's browser guard requires.
    async fn approve(&self) {
        let Some(code) = self.user_code.read().expect("code lock").clone() else {
            return;
        };
        let request = Request::builder()
            .method(Method::POST)
            .uri("/v1/device-auth/approve")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("sec-fetch-site", "none")
            .body(Bytes::from(format!("user_code={code}")))
            .expect("the approval request builds");
        let response = self.dispatch(request).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "the approval route answered {}",
            response.status()
        );
    }
}

#[async_trait]
impl HttpClient for HarnessHttp {
    async fn send(&self, request: Request<Bytes>) -> Result<http::Response<Bytes>, HttpError> {
        if request.uri().path().ends_with("/token") {
            // Approve once the first poll has been answered: the second poll
            // is the one a real person's approval would release.
            if self.token_calls.fetch_add(1, Ordering::SeqCst) == 1 {
                self.approve().await;
            }
        }
        Ok(self.dispatch(request).await)
    }
}

// ---------------------------------------------------------------------------
// The test

fn module() -> DeviceAuth {
    DeviceAuth::builder()
        .client(DeviceClient::new("sealb-cli").scopes(["read", "write"]))
        .issuer(TestIssuer)
        .random(TestRandom::default())
        .approver(TestApprover)
        .build()
}

#[pollster::test]
async fn the_client_drives_a_real_device_grant_end_to_end() {
    let clock = TestClock::default();
    let harness = TestHarness::with_ports(vec![Box::new(module())], {
        let clock = clock.clone();
        move |ports| ports.clock = Some(Arc::new(clock))
    });
    let http = HarnessHttp::new(harness.router.clone());

    // RFC 8628 §3.1: the code request.
    let auth = request_code(
        &http,
        "https://api.test/v1/device-auth/code",
        "sealb-cli",
        Some("read"),
        Some("Test CLI"),
    )
    .await
    .expect("the module issues a code");
    assert_eq!(auth.interval, 5);
    *http.user_code.write().expect("code lock") = Some(auth.user_code.clone());

    // §3.4: poll; the first answer is `authorization_pending`, the adapter
    // approves, and the second poll wins the credential.
    let credential = poll(
        &http,
        &clock,
        "https://api.test/v1/device-auth/token",
        "sealb-cli",
        &auth,
    )
    .await
    .expect("the credential is issued");
    assert_eq!(credential["access_token"], "issued-once");
    assert_eq!(credential["subject"], "alice");
    assert_eq!(credential["client_id"], "sealb-cli");
    assert_eq!(
        http.token_calls.load(Ordering::SeqCst),
        2,
        "one pending poll, then one that wins the credential"
    );

    // At most once: a further poll on the spent code is `expired_token`,
    // not a second credential.
    let again = poll(
        &http,
        &clock,
        "https://api.test/v1/device-auth/token",
        "sealb-cli",
        &auth,
    )
    .await;
    assert!(
        matches!(again, Err(DeviceFlowError::Expired)),
        "a spent code is expired, got {again:?}"
    );
}
