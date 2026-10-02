//! Shared test doubles for this crate's integration tests. A module rather
//! than a test target, so each test binary compiles it in.
// each test binary uses a different subset of these doubles
#![allow(dead_code)]
// Test-side recording fixture, not request state — the same category and
// allowance as the fakes in `cratefield-testing` (ADR 0007 policy).
#![allow(clippy::disallowed_types)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{Clock, HttpClient, HttpError};
use http::{HeaderMap, Request, Response};

/// A throwaway 2048-bit RSA key, generated for these tests only — NOT a real
/// GitHub App key. PKCS#1, the form GitHub's "Generate a private key" hands
/// out. Inline, the way `crates/adapter-apns/tests/apns.rs` and
/// `crates/adapter-fcm/tests/fcm.rs` carry theirs, so no `.pem` file is
/// committed.
pub(crate) const TEST_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEAqqDOOZFFToEy1LHZidDEoYITIgo51jBeY6fhI0TXaCHQobH9\noYQCU0KicbV3YUMBkd536Iu3DWnDrDUT2zjU3RZk+3P3MIar/fSaSMLl58vtHZ3x\nDzalIx8Sisd9xqCaZsT9BxO0j6NLszXcIZsT1YQ/w0giKrr5f/0KUw7XuB36JzrS\npXnjf9SpV5P7D/ZTv5zM5vthG/j6qPQmAbchNuqSNrfuECY2WyWLyCjcBi0vdRdu\n9CnyqjbsqF6t6+sCDeABk+/CPRtKx2hS+ckQ9DZoDIHcbb9+26yLOz8uSf/u2nOh\nQreB1w28irnwKSs3Yg3z7yT+vGWaUY15wGjDGQIDAQABAoIBABvayAfEVCLiexSX\nWxrBOtRd6ncwYaw6dbJBngKWsq6UdJ1s8+mJ5iJG+sNi2zQEzw0L2xnasx2ssi2a\n9ZygXLmh9gbJseUZWxsIcyZlMMiENTeUSN3Rryg6YpnGwtzp64LS7jaZTCz1vL4r\nEP5odVayMgGUdUVyBBiVi7mu7t7mu5dnUFRJzGyH9zc/vC3PGXEUcesqSk9ekSBL\nRKr2r6f97a5RMGP6ILsGjPsmViGP0svQ6jv4JNZ0OGcyV4jxJoU8Gj2n+oQ9D7sW\nTTzQG42UNlWCxXatO4PJMrWq8o9iY+qGnGf3BG887s3m7GEBJaarpoigRfh9Ibjj\n5IdBl+0CgYEA2vpQB017xLRUDL2xPahJU2XwyDJeZ2keu9r7Ffw3E2KJybWgsXRM\n6dqSklzPD3etUpQlVt/vGws/nbS7BTW8bSxumA27EnHAqUwdzDh2bNnRQltwUaOI\ns9bFzg5Gmw9eNYp5fUH6+j2FPv+UvmcvKVZVMeayhidLBKGmlb/q/tUCgYEAx3nZ\nGZX/xCjdwGwWsHiIS7aa6nW2nu+RHYq+X8AHVxlUpD9W8750TLU7pI9NEAe2xmm1\nDvWQIeKfBHQrN72Z59kMHQzQTGqCavhR/XoxyPpLmBw0KR93BGwLQly+2vIC6Acl\nQSzhJ2iv8NOl0yFOqBxbP5CVlUWYM6pZDZ8EfTUCgYARUWCI41DZgqVvCIV+6dM6\nvEIpowoiRYb/tlbLK1Izv0REZo/Z2OfIStfyqVJa180mTb8SOs2PJvmWAFgWFmTb\ngXsRnWxhDgv9l553qzN6clOBWvfsDPHfvymPnUNqOfHqbBQlmtU9eyYRkGb0E/b/\n3usH8kXGJE9jg2FIUJBGLQKBgAs44Kze0nfPsMINkq006r4PtOFx4+dHJQvbbWBn\npkIRK8Ddy1+FHHfgTk2wvi4jsPWyprwDtqshW77dZj0JjqoLfPH5cZKK/3FTLRGs\nmTZsVmplU83odkKqbWu7WgVpTh6NoFvtUXFtI1DSJ2ccXZd5mOyXjsLKGoj1kXMB\nujftAoGAFUvwzRR8eek6qDBlYI8QLvEUlBdMgD81g/9zeIf0GxvKtEXb04gPhwQN\nr+amghCXkkjudGAn0QL2vDdqv3z/EmZvsz5NzJcbYxEOwCE6AYlp3OkECOozAKFY\n6M303yDVPvZaZ9HhTiBelpDtfXCb/VGz15UgS/Xe9s5+skK0dmg=\n-----END RSA PRIVATE KEY-----\n";

/// The expiry the token fixtures carry, and the anchor the clock is set from,
/// so the two can never drift.
pub(crate) const EXPIRES_AT: &str = "2030-01-01T00:00:00Z";

/// An installation-token response body carrying `token`, in the shape GitHub
/// answers with (the same shape as `fixtures/installation-token.json`).
pub(crate) fn token_body(token: &str) -> String {
    format!(
        r#"{{"token":"{token}","expires_at":"{EXPIRES_AT}","permissions":{{"contents":"read"}},"repository_selection":"all"}}"#
    )
}

/// A clock whose time the test advances by hand.
pub(crate) struct StepClock(AtomicI64);

impl StepClock {
    pub(crate) fn at(secs: i64) -> Self {
        Self(AtomicI64::new(secs))
    }

    pub(crate) fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::Relaxed);
    }
}

#[async_trait]
impl Clock for StepClock {
    fn now(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::Relaxed)).expect("in range")
    }
}

/// A recording `HttpClient` that answers from a script. `yielding` makes each
/// `send` give the executor one turn before answering, so two concurrent
/// callers are genuinely both in flight.
pub(crate) struct RecordingHttp {
    inner: Mutex<Inner>,
}

struct Inner {
    responses: VecDeque<Result<Response<Bytes>, HttpError>>,
    requests: Vec<Request<Bytes>>,
    yielding: bool,
}

impl RecordingHttp {
    pub(crate) fn scripted(responses: Vec<Response<Bytes>>) -> Arc<Self> {
        Self::build(responses, false)
    }

    /// Like [`RecordingHttp::scripted`], but each `send` yields once before it
    /// answers — for the concurrency test.
    pub(crate) fn scripted_yielding(responses: Vec<Response<Bytes>>) -> Arc<Self> {
        Self::build(responses, true)
    }

    fn build(responses: Vec<Response<Bytes>>, yielding: bool) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                responses: responses.into_iter().map(Ok).collect(),
                requests: Vec::new(),
                yielding,
            }),
        })
    }

    /// Every request captured, in order.
    pub(crate) fn requests(&self) -> Vec<Request<Bytes>> {
        self.inner.lock().expect("http lock").requests.clone()
    }

    pub(crate) fn count(&self) -> usize {
        self.inner.lock().expect("http lock").requests.len()
    }

    /// The `Authorization` header of the `n`th request, if any.
    pub(crate) fn authorization(&self, n: usize) -> Option<String> {
        self.requests()
            .get(n)
            .and_then(|request| request.headers().get("authorization"))
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    }
}

#[async_trait]
impl HttpClient for RecordingHttp {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let (next, yielding) = {
            let mut inner = self.inner.lock().expect("http lock");
            inner.requests.push(request);
            (inner.responses.pop_front(), inner.yielding)
        };
        if yielding {
            yield_once().await;
        }
        next.unwrap_or_else(|| Err(HttpError::Transport("script exhausted".to_owned())))
    }
}

/// Gives the executor exactly one turn: `Pending` once (after waking), then
/// `Ready`.
async fn yield_once() {
    struct YieldOnce(bool);
    impl std::future::Future for YieldOnce {
        type Output = ();
        fn poll(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            if self.0 {
                std::task::Poll::Ready(())
            } else {
                self.0 = true;
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
        }
    }
    YieldOnce(false).await;
}

/// A response with `status`, `body`, and the given headers — so a test can set
/// `Link`, `ETag` or the rate-limit headers.
pub(crate) fn response(status: u16, body: &str, headers: &[(&str, &str)]) -> Response<Bytes> {
    let mut builder = Response::builder().status(status);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder
        .body(Bytes::from(body.to_owned()))
        .expect("response")
}

/// A `200` JSON response carrying `body`.
pub(crate) fn ok_json(body: impl Into<String>) -> Response<Bytes> {
    let body = body.into();
    response(200, &body, &[])
}

/// The headers of a captured request.
pub(crate) fn headers_of(request: &Request<Bytes>) -> HeaderMap {
    request.headers().clone()
}
