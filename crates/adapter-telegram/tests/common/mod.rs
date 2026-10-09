//! The small fakes the tests script: a [`FakeHttp`] over the
//! [`HttpClient`](cratefield_core::HttpClient) port (responses queued in
//! order, requests captured) and a [`ManualClock`] a test moves by hand.
//!
//! Compiled per test binary, so some helpers are unused in some of them.
//! Own fakes, not `cratefield-testing`'s: those live behind the kit's
//! `harness` feature — axum, tower, the SQLite adapter — which this crate's
//! tests need none of. adapter-linear's tests carry the same two fakes for
//! the same reason.

#![allow(dead_code)]
#![allow(clippy::disallowed_types)]
// Recording fakes and a moved-by-hand clock, not request state — the same
// category and allowance as the fakes in `cratefield-testing` (ADR 0007
// policy).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{Clock, HttpClient, HttpError};
use http::{Request, Response, StatusCode};
use time::OffsetDateTime;

#[derive(Clone)]
pub(crate) struct FakeHttp {
    inner: Arc<FakeHttpInner>,
}

struct FakeHttpInner {
    responses: Mutex<VecDeque<Result<Response<Bytes>, HttpError>>>,
    captured: Mutex<Vec<(String, String, String)>>, // method, uri, body
}

impl FakeHttp {
    /// Responds with `responses` in order, then always with a transport
    /// failure — a test that sees the failure scripted an overrun.
    #[must_use]
    pub(crate) fn scripted(responses: Vec<Result<Response<Bytes>, HttpError>>) -> Self {
        Self {
            inner: Arc::new(FakeHttpInner {
                responses: Mutex::new(responses.into_iter().collect()),
                captured: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Every captured request as `(method, uri, body)`.
    #[must_use]
    pub(crate) fn captured(&self) -> Vec<(String, String, String)> {
        self.inner.captured.lock().expect("fake http lock").clone()
    }
}

#[async_trait]
impl HttpClient for FakeHttp {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let (parts, body) = request.into_parts();
        self.inner.captured.lock().expect("fake http lock").push((
            parts.method.to_string(),
            parts.uri.to_string(),
            String::from_utf8_lossy(&body).to_string(),
        ));
        let next = self
            .inner
            .responses
            .lock()
            .expect("fake http lock")
            .pop_front();
        next.unwrap_or_else(|| Err(HttpError::Transport("fake http exhausted".to_owned())))
    }
}

/// A 200 with `body`.
pub(crate) fn ok(body: &str) -> Result<Response<Bytes>, HttpError> {
    status(StatusCode::OK, body)
}

/// A response with `status` and `body`.
pub(crate) fn status(status: StatusCode, body: &str) -> Result<Response<Bytes>, HttpError> {
    Response::builder()
        .status(status)
        .body(Bytes::from(body.to_owned()))
        .map_err(|error| HttpError::Transport(error.to_string()))
}

/// A [`Clock`] a test moves by hand. Every clone shares the one instant, so
/// the code under test and the test that advances it never diverge.
#[derive(Debug, Clone)]
pub(crate) struct ManualClock {
    at: Arc<Mutex<OffsetDateTime>>,
}

impl ManualClock {
    /// A clock stopped at `at`.
    #[must_use]
    pub(crate) fn new(at: OffsetDateTime) -> Self {
        Self {
            at: Arc::new(Mutex::new(at)),
        }
    }

    /// Moves the clock forward by `by`.
    pub(crate) fn advance(&self, by: Duration) {
        let span = time::Duration::try_from(by).expect("a representable span");
        *self.at.lock().expect("clock lock") += span;
    }
}

#[async_trait]
impl Clock for ManualClock {
    fn now(&self) -> OffsetDateTime {
        *self.at.lock().expect("clock lock")
    }
}
