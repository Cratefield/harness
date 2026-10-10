//! The `HttpClient` port (architecture section 5): plain `http` types over
//! bytes, so adapters (Resend, Turnstile) run unchanged on Workers
//! (`worker::Fetch`) and native (`reqwest`, phase 3).
//!
//! # Contract (issue #136)
//!
//! An outbound request is the one place a module or adapter can make the
//! runtime allocate or wait on behalf of an upstream it does not control,
//! so the port itself defines the bounds:
//!
//! 1. **Response size.** An implementation MUST refuse a response whose
//!    body exceeds the effective [`HttpPolicy`] cap, with
//!    [`HttpError::ResponseTooLarge`] — and MUST check the declared
//!    `Content-Length` before consuming the body, so a hostile length does
//!    not cost an allocation. A caller can only ever *lower* the cap
//!    below [`MAX_RESPONSE_BYTES`]. The one exemption is a
//!    [`StatusOnly`] request, which reads no body at all.
//! 2. **Deadline.** Every send is bounded by the effective
//!    [`HttpPolicy::timeout`]; an upstream that has not answered by then
//!    is abandoned (not awaited) with [`HttpError::DeadlineExceeded`], so
//!    a hung service cannot pin a Worker request or a native tenant. The
//!    native runtime enforces this inside `reqwest` (and thereby against
//!    each redirect hop); the Workers runtime cannot time `worker::Fetch`
//!    itself, so it is enforced through the [`Clock`](super::Clock) port by
//!    [`BoundedHttpClient`], which every runtime wires around its
//!    implementation.
//! 3. **Destinations.** An implementation that opens real sockets MUST
//!    refuse destinations a caller-supplied URL must never reach — non
//!    `http(s)` schemes, userinfo, and loopback, private, link-local,
//!    multicast or cloud-metadata addresses (169.254.169.254 and
//!    friends, in IPv6 and decimal/octal/hex encodings alike) — with
//!    [`HttpError::BlockedDestination`], and MUST re-vet **every redirect
//!    hop** rather than trusting the first destination. On Workers this
//!    falls to the platform, whose `fetch` refuses non-public
//!    destinations; the native runtime implements the vetting itself.
//!    An implementation that follows no redirects at all satisfies this
//!    by construction — the Workers port asks for `redirect: "manual"`
//!    and hands the caller the 3xx itself (issue #714).
//! 4. **Concurrency budget.** A runtime with a shared outbound client MUST
//!    cap in-flight requests at [`MAX_CONCURRENT_REQUESTS`] per process
//!    (one native process serves one tenant, so that cap *is* the
//!    per-tenant budget) and refuse past it rather than queue unbounded
//!    work.
//!
//! Bounds are per-operation and travel as a request extension
//! ([`HttpPolicy::of_request`]); the extensions never reach the wire,
//! implementations read them before rebuilding the transport request.
//!
//! # Streaming (issue #859)
//!
//! [`HttpClient::send_streaming`] is the same port with the body
//! unbuffered: the head (status and headers) is known when the call
//! returns and the bytes arrive chunk by chunk afterwards. The head is
//! still bounded by [`HttpPolicy::timeout`] (at most
//! [`MAX_RESPONSE_TIMEOUT`]); the **body** cannot be, because its whole
//! point is to outlive a short exchange — so it is bounded instead by the
//! quiet gap between two chunks ([`StreamPolicy::idle_timeout`]) and by a
//! whole-body ceiling ([`StreamPolicy::total_timeout`]), both carried by
//! [`StreamPolicy`] the same way: a request extension, clamped so a
//! caller may only tighten.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{FutureExt as _, StreamExt};
use thiserror::Error;

use super::Clock;
use crate::ports::timeout;
use crate::stream::BoxStream;

/// Hard ceiling on a response body this port may return: an adapter's
/// largest legitimate upstream reply (JWKS documents, Stripe objects,
/// LinkedIn `people` payloads) is orders of magnitude below it, and it is
/// far below anything that threatens isolate memory. Callers may lower it
/// per operation, never raise it.
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Deadline applied to an outbound call that asks for none. Longer than
/// the strictest in-tree self-bound (Turnstile's 5s verify), shorter than
/// anything that could pin a request.
pub const DEFAULT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

/// Ceiling on a caller-supplied deadline. A 30 s Worker request cannot
/// responsibly spend more than half of it waiting on one upstream.
pub const MAX_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// Per-process budget for concurrent outbound requests. The native
/// runtime shares one connection pool across the tenant it serves; this
/// is what stops one request's fan-out (say a cron fanning out emails)
/// from monopolising the pool and the response-buffer memory behind it.
pub const MAX_CONCURRENT_REQUESTS: usize = 32;

/// How quiet a streamed body may go — the largest gap between two chunks —
/// before [`BoundedHttpClient`] declares the upstream stalled and
/// abandons it. Long enough for a model's between-token pauses, short
/// enough that a hung connection cannot pin a request for the body's
/// whole ceiling.
pub const DEFAULT_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Ceiling on a caller-supplied [`StreamPolicy::idle_timeout`]: a
/// quiet-for-longer body is the caller's problem to justify, and never
/// this port's.
pub const MAX_STREAM_IDLE_TIMEOUT: Duration = Duration::from_mins(5);

/// Default whole-body ceiling for a streamed response. An order of
/// magnitude past [`DEFAULT_RESPONSE_TIMEOUT`], because the body's whole
/// point is to keep arriving; far below anything that could pin a
/// request's other work for a working day.
pub const DEFAULT_STREAM_TOTAL_TIMEOUT: Duration = Duration::from_mins(10);

/// Ceiling on a caller-supplied [`StreamPolicy::total_timeout`]: half an
/// hour of streamed body is the most any single exchange may ask for.
pub const MAX_STREAM_TOTAL_TIMEOUT: Duration = Duration::from_mins(30);

/// Hard ceiling on a streamed response body, the streaming twin of
/// [`MAX_RESPONSE_BYTES`]: a body that will not fit an isolate's memory is
/// refused at the chunk that would cross it, and a caller may only lower
/// the cap, never raise it.
pub const MAX_STREAM_BYTES: usize = 64 * 1024 * 1024;

/// Per-operation bounds on a **streamed** response body, attached to a
/// request as an extension and resolved by every implementation with
/// [`StreamPolicy::of_request`], the way [`HttpPolicy`] is. All fields
/// clamp to the port maxima: a caller may only tighten.
///
/// The two timeouts divide the exchange along its one natural seam. The
/// **head** — status and headers, everything known before the first byte
/// of body — is bounded by [`HttpPolicy::timeout`] (at most 30 s,
/// unchanged), because an upstream that cannot even answer is dead in the
/// buffered world too. The **body** is bounded instead by
/// [`idle_timeout`](Self::idle_timeout), the quiet gap between two chunks
/// (a model's between-token pauses are normal; a stalled connection is
/// not), and by [`total_timeout`](Self::total_timeout), the whole body's
/// ceiling measured from the head's return. A body that streams steadily
/// for twenty minutes is legal here and impossible under the 30 s cap —
/// that is the feature, not a hole. Whichever bound ends the body names
/// itself: the [`HttpError::DeadlineExceeded`] carries the idle gap when
/// a quiet gap expired, and the whole-body ceiling when that is what the
/// exchange ran out of.
///
/// [`max_bytes`](Self::max_bytes) is enforced chunk by chunk (and against
/// the declared `Content-Length` before the first chunk), the way the
/// buffered cap is enforced against the whole body at once.
///
/// # Cloudflare Workers
///
/// On the Workers runtime these bounds are what makes streaming survivable
/// there at all, because the platform's own limits shape what a streamed
/// exchange may cost (the numbers move; the authoritative page is
/// <https://developers.cloudflare.com/workers/platform/limits/>):
///
/// - **There is no wall-clock limit on a request while the client stays
///   connected**, and time spent waiting on I/O does not count as CPU
///   time — so a body that keeps arriving may legitimately run far past
///   any CPU budget, and the port's own idle and total ceilings are the
///   only thing standing between a streaming caller and a connection the
///   runtime would otherwise keep open indefinitely.
/// - **Subrequests per invocation are capped** — a few dozen on the Free
///   plan and a great many more on paid plans when this port was written
///   (50 / 1,000; the paid ceiling has since been raised and made
///   configurable) — and every hop of a redirect chain counts as one. A
///   retry loop over streamed responses spends the budget on the head, as
///   the buffered port always has.
/// - **At most 6 simultaneous open connections per invocation.** A
///   streamed exchange holds one of those six slots for its whole life,
///   which under an idle-timeout-quota of minutes is a long time to hold
///   a sixth of a request's concurrency: the total ceiling exists to keep
///   even a healthy stream from monopolising the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamPolicy {
    /// Largest gap allowed between two body chunks before the body is
    /// declared stalled and abandoned.
    pub idle_timeout: Duration,
    /// Whole-body ceiling, measured from the moment the head returned.
    pub total_timeout: Duration,
    /// Maximum accepted body size, enforced chunk by chunk.
    pub max_bytes: usize,
}

impl Default for StreamPolicy {
    fn default() -> Self {
        Self {
            idle_timeout: DEFAULT_STREAM_IDLE_TIMEOUT,
            total_timeout: DEFAULT_STREAM_TOTAL_TIMEOUT,
            max_bytes: MAX_STREAM_BYTES,
        }
    }
}

impl StreamPolicy {
    /// The effective policy for `request`: the attached [`StreamPolicy`]
    /// extension if any, clamped to the port ceilings.
    #[must_use]
    pub fn of_request<T>(request: &http::Request<T>) -> Self {
        request
            .extensions()
            .get::<StreamPolicy>()
            .copied()
            .unwrap_or_default()
            .clamped()
    }

    /// Clamps to [`MAX_STREAM_IDLE_TIMEOUT`] /
    /// [`MAX_STREAM_TOTAL_TIMEOUT`] / [`MAX_STREAM_BYTES`]: callers may
    /// lower a bound, never raise it.
    #[must_use]
    pub fn clamped(self) -> Self {
        Self {
            idle_timeout: self.idle_timeout.min(MAX_STREAM_IDLE_TIMEOUT),
            total_timeout: self.total_timeout.min(MAX_STREAM_TOTAL_TIMEOUT),
            max_bytes: self.max_bytes.min(MAX_STREAM_BYTES),
        }
    }
}

/// A streamed response body: the chunk shape
/// [`HttpClient::send_streaming`] returns behind a response's head.
/// Dropping it aborts the upstream exchange (see the method's contract).
pub type ByteStream = BoxStream<'static, Result<Bytes, HttpError>>;

/// Per-operation outbound bounds, attached to a request as an extension
/// and resolved by every implementation with [`HttpPolicy::of_request`].
/// Both fields clamp to the port maxima: a caller may only tighten.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpPolicy {
    /// Maximum accepted response body size.
    pub max_response_bytes: usize,
    /// Maximum time to wait for the upstream to answer.
    pub timeout: Duration,
}

impl Default for HttpPolicy {
    fn default() -> Self {
        Self {
            max_response_bytes: MAX_RESPONSE_BYTES,
            timeout: DEFAULT_RESPONSE_TIMEOUT,
        }
    }
}

impl HttpPolicy {
    /// The effective policy for `request`: the attached [`HttpPolicy`]
    /// extension if any, clamped to the port ceilings.
    #[must_use]
    pub fn of_request<T>(request: &http::Request<T>) -> Self {
        request
            .extensions()
            .get::<HttpPolicy>()
            .copied()
            .unwrap_or_default()
            .clamped()
    }

    /// Clamps to [`MAX_RESPONSE_BYTES`] / [`MAX_RESPONSE_TIMEOUT`]:
    /// callers may lower a bound, never raise it.
    #[must_use]
    pub fn clamped(self) -> Self {
        Self {
            max_response_bytes: self.max_response_bytes.min(MAX_RESPONSE_BYTES),
            timeout: self.timeout.min(MAX_RESPONSE_TIMEOUT),
        }
    }
}

/// Marks a request whose caller wants only the status line. An
/// implementation that honours it returns a response with no body and no
/// body-describing headers (`Content-Length`, `Content-Encoding`,
/// `Transfer-Encoding`), because there is no body here to describe.
///
/// Cheaper than `HEAD` when the caller already knows the endpoint and
/// only needs to know whether it answered — a liveness probe of a
/// customer's webhook URL, say, where a multi-megabyte body is a
/// liability and its absence is no information at all. The extensions
/// never reach the wire: implementations read this before rebuilding the
/// transport request, exactly as [`HttpPolicy`] is read.
///
/// Honoured today by the Workers port (`cratefield-runtime-cloudflare`'s
/// `FetchClient`). The native port does not read the extension and
/// answers such a request like any other; the marker asks, it does not
/// oblige.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusOnly;

/// The declared `Content-Length` of a response, when it parses as a
/// non-negative size. Implementations check this before touching the
/// body, so an oversized declared length is refused without allocating
/// for it (issue #136).
#[must_use]
pub fn declared_content_length(headers: &http::HeaderMap) -> Option<usize> {
    headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
}

#[derive(Debug, Clone, Error)]
pub enum HttpError {
    #[error("http request failed: {0}")]
    Transport(String),
    /// The upstream's response body exceeded the [`HttpPolicy`] cap.
    #[error("upstream response exceeds the {limit}-byte bound")]
    ResponseTooLarge {
        /// The effective cap that was exceeded.
        limit: usize,
    },
    /// The upstream did not answer within the [`HttpPolicy`] deadline and
    /// was abandoned.
    #[error("upstream deadline of {after:?} exceeded")]
    DeadlineExceeded {
        /// The effective deadline.
        after: Duration,
    },
    /// The destination (or one of its redirect hops) is refused by the
    /// outbound policy: scheme, userinfo, or a loopback / private /
    /// link-local / metadata address.
    #[error("destination refused by outbound policy: {0}")]
    BlockedDestination(String),
    /// The outbound budget refused the request before it reached the wire:
    /// the per-upstream token bucket could not carry its cost within the
    /// wait this client allows, or the per-provider daily quota is spent.
    /// `retry_after` is when the budget can carry the request again — the
    /// same contract a 429's `Retry-After` carries, for a request that was
    /// never sent (issue #765).
    #[error("outbound budget exhausted for {what}: retry after {retry_after:?}")]
    BudgetExhausted {
        /// What the budget is spent against — the budget router's key, an
        /// upstream name or `rpc:<key id>` shaped string.
        what: String,
        /// How long until the budget can carry the request again.
        retry_after: Duration,
    },
}

#[async_trait]
pub trait HttpClient: Send + Sync {
    /// Sends `request` and returns the fully-buffered response under the
    /// bounds this port carries: the body is at most
    /// [`MAX_RESPONSE_BYTES`] unless an [`HttpPolicy`] tightens it, the
    /// exchange is bounded by that policy's deadline
    /// (enforced through [`BoundedHttpClient`] on runtimes that wrap),
    /// the destination is vetted where real sockets are opened, and a
    /// runtime that keeps a concurrency budget holds one for the send.
    ///
    /// An implementation MAY honour a [`StatusOnly`] request extension by
    /// answering with no body and no body-describing headers; an
    /// implementation that does not read the extension answers it like
    /// any other request. The Workers port honours it today.
    async fn send(&self, request: http::Request<Bytes>)
    -> Result<http::Response<Bytes>, HttpError>;

    /// Sends `request` and returns the response with its **body as a
    /// stream** (issue #859): the status and headers are known when the
    /// future resolves — the head is bounded by [`HttpPolicy::timeout`],
    /// the same deadline `send` answers under — and the bytes arrive chunk
    /// by chunk afterwards, under the [`StreamPolicy`] the request carries.
    ///
    /// The body's bounds — the idle gap, the whole-body ceiling, the
    /// [`StreamPolicy::max_bytes`] cap and the declared-length refusal —
    /// are [`BoundedHttpClient`]'s, which every runtime wires around its
    /// transport; an implementation MAY enforce some of them itself (the
    /// native port applies the byte cap while streaming), and one that
    /// does not streams unbounded. Callers reach a transport only through
    /// the runtime's wrapper, so the bounds hold on every supported path.
    ///
    /// # Cancellation
    ///
    /// Dropping the returned body MUST abort the upstream exchange. This
    /// is what makes cancellation affordable on this port: a route whose
    /// client disconnects mid-completion drops the stream, the transport
    /// drops the request, and the upstream stops billing for a body
    /// nobody is reading. The [`BoundedHttpClient`] wrapper preserves the
    /// property on expiry and over-cap paths by dropping the inner body
    /// it wraps.
    ///
    /// The default implementation buffers: it calls [`Self::send`] and
    /// yields the whole body as one chunk. That is correct — every bound
    /// still holds — but it is not incremental, so a transport that can
    /// stream natively SHOULD override this; a caller cannot tell the
    /// difference except by timing.
    async fn send_streaming(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<ByteStream>, HttpError> {
        let (parts, body) = self.send(request).await?.into_parts();
        let body: ByteStream = Box::pin(futures_util::stream::once(async move { Ok(body) }));
        Ok(http::Response::from_parts(parts, body))
    }
}

/// Wraps any [`HttpClient`] so the port's bounds hold on every runtime:
/// the deadline is enforced through the [`Clock`](super::Clock) port (the
/// only timer core is allowed to use), and the response is refused — by
/// declared length before anything else, then by actual size — when it
/// exceeds the [`HttpPolicy`] cap.
///
/// This is defence in depth, not the only defence: the native adapter
/// also enforces the cap while streaming (before the oversized body is
/// ever buffered) and the Workers adapter checks the declared length and
/// then reads the body as a stream under the same cap, aborting at the
/// chunk that crosses it. Runtimes wire every `ports.http` through
/// this wrapper.
///
/// Streaming (`send_streaming`) is bounded the same way, with the body's
/// own seam: the head under the [`HttpPolicy`] deadline, the body under
/// the [`StreamPolicy`]'s idle gap, whole-body ceiling and byte cap — all
/// measured through the same clock, all dropping the inner body (and with
/// it the upstream exchange) on the way out. Whichever time bound ends
/// the body names itself in the [`HttpError::DeadlineExceeded`] it
/// raises: the idle gap when a quiet gap was what expired, the whole-body
/// ceiling when that did.
pub struct BoundedHttpClient {
    inner: Arc<dyn HttpClient>,
    clock: Arc<dyn Clock>,
}

impl BoundedHttpClient {
    /// Bounds `inner`'s sends by `clock`-measured deadlines and caps.
    #[must_use]
    pub fn new(inner: Arc<dyn HttpClient>, clock: Arc<dyn Clock>) -> Self {
        Self { inner, clock }
    }
}

#[async_trait]
impl HttpClient for BoundedHttpClient {
    async fn send(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        let policy = HttpPolicy::of_request(&request);
        let inner = Arc::clone(&self.inner);
        let Some(outcome) = timeout(
            self.clock.as_ref(),
            async move { inner.send(request).await },
            policy.timeout,
        )
        .await
        else {
            return Err(HttpError::DeadlineExceeded {
                after: policy.timeout,
            });
        };
        let response = outcome?;
        if declared_content_length(response.headers())
            .is_some_and(|len| len > policy.max_response_bytes)
        {
            return Err(HttpError::ResponseTooLarge {
                limit: policy.max_response_bytes,
            });
        }
        if response.body().len() > policy.max_response_bytes {
            return Err(HttpError::ResponseTooLarge {
                limit: policy.max_response_bytes,
            });
        }
        Ok(response)
    }

    async fn send_streaming(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<ByteStream>, HttpError> {
        // The head answers under the buffered port's deadline: an upstream
        // that cannot even produce headers is dead in the streaming world
        // too, and no body exists yet to abandon gracefully.
        let policy = HttpPolicy::of_request(&request);
        let stream_policy = StreamPolicy::of_request(&request);
        let inner = Arc::clone(&self.inner);
        let Some(outcome) = timeout(
            self.clock.as_ref(),
            async move { inner.send_streaming(request).await },
            policy.timeout,
        )
        .await
        else {
            return Err(HttpError::DeadlineExceeded {
                after: policy.timeout,
            });
        };
        let (parts, body) = outcome?.into_parts();
        // A declared length over the cap is refused before the first
        // chunk, exactly as the buffered port refuses one before the body
        // is consumed: a hostile length must not cost an allocation.
        if declared_content_length(&parts.headers).is_some_and(|len| len > stream_policy.max_bytes)
        {
            return Err(HttpError::ResponseTooLarge {
                limit: stream_policy.max_bytes,
            });
        }
        // The body's whole-life ceiling, fixed now and measured against
        // the same clock at every chunk, so the bound holds whatever the
        // transport does or does not time itself.
        let total =
            time::Duration::try_from(stream_policy.total_timeout).unwrap_or(time::Duration::MAX);
        let deadline = self.clock.now().saturating_add(total);
        let body: ByteStream = Box::pin(futures_util::stream::unfold(
            BoundedBody {
                stream: Some(body),
                clock: Arc::clone(&self.clock),
                deadline,
                idle_timeout: stream_policy.idle_timeout,
                total_timeout: stream_policy.total_timeout,
                max_bytes: stream_policy.max_bytes,
                delivered: 0,
                done: false,
            },
            |mut state| async move {
                if state.done {
                    return None;
                }
                // Unreachable while `done` is false, but the compiler
                // cannot know that: no stream left means the body is over.
                let mut stream = state.stream.take()?;
                // The whole-body ceiling first: past the deadline, even a
                // chunk arriving on time is refused. The *end* of the body
                // is not a chunk, though — it owes nobody a wait — so the
                // expiry poll is non-blocking: a body that already ended
                // ends cleanly here (all of it was delivered inside its
                // own time), an item already in hand would carry the body
                // past the ceiling and is refused, and anything still
                // pending has genuinely run out of time.
                let remaining: Duration = (state.deadline - state.clock.now())
                    .try_into()
                    .unwrap_or(Duration::ZERO);
                if remaining.is_zero() {
                    state.done = true;
                    let expired = HttpError::DeadlineExceeded {
                        after: state.total_timeout,
                    };
                    // `stream` drops on every arm, aborting the upstream
                    // exchange.
                    return match stream.next().now_or_never() {
                        Some(None) => None,
                        Some(Some(_)) | None => Some((Err(expired), state)),
                    };
                }
                // Each chunk is bounded by the quieter of the idle gap and
                // what the whole-body ceiling still allows.
                let budget = state.idle_timeout.min(remaining);
                // `timeout` needs a `'static` future, and the stream must
                // survive the poll to be polled again: it travels into the
                // poll and comes back out with its item. A clock that gives
                // up drops the future — and the stream with it, which is
                // the cancellation contract.
                let Some((stream, item)) = timeout(
                    state.clock.as_ref(),
                    async move {
                        let item = stream.next().await;
                        (stream, item)
                    },
                    budget,
                )
                .await
                else {
                    state.done = true;
                    // Name the bound that was in force: the body's own idle
                    // gap when that is what the poll was up against, the
                    // whole-body ceiling when the remaining allowance is
                    // what cut it short.
                    let after = if state.idle_timeout <= remaining {
                        state.idle_timeout
                    } else {
                        state.total_timeout
                    };
                    return Some((Err(HttpError::DeadlineExceeded { after }), state));
                };
                match item {
                    // A clean end: the body dropped itself, `None` ends
                    // the wrapper.
                    None => None,
                    Some(Err(err)) => {
                        state.done = true;
                        Some((Err(err), state))
                    }
                    Some(Ok(chunk)) => {
                        if state.delivered.saturating_add(chunk.len()) > state.max_bytes {
                            // The crossing chunk is refused, not delivered,
                            // and the body drops with the upstream.
                            state.done = true;
                            return Some((
                                Err(HttpError::ResponseTooLarge {
                                    limit: state.max_bytes,
                                }),
                                state,
                            ));
                        }
                        state.delivered += chunk.len();
                        state.stream = Some(stream);
                        Some((Ok(chunk), state))
                    }
                }
            },
        ));
        Ok(http::Response::from_parts(parts, body))
    }
}

/// The `unfold` state behind [`BoundedHttpClient::send_streaming`]'s body:
/// the inner chunk stream plus the clock, deadline and counters the three
/// body bounds are enforced with. `done` fuses the wrapper after its one
/// terminal error; `stream` is `None` exactly while a chunk poll is in
/// flight, which is also how the inner body gets dropped on expiry.
struct BoundedBody {
    stream: Option<ByteStream>,
    clock: Arc<dyn Clock>,
    deadline: time::OffsetDateTime,
    idle_timeout: Duration,
    total_timeout: Duration,
    max_bytes: usize,
    delivered: usize,
    done: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Response;

    /// Policy resolution is the port's whole vocabulary; pin the clamps.
    #[test]
    fn a_policy_clamps_to_the_port_ceilings() {
        let loose = HttpPolicy {
            max_response_bytes: usize::MAX,
            timeout: Duration::from_secs(3600),
        };
        let clamped = loose.clamped();
        assert_eq!(clamped.max_response_bytes, MAX_RESPONSE_BYTES);
        assert_eq!(clamped.timeout, MAX_RESPONSE_TIMEOUT);

        let tight = HttpPolicy {
            max_response_bytes: 1024,
            timeout: Duration::from_millis(50),
        };
        assert_eq!(tight.clamped(), tight, "tightening is honoured");

        let defaulted = HttpPolicy::of_request(&http::Request::new(Bytes::new()));
        assert_eq!(defaulted, HttpPolicy::default());
        let mut request = http::Request::new(Bytes::new());
        request.extensions_mut().insert(HttpPolicy {
            max_response_bytes: usize::MAX,
            timeout: Duration::from_secs(3600),
        });
        let resolved = HttpPolicy::of_request(&request);
        assert_eq!(resolved.max_response_bytes, MAX_RESPONSE_BYTES);
        assert_eq!(resolved.timeout, MAX_RESPONSE_TIMEOUT);
    }

    /// The inner client is never asked to police itself: a body over the
    /// cap, by declared length or by actual size, is refused here.
    struct ScriptedClient {
        response: Result<Response<Bytes>, HttpError>,
    }

    #[async_trait]
    impl HttpClient for ScriptedClient {
        async fn send(&self, _request: http::Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
            self.response.clone()
        }
    }

    struct NoTimerClock;

    #[async_trait]
    impl Clock for NoTimerClock {
        fn now(&self) -> time::OffsetDateTime {
            time::OffsetDateTime::UNIX_EPOCH
        }
        // default timeout_any: runs to completion — the wrapper's own
        // checks must then catch the violation.
    }

    struct AlwaysTimeoutClock;

    #[async_trait]
    impl Clock for AlwaysTimeoutClock {
        fn now(&self) -> time::OffsetDateTime {
            time::OffsetDateTime::UNIX_EPOCH
        }
        async fn timeout_any(
            &self,
            fut: futures_core::future::BoxFuture<'static, Box<dyn std::any::Any + Send>>,
            _after: Duration,
        ) -> Option<Box<dyn std::any::Any + Send>> {
            drop(fut);
            None
        }
    }

    fn bounded(inner: ScriptedClient, clock: Arc<dyn Clock>) -> BoundedHttpClient {
        BoundedHttpClient::new(Arc::new(inner), clock)
    }

    #[pollster::test]
    async fn an_oversized_response_body_is_refused() {
        let inner = ScriptedClient {
            response: Ok(Response::new(Bytes::from(vec![0_u8; 4_096]))),
        };
        let mut request = http::Request::new(Bytes::new());
        request.extensions_mut().insert(HttpPolicy {
            max_response_bytes: 1_024,
            timeout: Duration::from_secs(5),
        });
        let err = bounded(inner, Arc::new(NoTimerClock))
            .send(request)
            .await
            .expect_err("4 KiB over a 1 KiB cap must be refused");
        assert!(
            matches!(err, HttpError::ResponseTooLarge { limit: 1_024 }),
            "got {err}"
        );
    }

    #[pollster::test]
    async fn an_oversized_declared_length_is_refused_before_the_body_counts() {
        // Actual body is small, but the declared length lies about a huge
        // response; the wrapper refuses on the header alone.
        let inner = ScriptedClient {
            response: Ok(Response::builder()
                .header(http::header::CONTENT_LENGTH, "9000")
                .body(Bytes::from_static(b"hi"))
                .expect("test response")),
        };
        let mut request = http::Request::new(Bytes::new());
        request.extensions_mut().insert(HttpPolicy {
            max_response_bytes: 1_024,
            timeout: Duration::from_secs(5),
        });
        let err = bounded(inner, Arc::new(NoTimerClock))
            .send(request)
            .await
            .expect_err("a declared 9 KB over a 1 KiB cap must be refused");
        assert!(
            matches!(err, HttpError::ResponseTooLarge { .. }),
            "got {err}"
        );
    }

    #[pollster::test]
    async fn an_abandoned_send_is_a_deadline_not_a_hang() {
        // The clock gives up on the future (its contract: abandon, do not
        // await); the wrapper maps that to DeadlineExceeded with the
        // effective duration, even though the inner would have answered.
        let inner = ScriptedClient {
            response: Ok(Response::new(Bytes::from_static(b"late"))),
        };
        let err = bounded(inner, Arc::new(AlwaysTimeoutClock))
            .send(http::Request::new(Bytes::new()))
            .await
            .expect_err("an abandoned send must surface as the deadline");
        assert!(
            matches!(&err, HttpError::DeadlineExceeded { after } if *after == DEFAULT_RESPONSE_TIMEOUT),
            "got {err}"
        );
    }

    // -----------------------------------------------------------------
    // StreamPolicy (issue #859)

    /// A stream policy clamps exactly like the buffered one: tighten all
    /// you like, raise nothing past the port ceilings.
    // A day spelled in seconds is the point: it is the value being clamped.
    #[allow(clippy::duration_suboptimal_units)]
    #[test]
    fn a_stream_policy_clamps_to_the_port_ceilings() {
        let loose = StreamPolicy {
            idle_timeout: Duration::from_secs(3600),
            total_timeout: Duration::from_secs(86_400),
            max_bytes: usize::MAX,
        };
        let clamped = loose.clamped();
        assert_eq!(clamped.idle_timeout, MAX_STREAM_IDLE_TIMEOUT);
        assert_eq!(clamped.total_timeout, MAX_STREAM_TOTAL_TIMEOUT);
        assert_eq!(clamped.max_bytes, MAX_STREAM_BYTES);

        let tight = StreamPolicy {
            idle_timeout: Duration::from_secs(5),
            total_timeout: Duration::from_secs(30),
            max_bytes: 1_024,
        };
        assert_eq!(tight.clamped(), tight, "tightening is honoured");

        let defaulted = StreamPolicy::of_request(&http::Request::new(Bytes::new()));
        assert_eq!(defaulted, StreamPolicy::default());
        let mut request = http::Request::new(Bytes::new());
        request.extensions_mut().insert(StreamPolicy {
            idle_timeout: Duration::from_secs(3600),
            total_timeout: Duration::from_secs(86_400),
            max_bytes: usize::MAX,
        });
        let resolved = StreamPolicy::of_request(&request);
        assert_eq!(resolved.idle_timeout, MAX_STREAM_IDLE_TIMEOUT);
        assert_eq!(resolved.total_timeout, MAX_STREAM_TOTAL_TIMEOUT);
        assert_eq!(resolved.max_bytes, MAX_STREAM_BYTES);
    }

    // -----------------------------------------------------------------
    // Streaming bodies

    /// A client that streams natively: every `send_streaming` hands back a
    /// body delivering `chunks` one by one, counting how many any caller
    /// actually pulled (a refused head or a dropped body leaves it at
    /// zero — the assertion that a body was never consumed).
    struct StreamingClient {
        chunks: Vec<Vec<u8>>,
        content_length: Option<&'static str>,
        consumed: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl StreamingClient {
        fn new(chunks: Vec<Vec<u8>>) -> Arc<Self> {
            Arc::new(Self {
                chunks,
                content_length: None,
                consumed: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            })
        }

        /// A variant whose head declares a (possibly lying) length.
        fn with_content_length(chunks: Vec<Vec<u8>>, length: &'static str) -> Arc<Self> {
            Arc::new(Self {
                chunks,
                content_length: Some(length),
                consumed: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            })
        }

        fn consumed(&self) -> usize {
            self.consumed.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl HttpClient for StreamingClient {
        async fn send(&self, _request: http::Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
            Ok(Response::new(Bytes::from(self.chunks.concat())))
        }

        async fn send_streaming(
            &self,
            _request: http::Request<Bytes>,
        ) -> Result<Response<ByteStream>, HttpError> {
            let mut builder = Response::builder();
            if let Some(length) = self.content_length {
                builder = builder.header(http::header::CONTENT_LENGTH, length);
            }
            let response = builder.body(()).expect("test response head");
            let consumed = Arc::clone(&self.consumed);
            // Copied up front: the stream is `'static`, the fixture is not.
            let chunks = self.chunks.clone();
            let body: ByteStream = Box::pin(
                futures_util::stream::iter(chunks.into_iter().map(|chunk| Ok(Bytes::from(chunk))))
                    .inspect(move |_| {
                        consumed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }),
            );
            Ok(response.map(move |()| body))
        }
    }

    /// A clock whose `timeout_any` runs the first future to completion and
    /// abandons every later one — the head gets through, the body's first
    /// poll does not. Deterministic stand-in for a stalled upstream.
    struct HeadThenAbandon(std::sync::atomic::AtomicUsize);

    #[async_trait]
    impl Clock for HeadThenAbandon {
        fn now(&self) -> time::OffsetDateTime {
            time::OffsetDateTime::UNIX_EPOCH
        }
        async fn timeout_any(
            &self,
            fut: futures_core::future::BoxFuture<'static, Box<dyn std::any::Any + Send>>,
            _after: Duration,
        ) -> Option<Box<dyn std::any::Any + Send>> {
            if self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 0 {
                Some(fut.await)
            } else {
                drop(fut);
                None
            }
        }
    }

    /// A clock whose wall reading advances `step_secs` every time it is
    /// read — the only way time passes. `timeout_any` keeps the default
    /// run-to-completion behaviour, so what bounds a stream is exactly the
    /// wrapper's own deadline arithmetic.
    struct AdvancingClock {
        step_secs: i64,
        ticks: std::sync::atomic::AtomicUsize,
    }

    impl AdvancingClock {
        fn new(step_secs: i64) -> Arc<Self> {
            Arc::new(Self {
                step_secs,
                ticks: std::sync::atomic::AtomicUsize::new(0),
            })
        }
    }

    impl Clock for AdvancingClock {
        fn now(&self) -> time::OffsetDateTime {
            let tick = i64::try_from(
                self.ticks
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            )
            .unwrap_or(i64::MAX);
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(tick * self.step_secs)
        }
    }

    fn streaming_request(policy: Option<StreamPolicy>) -> http::Request<Bytes> {
        let mut request = http::Request::new(Bytes::new());
        if let Some(policy) = policy {
            request.extensions_mut().insert(policy);
        }
        request
    }

    /// Pulls a body to its end, collecting what it yielded.
    async fn drain(mut body: crate::ports::http::ByteStream) -> Vec<Result<Bytes, HttpError>> {
        let mut items = Vec::new();
        while let Some(item) = body.next().await {
            items.push(item);
        }
        items
    }

    #[pollster::test]
    async fn the_default_send_streaming_buffers_into_one_chunk() {
        // A client that never opted into streaming answers through the
        // default: one `send`, one chunk, bounds intact.
        let inner = ScriptedClient {
            response: Ok(Response::new(Bytes::from_static(b"buffered whole"))),
        };
        let client = BoundedHttpClient::new(Arc::new(inner), Arc::new(NoTimerClock));
        let response = client
            .send_streaming(http::Request::new(Bytes::new()))
            .await
            .expect("buffered fallback streams");
        let mut items = drain(response.into_body()).await;
        assert_eq!(items.len(), 1, "one round trip, one chunk: {items:?}");
        assert_eq!(items.remove(0).unwrap(), &b"buffered whole"[..]);
    }

    #[pollster::test]
    async fn a_streaming_head_abandoned_by_the_clock_is_a_deadline() {
        // The head is bounded by the buffered port's deadline, whatever
        // the body would have done.
        let inner = StreamingClient::new(vec![b"a".to_vec(), b"b".to_vec()]);
        let err = match BoundedHttpClient::new(inner.clone(), Arc::new(AlwaysTimeoutClock))
            .send_streaming(http::Request::new(Bytes::new()))
            .await
        {
            // No `Debug` on a streaming response, so `expect_err` cannot
            // name this arm — a `match` refuses it just as loudly.
            Ok(response) => {
                drop(response);
                panic!("an abandoned head must surface as the deadline");
            }
            Err(err) => err,
        };
        assert!(
            matches!(err, HttpError::DeadlineExceeded { after } if after == DEFAULT_RESPONSE_TIMEOUT),
            "got {err}"
        );
        assert_eq!(inner.consumed(), 0, "no body was ever handed out");
    }

    #[pollster::test]
    async fn a_declared_length_over_the_stream_cap_is_refused_before_a_chunk() {
        let inner = StreamingClient::with_content_length(vec![b"tiny".to_vec()], "9000");
        let mut request = streaming_request(None);
        request.extensions_mut().insert(StreamPolicy {
            idle_timeout: Duration::from_secs(5),
            total_timeout: Duration::from_secs(60),
            max_bytes: 1_024,
        });
        let err = match BoundedHttpClient::new(inner.clone(), Arc::new(NoTimerClock))
            .send_streaming(request)
            .await
        {
            Ok(response) => {
                drop(response);
                panic!("a declared 9 KB over a 1 KiB stream cap must be refused");
            }
            Err(err) => err,
        };
        assert!(
            matches!(err, HttpError::ResponseTooLarge { limit: 1_024 }),
            "got {err}"
        );
        assert_eq!(inner.consumed(), 0, "the body was never touched");
    }

    #[pollster::test]
    async fn an_idle_gap_that_goes_quiet_abandons_the_body() {
        // The head gets through; the body's first poll outlives the idle
        // gap (the clock abandons it). One Err names the bound, then the
        // stream ends — and the inner body was dropped un-read, which is
        // the cancellation contract.
        let inner = StreamingClient::new(vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
        let client = BoundedHttpClient::new(
            inner.clone(),
            Arc::new(HeadThenAbandon(std::sync::atomic::AtomicUsize::new(0))),
        );
        let response = client
            .send_streaming(http::Request::new(Bytes::new()))
            .await
            .expect("the head answers within the buffered deadline");
        let items = drain(response.into_body()).await;
        assert_eq!(
            items.len(),
            1,
            "one terminal error, then the end: {items:?}"
        );
        assert!(
            matches!(items[0], Err(HttpError::DeadlineExceeded { after }) if after == DEFAULT_STREAM_IDLE_TIMEOUT),
            "the idle bound is what expired: {:?}",
            items[0]
        );
        assert_eq!(inner.consumed(), 0, "the abandoned poll dropped the body");
    }

    #[pollster::test]
    async fn a_total_ceiling_ends_a_steady_stream() {
        // Thirty simulated seconds pass per body poll; the default
        // ten-minute ceiling stops the stream after its nineteenth chunk,
        // with the ceiling itself named as what expired.
        let chunks: Vec<Vec<u8>> = (0..40).map(|i| i.to_string().into_bytes()).collect();
        let inner = StreamingClient::new(chunks);
        let client = BoundedHttpClient::new(inner, AdvancingClock::new(30));
        let response = client
            .send_streaming(http::Request::new(Bytes::new()))
            .await
            .expect("the head answers");
        let items = drain(response.into_body()).await;
        assert_eq!(items.len(), 20, "19 chunks and one terminal error");
        for (index, item) in items.iter().enumerate().take(19) {
            let chunk = item.as_ref().expect("every steady chunk arrives");
            assert_eq!(&**chunk, index.to_string().as_bytes(), "chunk {index}");
        }
        assert!(
            matches!(items[19], Err(HttpError::DeadlineExceeded { after }) if after == DEFAULT_STREAM_TOTAL_TIMEOUT),
            "the whole-body ceiling is what expired: {:?}",
            items[19]
        );
    }

    #[pollster::test]
    async fn a_body_that_ended_inside_its_own_time_ends_cleanly_at_the_ceiling() {
        // One chunk, then the end. Thirty simulated seconds pass per clock
        // read, the ceiling is sixty: the chunk is delivered with thirty
        // seconds left, and the *next* poll finds the ceiling expired — but
        // the body is over. The expiry poll is non-blocking, so the ready
        // `None` is a clean end: everything was delivered inside the body's
        // own time, and no DeadlineExceeded is invented after the fact.
        let inner = StreamingClient::new(vec![b"only".to_vec()]);
        let mut request = streaming_request(None);
        request.extensions_mut().insert(StreamPolicy {
            idle_timeout: Duration::from_secs(60),
            total_timeout: Duration::from_secs(60),
            max_bytes: MAX_STREAM_BYTES,
        });
        let client = BoundedHttpClient::new(inner, AdvancingClock::new(30));
        let response = client
            .send_streaming(request)
            .await
            .expect("the head answers");
        let items = drain(response.into_body()).await;
        assert_eq!(
            items.len(),
            1,
            "the chunk, then a clean end — no error after the data: {items:?}"
        );
        assert_eq!(&items[0].as_ref().expect("the chunk")[..], b"only");
    }

    #[pollster::test]
    async fn a_chunk_already_in_hand_when_the_ceiling_expires_is_refused_not_delivered() {
        // Two chunks thirty simulated seconds apart under a sixty-second
        // ceiling. The first is delivered with thirty seconds left; by the
        // next poll the ceiling has run out, and the second chunk — already
        // in hand — would carry the body past it: refused, with the ceiling
        // named as what expired.
        let inner = StreamingClient::new(vec![b"first".to_vec(), b"second".to_vec()]);
        let mut request = streaming_request(None);
        request.extensions_mut().insert(StreamPolicy {
            idle_timeout: Duration::from_secs(60),
            total_timeout: Duration::from_secs(60),
            max_bytes: MAX_STREAM_BYTES,
        });
        let client = BoundedHttpClient::new(inner, AdvancingClock::new(30));
        let response = client
            .send_streaming(request)
            .await
            .expect("the head answers");
        let items = drain(response.into_body()).await;
        assert_eq!(
            items.len(),
            2,
            "the delivered chunk, the refusal: {items:?}"
        );
        assert_eq!(&items[0].as_ref().expect("the first chunk")[..], b"first");
        assert!(
            matches!(items[1], Err(HttpError::DeadlineExceeded { after }) if after == Duration::from_secs(60)),
            "the whole-body ceiling is what expired: {:?}",
            items[1]
        );
    }

    #[pollster::test]
    async fn the_error_names_the_whole_body_ceiling_when_that_is_what_expired() {
        // The idle gap is five minutes, the ceiling sixty seconds: a poll
        // the clock abandons was up against what the ceiling still allowed
        // (sixty < three hundred), so the error carries the ceiling — the
        // idle test above pins the mirror case, where the idle gap is the
        // smaller and is the one named.
        let inner = StreamingClient::new(vec![b"a".to_vec(), b"b".to_vec()]);
        let mut request = streaming_request(None);
        request.extensions_mut().insert(StreamPolicy {
            idle_timeout: MAX_STREAM_IDLE_TIMEOUT,
            total_timeout: Duration::from_secs(60),
            max_bytes: MAX_STREAM_BYTES,
        });
        let client = BoundedHttpClient::new(
            inner,
            Arc::new(HeadThenAbandon(std::sync::atomic::AtomicUsize::new(0))),
        );
        let response = client
            .send_streaming(request)
            .await
            .expect("the head answers");
        let items = drain(response.into_body()).await;
        assert_eq!(
            items.len(),
            1,
            "one terminal error, then the end: {items:?}"
        );
        assert!(
            matches!(items[0], Err(HttpError::DeadlineExceeded { after }) if after == Duration::from_secs(60)),
            "the ceiling is what expired, not the idle gap: {:?}",
            items[0]
        );
    }

    #[pollster::test]
    async fn a_steady_stream_outlives_the_buffered_deadline() {
        // Thirty-one simulated seconds per poll — each gap longer than the
        // whole-response cap a buffered send answers under — for forty
        // chunks: twenty minutes of body, delivered whole, because the
        // body is governed by the stream bounds, not `HttpPolicy`.
        let chunks: Vec<Vec<u8>> = (0..40).map(|i| i.to_string().into_bytes()).collect();
        let inner = StreamingClient::new(chunks);
        let mut request = streaming_request(None);
        request.extensions_mut().insert(StreamPolicy {
            idle_timeout: Duration::from_secs(60),
            total_timeout: MAX_STREAM_TOTAL_TIMEOUT,
            max_bytes: MAX_STREAM_BYTES,
        });
        let client = BoundedHttpClient::new(inner, AdvancingClock::new(31));
        let response = client
            .send_streaming(request)
            .await
            .expect("the head answers");
        let items = drain(response.into_body()).await;
        assert_eq!(
            items.len(),
            40,
            "forty chunks under a half-hour ceiling, then a clean end"
        );
        assert!(items.iter().all(Result::is_ok), "no bound fired: {items:?}");
        // The digits of 0..=39: ten one-digit numbers, thirty two-digit.
        assert_eq!(
            items
                .iter()
                .map(|item| item.as_ref().unwrap().len())
                .sum::<usize>(),
            10 + 60,
        );
    }

    #[pollster::test]
    async fn a_chunk_over_the_stream_byte_cap_is_refused_not_delivered() {
        let inner = StreamingClient::new(vec![
            b"12345".to_vec(),
            b"67890".to_vec(),
            b"unreached".to_vec(),
        ]);
        let mut request = streaming_request(None);
        request.extensions_mut().insert(StreamPolicy {
            idle_timeout: Duration::from_secs(5),
            total_timeout: Duration::from_secs(60),
            max_bytes: 8,
        });
        let client = BoundedHttpClient::new(inner, Arc::new(NoTimerClock));
        let response = client
            .send_streaming(request)
            .await
            .expect("the head answers");
        let items = drain(response.into_body()).await;
        assert_eq!(items.len(), 2, "the fit chunk, the refusal, then the end");
        assert_eq!(&items[0].as_ref().unwrap()[..], &b"12345"[..]);
        assert!(
            matches!(items[1], Err(HttpError::ResponseTooLarge { limit: 8 })),
            "the crossing chunk is refused: {:?}",
            items[1]
        );
    }
}
