//! `HttpClient` over `worker::Fetch`.
//!
//! # What a caller gets
//!
//! The body is read as a stream under the [`HttpPolicy`] cap: no more
//! than the cap is ever buffered on the Rust side, and the read stops
//! at the chunk that crosses it, so an upstream that streams without
//! declaring a length cannot spend the isolate's memory on order to be
//! refused. (Workerd may have buffered some of the body before the
//! headers arrived; what the cap bounds is this side of that.) A request
//! marked [`StatusOnly`](cratefield_core::StatusOnly) is answered from
//! the status line alone, its body never read. Redirects are not
//! followed: a 3xx comes back as it is, with its `Location`.
//!
//! # A failure message here never carries the request URL
//!
//! This is the production path for every venture on this harness, and the
//! runtime whose errors reach Workers Logs through `console_error!`. A
//! `worker::Error` is not safe to stringify: `Error::JsError(s)` and
//! `Error::UnknownJsError { .. }` carry workerd's own message, and workerd
//! names the destination it could not reach — "Fetch API cannot load:
//! `<the whole URL>`".
//!
//! For some callers that URL *is* the credential. An APNs request path is
//! the device token (`/3/device/<token>`) and a Web Push endpoint is a
//! bearer capability — whoever holds it can push to that browser
//! indefinitely, which is why [`cratefield_core::Recipient`] prints
//! fingerprints and says the value must appear "never in a log, an event
//! payload, or an error body". A transport failure would otherwise write
//! that credential into Workers Logs while the caller two lines away is
//! carefully printing a fingerprint (issue #229; the native port was the
//! same leak, issue #228).
//!
//! So no error is ever stringified whole here. Every failure goes through
//! [`transport`], which keeps the destination's origin, drops its path, and
//! then hands the result to [`cratefield_core::scrub_text`] for every other
//! shape of secret a layer below might have quoted.

use std::fmt::Write as _;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use cratefield_core::{
    HttpClient, HttpError, HttpPolicy, StatusOnly, scrub_request_url, scrub_text,
};
use futures_core::Stream;
use futures_util::StreamExt;
use worker::send::IntoSendFuture;
use worker::{Fetch, Headers, Method, Request as WorkerRequest, RequestInit, RequestRedirect};

/// The Workers implementation of the [`HttpClient`] port: one `fetch` per
/// send, through the isolate's own stack.
pub struct FetchClient;

/// Buffer the capped read starts with: an ordinary upstream reply fits
/// without a reallocation, a larger one grows from here. Never more than
/// the cap itself, whatever the cap is.
const INITIAL_READ_CAPACITY: usize = 16 * 1024;

#[async_trait]
impl HttpClient for FetchClient {
    async fn send(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        let policy = HttpPolicy::of_request(&request);
        let status_only = request.extensions().get::<StatusOnly>().is_some();
        let (parts, body) = request.into_parts();
        // Kept for the whole exchange: it is what every failure below is
        // scrubbed against, and the only thing here that knows which parts
        // of a message are this request's URL.
        let url = parts.uri.to_string();
        let mut init = RequestInit::new();
        init.method = Method::from(parts.method.as_str().to_string());
        let headers = Headers::new();
        for (name, value) in &parts.headers {
            let _ = headers.set(name.as_str(), value.to_str().unwrap_or_default());
        }
        init.headers = headers;
        // A redirect is answered, not taken. `Follow` is the platform
        // default and would let an upstream move the exchange to another
        // host, or down to `http`, after the destination was chosen. The
        // caller sees the 3xx with its `Location` and decides for itself.
        init.with_redirect(RequestRedirect::Manual);

        // A body is attached only when there is one. The Fetch spec refuses
        // to construct a Request whose method is GET or HEAD and whose body
        // is non-null, and an empty JS string is not null: setting it
        // unconditionally makes every GET through this port throw a
        // TypeError before it leaves the isolate.
        //
        // Nothing caught it because every adapter shipped so far POSTs
        // (Resend, Turnstile). The first GET consumer is OpenID Connect
        // discovery in the `auth-oidc` crate, which fetches a configuration
        // document and a JWKS.
        if !body.is_empty() {
            // The port's adapters send JSON bodies; non-UTF-8 is a hard
            // error rather than a lossy corruption.
            let body_text =
                String::from_utf8(body.to_vec()).map_err(|err| transport(&err, &url))?;
            init.with_body(Some(worker::wasm_bindgen::JsValue::from_str(&body_text)));
        }
        let worker_request =
            WorkerRequest::new_with_init(&url, &init).map_err(|err| transport(&err, &url))?;

        let mut response = Fetch::Request(worker_request)
            .send()
            .into_send()
            .await
            .map_err(|err| transport(&err, &url))?;

        // The whole body is read into one buffer, so refuse a declared
        // body the cap has already out before reading any of it (issue
        // #136). A status-only probe reads no body, so the declared
        // length is not something it asked for: checking it here would
        // refuse exactly the large resource a liveness probe exists to
        // ask about. The body-describing headers are dropped below
        // instead, so `BoundedHttpClient` sees no length either.
        if !status_only {
            let declared = response
                .headers()
                .get("content-length")
                .ok()
                .flatten()
                .and_then(|length| length.trim().parse::<usize>().ok());
            if declared.is_some_and(|declared| declared > policy.max_response_bytes) {
                return Err(HttpError::ResponseTooLarge {
                    limit: policy.max_response_bytes,
                });
            }
        }

        let headers = response_headers(response.headers(), status_only);
        let mut builder = http::Response::builder().status(response.status_code());
        if let Some(map) = builder.headers_mut() {
            *map = headers;
        }

        if status_only {
            // The body is never read: the `worker::Response` is dropped
            // without being streamed. Dropping it releases the platform's
            // handle on the fetch, so nothing is read into the isolate —
            // how much of the body the platform had already received is
            // workerd's business, not a promise this port makes.
            return builder
                .body(Bytes::new())
                .map_err(|err| transport(&err, &url));
        }

        let bytes = capped_body(response.stream(), policy.max_response_bytes, &url)
            .into_send()
            .await?;
        builder.body(bytes).map_err(|err| transport(&err, &url))
    }
}

/// Copies a response's headers, dropping the ones that describe a body
/// when there is no body behind them.
///
/// A status-only response carries no body, so a `content-length` left on
/// it is a length nothing is behind: `BoundedHttpClient` — which every
/// runtime wraps around this port — refuses a declared length over the
/// cap, so a probe of a large resource would fail on a length the caller
/// never asked for.
///
/// Generic over the iterator rather than taking a `worker::Headers`,
/// which cannot be constructed off-wasm, so the decision is testable
/// natively through the same iterator the platform's headers produce.
fn response_headers<I>(from: I, status_only: bool) -> http::HeaderMap
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut headers = http::HeaderMap::new();
    for (name, value) in from {
        if status_only && is_body_describing(&name) {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::try_from(name.as_str()),
            http::HeaderValue::try_from(value.as_str()),
        ) {
            headers.insert(name, value);
        }
    }
    headers
}

/// The body of a response, capped, with the platform's "there is no
/// stream here" answer taken at face value.
///
/// `worker::Response::stream()` refuses every body that is not a
/// `Stream`, and `ResponseBody::Empty` is what the platform delivers for
/// every null-body status (101/103/204/205/304) and for the reply to a
/// `HEAD`. That is an empty body, not a failed send: the refusal is taken
/// at face value here, so reading under the cap does not turn every 204 No
/// Content into one.
async fn capped_body<S>(
    stream: worker::Result<S>,
    limit: usize,
    url: &str,
) -> Result<Bytes, HttpError>
where
    S: Stream<Item = worker::Result<Vec<u8>>> + Unpin,
{
    match stream {
        Ok(stream) => read_capped(stream, limit, url).await,
        Err(_) => Ok(Bytes::new()),
    }
}

/// Headers that describe a body. A response built with no body must not
/// keep them, or a caller — and the `BoundedHttpClient` every runtime
/// wraps around this port — reads a length there is nothing behind.
fn is_body_describing(name: &str) -> bool {
    // The platform lowercases what it hands over, but the port promises
    // nothing about an implementation's casing, and a `content-length`
    // left in place would be a lie a caller believes.
    let Ok(name) = http::HeaderName::try_from(name) else {
        return false;
    };
    matches!(
        name,
        http::header::CONTENT_LENGTH
            | http::header::CONTENT_ENCODING
            | http::header::TRANSFER_ENCODING
    )
}

/// Reads a response body as a stream and refuses it the moment it passes
/// `limit` (issue #714).
///
/// The declared `content-length` is only a claim: a customer-supplied
/// URL can stream a chunked body that never declares one, and
/// `Response::bytes()` buffers whatever arrives — so the body is read
/// chunk by chunk and each chunk is checked *before* it is appended. The
/// chunk that crosses the cap is examined as a length and dropped along
/// with the buffer; returning here releases the `ByteStream` and with it
/// the platform's handle on the fetch, so the pending read stops here
/// and no further bytes are buffered on this side. An upstream that never
/// stops sending costs one chunk past the cap, not the isolate's memory.
///
/// Generic over the stream so the decision logic is testable off-wasm:
/// `worker::ByteStream` cannot be constructed outside wasm, and an
/// aborted one is indistinguishable from one that ended.
async fn read_capped<S>(mut stream: S, limit: usize, url: &str) -> Result<Bytes, HttpError>
where
    S: Stream<Item = worker::Result<Vec<u8>>> + Unpin,
{
    // A capacity hint, not an allocation of the whole cap: `BytesMut`
    // grows geometrically, so an unbuffered start can transiently hold
    // twice what it has been given. This covers an ordinary reply in one
    // go and never exceeds the cap itself.
    let mut buffered = BytesMut::with_capacity(limit.min(INITIAL_READ_CAPACITY));
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|err| transport(&err, url))?;
        if buffered.len().saturating_add(chunk.len()) > limit {
            return Err(HttpError::ResponseTooLarge { limit });
        }
        buffered.extend_from_slice(&chunk);
    }
    Ok(buffered.freeze())
}

/// The only place in this module that builds an [`HttpError::Transport`],
/// so a sixth failure site cannot be added that reports a raw error string
/// — which is exactly how the first five came to (issue #229).
fn transport(err: &dyn std::error::Error, url: &str) -> HttpError {
    HttpError::Transport(safe_message(err, url))
}

/// An error as a message this crate may hand on — to [`HttpError`], and
/// from there to `console_error!`, a dead-letter row and an operator's
/// terminal.
///
/// Three things happen here, and the last two are why this is not
/// `err.to_string()`:
///
/// 1. **The causes go in.** `worker::Error`'s `Display` is deliberately
///    thin for every variant that wraps another error — `Error::Io` prints
///    "I/O error", `Error::Http` prints "HTTP error" — because the crate
///    expects consumers to walk `source()`, which it implements for the
///    wrapped Rust errors *and* for a JS error's `cause` chain. Asking
///    `Display` alone therefore throws away the half that says what went
///    wrong. This is the same thing the native port learned about
///    `reqwest::Error` (issue #228), and it means redaction makes these
///    messages more diagnosable, not less.
/// 2. **The URL comes out.** With the chain in, a workerd fetch failure
///    reads "Fetch API cannot load: `<the whole URL>`", path and query
///    included — see the module note for why that is a disclosure and not
///    a detail. [`cratefield_core::scrub_request_url`] cuts it back to the
///    origin, and redacts the bare request target a cause is free to quote
///    on its own.
/// 3. **Everything else is scrubbed too.** A cause may quote a `Bearer`
///    credential, a signed token or an address that has nothing to do with
///    this request's URL, so the result goes through
///    [`cratefield_core::scrub_text`] — the same pass every log field takes
///    (issue #135).
fn safe_message(err: &dyn std::error::Error, url: &str) -> String {
    let mut message = err.to_string();
    let mut cause = err.source();
    while let Some(current) = cause {
        let _ = write!(message, ": {current}");
        cause = current.source();
    }
    scrub_text(&scrub_request_url(&message, url))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::stream;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The APNs shape, because it is the worst case: the device token is
    /// the request *path*, so a message that quotes the URL publishes the
    /// credential.
    const TOKEN: &str = "0a1b2c3d4e5f60718293a4b5c6d7e8f900112233445566778899aabbccddeeff";

    fn apns_url() -> String {
        format!("https://api.push.apple.com/3/device/{TOKEN}")
    }

    fn assert_safe(message: &str) {
        assert!(
            !message.contains(TOKEN),
            "the device token leaked: {message}"
        );
        assert!(
            !message.contains("/3/device"),
            "the request path leaked: {message}"
        );
    }

    /// What workerd actually throws when a fetch cannot be completed: a
    /// `TypeError` whose message names the destination in full. Arriving
    /// as `Error::JsError` (a thrown string) or inside `UnknownJsError`'s
    /// message, it is the same disclosure either way.
    #[test]
    fn a_workerd_fetch_failure_names_the_origin_and_never_the_request_path() {
        let url = apns_url();
        let err = worker::Error::JsError(format!("TypeError: Fetch API cannot load: {url}."));

        let message = safe_message(&err, &url);

        assert_safe(&message);
        // And it is still an error somebody can act on: which host, and
        // what the runtime actually said.
        assert!(
            message.contains("https://api.push.apple.com"),
            "the destination is named: {message}"
        );
        assert!(
            message.contains("Fetch API cannot load"),
            "the cause survives the redaction: {message}"
        );
    }

    /// The property the native port found and this one had to be checked
    /// for separately: `Display` is nearly empty for the variants that
    /// wrap another error, and the detail lives in `source()`. Walking the
    /// chain is what makes the redacted message *better* than the leaky
    /// one — and a cause quotes whatever it was handed, so it is scrubbed
    /// too.
    #[test]
    fn the_cause_chain_is_walked_and_scrubbed() {
        let url = apns_url();
        let inner =
            std::io::Error::other(format!("connection refused sending to /3/device/{TOKEN}"));
        let err = worker::Error::Io(inner);

        assert_eq!(
            err.to_string(),
            "I/O error",
            "if `Display` ever carries the cause, this pass can stop appending it"
        );

        let message = safe_message(&err, &url);

        assert_safe(&message);
        assert!(
            message.contains("connection refused"),
            "the cause is what makes this diagnosable: {message}"
        );
    }

    /// `scrub_text`'s own rules still apply on top: a cause is free to
    /// quote a credential that has nothing to do with this request's URL.
    #[test]
    fn a_secret_a_cause_quotes_is_scrubbed_even_when_it_is_not_the_url() {
        let url = apns_url();
        let err = worker::Error::JsError(
            "rejected the Authorization: Bearer abcdefghijklmnop12345 we sent".to_owned(),
        );

        let message = safe_message(&err, &url);

        assert!(
            !message.contains("abcdefghijklmnop12345"),
            "scrub_text is the second net: {message}"
        );
    }

    /// Every failure site in `send` hands a different error type to
    /// [`transport`], and each one is a `Transport` variant whose message
    /// has been through the redaction — including the two that are not
    /// `worker::Error` at all.
    #[test]
    fn every_error_type_a_failure_site_produces_is_redacted() {
        let url = apns_url();
        let quoting = |what: &str| format!("{what} at {url}");

        // 1. A non-UTF-8 request body (`String::from_utf8`).
        let utf8 = String::from_utf8(vec![0xff, 0xfe]).expect_err("not UTF-8");
        // 2-4. Request construction, `Fetch::send`, and reading the body,
        //      all of which fail as `worker::Error` — as a thrown JS
        //      string, and as a wrapped Rust error with a cause.
        let js = worker::Error::JsError(quoting("TypeError: Fetch API cannot load:"));
        let rust = worker::Error::RustError(quoting("could not construct a request"));
        let io = worker::Error::Io(std::io::Error::other(quoting("network connection lost")));
        // 5. Building the `http::Response` back (`http::Error`).
        let http_err = http::Response::builder()
            .status(200)
            .header("x-\u{0}bad", "v")
            .body(())
            .expect_err("an invalid header name is a builder error");

        let sites: [&dyn std::error::Error; 5] = [&utf8, &js, &rust, &io, &http_err];
        for err in sites {
            let HttpError::Transport(message) = transport(err, &url) else {
                panic!("every site reports a transport failure");
            };
            assert_safe(&message);
        }
    }

    /// The five sites were five copies of `err.to_string()`, which is how
    /// one leak became five. Only one of them may build the error now, so
    /// a sixth site added later cannot quietly reintroduce the pattern:
    /// the module has exactly one `HttpError::Transport(` in it, in
    /// [`transport`].
    #[test]
    fn only_one_place_in_this_module_builds_a_transport_error() {
        let source = include_str!("http.rs");
        let module = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(before, _)| before);

        assert_eq!(
            module.matches("HttpError::Transport(").count(),
            1,
            "a failure site must call `transport`, not build the error itself"
        );
    }
    /// Redirects are answered, not taken: following one would let an
    /// upstream move the exchange to another host, or down to `http`,
    /// after this port had already chosen the destination. The init the
    /// request is built from therefore asks for `Manual` exactly once,
    /// and the caller gets the 3xx with its `Location` and decides.
    #[test]
    fn a_redirect_is_never_followed_by_the_transport_request() {
        let source = include_str!("http.rs");
        let module = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(before, _)| before);

        // Not a containment check: `with_redirect` and `Manual` also
        // appear in prose and would be "present" even if the call were
        // commented out. What matters is this exact call, on the init
        // the request is actually built from.
        assert_eq!(
            module
                .matches("init.with_redirect(RequestRedirect::Manual)")
                .count(),
            1,
            "the init the request is built from must ask for `Manual` exactly once"
        );
    }

    // ---------------------------------------------------- the capped read
    //
    // `worker::ByteStream` cannot be constructed outside wasm, so the
    // reader is generic and these drive it with synthetic streams in the
    // shape workerd delivers: `Vec<u8>` per chunk, `worker::Error` on a
    // chunk the runtime could not read.

    /// The cap every capped-read test is measured against.
    const LIMIT: usize = 4096;
    /// One chunk's worth of bytes; four of them fill `LIMIT` exactly.
    const CHUNK: usize = 1024;

    /// A body of `chunks` chunks of `CHUNK` bytes, plus a count of how
    /// many were handed out, so a test can see how far the reader got
    /// before it stopped.
    fn counting_chunks(
        chunks: usize,
    ) -> (
        impl Stream<Item = worker::Result<Vec<u8>>>,
        Arc<AtomicUsize>,
    ) {
        let pulled = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&pulled);
        let body = stream::iter(0..chunks).map(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(vec![b'x'; CHUNK])
        });
        (body, pulled)
    }

    /// The cap refuses a body it has no header for. A body that arrives
    /// in chunks, each one inside the cap and the total well past it, is
    /// refused mid-read; and one chunk larger than the whole cap is
    /// refused too, because the check runs before the append.
    #[test]
    fn a_body_past_the_cap_is_refused_however_it_arrives() {
        let url = apns_url();
        let (chunked, _) = counting_chunks(6);
        let one_big: Vec<worker::Result<Vec<u8>>> = vec![Ok(vec![b'x'; LIMIT + 1])];

        let refusals = [
            pollster::block_on(read_capped(chunked, LIMIT, &url)),
            pollster::block_on(read_capped(stream::iter(one_big), LIMIT, &url)),
        ];

        for got in refusals {
            assert!(
                matches!(got, Err(HttpError::ResponseTooLarge { limit: LIMIT })),
                "a body past the cap must be refused, got {got:?}"
            );
        }
    }

    /// A body under the cap is the ordinary case and must come back whole
    /// and in order.
    #[test]
    fn a_body_under_the_cap_is_read_whole_and_byte_identical() {
        let url = apns_url();
        let parts: Vec<worker::Result<Vec<u8>>> = vec![
            Ok(b"hello ".to_vec()),
            Ok(b"capped ".to_vec()),
            Ok(b"world".to_vec()),
        ];

        let body = pollster::block_on(read_capped(stream::iter(parts), LIMIT, &url))
            .expect("a body under the cap must read");

        assert_eq!(body, Bytes::from_static(b"hello capped world"));
    }

    /// Refusing has to be an abort, not a drain: the reader stops at the
    /// chunk that crosses the cap, which is the whole point against an
    /// upstream that never stops sending.
    #[test]
    fn the_reader_aborts_at_the_cap_instead_of_draining_the_stream() {
        let url = apns_url();
        let (chunks, pulled) = counting_chunks(64);

        let err = pollster::block_on(read_capped(chunks, LIMIT, &url))
            .expect_err("an endless body must be refused, not buffered");
        assert!(
            matches!(err, HttpError::ResponseTooLarge { limit: LIMIT }),
            "got {err}"
        );

        assert_eq!(
            pulled.load(Ordering::SeqCst),
            LIMIT / CHUNK + 1,
            "reading stops at the chunk that crosses the cap, and nowhere later"
        );
    }

    /// A chunk workerd could not read is a failure like any other, and
    /// goes through [`transport`] — so the redaction this module exists
    /// to apply still applies, and the streaming read adds no new site
    /// that could bypass it.
    #[test]
    fn a_stream_error_is_reported_through_transport_and_scrubbed() {
        let url = apns_url();
        let parts: Vec<worker::Result<Vec<u8>>> = vec![
            Ok(b"ok".to_vec()),
            Err(worker::Error::JsError(format!(
                "TypeError: network error reading {url}"
            ))),
        ];

        let err = pollster::block_on(read_capped(stream::iter(parts), LIMIT, &url))
            .expect_err("an unreadable chunk must fail the send");

        let HttpError::Transport(message) = &err else {
            panic!("a stream error is reported as a transport failure, got {err}");
        };
        assert_safe(message);
        assert!(
            message.contains("network error reading"),
            "the cause survives the redaction: {message}"
        );
    }

    /// The `status_only` wiring in `send`, which cannot run off-wasm: the
    /// header copy is where the marker is honoured, so that decision lives
    /// in a helper the tests can drive. A status-only reply keeps the
    /// headers a probe wants — the endpoint in `location`, the answer's
    /// shape in `content-type` — and loses every header describing a body
    /// it is not getting, in any casing. A `content-length` left there is a
    /// length nothing is behind, and `BoundedHttpClient` refuses a declared
    /// length over the cap, so a probe of a large resource would fail on a
    /// length it never asked for.
    #[test]
    fn a_status_only_response_keeps_every_header_that_does_not_describe_a_body() {
        let reply: Vec<(String, String)> = [
            ("content-length", "4194304"),
            ("Content-Length", "4194304"),
            ("content-encoding", "gzip"),
            ("transfer-encoding", "chunked"),
            ("content-type", "application/json"),
            ("location", "https://example.com/hook"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect();

        let probe = response_headers(reply.clone(), true);
        for dropped in [
            http::header::CONTENT_LENGTH,
            http::header::CONTENT_ENCODING,
            http::header::TRANSFER_ENCODING,
        ] {
            assert_eq!(
                probe.get(&dropped),
                None,
                "a probe reads no body, so {dropped:?} describes nothing"
            );
        }
        for kept in [
            (http::header::CONTENT_TYPE, "application/json"),
            (http::header::LOCATION, "https://example.com/hook"),
        ] {
            assert_eq!(
                probe.get(kept.0),
                Some(&http::HeaderValue::from_static(kept.1)),
                "a header that is not about the body is still the caller's"
            );
        }

        // An ordinary send keeps every one of them: the marker decides,
        // not the header.
        let whole = response_headers(reply, false);
        assert_eq!(
            whole.get(http::header::CONTENT_LENGTH),
            Some(&http::HeaderValue::from_static("4194304")),
            "a body that is really there is still described"
        );
        assert_eq!(
            whole.get(http::header::CONTENT_ENCODING),
            Some(&http::HeaderValue::from_static("gzip"))
        );
    }

    /// `worker::Response::stream()` refuses every body that is not a
    /// stream, and `ResponseBody::Empty` is what the platform hands over for
    /// a null-body status (101/103/204/205/304) and for the reply to a
    /// `HEAD`. A 204 is the commonest "accepted, nothing to say" an
    /// upstream sends; reading it as a transport failure would break every
    /// adapter on this harness. The other half: a body that *is* a stream
    /// is still read under the cap, so this is a read and not a swallow.
    #[test]
    fn a_null_body_is_empty_and_a_streamable_one_is_still_read() {
        let url = apns_url();
        let unstreamable: worker::Result<
            futures_util::stream::Iter<std::vec::IntoIter<worker::Result<Vec<u8>>>>,
        > = Err(worker::Error::RustError("body is not streamable".into()));
        let parts: Vec<worker::Result<Vec<u8>>> =
            vec![Ok(b"hello ".to_vec()), Ok(b"world".to_vec())];

        let empty = pollster::block_on(capped_body(unstreamable, LIMIT, &url))
            .expect("a 204 is a successful answer, not a failed read");
        let read = pollster::block_on(capped_body(Ok(stream::iter(parts)), LIMIT, &url))
            .expect("a streamable body must read");

        assert!(empty.is_empty(), "a null body reads as empty: {empty:?}");
        assert_eq!(read, Bytes::from_static(b"hello world"));
    }
}
