//! Incremental Server-Sent Events decoding (issue #859).
//!
//! A streamed completion arrives as `text/event-stream` — the wire format
//! the [`TextModel::stream`](crate::TextModel::stream) adapters consume —
//! and its units are events, not bytes: one chunk from the transport can
//! carry three events, half of one, or the middle of a UTF-8 character.
//! This module is the one parser for that, written to the WHATWG
//! Server-Sent Events "event stream interpretation" so adapters share a
//! decoder instead of each re-deriving the corner cases:
//!
//! - lines end at `\n`, `\r\n` **or** `\r` (a lone CR is a line break,
//!   the spec's legacy rule);
//! - lines beginning with `:` are comments, ignored;
//! - a field is `name: value`; the colon may be absent (an empty value),
//!   and exactly one leading space of the value is stripped — `data: hi`
//!   and `data:hi` are the same field;
//! - `event`, `data` and `id` fields are kept; `data` lines accumulate in
//!   order and join with `\n` at dispatch; `id` persists across events
//!   (it is the stream's `last-event-id`), and an **empty** `id:` clears
//!   it;
//! - a blank line dispatches the pending event; a stream of fields with
//!   no data lines dispatches nothing;
//! - `retry` and any unknown field are ignored — an in-process decoder
//!   has no reconnect interval to learn.
//!
//! Bytes are buffered until a line ends, which is also what makes UTF-8
//! split across chunks safe: a line terminator is ASCII, so it can never
//! appear inside a multi-byte character, and no partial character is ever
//! decoded. The buffer is not unbounded — a single line is capped at
//! [`MAX_SSE_LINE_BYTES`], past which the source has stopped making sense
//! and the stream is refused rather than buffered into memory.
//!
//! The output side is [`SseDecoder`] for callers that already have a
//! chunk loop, and [`sse_events`] for callers that have a `ByteStream`
//! (the [`HttpClient::send_streaming`](crate::HttpClient::send_streaming)
//! shape) and want a stream of events.
//!
//! # Encoding (issue #860)
//!
//! The other direction lives here too: [`SseEvent::encode`] frames one
//! event back into the wire bytes the decode rules above read — an event
//! that round-trips through encode and decode is unchanged — and
//! [`SseResponse`] streams a whole sequence of events as a response body,
//! one chunk per event, with a comment heartbeat over any quiet stretch.
//! The heartbeat is timed through the [`Clock`] port, so the
//! same code serves a tokio runtime and a Workers isolate (`futures_timer`
//! cannot fire on wasm). For the UI message stream dialect chat frontends
//! speak, the [`ui_message`] submodule is the encoder.

// The Vercel AI SDK "UI message stream" encoder (issue #860), in its own
// file: this module keeps the wire framing, `sse/ui_message.rs` the chat
// chunk vocabulary written on top of it.
pub mod ui_message;

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures_core::Stream;
use futures_core::future::BoxFuture;
use futures_util::StreamExt;
use http::{HeaderName, HeaderValue};

use crate::ports::{ByteStream, Clock, HttpError, timeout};
use crate::stream::{BoxStream, ResponseStream};

/// The largest single line the decoder will hold while waiting for its
/// terminator. An SSE line is one field or one `data:` fragment, so a
/// legitimate one is kilobytes at most; a line that grows past this is
/// not an event anyone asked for but a misbehaving or hostile source
/// pinning memory with a terminator that never comes. [`sse_events`]
/// answers it with `HttpError::ResponseTooLarge { limit: this }` and
/// ends; a caller driving [`SseDecoder`] directly reads
/// [`SseDecoder::overflowed`] and refuses the stream the same way. The
/// cap is on one unterminated line, so the buffer never grows past it
/// plus one transport chunk, and it is never raised.
pub const MAX_SSE_LINE_BYTES: usize = 1024 * 1024;

/// One dispatched Server-Sent Event: what the stream said, in the spec's
/// three fields. `event` is `None` when the source never named one (the
/// wire's default type is `"message"`, which a consumer can apply itself —
/// the port keeps the *absence* visible, the way
/// [`Completion::cached_input_tokens`](crate::Completion::cached_input_tokens)
/// keeps an absent cache report visible).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    /// The `event:` field's value, when the source sent one.
    pub event: Option<String>,
    /// The `data:` lines, in order, joined with `\n`.
    pub data: String,
    /// The last `id:` field seen when this event dispatched.
    pub id: Option<String>,
}

impl SseEvent {
    /// An unnamed event carrying just `data` — the shape the
    /// [`ui_message`] encoder writes and most relays need. Set `event`
    /// and `id` through a struct literal when a caller names its events.
    #[must_use]
    pub fn new(data: impl Into<String>) -> Self {
        Self {
            event: None,
            data: data.into(),
            id: None,
        }
    }

    /// Frames the event into wire bytes — the inverse of the decode rules
    /// the module documentation lists, so a decoded event that encodes
    /// decodes back unchanged. The optional `event:` and `id:` lines come
    /// first (a decoder keeps only the last of each, so one line is all
    /// an event can mean), then every line of `data` — split on `\r\n`,
    /// `\n` and `\r`, the three line endings [`SseDecoder`] reads — as
    /// its own `data:` line, then the blank line that dispatches. CR and
    /// LF are stripped from `event` and `id` first, so a value carrying a
    /// line break cannot forge a field it does not own.
    ///
    /// The bytes are one complete event: an SSE response writes one per
    /// chunk and flushes, no read-ahead.
    #[must_use]
    pub fn encode(&self) -> Bytes {
        let mut wire = String::new();
        for (field, value) in [("event", &self.event), ("id", &self.id)] {
            if let Some(value) = value {
                wire.push_str(field);
                wire.push_str(": ");
                wire.extend(
                    value
                        .chars()
                        .filter(|character| !matches!(character, '\r' | '\n')),
                );
                wire.push('\n');
            }
        }
        for line in split_data_lines(&self.data) {
            wire.push_str("data: ");
            wire.push_str(line);
            wire.push('\n');
        }
        wire.push('\n');
        Bytes::from(wire)
    }
}

/// Splits an event's `data` on the decoder's three line endings — `\r\n`,
/// `\n`, and the spec's legacy lone `\r` — one `data:` line per piece, so
/// what encodes decodes back joined the same way. A `\r\n` pair is one
/// break, not a break plus an empty line.
fn split_data_lines(data: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut rest = data;
    while let Some(index) = rest.find(['\r', '\n']) {
        lines.push(&rest[..index]);
        let tail = &rest[index..];
        // A `\r\n` pair is one break: past both bytes; a lone break, past one.
        rest = tail.strip_prefix("\r\n").unwrap_or(&tail[1..]);
    }
    lines.push(rest);
    lines
}

/// An incremental Server-Sent Events decoder: feed it the chunks as they
/// arrive, take the events that become complete.
///
/// Chunk boundaries are irrelevant — a chunk may split a line, a `\r\n`
/// pair, or a UTF-8 character; the decoder buffers raw bytes until a line
/// ends, so nothing partial is ever decoded. The one line it will not
/// buffer forever is an unterminated one past [`MAX_SSE_LINE_BYTES`]:
/// that latches [`overflowed`](Self::overflowed), the line is released,
/// and every later push is ignored until [`finish`](Self::finish) resets
/// the decoder — the spec's framing means nothing after a line that size
/// can be trusted to re-sync against.
#[derive(Default)]
pub struct SseDecoder {
    /// Raw bytes of the line currently being read. Buffers bytes, not
    /// text, precisely so a split multi-byte character waits for its
    /// remainder instead of being decoded half-formed.
    buffer: Vec<u8>,
    /// The pending event's `event:` field, if one was named.
    event: Option<String>,
    /// The pending event's `data:` lines, in order; joined with `\n` at
    /// dispatch. One value per line, so a `data:` line carrying an empty
    /// string stays an empty line in the join, per spec.
    data: Vec<String>,
    /// The last `id:` field seen — the stream's `last-event-id`, which
    /// persists across events until an empty `id:` clears it.
    id: Option<String>,
    /// Whether the leading byte-order mark question is settled: either one
    /// was stripped, or the stream provably does not start with one. A BOM
    /// split across pushes waits in the buffer until it can be decided.
    bom_checked: bool,
    /// Whether the last line processed ended with a bare `\r` that was the
    /// buffer's final byte. The next push's leading `\n` is that break's
    /// other half — a `\r\n` pair split across chunks is one break, not a
    /// break plus a spurious blank line.
    split_cr: bool,
    /// A single unterminated line grew past [`MAX_SSE_LINE_BYTES`]: the
    /// line was released and the decoder is fused — it ignores everything
    /// until [`finish`](Self::finish) resets it — because a stream that
    /// sends one is refusing to frame events at all.
    overflowed: bool,
}

impl SseDecoder {
    /// Whether a single unterminated line has grown past
    /// [`MAX_SSE_LINE_BYTES`]. Once true the decoder is fused — every
    /// push is ignored — until [`finish`](Self::finish) resets it; the
    /// caller should refuse the stream, as [`sse_events`] does with
    /// `HttpError::ResponseTooLarge { limit: MAX_SSE_LINE_BYTES }`.
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Feeds one transport chunk in, returns every event that became
    /// complete because of it, in order. Empty once
    /// [`overflowed`](Self::overflowed) has latched — nothing more is
    /// taken from a stream that stopped framing events — until
    /// [`finish`](Self::finish) resets the decoder.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
        const BOM: &[u8] = b"\xEF\xBB\xBF";
        if self.overflowed {
            return Vec::new();
        }
        let mut chunk = chunk;
        if self.split_cr {
            // The `\r` was consumed last push; its `\n` half is furniture.
            self.split_cr = false;
            if let Some(rest) = chunk.strip_prefix(b"\n".as_slice()) {
                chunk = rest;
            }
        }
        self.buffer.extend_from_slice(chunk);
        // A leading byte-order mark is transport furniture, not content:
        // the spec ignores it wherever it starts. Nothing before the first
        // line break can end a line, so a held BOM prefix costs nothing.
        if !self.bom_checked {
            if self.buffer.starts_with(BOM) {
                self.buffer.drain(..BOM.len());
                self.bom_checked = true;
            } else if !BOM.starts_with(&self.buffer) {
                self.bom_checked = true;
            }
        }

        let mut events = Vec::new();
        while let Some(line) = self.next_line() {
            if let Some(event) = self.field_line(&line) {
                events.push(event);
            }
        }
        // Complete lines are never the problem — they are consumed as they
        // end. What is left is one unterminated line, and one past the
        // ceiling is not an event waiting to finish but a source that has
        // stopped framing events at all: release the line, latch the
        // overflow, and let the caller refuse the stream.
        if self.buffer.len() > MAX_SSE_LINE_BYTES {
            self.overflowed = true;
            self.buffer.clear();
        }
        events
    }

    /// Ends the stream. Per spec — and this decoder follows the spec — an
    /// event is dispatched **only** by its terminating blank line, so a
    /// partial event left in the buffers at end of stream is discarded,
    /// never flushed: the answer is `None`, always. (The signature stays
    /// an `Option` so a caller can treat it uniformly with
    /// [`push`](Self::push), and so a future, explicitly non-default
    /// "flush unterminated" policy would not change the shape.)
    ///
    /// The decoder resets — an [`overflowed`](Self::overflowed) latch
    /// included — ready for the next body.
    pub fn finish(&mut self) -> Option<SseEvent> {
        self.buffer.clear();
        self.event = None;
        self.data.clear();
        self.id = None;
        self.bom_checked = false;
        self.split_cr = false;
        self.overflowed = false;
        None
    }

    /// The next complete line in the byte buffer, with its terminator
    /// consumed. `\n`, `\r\n` and `\r` all end a line (and a `\r\n` pair
    /// is one break, not two).
    fn next_line(&mut self) -> Option<String> {
        let end = self
            .buffer
            .iter()
            .position(|byte| matches!(byte, b'\n' | b'\r'))?;
        let crlf = self.buffer[end] == b'\r' && self.buffer.get(end + 1) == Some(&b'\n');
        let line = String::from_utf8_lossy(&self.buffer[..end]).into_owned();
        // The line *and* its terminator go: `end` names the delimiter, so
        // it is consumed too, plus the `\n` of a `\r\n` pair. Skipping this
        // would leave the delimiter in the buffer and loop forever. A `\r`
        // that ends the buffer may be half of a `\r\n` the next push
        // completes — `split_cr` remembers to swallow that half.
        self.split_cr = self.buffer[end] == b'\r' && end + 1 == self.buffer.len();
        self.buffer.drain(..end + 1 + usize::from(crlf));
        Some(line)
    }

    /// One complete field line. Returns an event only when the line
    /// dispatches one (a blank line over a pending event).
    fn field_line(&mut self, line: &str) -> Option<SseEvent> {
        if line.is_empty() {
            return self.dispatch();
        }
        if line.starts_with(':') {
            return None; // a comment; ignored, per spec
        }
        let (name, value) = match line.split_once(':') {
            Some((name, value)) => (name, value.strip_prefix(' ').unwrap_or(value)),
            None => (line, ""),
        };
        match name {
            "event" => self.event = Some(value.to_owned()),
            "data" => self.data.push(value.to_owned()),
            // A NUL poisons the whole field (spec), not just the id.
            "id" if !value.contains('\0') => {
                self.id = (!value.is_empty()).then(|| value.to_owned());
            }
            // `retry` names a reconnect interval; an in-process decoder
            // has nothing to reconnect. Anything else is ignored too, so
            // a future field never breaks this one.
            _ => {}
        }
        None
    }

    /// Dispatches the pending event, if it has data lines. No data lines
    /// means nothing is dispatched (but a named `event:` still resets,
    /// per spec) — an event that says nothing is not an event.
    fn dispatch(&mut self) -> Option<SseEvent> {
        if self.data.is_empty() {
            self.event = None;
            return None;
        }
        let event = SseEvent {
            event: self.event.take(),
            data: self.data.join("\n"),
            id: self.id.clone(),
        };
        self.data.clear();
        Some(event)
    }
}

/// Decodes a streamed response body into Server-Sent Events: [`sse_events`]
/// is to [`ByteStream`] what the decoder is to raw chunks. The body's
/// errors surface as items (`Err`) and end the stream — dropping the
/// returned stream drops the body, which cancels the upstream exchange,
/// the same contract the body itself carries.
pub fn sse_events(body: ByteStream) -> BoxStream<'static, Result<SseEvent, HttpError>> {
    Box::pin(futures_util::stream::unfold(
        Pipeline {
            body: Some(body),
            decoder: SseDecoder::default(),
            pending: Vec::new().into_iter(),
            done: false,
        },
        |mut pipe| async move {
            loop {
                if let Some(event) = pipe.pending.next() {
                    return Some((Ok(event), pipe));
                }
                if pipe.done {
                    return None;
                }
                let Some(mut body) = pipe.body.take() else {
                    // Unreachable while `done` is false, but the compiler
                    // cannot know that: no body left means the stream is
                    // over, and `None` ends it for good.
                    return None;
                };
                match body.next().await {
                    Some(Ok(chunk)) => {
                        pipe.body = Some(body);
                        pipe.pending = pipe.decoder.push(&chunk).into_iter();
                        // One unterminated line grew past MAX_SSE_LINE_BYTES:
                        // refuse the rest of the body with the cap that
                        // tripped, and end. The chunk's own already-decoded
                        // events go with it — a source that has stopped
                        // framing events is not one to keep reading.
                        if pipe.decoder.overflowed() {
                            pipe.done = true;
                            return Some((
                                Err(HttpError::ResponseTooLarge {
                                    limit: MAX_SSE_LINE_BYTES,
                                }),
                                pipe,
                            ));
                        }
                    }
                    Some(Err(err)) => {
                        // The body's error is the stream's error, and the
                        // body drops here, cancelling the upstream.
                        pipe.done = true;
                        return Some((Err(err), pipe));
                    }
                    None => {
                        pipe.done = true;
                        return pipe.decoder.finish().map(|event| (Ok(event), pipe));
                    }
                }
            }
        },
    ))
}

/// The `unfold` state behind [`sse_events`]: the body being drained, the
/// decoder it feeds, the events a chunk produced that have not been
/// yielded yet, and the `done` flag that fuses the pipeline after the
/// body ends or errors.
struct Pipeline {
    body: Option<ByteStream>,
    decoder: SseDecoder,
    pending: std::vec::IntoIter<SseEvent>,
    done: bool,
}

/// How long a [`SseResponse`] may go without an event before it writes a
/// comment heartbeat to the wire. Long enough that a healthy model stream
/// — deltas seconds apart — never sends one, short enough that the
/// proxies in front of a hosted runtime do not time an idle response
/// out. The clock restarts on every event, so this bounds the gap
/// between chunks, never the response's whole life.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

/// A Server-Sent Events response (issue #860): a stream of [`SseEvent`]s
/// bridged to the wire one chunk per event, a `: heartbeat` comment
/// keeping the connection warm over any quiet stretch, and the headers an
/// SSE response needs — `content-type: text/event-stream`,
/// `cache-control: no-cache` and `x-accel-buffering: no` — plus any the
/// caller adds with [`header`](Self::header).
///
/// The body is a [`ResponseStream`], so it bridges exactly the way every
/// streamed response here does: polled directly on native runtimes, and
/// taken out of the response extensions with [`ResponseStream::take`]
/// where an axum body cannot be converted — `runtime-cloudflare`. The
/// heartbeat is timed through the [`Clock`] port —
/// [`Clock::timeout_any`] over a future that never resolves, on an owned
/// clock — so core needs no timer of its own and the same code runs on
/// tokio and on Workers (`futures_timer` cannot fire on wasm).
///
/// # Cancellation
///
/// The body polls its source only when the consumer polls, and drops
/// with it: a client that disconnects drops the body, the body drops the
/// source, and for a source carrying a model stream that is the
/// cancellation contract
/// [`TextModel::stream`](crate::TextModel::stream) carries — the
/// disconnect stops the upstream spend.
///
/// [`Clock::timeout_any`]: crate::Clock::timeout_any
pub struct SseResponse {
    events: BoxStream<'static, SseEvent>,
    clock: Arc<dyn Clock>,
    every: Duration,
    extra_headers: Vec<(HeaderName, HeaderValue)>,
}

impl SseResponse {
    /// Streams `events` as the response body, heartbeating every
    /// [`HEARTBEAT_INTERVAL`] of silence, timed by `clock`.
    #[must_use]
    pub fn new<S>(events: S, clock: Arc<dyn Clock>) -> Self
    where
        S: Stream<Item = SseEvent> + Send + 'static,
    {
        Self {
            events: Box::pin(events),
            clock,
            every: HEARTBEAT_INTERVAL,
            extra_headers: Vec::new(),
        }
    }

    /// Moves the heartbeat interval: a heartbeat after `every` of
    /// silence, or none at all when `every` is zero — a source that
    /// heartbeats itself needs no help, and a response that answers once
    /// needs none.
    #[must_use]
    pub fn heartbeat_every(mut self, every: Duration) -> Self {
        self.every = every;
        self
    }

    /// Adds one header to the response, over the SSE defaults when it
    /// names one of them — the escape hatch for a caller whose proxy in
    /// front needs something else.
    #[must_use]
    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.extra_headers.push((name, value));
        self
    }
}

impl IntoResponse for SseResponse {
    fn into_response(self) -> Response {
        let body = ResponseStream::new(
            SseBody::new(self.events, self.clock, self.every)
                .map(Ok::<Bytes, std::convert::Infallible>),
        );
        // The handle rides on the response the way every `ResponseStream`'s
        // does, so a runtime that bridges by taking the stream out of the
        // extensions — `runtime-cloudflare` — gets this one too.
        let mut response = body.into_response();
        let headers = response.headers_mut();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream"),
        );
        headers.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        );
        headers.insert(
            HeaderName::from_static("x-accel-buffering"),
            HeaderValue::from_static("no"),
        );
        for (name, value) in self.extra_headers {
            headers.insert(name, value);
        }
        response
    }
}

/// The body behind [`SseResponse`]: one chunk per source event, a
/// heartbeat whenever the sleep elapses before the next one, and the end
/// of the source as the end of the stream — heartbeats keep a quiet
/// source's connection warm, they do not keep a dead one open.
struct SseBody {
    source: BoxStream<'static, SseEvent>,
    clock: Arc<dyn Clock>,
    every: Duration,
    /// The heartbeat sleep, armed afresh on every event and every
    /// heartbeat: [`Clock::timeout_any`] over a future that never
    /// resolves, on an owned clock clone. `None` when heartbeats are off.
    ///
    /// [`Clock::timeout_any`]: crate::Clock::timeout_any
    sleep: Option<BoxFuture<'static, Option<()>>>,
}

impl SseBody {
    fn new(source: BoxStream<'static, SseEvent>, clock: Arc<dyn Clock>, every: Duration) -> Self {
        let mut body = Self {
            source,
            clock,
            every,
            sleep: None,
        };
        body.rearm();
        body
    }

    /// Arms a fresh sleep. [`Clock::timeout_any`](crate::Clock::timeout_any)
    /// borrows the clock, so the boxed future owns a clone and the borrow
    /// lives inside it — the body keeps the clock only to re-arm.
    fn rearm(&mut self) {
        if self.every.is_zero() {
            self.sleep = None;
            return;
        }
        let clock = Arc::clone(&self.clock);
        let every = self.every;
        self.sleep = Some(Box::pin(async move {
            timeout::<()>(clock.as_ref(), futures_util::future::pending(), every).await
        }));
    }
}

impl Stream for SseBody {
    type Item = Bytes;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Bytes>> {
        let this = self.get_mut();
        // The source first, on every poll: an event due at the same
        // moment as a heartbeat wins, and the heartbeat's slot is spent
        // on the re-arm instead.
        match this.source.as_mut().poll_next(cx) {
            // One event, one chunk, one flush — no batching, no
            // read-ahead. The clock restarts here: the interval bounds
            // the gap between events.
            Poll::Ready(Some(event)) => {
                this.rearm();
                return Poll::Ready(Some(event.encode()));
            }
            // The source ended, and with it the heartbeats: the stream
            // ends here, and nothing keeps the connection open for it.
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Pending => {}
        }
        let Some(sleep) = this.sleep.as_mut() else {
            return Poll::Pending;
        };
        // Any answer means the interval elapsed — the never-resolving
        // inner future is the only thing the clock could have abandoned.
        // Re-arm before yielding, so the next gap is measured from this
        // heartbeat, not from the last event.
        if sleep.as_mut().poll(cx).is_ready() {
            this.rearm();
            Poll::Ready(Some(Bytes::from_static(b": heartbeat\n\n")))
        } else {
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    /// Decodes `chunks` as one stream would, in order.
    fn decode(chunks: &[&[u8]]) -> Vec<SseEvent> {
        let mut decoder = SseDecoder::default();
        let mut events = Vec::new();
        for chunk in chunks {
            events.extend(decoder.push(chunk));
        }
        events.extend(decoder.finish());
        events
    }

    /// The sample event stream the split tests run against: every field
    /// kind, every line ending. (The `\`-continued literal skips the
    /// newline and the next line's indent, so the pieces below are the
    /// exact bytes.)
    const SAMPLE: &[u8] = b": comment, ignored\r\n\
                           event: token\n\
                           id: 42\r\n\
                           data: first\n\
                           \n\
                           data:second\n\
                           data:   padded\r\n\
                           \n\
                           : another comment\n\
                           data: \xF0\x9F\x8C\xB0\n\
                           \n";

    fn sample_events() -> Vec<SseEvent> {
        vec![
            SseEvent {
                event: Some("token".to_owned()),
                data: "first".to_owned(),
                id: Some("42".to_owned()),
            },
            SseEvent {
                event: None,
                data: "second\n  padded".to_owned(),
                id: Some("42".to_owned()),
            },
            SseEvent {
                event: None,
                data: "\u{1F330}".to_owned(),
                id: Some("42".to_owned()),
            },
        ]
    }

    #[test]
    fn a_stream_decodes_into_its_events() {
        assert_eq!(decode(&[SAMPLE]), sample_events());
    }

    #[test]
    fn a_sample_split_at_every_byte_offset_decodes_the_same() {
        // The chunk boundary must be invisible: every single split point
        // of the sample produces the same events.
        for split in 0..=SAMPLE.len() {
            let events = decode(&[&SAMPLE[..split], &SAMPLE[split..]]);
            assert_eq!(events, sample_events(), "split at {split}");
        }
    }

    #[test]
    fn a_sample_dripped_byte_by_byte_decodes_the_same() {
        let chunks: Vec<&[u8]> = SAMPLE.iter().map(std::slice::from_ref).collect();
        assert_eq!(decode(&chunks), sample_events());
    }

    #[test]
    fn lone_carriage_returns_break_lines_too() {
        // The spec's legacy rule: a bare CR is a line break, so
        // "data:a\r\rdata:b\r\r" frames two events with no LF anywhere —
        // and "data:a\rdata:b\r\r" joins, CR breaking the line exactly
        // like LF would.
        let events = decode(&[b"data:a\r\rdata:b\r\r"]);
        assert_eq!(
            events,
            vec![
                SseEvent {
                    event: None,
                    data: "a".to_owned(),
                    id: None,
                },
                SseEvent {
                    event: None,
                    data: "b".to_owned(),
                    id: None,
                },
            ]
        );
    }

    #[test]
    fn a_crlf_pair_is_one_break_not_two() {
        let events = decode(&[b"data:x\r\ndata:y\r\n\r\n"]);
        assert_eq!(events.len(), 1, "one event, and the second line joined");
        assert_eq!(events[0].data, "x\ny");
    }

    #[test]
    fn an_event_without_data_lines_is_never_dispatched() {
        // `event:` alone, then a blank line: the type buffer resets,
        // nothing dispatches. The trailing `data:` then belongs to a
        // fresh event.
        let events = decode(&[b"event: ping\n\ndata: hi\n\n"]);
        assert_eq!(
            events,
            vec![SseEvent {
                event: None,
                data: "hi".to_owned(),
                id: None,
            }]
        );
    }

    #[test]
    fn an_empty_data_line_still_dispatches_an_empty_event() {
        // One `data:` line with an empty value is a data buffer of one
        // (empty) line: the spec dispatches it, with empty data.
        let events = decode(&[b"data:\n\n"]);
        assert_eq!(
            events,
            vec![SseEvent {
                event: None,
                data: String::new(),
                id: None,
            }]
        );
    }

    #[test]
    fn an_id_persists_and_an_empty_id_clears_it() {
        let events = decode(&[b"id: 1\ndata: a\n\nid: 2\ndata: b\n\nid:\ndata: c\n\n"]);
        let ids: Vec<Option<&str>> = events.iter().map(|event| event.id.as_deref()).collect();
        assert_eq!(ids, vec![Some("1"), Some("2"), None], "{events:?}");
    }

    #[test]
    fn an_id_carrying_a_nul_is_ignored_wholesale() {
        let events = decode(&[b"id: a\0b\ndata: x\n\n"]);
        assert_eq!(events[0].id, None, "{events:?}");
    }

    #[test]
    fn a_leading_byte_order_mark_is_not_content() {
        let events = decode(&[b"\xEF\xBB\xBFdata: hi\n\n"]);
        assert_eq!(events[0].data, "hi");
        // And one that arrives split across the first two chunks: only
        // the true prefix is stripped.
        let events = decode(&[b"\xEF\xBB", b"\xBFdata: hi\n\n"]);
        assert_eq!(events[0].data, "hi");
    }

    #[test]
    fn utf8_split_across_chunks_survives() {
        // The acorn is three bytes past the label; split inside it.
        let events = decode(&[b"data: \xF0\x9F", b"\x8C\xB0\n\n"]);
        assert_eq!(events[0].data, "\u{1F330}");
    }

    #[test]
    fn finish_discards_an_unterminated_event_and_resets() {
        let mut decoder = SseDecoder::default();
        assert!(decoder.push(b"data: half").is_empty());
        assert_eq!(decoder.finish(), None, "no blank line, no event");

        // Reset: the next body decodes from empty.
        let events = decoder.push(b"data: fresh\n\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "fresh");
        assert_eq!(decoder.finish(), None);
    }

    #[test]
    fn a_line_at_the_ceiling_is_an_event_a_line_past_it_overflows() {
        // `data: ` plus a payload of exactly the ceiling: the whole line
        // fits, terminates, and dispatches like any other.
        let mut decoder = SseDecoder::default();
        let at_cap = format!("data: {}\n\n", "a".repeat(MAX_SSE_LINE_BYTES - 6));
        let events = decoder.push(at_cap.as_bytes());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data.len(), MAX_SSE_LINE_BYTES - 6);
        assert!(!decoder.overflowed(), "a line at the cap is a line");

        // One byte past it, unterminated: the overflow latches, the line
        // is released, later pushes are ignored, and finish resets the
        // decoder for the next body.
        let mut decoder = SseDecoder::default();
        let over = format!("data: {}", "a".repeat(MAX_SSE_LINE_BYTES));
        assert!(decoder.push(over.as_bytes()).is_empty());
        assert!(decoder.overflowed());
        assert!(
            decoder.push(b"data: more\n\n").is_empty(),
            "a fused decoder takes nothing more"
        );
        assert_eq!(decoder.finish(), None);
        assert!(!decoder.overflowed(), "finish resets the latch");
        let events = decoder.push(b"data: fresh\n\n");
        assert_eq!(events.len(), 1, "the next body decodes from empty");
    }

    #[test]
    fn complete_lines_never_trip_the_ceiling_however_large_the_chunk() {
        // The cap is on one *unterminated* line: a chunk many times the
        // ceiling of whole lines is ordinary input, decoded in full.
        let line = format!("data: {}\n\n", "a".repeat(MAX_SSE_LINE_BYTES - 6));
        let mut body = String::new();
        body.push_str(&line.repeat(3));
        let mut decoder = SseDecoder::default();
        let events = decoder.push(body.as_bytes());
        assert_eq!(events.len(), 3);
        assert!(!decoder.overflowed());
    }

    #[pollster::test]
    async fn sse_events_refuses_a_line_past_the_ceiling_and_ends() {
        let small = b"data: small\n\n".to_vec();
        let oversized = format!("data: {}", "x".repeat(MAX_SSE_LINE_BYTES + 1));
        let body: ByteStream = Box::pin(futures_util::stream::iter(vec![
            Ok::<Bytes, HttpError>(Bytes::from(small)),
            Ok(Bytes::from(oversized)),
        ]));
        let items: Vec<Result<SseEvent, HttpError>> = sse_events(body).collect().await;
        assert_eq!(
            items.len(),
            2,
            "the small event, then the refusal, then the end: {items:?}"
        );
        assert_eq!(items[0].as_ref().expect("the small event").data, "small");
        assert!(
            matches!(
                &items[1],
                Err(HttpError::ResponseTooLarge { limit }) if *limit == MAX_SSE_LINE_BYTES
            ),
            "the line ceiling is the limit: {:?}",
            items[1]
        );
    }

    #[pollster::test]
    async fn sse_events_drains_a_body_into_events() {
        let body: ByteStream = Box::pin(futures_util::stream::iter(vec![
            Ok::<Bytes, HttpError>(Bytes::from_static(b"event: a\ndata: one")),
            Ok(Bytes::from_static(b"\n\ndata: two\n\n")),
        ]));
        let events: Vec<SseEvent> = sse_events(body)
            .filter_map(|item| async move { item.ok() })
            .collect()
            .await;
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event.as_deref(), Some("a"));
        assert_eq!(events[0].data, "one");
        assert_eq!(events[1].data, "two");
    }

    #[pollster::test]
    async fn sse_events_surfaces_a_body_error_and_ends() {
        let body: ByteStream = Box::pin(futures_util::stream::iter(vec![
            Ok::<Bytes, HttpError>(Bytes::from_static(b"data: one\n\n")),
            Err(HttpError::Transport("socket dropped".to_owned())),
        ]));
        let items: Vec<Result<SseEvent, HttpError>> = sse_events(body).collect().await;
        assert_eq!(items.len(), 2, "the event, then the error, then the end");
        assert_eq!(items[0].as_ref().unwrap().data, "one");
        assert!(items[1].is_err(), "the transport error surfaces as-is");
    }

    /// Encodes `event` and decodes it straight back through the real
    /// decoder — the round-trip `encode` promises.
    fn round_trip(event: &SseEvent) -> Vec<SseEvent> {
        let mut decoder = SseDecoder::default();
        decoder.push(&event.encode())
    }

    #[test]
    fn an_event_encodes_to_what_the_decoder_reads_back() {
        let event = SseEvent {
            event: Some("token".to_owned()),
            data: "first\nsecond".to_owned(),
            id: Some("42".to_owned()),
        };
        assert_eq!(round_trip(&event), vec![event.clone()]);

        // The exact framing: named fields first, one `data:` line per
        // data line, the blank line that dispatches last.
        assert_eq!(
            &event.encode()[..],
            b"event: token\nid: 42\ndata: first\ndata: second\n\n"
        );
    }

    #[test]
    fn crlf_and_a_lone_cr_break_data_lines_when_encoding() {
        // The encoder splits on the decoder's three line endings, so the
        // decoded data — the join of the data lines — is the same however
        // the original was broken.
        let event = SseEvent::new("a\r\nb\rc\nd");
        assert_eq!(
            round_trip(&event),
            vec![SseEvent {
                event: None,
                data: "a\nb\nc\nd".to_owned(),
                id: None,
            }]
        );
    }

    #[test]
    fn a_line_break_in_event_or_id_cannot_forge_a_field() {
        let event = SseEvent {
            event: Some("to\r\nid: forged".to_owned()),
            data: "x".to_owned(),
            id: Some("a\nbroke".to_owned()),
        };
        let decoded = round_trip(&event);
        assert_eq!(decoded.len(), 1, "one event, not two");
        assert_eq!(decoded[0].event.as_deref(), Some("toid: forged"));
        assert_eq!(decoded[0].id.as_deref(), Some("abroke"));
    }

    #[test]
    fn an_encoding_survives_being_dripped_byte_by_byte() {
        let event = SseEvent {
            event: Some("tick".to_owned()),
            data: "one\ntwo".to_owned(),
            id: None,
        };
        let wire = event.encode();
        let mut decoder = SseDecoder::default();
        let mut events = Vec::new();
        for byte in &wire {
            events.extend(decoder.push(std::slice::from_ref(byte)));
        }
        assert_eq!(events, vec![event]);
    }
}
