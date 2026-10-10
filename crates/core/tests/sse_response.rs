//! `SseResponse` and `ui_message_response` over the wire (issue #860):
//! the headers a client sees, the heartbeat that fires only through a
//! test-triggered clock, the framing of a whole UI message stream, and
//! the cancellation contract — a consumer that takes the stream from the
//! response's extensions and drops it drops the model upstream with it.
//!
//! No real time passes anywhere: the heartbeat tests drive the body by
//! hand with a no-op waker and resolve sleeps by firing their trigger,
//! so a missing heartbeat fails the test instead of hanging it.
#![expect(
    clippy::disallowed_types,
    reason = "the fakes record and fire their state, as the stubs in cratefield-testing do"
)]

use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use async_trait::async_trait;
use axum::response::IntoResponse;
use bytes::Bytes;
use futures_core::future::BoxFuture;
use futures_util::StreamExt as _;
use http::{HeaderName, HeaderValue};

use cratefield_core::sse::ui_message::{UiMessageChunk, text_stream_chunks, ui_message_response};
use cratefield_core::sse::{SseEvent, SseResponse};
use cratefield_core::{
    BoxStream, Clock, ModelTier, Prompt, ResponseStream, SystemClock, TextDelta, TextModel,
    TextModelError, stream_owned,
};

/// A [`Clock`] whose sleeps resolve only when the test fires their
/// trigger: a heartbeat becomes observable without real time and without
/// a busy loop — the trigger wakes the sleeping future and the next hand
/// poll sees it.
struct TriggerClock {
    /// One entry per sleep, in the order they were armed.
    sleeps: Mutex<Vec<Arc<Trigger>>>,
}

#[derive(Default)]
struct Trigger {
    fired: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl Trigger {
    /// Resolves the sleeping future and wakes it, so the next poll
    /// observes the timeout.
    fn fire(&self) {
        self.fired.store(true, Ordering::SeqCst);
        if let Some(waker) = self.waker.lock().expect("trigger lock").take() {
            waker.wake();
        }
    }
}

/// The sleep a [`TriggerClock`] hands back: `None` once its trigger
/// fires — a timeout with nothing to report — and never otherwise.
struct Sleep {
    trigger: Arc<Trigger>,
}

impl Future for Sleep {
    type Output = Option<Box<dyn Any + Send>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.trigger.fired.load(Ordering::SeqCst) {
            return Poll::Ready(None);
        }
        *self.trigger.waker.lock().expect("trigger lock") = Some(cx.waker().clone());
        Poll::Pending
    }
}

#[async_trait]
impl Clock for TriggerClock {
    fn now(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::UNIX_EPOCH
    }

    async fn timeout_any(
        &self,
        _fut: BoxFuture<'static, Box<dyn Any + Send>>,
        _after: Duration,
    ) -> Option<Box<dyn Any + Send>> {
        let trigger = Arc::new(Trigger::default());
        self.sleeps
            .lock()
            .expect("sleeps lock")
            .push(Arc::clone(&trigger));
        Sleep { trigger }.await
    }
}

impl TriggerClock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            sleeps: Mutex::new(Vec::new()),
        })
    }

    /// How many sleeps were armed — the observable of "the timer reset".
    fn sleeps_armed(&self) -> usize {
        self.sleeps.lock().expect("sleeps lock").len()
    }

    /// Fires the `index`th sleep armed, oldest first.
    fn fire(&self, index: usize) {
        self.sleeps.lock().expect("sleeps lock")[index].fire();
    }
}

/// What one hand poll of a body stream saw.
enum Timed<T> {
    Ready(T),
    Pending,
}

/// Polls the stream once, by hand, with the no-op waker.
fn poll_next<S>(stream: &mut S) -> Timed<Option<S::Item>>
where
    S: futures_core::Stream + Unpin,
{
    // The no-op waker: the tests poll by hand and fire triggers
    // explicitly, so a wake carries no information.
    let mut cx = Context::from_waker(Waker::noop());
    match Pin::new(stream).poll_next(&mut cx) {
        Poll::Ready(item) => Timed::Ready(item),
        Poll::Pending => Timed::Pending,
    }
}

/// A body data frame as bytes, for the assertions below.
fn ready_bytes(frame: Option<Result<Bytes, axum::Error>>) -> Bytes {
    frame
        .expect("the body produced a frame")
        .expect("the body chunked cleanly")
}

#[test]
fn a_quiet_stream_heartbeats_when_its_trigger_fires() {
    let clock = TriggerClock::new();
    let response = SseResponse::new(futures_util::stream::pending::<SseEvent>(), clock.clone())
        .into_response();
    let mut body = response.into_body().into_data_stream();

    // The poll parks on the interval's one sleep.
    assert!(matches!(poll_next(&mut body), Timed::Pending));
    assert_eq!(clock.sleeps_armed(), 1);

    // The trigger fires: the timeout resolves to nothing, and the body
    // answers with the comment instead.
    clock.fire(0);
    let Timed::Ready(frame) = poll_next(&mut body) else {
        panic!("the fired trigger did not produce the heartbeat");
    };
    assert_eq!(ready_bytes(frame), &b": heartbeat\n\n"[..]);

    // The timer rearmed: the next quiet stretch needs its own firing.
    assert!(matches!(poll_next(&mut body), Timed::Pending));
    assert_eq!(clock.sleeps_armed(), 2);
    clock.fire(1);
    let Timed::Ready(frame) = poll_next(&mut body) else {
        panic!("the second heartbeat never came");
    };
    assert_eq!(ready_bytes(frame), &b": heartbeat\n\n"[..]);
}

#[test]
fn an_event_resets_the_heartbeat_timer() {
    let clock = TriggerClock::new();
    let source =
        futures_util::stream::iter([SseEvent::new("only")]).chain(futures_util::stream::pending());
    let response = SseResponse::new(source, clock.clone()).into_response();
    let mut body = response.into_body().into_data_stream();

    let Timed::Ready(frame) = poll_next(&mut body) else {
        panic!("the first poll answers with the event");
    };
    assert_eq!(ready_bytes(frame), &b"data: only\n\n"[..]);

    // The event reset the timer: the construction sleep was replaced
    // before anything waited on it, so no trigger ever armed for it.
    assert_eq!(clock.sleeps_armed(), 0);

    // The quiet stretch after the event parks on a fresh sleep, and only
    // firing that one heartbeats.
    assert!(matches!(poll_next(&mut body), Timed::Pending));
    assert_eq!(clock.sleeps_armed(), 1);
    clock.fire(0);
    let Timed::Ready(frame) = poll_next(&mut body) else {
        panic!("the fresh trigger did not heartbeat");
    };
    assert_eq!(ready_bytes(frame), &b": heartbeat\n\n"[..]);
    assert_eq!(clock.sleeps_armed(), 1, "one sleep per quiet stretch");
}

#[test]
fn the_source_ending_ends_the_stream_without_a_heartbeat() {
    let clock = TriggerClock::new();
    let response = SseResponse::new(futures_util::stream::iter([SseEvent::new("done")]), clock)
        .into_response();
    let mut body = response.into_body().into_data_stream();

    assert!(matches!(poll_next(&mut body), Timed::Ready(Some(_))));
    assert!(
        matches!(poll_next(&mut body), Timed::Ready(None)),
        "the source's end is the stream's end"
    );
    // There is nothing left to heartbeat: the sleep went with the body.
    assert!(matches!(poll_next(&mut body), Timed::Ready(None)));
}

#[test]
fn a_zero_heartbeat_never_arms_a_sleep() {
    let clock = TriggerClock::new();
    let response = SseResponse::new(futures_util::stream::pending::<SseEvent>(), clock.clone())
        .heartbeat_every(Duration::ZERO)
        .into_response();
    let mut body = response.into_body().into_data_stream();

    assert!(matches!(poll_next(&mut body), Timed::Pending));
    assert_eq!(clock.sleeps_armed(), 0, "off is off: no timer armed");
}

#[test]
fn the_sse_headers_are_set_and_the_caller_owns_the_rest() {
    let response = SseResponse::new(
        futures_util::stream::empty::<SseEvent>(),
        Arc::new(SystemClock),
    )
    .header(
        HeaderName::from_static("x-session-id"),
        HeaderValue::from_static("route-set"),
    )
    .into_response();
    let (parts, _body) = response.into_parts();

    assert_eq!(parts.headers["content-type"], "text/event-stream");
    assert_eq!(parts.headers["cache-control"], "no-cache");
    assert_eq!(parts.headers["x-accel-buffering"], "no");
    assert_eq!(parts.headers["x-session-id"], "route-set");
}

#[test]
fn a_ui_message_response_names_its_dialect_and_frames_the_marker() {
    let chunks = futures_util::stream::iter(vec![
        UiMessageChunk::Start {
            message_id: Some("m1".to_owned()),
            message_metadata: None,
        },
        UiMessageChunk::StartStep,
        UiMessageChunk::Finish {
            finish_reason: None,
            message_metadata: None,
        },
    ]);
    let response = ui_message_response(chunks, Arc::new(SystemClock)).into_response();
    let (parts, body) = response.into_parts();

    assert_eq!(
        parts.headers["x-vercel-ai-ui-message-stream"], "v1",
        "the dialect header rides on top of the SSE ones"
    );
    let bytes = pollster::block_on(axum::body::to_bytes(body, 64 * 1024))
        .expect("the body reads to its end");

    // Every event is one data line of JSON; the marker is the last.
    let events: Vec<&str> = std::str::from_utf8(&bytes)
        .expect("the body is utf-8")
        .split("\n\n")
        .filter(|event| !event.is_empty())
        .collect();
    let data: Vec<&str> = events
        .iter()
        .map(|event| event.strip_prefix("data: ").expect("a data line"))
        .collect();
    assert_eq!(data.last(), Some(&"[DONE]"), "the marker closes the stream");
    let chunks: Vec<serde_json::Value> = data[..data.len() - 1]
        .iter()
        .map(|line| serde_json::from_str(line).expect("every chunk is JSON"))
        .collect();
    assert_eq!(chunks[0]["type"], "start");
    assert_eq!(chunks[0]["messageId"], "m1");
    assert_eq!(chunks[1]["type"], "start-step");
    assert_eq!(chunks[2]["type"], "finish");
}

/// A model that hands out one delta and then never answers again: the
/// state only a dropped consumer cancels. The stream it returns clears
/// the open flag when dropped, which is how the test sees the
/// cancellation.
struct HoldingModel {
    open: Arc<AtomicBool>,
    produced: Arc<AtomicUsize>,
}

impl HoldingModel {
    fn new() -> (Arc<Self>, Arc<AtomicBool>, Arc<AtomicUsize>) {
        let open = Arc::new(AtomicBool::new(false));
        let produced = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(Self {
                open: Arc::clone(&open),
                produced: Arc::clone(&produced),
            }),
            open,
            produced,
        )
    }
}

#[async_trait]
impl TextModel for HoldingModel {
    async fn complete(
        &self,
        _prompt: &Prompt,
    ) -> Result<cratefield_core::Completion, TextModelError> {
        Err(TextModelError::NotConfigured)
    }

    fn stream<'a>(
        &'a self,
        _prompt: &'a Prompt,
    ) -> BoxStream<'a, Result<TextDelta, TextModelError>> {
        self.open.store(true, Ordering::SeqCst);
        Box::pin(HoldingStream {
            open: Arc::clone(&self.open),
            produced: Arc::clone(&self.produced),
            gave: false,
        })
    }

    fn supports(&self, _tier: ModelTier, _capability: cratefield_core::Capability) -> bool {
        true
    }
}

/// The held model stream: one delta, then pending forever, and the open
/// flag clears exactly when the stream is dropped.
struct HoldingStream {
    open: Arc<AtomicBool>,
    produced: Arc<AtomicUsize>,
    gave: bool,
}

impl futures_core::Stream for HoldingStream {
    type Item = Result<TextDelta, TextModelError>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.gave {
            return Poll::Pending;
        }
        this.gave = true;
        this.produced.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Some(Ok(TextDelta::Text("first".to_owned()))))
    }
}

impl Drop for HoldingStream {
    fn drop(&mut self) {
        self.open.store(false, Ordering::SeqCst);
    }
}

#[test]
fn dropping_the_taken_stream_cancels_the_model_upstream() {
    let (model, open, produced) = HoldingModel::new();
    let prompt = Prompt::new(ModelTier::Fast).user("hello");
    let response = ui_message_response(
        text_stream_chunks(stream_owned(model, prompt)),
        Arc::new(SystemClock),
    )
    .into_response();

    // The runtime path: take the stream from the extensions instead of
    // polling the axum body.
    let handle = response
        .extensions()
        .get::<ResponseStream>()
        .cloned()
        .expect("the response carries the stream handle");
    let mut taken = handle.take().expect("the body has not consumed the stream");

    // Read exactly one chunk — the opening `start` — then hang up.
    let first = pollster::block_on(taken.next())
        .expect("the first chunk")
        .expect("the chunk is infallible");
    assert!(
        first.starts_with(b"data: {\"type\":\"start\""),
        "the first chunk opens the message: {first:?}"
    );
    drop(taken);

    // The model's stream is gone, and nothing was pulled past the one
    // delta the first chunk consumed.
    assert!(!open.load(Ordering::SeqCst), "the model stream was dropped");
    assert_eq!(
        produced.load(Ordering::SeqCst),
        1,
        "no delta beyond the one read was produced"
    );
}
