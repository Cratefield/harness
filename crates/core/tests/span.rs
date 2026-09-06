//! Issue #14 acceptance: one structured span per request with
//! `request_id`, `method`, `route` (matched, not raw), `module`,
//! `status`, `duration_ms`, `ip_hash`, `ua_family` — and no email can
//! appear in any of them.

// Test-side recording fixture, not request state — the same category
// and allowance as the fakes in `factory0-testing` (ADR 0007 policy).
#![allow(clippy::disallowed_types)]

mod common;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::http::{HeaderValue, Method, Request, StatusCode, header};
use common::*;
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

#[derive(Default)]
struct SpanCapturingSubscriber {
    spans: Mutex<Vec<(String, BTreeMap<String, String>)>>,
}

impl SpanCapturingSubscriber {
    fn snapshot(&self, name: &str) -> BTreeMap<String, String> {
        self.spans
            .lock()
            .expect("span lock")
            .iter()
            .filter(|(span_name, _)| span_name == name)
            .map(|(_, fields)| fields.clone())
            .reduce(|mut merged, next| {
                merged.extend(next);
                merged
            })
            .unwrap_or_default()
    }
}

impl Subscriber for SpanCapturingSubscriber {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, attributes: &Attributes<'_>) -> Id {
        let mut visitor = FieldCollector::default();
        attributes.record(&mut visitor);
        self.spans
            .lock()
            .expect("span lock")
            .push((attributes.metadata().name().to_owned(), visitor.fields));
        Id::from_u64(1)
    }

    fn record(&self, _id: &Id, values: &Record<'_>) {
        let mut visitor = FieldCollector::default();
        values.record(&mut visitor);
        let mut spans = self.spans.lock().expect("span lock");
        if let Some((_, fields)) = spans.last_mut() {
            fields.extend(visitor.fields);
        }
    }

    fn record_follows_from(&self, _follows: &Id, _to: &Id) {}

    fn event(&self, _event: &Event<'_>) {}

    fn enter(&self, _id: &Id) {}

    fn exit(&self, _id: &Id) {}
}

#[derive(Default)]
struct FieldCollector {
    fields: BTreeMap<String, String>,
}

impl tracing::field::Visit for FieldCollector {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields
            .insert(field.name().to_owned(), value.to_owned());
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.fields
            .insert(field.name().to_owned(), format!("{value:?}"));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields
            .insert(field.name().to_owned(), format!("{value}"));
    }
}

#[derive(Clone)]
struct SharedSubscriber(Arc<SpanCapturingSubscriber>);

impl Subscriber for SharedSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.0.enabled(metadata)
    }
    fn new_span(&self, attributes: &Attributes<'_>) -> Id {
        self.0.new_span(attributes)
    }
    fn record(&self, id: &Id, values: &Record<'_>) {
        self.0.record(id, values);
    }
    fn record_follows_from(&self, follows: &Id, to: &Id) {
        self.0.record_follows_from(follows, to);
    }
    fn event(&self, event: &Event<'_>) {
        self.0.event(event);
    }
    fn enter(&self, id: &Id) {
        self.0.enter(id);
    }
    fn exit(&self, id: &Id) {
        self.0.exit(id);
    }
}

fn assert_is_hash(value: &str) {
    assert_eq!(value.len(), 12, "ip_hash shape: {value}");
    assert!(value.chars().all(|c| c.is_ascii_hexdigit()), "{value}");
}

#[test]
fn request_span_shape_snapshot() {
    let harness = harness_with_sample();
    let router = harness.router(ports_with(None));
    let subscriber = SharedSubscriber(Arc::default());
    let dispatch = tracing::dispatcher::Dispatch::new(subscriber.clone());

    tracing::dispatcher::with_default(&dispatch, || {
        pollster::block_on(async {
            let request = Request::builder()
                .method(Method::GET)
                .uri("/v1/sample/hello")
                .header("cf-connecting-ip", HeaderValue::from_static("203.0.113.9"))
                .header(
                    header::USER_AGENT,
                    HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"),
                )
                .body(axum::body::Body::empty())
                .expect("request");
            let response = tower::ServiceExt::oneshot(router, request)
                .await
                .expect("router answers");
            assert_eq!(response.status(), StatusCode::OK);
        });
    });

    let fields = subscriber.0.snapshot("request");
    assert_eq!(fields["method"], "GET");
    assert_eq!(fields["route"], "/v1/sample/hello", "matched path, not raw");
    assert_eq!(fields["module"], "sample");
    assert_eq!(fields["status"], "200");
    assert!(
        fields["duration_ms"].parse::<u64>().is_ok(),
        "duration_ms: {}",
        fields["duration_ms"]
    );
    assert_is_hash(&fields["ip_hash"]);
    assert_eq!(fields["ua_family"], "mozilla");
    assert!(
        fields.contains_key("request_id"),
        "request id on the span: {fields:?}"
    );
    assert!(
        !fields.values().any(|value| value.contains('@')),
        "no emails on the span: {fields:?}"
    );

    // Snapshot the shape: value-stable fields verbatim, timing values
    // normalized so snapshots stay deterministic.
    let mut shape: Vec<String> = fields
        .iter()
        .map(|(name, value)| {
            if name == "duration_ms" || name == "ip_hash" || name == "request_id" {
                format!(
                    "{name}=<{}>",
                    if name == "ip_hash" { "12-hex" } else { "value" }
                )
            } else {
                format!("{name}={value}")
            }
        })
        .collect();
    shape.sort();
    insta::assert_snapshot!(shape.join("\n"));
}
