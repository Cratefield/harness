//! `tracing-subscriber` JSON to stdout (issue #19) with the crate-wide
//! redaction rules applied in the formatter — the native counterpart of
//! `factory0-runtime-cloudflare`'s hand-rolled console subscriber (which
//! exists because a dispatcher hangs the workerd isolate; none of that
//! applies on tokio, so here the real subscriber runs).
//!
//! One JSON line per event: `timestamp`, `level`, `target`, the event's
//! fields (secret-ish names `[redacted]`, email-ish values as truncated
//! SHA-256 hashes — the rules live in `factory0-core` so Workers and
//! native logs cannot drift). Span fields are not emitted as events; the
//! per-request span is carried on the `Scope`, its shape asserted by
//! core's tests. `RUST_LOG` sets the filter (default `info`).

use std::fmt;
use std::sync::OnceLock;

use serde_json::{Map, Value, json};
use tracing::field::Visit;
use tracing::{Event, Subscriber};
use tracing_subscriber::Registry;
use tracing_subscriber::fmt as ts_fmt;
use tracing_subscriber::fmt::format::{DefaultFields, Writer};
use tracing_subscriber::fmt::{FmtContext, FormatEvent};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;

static INSTALLED: OnceLock<()> = OnceLock::new();

/// Installs the stdout JSON subscriber exactly once per process.
/// Process-wide infrastructure installed before the first response, not
/// request state (ADR 0007). Fails silently only when the process
/// already installed another global subscriber (e.g. a test harness),
/// which then keeps receiving the events.
pub fn install_tracing() {
    INSTALLED.get_or_init(|| {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        let fmt_layer = ts_fmt::Layer::default()
            .event_format(RedactingJson)
            .with_writer(std::io::stdout);
        let subscriber = Registry::default().with(filter).with(fmt_layer);
        let _ = tracing::subscriber::set_global_default(subscriber);
    });
}

/// A `FormatEvent` that mirrors the Workers subscriber's JSON line with
/// core's redaction rules applied to every field. Serializes to a string
/// first: the tracing `Writer` only implements `fmt::Write`.
struct RedactingJson;

impl<S> FormatEvent<S, DefaultFields> for RedactingJson
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, DefaultFields>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut visitor = RedactingVisitor::default();
        event.record(&mut visitor);

        let metadata = event.metadata();
        let mut fields = visitor.fields;
        fields.insert("level".into(), json!(metadata.level().as_str()));
        fields.insert("target".into(), json!(metadata.target()));
        let timestamp = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "unknown".to_owned());
        fields.insert("timestamp".into(), json!(timestamp));

        writer.write_str(&Value::Object(fields).to_string())?;
        writer.write_char('\n')
    }
}

/// The field half of runtime-cloudflare's `JsonRedactingVisitor`: the
/// redaction rules themselves are `factory0_core::redacted_value`.
#[derive(Default)]
struct RedactingVisitor {
    fields: Map<String, Value>,
}

impl RedactingVisitor {
    fn record_field(&mut self, name: &str, value: &str) {
        let redacted = factory0_core::redacted_value(name, value);
        if redacted == "[redacted]" {
            self.fields.insert(name.to_owned(), json!("[redacted]"));
        } else if let Some(hash) = redacted.strip_prefix("subject_hash:") {
            self.fields
                .insert(format!("{name}_hash"), json!(format!("sha256:{hash}")));
        } else {
            self.fields.insert(name.to_owned(), json!(value));
        }
    }
}

impl Visit for RedactingVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.record_field(field.name(), value);
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        self.record_field(field.name(), &format!("{value:?}"));
    }

    fn record_error(
        &mut self,
        field: &tracing::field::Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        self.record_field(field.name(), &value.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visitor_redacts_like_core() {
        let mut visitor = RedactingVisitor::default();
        visitor.record_field("authorization", "Bearer x");
        visitor.record_field("email", "nick@example.com");
        visitor.record_field("outcome", "sent");
        assert_eq!(visitor.fields["authorization"], "[redacted]");
        assert!(
            visitor.fields["email_hash"]
                .as_str()
                .is_some_and(|hash| hash.starts_with("sha256:"))
        );
        assert_eq!(visitor.fields["outcome"], "sent");
    }
}
