//! Tracing on Workers and native runs.
//!
//! **wasm32:** installing any tracing dispatcher (`set_global_default`,
//! `set_default`) hangs the single-threaded workerd/miniflare isolate
//! (verified empirically on wrangler 4.129). `install_tracing` is therefore
//! a no-op on wasm, and runtime logging goes through the crate's `rt_log!`
//! macro, which writes plain lines to `worker::console_log!`/`console_error!`
//! (Workers Logs picks them up).
//!
//! **Native (tests, the future `runtime-native`):** a hand-rolled
//! subscriber writes one JSON line per event with field redaction per
//! architecture section 11 — names matching
//! `(?i)secret|token|key|authorization|password` become `[redacted]`, and
//! email-ish fields are logged only as a truncated SHA-256 hash. Span
//! fields are not emitted; harness spans carry only the request id.

use std::sync::OnceLock;

static INSTALLED: OnceLock<()> = OnceLock::new();

/// Installs the console JSON subscriber exactly once per process. This is
/// process-wide infrastructure installed before the first response, not
/// request state (ADR 0007). No-op on wasm32 (see module docs).
pub fn install_tracing() {
    #[cfg(target_arch = "wasm32")]
    {
        let _ = INSTALLED;
    }
    #[cfg(not(target_arch = "wasm32"))]
    INSTALLED.get_or_init(|| {
        let guard = tracing::dispatcher::set_default(&tracing::dispatcher::Dispatch::new(
            ConsoleSubscriber {
                next_span: AtomicU64::new(0),
            },
        ));
        std::mem::forget(guard);
    });
}

#[cfg(not(target_arch = "wasm32"))]
mod native_subscriber {
    use std::fmt;
    use std::sync::atomic::AtomicU64;

    use serde_json::{Map, Value, json};
    use sha2::{Digest, Sha256};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Level, Metadata, Subscriber};

    fn redact_field(name: &str) -> bool {
        let lowered = name.to_ascii_lowercase();
        ["secret", "token", "key", "authorization", "password"]
            .iter()
            .any(|needle| lowered.contains(needle))
    }

    fn is_email_field(name: &str) -> bool {
        let lowered = name.to_ascii_lowercase();
        lowered.contains("email") || lowered == "subject"
    }

    fn subject_hash(value: &str) -> String {
        let digest = Sha256::digest(value.as_bytes());
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).take(16).collect();
        format!("sha256:{hex}")
    }

    #[derive(Default)]
    struct RedactingVisitor {
        fields: Map<String, Value>,
    }

    impl RedactingVisitor {
        fn record_field(&mut self, name: &str, value: &str) {
            if redact_field(name) {
                self.fields.insert(name.to_string(), json!("[redacted]"));
            } else if is_email_field(name) && value.contains('@') {
                self.fields
                    .insert(format!("{name}_hash"), json!(subject_hash(value)));
            } else {
                self.fields.insert(name.to_string(), json!(value));
            }
        }
    }

    impl Visit for RedactingVisitor {
        fn record_str(&mut self, field: &Field, value: &str) {
            self.record_field(field.name(), value);
        }

        fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
            let formatted = format!("{value:?}");
            self.record_field(field.name(), &formatted);
        }

        fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
            let formatted = value.to_string();
            self.record_field(field.name(), &formatted);
        }
    }

    pub struct ConsoleSubscriber {
        pub next_span: AtomicU64,
    }

    impl Subscriber for ConsoleSubscriber {
        fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _span: &Attributes<'_>) -> Id {
            use std::sync::atomic::Ordering;
            let next = self.next_span.fetch_add(1, Ordering::Relaxed) + 1;
            Id::from_u64(next)
        }

        fn record(&self, _span: &Id, _values: &Record<'_>) {}

        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

        fn event(&self, event: &Event<'_>) {
            let mut visitor = RedactingVisitor::default();
            event.record(&mut visitor);

            let metadata = event.metadata();
            visitor
                .fields
                .insert("level".into(), json!(metadata.level().as_str()));
            visitor
                .fields
                .insert("target".into(), json!(metadata.target()));

            let timestamp = time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "unknown".to_string());
            visitor.fields.insert("timestamp".into(), json!(timestamp));

            let line = Value::Object(visitor.fields).to_string();
            if *metadata.level() == Level::ERROR {
                worker::console_error!("{line}");
            } else {
                worker::console_log!("{line}");
            }
        }

        fn enter(&self, _span: &Id) {}

        fn exit(&self, _span: &Id) {}
    }
}

#[cfg(not(target_arch = "wasm32"))]
use native_subscriber::ConsoleSubscriber;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::atomic::AtomicU64;
