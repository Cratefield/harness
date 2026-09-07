//! Tracing on Workers and native runs.
//!
//! **wasm32:** installing any tracing dispatcher (`set_global_default`,
//! `set_default`) hangs the single-threaded workerd/miniflare isolate
//! (verified empirically on wrangler 4.129). So `install_tracing` installs no
//! dispatcher on wasm; instead it registers a forwarder with core
//! ([`cratefield_core::set_error_forwarder`]) so core's internal-error
//! diagnostics — every `tracing::error!` that maps a failure to a 500 — reach
//! `worker::console_error!` instead of vanishing (issue #107). Runtime logging
//! goes through the crate's `rt_log!` macro, which writes plain lines to
//! `worker::console_log!`/`console_error!` (Workers Logs picks them up).
//!
//! **Native (tests, the future `runtime-native`):** a hand-rolled
//! subscriber writes one JSON line per event with field redaction per
//! architecture section 11 — names matching
//! `(?i)secret|token|key|authorization|password` become `[redacted]`, and
//! email-ish fields are logged only as a truncated SHA-256 hash (rules
//! in `cratefield_core::logging`, so runtimes cannot drift). Span fields
//! are not emitted as events; the per-request span (issue #14) is
//! carried on the `Scope` and its shape is asserted by core's tests.

use std::sync::OnceLock;

static INSTALLED: OnceLock<()> = OnceLock::new();

/// Installs the console JSON subscriber exactly once per process. This is
/// process-wide infrastructure installed before the first response, not
/// request state (ADR 0007). No-op on wasm32 (see module docs).
pub fn install_tracing() {
    #[cfg(target_arch = "wasm32")]
    INSTALLED.get_or_init(|| {
        // No tracing dispatcher on wasm (it hangs the isolate). Instead give
        // core a forwarder so its internal-error diagnostics — the ones that
        // map a failure to a 500 — reach Workers Logs via `console_error!`,
        // rather than vanishing (issue #107).
        cratefield_core::set_error_forwarder(|line| worker::console_error!("[error] {line}"));
    });
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
    use std::sync::atomic::AtomicU64;

    use serde_json::{Map, Value, json};
    use tracing::field::Visit;
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Level, Metadata, Subscriber};

    /// Extends core's [`RedactingVisitor`] with the JSON representation
    /// the console line needs; the redaction rules themselves live in
    /// core so every runtime shares them.
    #[derive(Default)]
    struct JsonRedactingVisitor {
        fields: Map<String, Value>,
    }

    impl JsonRedactingVisitor {
        fn record_field(&mut self, name: &str, value: &str) {
            let redacted = cratefield_core::redacted_value(name, value);
            if redacted == "[redacted]" {
                self.fields.insert(name.to_owned(), json!("[redacted]"));
            } else if let Some(hash) = redacted.strip_prefix("subject_hash:").map(str::to_owned) {
                self.fields
                    .insert(format!("{name}_hash"), json!(format!("sha256:{hash}")));
            } else {
                self.fields.insert(name.to_owned(), json!(value));
            }
        }
    }

    impl Visit for JsonRedactingVisitor {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.record_field(field.name(), value);
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
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
            let mut visitor = JsonRedactingVisitor::default();
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
