//! The in-process event bus (issue #4, architecture section 4).
//!
//! It exists so `waitlist.confirmed` can feed `email-signup` without a crate
//! dependency between them. Handlers run through the request's [`Scope`]
//! defer (`wait_until` on Workers); errors are logged with the event name
//! and never fail the request. There is **no ordering guarantee and no
//! persistence** — if the isolate dies between response and deferred run,
//! the event is lost. Durable workflows are out of scope for the harness.

use crate::scope::Scope;
use futures_core::future::BoxFuture;
use serde_json::Value;
use std::sync::Arc;
use tracing::{error, warn};

/// Error type for handler and scheduled-work results.
pub type AnyError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Event names are `"<module>.<event>"`, e.g. `waitlist.confirmed`.
pub type EventName = String;

/// A registered handler: receives the emitting request's scope and the
/// payload.
pub type EventHandler =
    Arc<dyn Fn(&Scope, Value) -> BoxFuture<'static, Result<(), AnyError>> + Send + Sync>;

/// Registry of handlers, built once by `Harness::build` from every module's
/// `events()`. Cheap to clone (one `Arc`).
#[derive(Clone, Default)]
pub struct EventBus {
    handlers: Arc<Vec<(EventName, EventHandler)>>,
}

impl EventBus {
    /// An empty bus (a harness with no subscriptions).
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a bus from collected `(name, handler)` pairs, appending the
    /// new pairs after any existing ones (copy-on-write if the bus is
    /// already shared). Modules register via `Module::events()` at
    /// `Harness::build`.
    #[must_use]
    pub fn on(self, name: impl Into<EventName>, handler: EventHandler) -> Self {
        let mut handlers: Vec<(EventName, EventHandler)> = match Arc::try_unwrap(self.handlers) {
            Ok(handlers) => handlers,
            Err(shared) => (*shared).clone(),
        };
        handlers.push((name.into(), handler));
        Self {
            handlers: Arc::new(handlers),
        }
    }

    /// The registered (name, handler) pairs, in registration order.
    pub fn handlers(&self) -> &[(EventName, EventHandler)] {
        &self.handlers
    }

    /// Runs every handler registered for `name` through the scope's defer,
    /// in the emitting request's `wait_until`. Never fails the request;
    /// handler errors are logged with the event name.
    // The by-value payload is the API fixed by issue #4; handlers each get
    // a clone.
    #[allow(clippy::needless_pass_by_value)]
    pub fn emit_in(&self, scope: &Scope, name: &str, payload: Value) {
        let matched: Vec<&(EventName, EventHandler)> = self
            .handlers
            .iter()
            .filter(|(handler_name, _)| handler_name == name)
            .collect();
        for (_, handler) in &matched {
            let fut = handler(scope, payload.clone());
            let event = name.to_string();
            scope.defer.wait_until(Box::pin(async move {
                if let Err(err) = fut.await {
                    error!(event = %event, error = %err, "event handler failed");
                }
            }));
        }
        if matched.is_empty() && !self.handlers.is_empty() {
            warn!(event = %name, "emitted event has no registered handler");
        }
    }
}
