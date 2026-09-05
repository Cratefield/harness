//! `EventBus` tests (issue #4): emit/on across two modules, handler errors
//! never fail the caller, deferred through the scope's Defer (a counting
//! inline fake), wired at `Harness::build`.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use factory0_core::{
    AnyError, BoxFuture, Config, ConfigError, EventBus, Harness, Migrations, Module, ModuleContext,
    Port, Runtime, Scope,
};
use futures_core::future::BoxFuture as CoreBoxFuture;
use std::sync::mpsc;

// A defer that counts invocations and runs the future inline, so tests can
// observe both the deferral and the handler's effect.
struct InlineDefer(AtomicUsize);

impl factory0_core::Defer for InlineDefer {
    fn wait_until(&self, fut: CoreBoxFuture<'static, ()>) {
        self.0.fetch_add(1, Ordering::SeqCst);
        pollster::block_on(fut);
    }
}

fn scope_with(defer: &Arc<InlineDefer>) -> Scope {
    Scope {
        request_id: "test-request-0001".to_string(),
        defer: Arc::clone(defer) as Arc<dyn factory0_core::Defer>,
        span: tracing::info_span!("test"),
    }
}

struct EmittingModule;

impl Module for EmittingModule {
    fn name(&self) -> &'static str {
        "waitlist"
    }
    fn version(&self) -> &'static str {
        "0.0.0"
    }
    fn requires(&self) -> &'static [Port] {
        &[]
    }
    fn migrations(&self) -> Migrations {
        Migrations::default()
    }
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        axum::Router::new()
    }
}

struct RecordingModule {
    /// Fails on every event when true.
    fail: bool,
    sink: mpsc::Sender<String>,
    seen: Arc<AtomicUsize>,
}

impl Module for RecordingModule {
    fn name(&self) -> &'static str {
        "email-signup"
    }
    fn version(&self) -> &'static str {
        "0.0.0"
    }
    fn requires(&self) -> &'static [Port] {
        &[]
    }
    fn migrations(&self) -> Migrations {
        Migrations::default()
    }
    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }
    fn router(&self, _ctx: ModuleContext) -> axum::Router {
        axum::Router::new()
    }
    fn events(&self) -> Vec<(factory0_core::EventName, factory0_core::EventHandler)> {
        let sink = self.sink.clone();
        let seen = Arc::clone(&self.seen);
        let fail = self.fail;
        vec![(
            "waitlist.confirmed".to_string(),
            Arc::new(
                move |_scope: &Scope,
                      payload: serde_json::Value|
                      -> BoxFuture<'static, Result<(), AnyError>> {
                    seen.fetch_add(1, Ordering::SeqCst);
                    let sink = sink.clone();
                    Box::pin(async move {
                        if fail {
                            return Err("recording module is set to fail".into());
                        }
                        sink.send(payload["subject"].as_str().unwrap_or("?").to_string())
                            .expect("test sink open");
                        Ok(())
                    })
                },
            ),
        )]
    }
}

struct AllPorts;

impl Runtime for AllPorts {
    fn provides(&self) -> Vec<Port> {
        Port::ALL.to_vec()
    }
}

fn two_module_harness(recorder: RecordingModule) -> Harness {
    Harness::builder()
        .venture(
            factory0_core::Venture::new("test-venture", "test.example")
                .cors_origins(["https://test.example"]),
        )
        .module(EmittingModule)
        .module(recorder)
        .runtime(AllPorts)
        .build()
        .expect("two-module harness builds")
}

#[test]
fn emit_reaches_a_handler_registered_by_another_module() {
    let (tx, rx) = mpsc::channel::<String>();
    let seen = Arc::new(AtomicUsize::new(0));
    let harness = two_module_harness(RecordingModule {
        fail: false,
        sink: tx,
        seen: Arc::clone(&seen),
    });

    let defer = Arc::new(InlineDefer(AtomicUsize::new(0)));
    let scope = scope_with(&defer);

    harness.events().emit_in(
        &scope,
        "waitlist.confirmed",
        serde_json::json!({ "subject": "nick@example.com" }),
    );

    assert_eq!(seen.load(Ordering::SeqCst), 1, "handler ran once");
    assert_eq!(
        defer.0.load(Ordering::SeqCst),
        1,
        "emit_in deferred through the scope's defer"
    );
    assert_eq!(rx.try_recv().expect("payload recorded"), "nick@example.com");
}

#[test]
fn handler_error_does_not_fail_the_emit_or_the_request() {
    let (tx, rx) = mpsc::channel::<String>();
    let seen = Arc::new(AtomicUsize::new(0));
    let harness = two_module_harness(RecordingModule {
        fail: true,
        sink: tx,
        seen: Arc::clone(&seen),
    });

    let defer = Arc::new(InlineDefer(AtomicUsize::new(0)));
    let scope = scope_with(&defer);

    // Must not panic and must not return a Result to the caller.
    harness.events().emit_in(
        &scope,
        "waitlist.confirmed",
        serde_json::json!({ "subject": "x@example.com" }),
    );

    assert_eq!(seen.load(Ordering::SeqCst), 1);
    assert!(rx.try_recv().is_err(), "failing handler recorded nothing");
}

#[test]
fn events_with_no_handlers_log_but_do_not_fail() {
    let harness = two_module_harness(RecordingModule {
        fail: false,
        sink: mpsc::channel::<String>().0,
        seen: Arc::new(AtomicUsize::new(0)),
    });
    let defer = Arc::new(InlineDefer(AtomicUsize::new(0)));
    let scope = scope_with(&defer);
    harness
        .events()
        .emit_in(&scope, "nobody.listens", serde_json::json!({}));
    assert_eq!(defer.0.load(Ordering::SeqCst), 0);
}

#[test]
fn bus_is_shared_with_module_contexts() {
    let (tx, _rx) = mpsc::channel::<String>();
    let harness = two_module_harness(RecordingModule {
        fail: false,
        sink: tx,
        seen: Arc::new(AtomicUsize::new(0)),
    });
    assert_eq!(harness.events().handlers().len(), 1);
    assert_eq!(harness.events().handlers()[0].0, "waitlist.confirmed");
}

#[test]
fn bus_on_appends_after_existing_handlers() {
    let (tx, _rx) = mpsc::channel::<String>();
    let harness = two_module_harness(RecordingModule {
        fail: false,
        sink: tx,
        seen: Arc::new(AtomicUsize::new(0)),
    });
    let count = Arc::new(AtomicUsize::new(0));
    let second_seen = Arc::clone(&count);
    let bus = harness.events().clone().on(
        "waitlist.confirmed",
        Arc::new(move |_scope: &Scope, _payload: serde_json::Value| {
            let seen = Arc::clone(&second_seen);
            Box::pin(async move {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }) as BoxFuture<'static, Result<(), AnyError>>
        }),
    );
    assert_eq!(bus.handlers().len(), 2);

    let defer = Arc::new(InlineDefer(AtomicUsize::new(0)));
    let scope = scope_with(&defer);
    bus.emit_in(&scope, "waitlist.confirmed", serde_json::json!({}));
    assert_eq!(count.load(Ordering::SeqCst), 1, "second handler ran");
}

#[test]
fn default_bus_is_empty() {
    assert_eq!(EventBus::new().handlers().len(), 0);
}
