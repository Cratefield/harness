//! Issue #673 acceptance for the Owlpost inbound-events module: the route
//! refuses what does not verify, deduplicates on the envelope's id, turns
//! deliveries into bus events, and a failed hook leaves the key unclaimed
//! so the provider's retry is not swallowed.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use cratefield_adapter_owlpost::webhook::SIGNATURE_HEADER;
use cratefield_core::{EventHandler, EventName, MapConfig, Migrations, Module, Port, Statement};
use cratefield_module_owlpost::{EVENTS, InboundMail, Owlpost, OwlpostEvents, SECRET_KEY};
use cratefield_testing::{TestHarness, sign_stripe_style};
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "whsec_owlpost-test-secret";
const NOW: i64 = 1_800_000_000; // the kit's fixed clock epoch
const PATH: &str = "/v1/owlpost/events";

type Captured = Arc<RwLock<Vec<(String, Value)>>>;
type HookCalls = Arc<RwLock<Vec<InboundMail>>>;

/// Subscribes to every [`EVENTS`] name, so the tests can assert on
/// emissions the way a subscribing module would hear them.
struct Recorder {
    seen: Captured,
}

impl Module for Recorder {
    fn name(&self) -> &'static str {
        "recorder"
    }

    fn version(&self) -> &'static str {
        "0.0.0"
    }

    fn requires(&self) -> &'static [Port] {
        &[]
    }

    fn migrations(&self) -> Migrations {
        Migrations::EMPTY
    }

    fn validate_config(
        &self,
        _cfg: &dyn cratefield_core::Config,
    ) -> Result<(), cratefield_core::ConfigError> {
        Ok(())
    }

    fn router(&self, _ctx: cratefield_core::ModuleContext) -> axum::Router {
        axum::Router::new()
    }

    fn events(&self) -> Vec<(EventName, EventHandler)> {
        EVENTS
            .iter()
            .map(|name| {
                let seen = Arc::clone(&self.seen);
                let event = (*name).to_owned();
                let for_handler = event.clone();
                let handler: EventHandler = Arc::new(move |_scope, payload| {
                    let seen = Arc::clone(&seen);
                    let name = for_handler.clone();
                    Box::pin(async move {
                        seen.write().expect("captured lock").push((name, payload));
                        Ok(())
                    })
                });
                (event, handler)
            })
            .collect()
    }
}

fn kit_with(hooks: OwlpostEvents, config: Vec<(&str, &str)>) -> (TestHarness, Captured) {
    let seen = Arc::new(RwLock::new(Vec::new()));
    let kit = TestHarness::with_ports(
        vec![
            Box::new(Owlpost::new(hooks)),
            Box::new(Recorder {
                seen: Arc::clone(&seen),
            }),
        ],
        |ports| {
            ports.config = Arc::new(MapConfig::from_pairs(config));
        },
    );
    (kit, seen)
}

fn kit() -> (TestHarness, Captured) {
    kit_with(OwlpostEvents::new(), vec![(SECRET_KEY, SECRET)])
}

/// A hook that records what it was handed and (while `fail` is set)
/// refuses, the way a venture's downstream does while it is down.
fn hook(fail: Arc<AtomicBool>) -> (OwlpostEvents, HookCalls) {
    let calls = Arc::new(RwLock::new(Vec::new()));
    let calls_for_hook = Arc::clone(&calls);
    let hooks = OwlpostEvents::new().on_inbound(move |mail| {
        let calls = Arc::clone(&calls_for_hook);
        let fail = Arc::clone(&fail);
        Box::pin(async move {
            calls.write().expect("hook lock").push(mail);
            if fail.load(Ordering::SeqCst) {
                return Err("the venture's inbound worker is down".into());
            }
            Ok(())
        })
    });
    (hooks, calls)
}

/// One delivery, signed the way Owlpost signs; the reply is the status and
/// the problem-or-ok JSON.
async fn deliver(kit: &TestHarness, secret: &str, t: i64, body: &[u8]) -> (StatusCode, Value) {
    let headers = sign_stripe_style(SIGNATURE_HEADER, secret, t, body);
    let mut builder = Request::builder().method(Method::POST).uri(PATH);
    for (name, value) in &headers {
        builder = builder.header(name, value);
    }
    let response = kit
        .router
        .clone()
        .oneshot(
            builder
                .header("content-type", "application/json")
                .body(Body::from(body.to_vec()))
                .expect("request builds"),
        )
        .await
        .expect("router answers");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body reads");
    (
        status,
        serde_json::from_slice(&bytes).expect("problem or ok JSON"),
    )
}

fn envelope(id: &str, event_type: &str, data: &Value) -> Vec<u8> {
    json!({
        "id": id,
        "type": event_type,
        "created_at": "2026-10-08T00:00:00Z",
        "data": data,
    })
    .to_string()
    .into_bytes()
}

fn received(id: &str) -> Vec<u8> {
    envelope(
        id,
        "message.received",
        &json!({
            "message_id": "msg_1",
            "from": "sender@example.com",
            "to": ["venture@example.com"],
            "subject": "Hello",
        }),
    )
}

async fn events(kit: &TestHarness, seen: &Captured) -> Vec<(String, Value)> {
    kit.defer.drain().await;
    seen.read().expect("captured lock").clone()
}

#[pollster::test]
async fn inbound_mail_reaches_the_hook_and_the_bus() {
    let fail = Arc::new(AtomicBool::new(false));
    let (hooks, calls) = hook(fail);
    let (kit, seen) = kit_with(hooks, vec![(SECRET_KEY, SECRET)]);

    let received = received("evt_1");
    let held = envelope(
        "evt_2",
        "message.held",
        &json!({ "message_id": "msg_2", "reason": "spam score" }),
    );
    let (status, body) = deliver(&kit, SECRET, NOW, &received).await;
    assert!(status.is_success(), "{status}: {body}");
    let (status, body) = deliver(&kit, SECRET, NOW + 1, &held).await;
    assert!(status.is_success(), "{status}: {body}");

    let calls = calls.read().expect("hook lock").clone();
    assert_eq!(calls.len(), 2, "one received, one held");
    assert_eq!(calls[0].message_id, "msg_1");
    assert_eq!(calls[0].from, "sender@example.com");
    assert_eq!(calls[0].subject.as_deref(), Some("Hello"));
    assert!(!calls[0].held);

    // The bus heard both as `owlpost.inbound`. The hold names nobody: no
    // sender, recipients or subject — and no body, which the delivery
    // never carried.
    let on_bus = events(&kit, &seen).await;
    let inbound: Vec<_> = on_bus
        .iter()
        .filter(|(name, _)| name == "owlpost.inbound")
        .map(|(_, payload)| payload)
        .collect();
    assert_eq!(inbound.len(), 2);
    let mail = inbound
        .iter()
        .find(|mail| mail["held"] == false)
        .expect("received");
    assert_eq!(mail["message_id"], "msg_1");
    let held = inbound
        .iter()
        .find(|mail| mail["held"] == true)
        .expect("held");
    assert_eq!(held["reason"], "spam score");
    assert_eq!(held["from"], "");
    assert_eq!(held["to"], json!([]));
    assert!(held["subject"].is_null());
    assert!(held.get("body").is_none());
}

#[pollster::test]
async fn a_delivery_that_does_not_verify_is_refused() {
    let (kit, _seen) = kit();

    let (status, reply) = deliver(&kit, "whsec_not-the-secret", NOW, &received("evt_1")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{reply}");
    assert_eq!(reply["title"], "Unverified delivery");

    // Outside the verifier's ±300 s tolerance: the same single refusal.
    let (status, reply) = deliver(&kit, SECRET, NOW - 301, &received("evt_1")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{reply}");

    // Verified but not a well-formed envelope.
    let (status, reply) = deliver(&kit, SECRET, NOW, b"not json").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");

    // Fail closed: a deployment with no secret serves nobody.
    let (secretless, _) = kit_with(OwlpostEvents::new(), vec![]);
    let (status, _) = deliver(&secretless, SECRET, NOW, &received("evt_1")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    let rows = kit
        .db
        .query(&Statement::new("SELECT event_key FROM owlpost_inbox"))
        .await
        .expect("query");
    assert!(rows.is_empty(), "a refused delivery left no trace");
}

#[pollster::test]
async fn a_redelivery_runs_once_and_a_failed_hook_is_retried() {
    let fail = Arc::new(AtomicBool::new(false));
    let (hooks, calls) = hook(Arc::clone(&fail));
    let (kit, seen) = kit_with(hooks, vec![(SECRET_KEY, SECRET)]);

    // The first delivery is processed; its redelivery is a 200 no-op.
    let (first, _) = deliver(&kit, SECRET, NOW, &received("evt_1")).await;
    let (again, _) = deliver(&kit, SECRET, NOW + 5, &received("evt_1")).await;
    assert!(first.is_success() && again.is_success(), "{first} {again}");
    assert_eq!(
        calls.read().expect("hook lock").len(),
        1,
        "the hook ran once"
    );

    // With the venture's worker down, the delivery fails 5xx ...
    fail.store(true, Ordering::SeqCst);
    let (down, body) = deliver(&kit, SECRET, NOW + 10, &received("evt_2")).await;
    assert_eq!(down, StatusCode::INTERNAL_SERVER_ERROR, "{body}");

    // ... and the recovery retry is processed, not swallowed.
    fail.store(false, Ordering::SeqCst);
    let (retried, _) = deliver(&kit, SECRET, NOW + 15, &received("evt_2")).await;
    assert!(retried.is_success(), "the retry was not swallowed");
    assert_eq!(
        calls.read().expect("hook lock").len(),
        3,
        "evt_1 once; evt_2 on the failed attempt and on the retry"
    );

    let heard = events(&kit, &seen).await;
    let inbound = heard
        .iter()
        .filter(|(name, _)| name == "owlpost.inbound")
        .count();
    assert_eq!(inbound, 2, "the bus heard each mail once");
}

#[pollster::test]
async fn a_bounced_delivery_emits_owlpost_bounced_and_an_unknown_type_stays_quiet() {
    let (kit, seen) = kit();
    let bounced = envelope(
        "evt_3",
        "email.bounced",
        &json!({
            "message_id": "msg_3",
            "to": ["b@example.com"],
            "code": "550",
        }),
    );
    let (status, reply) = deliver(&kit, SECRET, NOW, &bounced).await;
    assert!(status.is_success(), "{status}: {reply}");

    // A type the module does not know: still a 200, nothing emitted, and
    // its redelivery is a no-op rather than a second look.
    let pigeon = envelope("evt_4", "carrier.pigeon", &json!({}));
    let (status, reply) = deliver(&kit, SECRET, NOW + 1, &pigeon).await;
    assert!(status.is_success(), "{status}: {reply}");
    let (again, _) = deliver(&kit, SECRET, NOW + 2, &pigeon).await;
    assert!(again.is_success());

    let heard = events(&kit, &seen).await;
    assert_eq!(heard.len(), 1, "the unknown type emitted nothing");
    let bounced = &heard[0];
    assert_eq!(bounced.0, "owlpost.bounced");
    assert_eq!(bounced.1["event_id"], "evt_3");
    assert_eq!(bounced.1["message_id"], "msg_3");
    assert_eq!(bounced.1["to"], json!(["b@example.com"]));
    assert_eq!(bounced.1["occurred_at"], "2026-10-08T00:00:00Z");
}
