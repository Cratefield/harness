//! Fixture tests for the Stripe adapter: request shaping, error mapping, and
//! webhook signature verification. The live path against Stripe is
//! `needs-human` (issue #102).
#![allow(clippy::disallowed_types)] // test doubles record calls via a Mutex

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use cratefield_adapter_stripe::Stripe;
use cratefield_core::{
    CheckoutRequest, Clock, ConnectAccountLinkRequest, HttpClient, HttpError, LineItem, Money,
    Payments, PaymentsError, RefundRequest, SubscriptionCheckoutRequest, TransferCharge,
};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

// ---------------------------------------------------------------------------
// Test doubles

struct FixedClock(i64);
#[async_trait::async_trait]
impl Clock for FixedClock {
    fn now(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(self.0).unwrap()
    }
}

/// Records requests and replies with one scripted response.
struct ScriptedHttp {
    requests: Mutex<Vec<http::Request<Bytes>>>,
    status: u16,
    body: String,
}
impl ScriptedHttp {
    fn ok(body: &str) -> Arc<Self> {
        Arc::new(Self {
            requests: Mutex::new(Vec::new()),
            status: 200,
            body: body.to_owned(),
        })
    }
    fn replying(status: u16, body: &str) -> Arc<Self> {
        Arc::new(Self {
            requests: Mutex::new(Vec::new()),
            status,
            body: body.to_owned(),
        })
    }
    fn bodies(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|req| String::from_utf8(req.body().to_vec()).unwrap())
            .collect()
    }
    fn last_body(&self) -> String {
        self.bodies().pop().unwrap()
    }
    fn last_uri(&self) -> String {
        self.requests
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .uri()
            .to_string()
    }
    fn last_header(&self, name: &str) -> String {
        let guard = self.requests.lock().unwrap();
        guard
            .last()
            .unwrap()
            .headers()
            .get(name)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    }
}
#[async_trait::async_trait]
impl HttpClient for ScriptedHttp {
    async fn send(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        self.requests.lock().unwrap().push(request);
        Ok(http::Response::builder()
            .status(self.status)
            .body(Bytes::from(self.body.clone()))
            .unwrap())
    }
}

fn stripe(http: Arc<ScriptedHttp>) -> Stripe {
    Stripe::new(
        http,
        Arc::new(FixedClock(1_700_000_000)),
        "sk_test_x",
        "whsec_test",
    )
}

fn meta() -> BTreeMap<String, String> {
    BTreeMap::from([("order".to_owned(), "42".to_owned())])
}

// ---------------------------------------------------------------------------
// Checkout

#[test]
fn create_checkout_posts_a_payment_session() {
    let http = ScriptedHttp::ok(r#"{"id":"cs_1","url":"https://checkout.stripe.com/c/cs_1"}"#);
    let s = stripe(http.clone());
    let session = pollster::block_on(s.create_checkout(&CheckoutRequest {
        customer_ref: None,
        customer_email: Some("a@b.test".to_owned()),
        line: LineItem {
            name: "Membership".to_owned(),
            amount: Money::new(1500, "usd"),
            quantity: 1,
        },
        success_url: "https://x/ok".to_owned(),
        cancel_url: "https://x/no".to_owned(),
        metadata: meta(),
        idempotency_key: "idem-1".to_owned(),
    }))
    .unwrap();

    assert_eq!(session.id, "cs_1");
    assert_eq!(session.url, "https://checkout.stripe.com/c/cs_1");
    assert!(http.last_uri().ends_with("/v1/checkout/sessions"));
    assert_eq!(http.last_header("Idempotency-Key"), "idem-1");
    assert_eq!(http.last_header("authorization"), "Bearer sk_test_x");

    let body = http.last_body();
    assert!(body.contains("mode=payment"));
    assert!(body.contains("line_items%5B0%5D%5Bprice_data%5D%5Bunit_amount%5D=1500"));
    assert!(body.contains("line_items%5B0%5D%5Bprice_data%5D%5Bcurrency%5D=usd"));
    assert!(body.contains("customer_email=a%40b.test"));
    assert!(body.contains("metadata%5Border%5D=42"));
}

#[test]
fn create_subscription_checkout_carries_price_and_trial() {
    let http = ScriptedHttp::ok(r#"{"id":"cs_2","url":"https://checkout.stripe.com/c/cs_2"}"#);
    let s = stripe(http.clone());
    pollster::block_on(
        s.create_subscription_checkout(&SubscriptionCheckoutRequest {
            customer_ref: None,
            customer_email: None,
            price_ref: "price_123".to_owned(),
            trial_days: Some(14),
            success_url: "https://x/ok".to_owned(),
            cancel_url: "https://x/no".to_owned(),
            metadata: BTreeMap::new(),
            idempotency_key: "idem-2".to_owned(),
        }),
    )
    .unwrap();

    let body = http.last_body();
    assert!(body.contains("mode=subscription"));
    assert!(body.contains("line_items%5B0%5D%5Bprice%5D=price_123"));
    assert!(body.contains("subscription_data%5Btrial_period_days%5D=14"));
}

// ---------------------------------------------------------------------------
// Connect + transfer

#[test]
fn connect_account_link_creates_account_then_link() {
    // Two calls: create the account, then create the onboarding link. A
    // sequencing double returns a scripted response per call.
    let seq = SequencedHttp::new(vec![
        (200, r#"{"id":"acct_9"}"#.to_owned()),
        (
            200,
            r#"{"url":"https://connect.stripe.com/setup/acct_9"}"#.to_owned(),
        ),
    ]);
    let s = Stripe::new(
        seq.clone(),
        Arc::new(FixedClock(1_700_000_000)),
        "sk_test_x",
        "whsec_test",
    );
    let link = pollster::block_on(s.create_connect_account_link(&ConnectAccountLinkRequest {
        account_ref: None,
        refresh_url: "https://x/refresh".to_owned(),
        return_url: "https://x/return".to_owned(),
        idempotency_key: "idem-3".to_owned(),
    }))
    .unwrap();

    assert_eq!(link.account_id, "acct_9");
    assert_eq!(link.url, "https://connect.stripe.com/setup/acct_9");

    let bodies = seq.bodies();
    assert!(bodies[0].contains("type=express"));
    assert!(bodies[1].contains("account=acct_9"));
    assert!(bodies[1].contains("type=account_onboarding"));
}

#[test]
fn charge_with_transfer_sends_fee_and_destination() {
    let http = ScriptedHttp::ok(r#"{"id":"pi_7","status":"requires_confirmation"}"#);
    let s = stripe(http.clone());
    let charge = pollster::block_on(s.charge_with_transfer(&TransferCharge {
        customer_ref: Some("cus_1".to_owned()),
        amount: Money::new(2000, "usd"),
        destination_account: "acct_9".to_owned(),
        application_fee: Money::new(240, "usd"),
        metadata: BTreeMap::new(),
        idempotency_key: "idem-4".to_owned(),
    }))
    .unwrap();

    assert_eq!(charge.id, "pi_7");
    assert_eq!(charge.status, "requires_confirmation");
    let body = http.last_body();
    assert!(body.contains("amount=2000"));
    assert!(body.contains("application_fee_amount=240"));
    assert!(body.contains("transfer_data%5Bdestination%5D=acct_9"));
    assert!(body.contains("customer=cus_1"));
}

#[test]
fn refund_full_and_partial() {
    let http = ScriptedHttp::ok(r#"{"id":"re_1"}"#);
    let s = stripe(http.clone());
    pollster::block_on(s.refund(&RefundRequest {
        payment_ref: "pi_7".to_owned(),
        amount: None,
        idempotency_key: "idem-5".to_owned(),
    }))
    .unwrap();
    let full = http.last_body();
    assert!(full.contains("payment_intent=pi_7"));
    assert!(!full.contains("amount="));

    let http2 = ScriptedHttp::ok(r#"{"id":"re_2"}"#);
    let s2 = stripe(http2.clone());
    pollster::block_on(s2.refund(&RefundRequest {
        payment_ref: "pi_7".to_owned(),
        amount: Some(Money::new(500, "usd")),
        idempotency_key: "idem-6".to_owned(),
    }))
    .unwrap();
    assert!(http2.last_body().contains("amount=500"));
}

// ---------------------------------------------------------------------------
// Error mapping + NotConfigured

#[test]
fn maps_402_to_rejected_and_500_to_transient() {
    let http = ScriptedHttp::replying(402, r#"{"error":{"message":"Your card was declined."}}"#);
    let s = stripe(http);
    let err = pollster::block_on(s.refund(&RefundRequest {
        payment_ref: "pi_x".to_owned(),
        amount: None,
        idempotency_key: "k".to_owned(),
    }))
    .unwrap_err();
    assert!(matches!(err, PaymentsError::Rejected(m) if m.contains("declined")));

    let http = ScriptedHttp::replying(503, "");
    let s = stripe(http);
    let err = pollster::block_on(s.refund(&RefundRequest {
        payment_ref: "pi_x".to_owned(),
        amount: None,
        idempotency_key: "k".to_owned(),
    }))
    .unwrap_err();
    assert!(matches!(err, PaymentsError::Transient(_)));
}

#[test]
fn not_configured_never_calls_the_network() {
    let s = Stripe::not_configured();
    let err = pollster::block_on(s.refund(&RefundRequest {
        payment_ref: "pi_x".to_owned(),
        amount: None,
        idempotency_key: "k".to_owned(),
    }))
    .unwrap_err();
    assert!(matches!(err, PaymentsError::NotConfigured));
}

// ---------------------------------------------------------------------------
// Webhook verification

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn sign(secret: &str, timestamp: i64, body: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{timestamp}.{body}").as_bytes());
    hex_encode(&mac.finalize().into_bytes())
}

#[test]
fn verify_webhook_accepts_a_valid_signature() {
    let body =
        r#"{"id":"evt_1","type":"checkout.session.completed","data":{"object":{"id":"cs_1"}}}"#;
    let sig = sign("whsec_test", 1_700_000_000, body);
    let header = format!("t=1700000000,v1={sig}");

    let http = ScriptedHttp::ok("");
    let s = stripe(http);
    let event = pollster::block_on(s.verify_webhook(&header, body.as_bytes())).unwrap();
    assert_eq!(event.id, "evt_1");
    assert_eq!(event.kind, "checkout.session.completed");
    assert_eq!(event.data["id"], "cs_1");
}

#[test]
fn verify_webhook_refuses_a_tampered_signature() {
    let body = r#"{"id":"evt_1","type":"checkout.session.completed","data":{"object":{}}}"#;
    // A signature over different content.
    let sig = sign("whsec_test", 1_700_000_000, "{}");
    let header = format!("t=1700000000,v1={sig}");

    let http = ScriptedHttp::ok("");
    let s = stripe(http);
    let err = pollster::block_on(s.verify_webhook(&header, body.as_bytes())).unwrap_err();
    assert!(matches!(err, PaymentsError::SignatureInvalid(_)));
}

#[test]
fn verify_webhook_refuses_a_stale_timestamp() {
    let body = r#"{"id":"evt_1","type":"x","data":{"object":{}}}"#;
    // Signed at a time far outside the tolerance of the fixed clock.
    let old = 1_700_000_000 - 3600;
    let sig = sign("whsec_test", old, body);
    let header = format!("t={old},v1={sig}");

    let http = ScriptedHttp::ok("");
    let s = stripe(http);
    let err = pollster::block_on(s.verify_webhook(&header, body.as_bytes())).unwrap_err();
    assert!(matches!(err, PaymentsError::SignatureInvalid(m) if m.contains("tolerance")));
}

#[test]
fn verify_webhook_without_a_secret_is_not_configured() {
    let http = ScriptedHttp::ok("");
    let s = Stripe::new(http, Arc::new(FixedClock(1_700_000_000)), "sk_test_x", "");
    let err = pollster::block_on(s.verify_webhook("t=1,v1=deadbeef", b"{}")).unwrap_err();
    assert!(matches!(err, PaymentsError::NotConfigured));
}

// ---------------------------------------------------------------------------
// A tiny HttpClient that returns a scripted sequence of responses.

#[derive(Clone)]
struct SequencedHttp {
    inner: Arc<SequencedInner>,
}
struct SequencedInner {
    responses: Mutex<std::collections::VecDeque<(u16, String)>>,
    requests: Mutex<Vec<http::Request<Bytes>>>,
}
impl SequencedHttp {
    fn new(responses: Vec<(u16, String)>) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(SequencedInner {
                responses: Mutex::new(responses.into_iter().collect()),
                requests: Mutex::new(Vec::new()),
            }),
        })
    }
    fn bodies(&self) -> Vec<String> {
        self.inner
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(|req| String::from_utf8(req.body().to_vec()).unwrap())
            .collect()
    }
}
#[async_trait::async_trait]
impl HttpClient for SequencedHttp {
    async fn send(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        self.inner.requests.lock().unwrap().push(request);
        let (status, body) = self
            .inner
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("no scripted response left");
        Ok(http::Response::builder()
            .status(status)
            .body(Bytes::from(body))
            .unwrap())
    }
}
