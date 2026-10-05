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
    Payments, PaymentsError, PortalSessionRequest, RefundRequest, SubscriptionCheckoutRequest,
    SubscriptionStatus, TransferCharge, UsageReport,
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
    fn last_method(&self) -> String {
        self.requests
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .method()
            .to_string()
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
// Customer portal + subscriptions

#[test]
fn create_portal_session_posts_a_billing_portal_session() {
    let http = ScriptedHttp::ok(r#"{"url":"https://billing.stripe.com/p/session/tok_1"}"#);
    let s = stripe(http.clone());
    let session = pollster::block_on(s.create_portal_session(&PortalSessionRequest {
        customer_ref: "cus_1".to_owned(),
        return_url: "https://x/account".to_owned(),
        idempotency_key: "idem-7".to_owned(),
    }))
    .unwrap();

    assert_eq!(session.url, "https://billing.stripe.com/p/session/tok_1");
    assert_eq!(http.last_method(), "POST");
    assert!(http.last_uri().ends_with("/v1/billing_portal/sessions"));
    assert_eq!(http.last_header("Idempotency-Key"), "idem-7");
    let body = http.last_body();
    assert!(body.contains("customer=cus_1"));
    assert!(body.contains("return_url=https%3A%2F%2Fx%2Faccount"));
}

/// A subscription body as API 2024-06-20 returns it: `current_period_end` at
/// the top level, the price and quantity under `items.data[0]`.
const ACTIVE_SUBSCRIPTION: &str = r#"{
    "id":"sub_1","object":"subscription","customer":"cus_1","status":"active",
    "cancel_at_period_end":false,"current_period_end":1735689600,
    "metadata":{"order":"42"},
    "items":{"object":"list","data":[{"id":"si_1","quantity":2,"price":{"id":"price_123"}}]}
}"#;

#[test]
fn get_subscription_reads_the_stripe_object() {
    let http = ScriptedHttp::ok(ACTIVE_SUBSCRIPTION);
    let s = stripe(http.clone());
    let sub = pollster::block_on(s.get_subscription("sub_1")).unwrap();

    assert_eq!(sub.id, "sub_1");
    assert_eq!(sub.customer_ref, "cus_1");
    assert_eq!(sub.status, SubscriptionStatus::Active);
    assert_eq!(sub.price_ref.as_deref(), Some("price_123"));
    assert_eq!(sub.quantity, 2);
    assert_eq!(
        sub.current_period_end,
        Some(time::OffsetDateTime::from_unix_timestamp(1_735_689_600).unwrap())
    );
    assert!(!sub.cancel_at_period_end);
    assert_eq!(sub.metadata.get("order").map(String::as_str), Some("42"));

    assert_eq!(http.last_method(), "GET");
    assert!(http.last_uri().ends_with("/v1/subscriptions/sub_1"));
}

#[test]
fn get_subscription_reads_cancel_at_period_end_and_an_expanded_customer() {
    // The customer is expanded into an object, not a bare id.
    let http = ScriptedHttp::ok(
        r#"{"id":"sub_2","customer":{"id":"cus_2","object":"customer"},"status":"active",
            "cancel_at_period_end":true,"current_period_end":1735689600,
            "items":{"data":[{"quantity":1,"price":{"id":"price_9"}}]}}"#,
    );
    let s = stripe(http);
    let sub = pollster::block_on(s.get_subscription("sub_2")).unwrap();
    assert_eq!(sub.customer_ref, "cus_2");
    assert!(sub.cancel_at_period_end);
}

#[test]
fn get_subscription_falls_back_to_the_item_period_end() {
    // API 2025-03-31 ("basil") moved `current_period_end` onto the items; the
    // adapter reads it from there when the top level has none.
    let http = ScriptedHttp::ok(
        r#"{"id":"sub_3","customer":"cus_3","status":"trialing",
            "items":{"data":[{"quantity":1,"price":{"id":"price_5"},"current_period_end":1735689600}]}}"#,
    );
    let s = stripe(http);
    let sub = pollster::block_on(s.get_subscription("sub_3")).unwrap();
    assert_eq!(sub.status, SubscriptionStatus::Trialing);
    assert_eq!(
        sub.current_period_end,
        Some(time::OffsetDateTime::from_unix_timestamp(1_735_689_600).unwrap())
    );
}

#[test]
fn get_subscription_keeps_an_unknown_status() {
    let http = ScriptedHttp::ok(
        r#"{"id":"sub_4","customer":"cus_4","status":"new_thing",
            "items":{"data":[{"quantity":1,"price":{"id":"price_1"}}]}}"#,
    );
    let s = stripe(http);
    let sub = pollster::block_on(s.get_subscription("sub_4")).unwrap();
    assert_eq!(
        sub.status,
        SubscriptionStatus::Other("new_thing".to_owned())
    );
}

#[test]
fn get_subscription_rejects_an_id_that_would_change_the_path() {
    let http = ScriptedHttp::ok(ACTIVE_SUBSCRIPTION);
    let s = stripe(http.clone());
    for bad in ["", "sub/1", "sub?x=1", "sub #1", ".."] {
        let err = pollster::block_on(s.get_subscription(bad)).unwrap_err();
        assert!(matches!(err, PaymentsError::Rejected(_)), "id {bad:?}");
    }
    assert!(http.bodies().is_empty(), "a bad id must never reach Stripe");
}

#[test]
fn list_subscriptions_asks_for_all_statuses_by_customer() {
    let http = ScriptedHttp::ok(
        r#"{"object":"list","data":[
            {"id":"sub_1","customer":"cus_1","status":"active","cancel_at_period_end":true,
             "current_period_end":1735689600,
             "items":{"data":[{"quantity":1,"price":{"id":"price_123"}}]}},
            {"id":"sub_2","customer":"cus_1","status":"canceled","cancel_at_period_end":false,
             "items":{"data":[{"quantity":1,"price":{"id":"price_123"}}]}}
        ]}"#,
    );
    let s = stripe(http.clone());
    let subs = pollster::block_on(s.list_subscriptions("cus_1")).unwrap();

    assert_eq!(subs.len(), 2);
    assert_eq!(subs[0].status, SubscriptionStatus::Active);
    assert!(subs[0].cancel_at_period_end);
    assert_eq!(subs[1].status, SubscriptionStatus::Canceled);

    let uri = http.last_uri();
    assert!(uri.contains("/v1/subscriptions?"));
    assert!(uri.contains("customer=cus_1"));
    assert!(uri.contains("status=all"), "canceled subs must be included");
    assert!(uri.contains("limit=100"), "ask for Stripe's maximum page");
}

#[test]
fn list_subscriptions_follows_pagination_with_starting_after() {
    // Page one says there is more; the next request must carry
    // `starting_after` naming the last id of page one.
    let seq = SequencedHttp::new(vec![
        (
            200,
            r#"{"object":"list","has_more":true,"data":[
                {"id":"sub_1","customer":"cus_1","status":"active",
                 "items":{"data":[{"quantity":1,"price":{"id":"price_1"}}]}}
            ]}"#
            .to_owned(),
        ),
        (
            200,
            r#"{"object":"list","has_more":false,"data":[
                {"id":"sub_2","customer":"cus_1","status":"canceled",
                 "items":{"data":[{"quantity":1,"price":{"id":"price_1"}}]}}
            ]}"#
            .to_owned(),
        ),
    ]);
    let s = Stripe::new(
        seq.clone(),
        Arc::new(FixedClock(1_700_000_000)),
        "sk_test_x",
        "whsec_test",
    );
    let subs = pollster::block_on(s.list_subscriptions("cus_1")).unwrap();

    assert_eq!(subs.len(), 2);
    assert_eq!(subs[0].id, "sub_1");
    assert_eq!(subs[1].id, "sub_2");

    let uris = seq.uris();
    assert_eq!(uris.len(), 2, "the second page must be fetched");
    assert!(!uris[0].contains("starting_after"));
    assert!(
        uris[1].contains("starting_after=sub_1"),
        "second page starts after the last id: {}",
        uris[1]
    );
}

#[test]
fn portal_and_subscriptions_not_configured_never_call_the_network() {
    let s = Stripe::not_configured();
    let portal = PortalSessionRequest {
        customer_ref: "cus_1".to_owned(),
        return_url: "https://x".to_owned(),
        idempotency_key: "k".to_owned(),
    };
    assert!(matches!(
        pollster::block_on(s.create_portal_session(&portal)),
        Err(PaymentsError::NotConfigured)
    ));
    assert!(matches!(
        pollster::block_on(s.get_subscription("sub_1")),
        Err(PaymentsError::NotConfigured)
    ));
    assert!(matches!(
        pollster::block_on(s.list_subscriptions("cus_1")),
        Err(PaymentsError::NotConfigured)
    ));
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
// Metered usage reporting

/// A realistic `billing.meter_event` response body (the fields Stripe
/// documents); the success path does not read it, but the fixture keeps the
/// exchange honest.
const METER_EVENT_BODY: &str = r#"{"object":"billing.meter_event","created":1704824589,"event_name":"extra_avatar_minutes","identifier":"sub_1:extra_avatar_minutes:1711998000","livemode":false,"payload":{"value":"3","stripe_customer_id":"cus_NciAYcXfLnqBoz"},"timestamp":1711998000}"#;

/// One hourly report, at a non-aligned instant so the truncation is exercised.
fn usage_report() -> UsageReport {
    UsageReport::hourly(
        "sub_1",
        "extra_avatar_minutes",
        "cus_NciAYcXfLnqBoz",
        3,
        time::OffsetDateTime::from_unix_timestamp(1_712_000_000).unwrap(),
    )
}

#[test]
fn report_usage_posts_the_documented_meter_event_form() {
    let http = ScriptedHttp::ok(METER_EVENT_BODY);
    let s = stripe(http.clone());
    let report = usage_report();
    let reported = pollster::block_on(s.report_usage(&report)).unwrap();

    assert!(!reported.already_reported);
    assert_eq!(reported.identifier, report.identifier);

    assert!(http.last_uri().ends_with("/v1/billing/meter_events"));
    // The identifier doubles as the Idempotency-Key, unencoded (a header).
    assert_eq!(http.last_header("Idempotency-Key"), report.identifier);
    assert_eq!(http.last_header("authorization"), "Bearer sk_test_x");

    let body = http.last_body();
    assert!(body.contains("event_name=extra_avatar_minutes"));
    assert!(body.contains("payload%5Bstripe_customer_id%5D=cus_NciAYcXfLnqBoz"));
    assert!(body.contains("payload%5Bvalue%5D=3"));
    // In a form value the identifier's colons are percent-encoded.
    let encoded_id = report.identifier.replace(':', "%3A");
    assert!(body.contains(&format!("identifier={encoded_id}")));
    assert!(body.contains(&format!("timestamp={}", report.timestamp.unix_timestamp())));
    // The window is the top of the hour, from the truncation.
    assert_eq!(report.timestamp.unix_timestamp() % 3600, 0);
}

#[test]
fn report_usage_treats_a_duplicate_identifier_as_success() {
    // The documented `duplicate_meter_event` code, and the message-only body
    // some Stripe responses carry for the same refusal.
    for body in [
        r#"{"error":{"code":"duplicate_meter_event","message":"A meter event with a duplicate identifier has already been submitted."}}"#,
        r#"{"error":{"message":"A meter event with a duplicate identifier has already been submitted."}}"#,
    ] {
        let report = usage_report();
        let reported =
            pollster::block_on(stripe(ScriptedHttp::replying(400, body)).report_usage(&report))
                .unwrap();
        assert!(reported.already_reported, "a duplicate is success");
        assert_eq!(reported.identifier, report.identifier);
    }
}

#[test]
fn report_usage_does_not_treat_an_unrelated_400_as_a_duplicate() {
    // "duplicate" without "identifier" is some other complaint: it must stay
    // a rejection, never a silent success. Same for a message with neither.
    for message in ["This duplicate request was rejected.", "Something else."] {
        let body = format!(r#"{{"error":{{"message":"{message}"}}}}"#);
        let http = ScriptedHttp::replying(400, &body);
        let err = pollster::block_on(stripe(http).report_usage(&usage_report())).unwrap_err();
        assert!(
            matches!(err, PaymentsError::Rejected(_)),
            "message {message:?}"
        );
    }
}

#[test]
fn report_usage_maps_a_concurrent_conflict_to_transient() {
    let http = ScriptedHttp::replying(
        409,
        r#"{"error":{"code":"too_many_concurrent_requests","message":"Cannot create multiple usage events for the same customer, meter concurrently."}}"#,
    );
    let err = pollster::block_on(stripe(http).report_usage(&usage_report())).unwrap_err();
    assert!(matches!(err, PaymentsError::Transient(_)));
}

#[test]
fn report_usage_maps_an_inactive_meter_to_rejected() {
    let http = ScriptedHttp::replying(
        400,
        r#"{"error":{"code":"no_meter","message":"No meter found for the given event name."}}"#,
    );
    let err = pollster::block_on(stripe(http).report_usage(&usage_report())).unwrap_err();
    assert!(
        matches!(err, PaymentsError::Rejected(m) if m.contains("no_meter") && m.contains("No meter found")),
        "Stripe's code and message must both survive"
    );
}

#[test]
fn report_usage_maps_5xx_and_429_to_transient() {
    for status in [500u16, 429] {
        let http = ScriptedHttp::replying(status, r#"{"error":{"message":"try later"}}"#);
        let err = pollster::block_on(stripe(http).report_usage(&usage_report())).unwrap_err();
        assert!(
            matches!(err, PaymentsError::Transient(_)),
            "status {status}"
        );
    }
}

#[test]
fn report_usage_not_configured_never_calls_the_network() {
    let err =
        pollster::block_on(Stripe::not_configured().report_usage(&usage_report())).unwrap_err();
    assert!(matches!(err, PaymentsError::NotConfigured));
}

#[test]
fn report_usage_rejects_an_empty_identifier_without_a_request() {
    let http = ScriptedHttp::ok(METER_EVENT_BODY);
    let s = stripe(http.clone());
    let report = UsageReport {
        identifier: String::new(),
        ..usage_report()
    };
    let err = pollster::block_on(s.report_usage(&report)).unwrap_err();
    assert!(matches!(err, PaymentsError::Rejected(_)));
    assert!(
        http.bodies().is_empty(),
        "a malformed report must not reach Stripe"
    );
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

#[test]
fn verify_webhook_accepts_one_valid_signature_among_several() {
    // What a signing-secret rotation looks like on the wire: Stripe signs
    // with both secrets for the overlap, and one match is enough.
    let body = r#"{"id":"evt_1","type":"x","data":{"object":{}}}"#;
    let old = sign("whsec_rotated_out", 1_700_000_000, body);
    let current = sign("whsec_test", 1_700_000_000, body);
    let header = format!("t=1700000000,v1={old},v1={current}");

    let http = ScriptedHttp::ok("");
    let s = stripe(http);
    let event = pollster::block_on(s.verify_webhook(&header, body.as_bytes())).unwrap();
    assert_eq!(event.id, "evt_1");
}

#[test]
fn verify_webhook_accepts_a_matching_last_candidate() {
    // Every candidate before the match is wrong — including one of the
    // wrong length — so the match is the last thing checked. The check
    // must walk the whole list, not stop at the first candidate.
    let body = r#"{"id":"evt_1","type":"x","data":{"object":{}}}"#;
    let tampered = sign("whsec_test", 1_700_000_000, "{}");
    let current = sign("whsec_test", 1_700_000_000, body);
    let header = format!("t=1700000000,v1={tampered},v1=deadbeef,v1={current}");

    let http = ScriptedHttp::ok("");
    let s = stripe(http);
    let event = pollster::block_on(s.verify_webhook(&header, body.as_bytes())).unwrap();
    assert_eq!(event.id, "evt_1");
}

#[test]
fn verify_webhook_refuses_a_signature_of_the_wrong_length() {
    // A `v1` that does not decode to exactly 32 bytes compares unequal
    // (constant-time equality is false on a length mismatch) — it never
    // panics or takes a different path.
    let body = r#"{"id":"evt_1","type":"x","data":{"object":{}}}"#;
    let header = "t=1700000000,v1=deadbeef";

    let http = ScriptedHttp::ok("");
    let s = stripe(http);
    let err = pollster::block_on(s.verify_webhook(header, body.as_bytes())).unwrap_err();
    assert!(matches!(err, PaymentsError::SignatureInvalid(_)));
}

#[test]
fn verify_webhook_refuses_when_no_candidate_matches() {
    let body = r#"{"id":"evt_1","type":"x","data":{"object":{}}}"#;
    let other = sign("whsec_other", 1_700_000_000, body);
    let truncated = format!("{other}abcd"); // right prefix, wrong length
    let header = format!("t=1700000000,v1={other},v1={truncated}");

    let http = ScriptedHttp::ok("");
    let s = stripe(http);
    let err = pollster::block_on(s.verify_webhook(&header, body.as_bytes())).unwrap_err();
    assert!(matches!(err, PaymentsError::SignatureInvalid(_)));
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
    fn uris(&self) -> Vec<String> {
        self.inner
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(|req| req.uri().to_string())
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
