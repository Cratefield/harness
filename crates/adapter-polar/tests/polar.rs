//! Fixture tests for the Polar adapter: request shaping for every mapped
//! call, error mapping, webhook signature verification under both of Polar's
//! key derivations, the event mapping for every webhook type, a dispute
//! lifecycle, refund and usage-ingestion idempotency, and `Unsupported`.
//!
//! The response bodies in `tests/fixtures/` are shaped field-for-field on
//! Polar's published `OpenAPI` schemas (API version 2026-04: `Checkout`,
//! `Order`, `Subscription`, `CustomerIndividual`, `CustomerSession`,
//! `Refund`, `Dispute`) with dummy ids and amounts. The live path against the
//! Polar sandbox is `needs-human`: it needs an organization token, which
//! does not live in the repo.
#![allow(clippy::disallowed_types)] // test doubles record calls via a Mutex

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use cratefield_adapter_polar::{
    CheckoutChange, CustomerChange, CustomerIds, Environment, OrderChange, Polar, PolarEvent,
    RefundChange, RefundReason, SubscriptionChange, normalize, signature_header,
};
use cratefield_core::{
    CheckoutRequest, Clock, ConnectAccountLinkRequest, Database, DisputeListRequest, DisputePhase,
    DisputeStatus, HttpClient, HttpError, Inbox, LineItem, MapConfig, Money, Payments,
    PaymentsError, PortalSessionRequest, RefundRequest, Statement, SubscriptionCheckoutRequest,
    TransferCharge, UsageReport, WebhookEvent,
};
use hmac::{Hmac, KeyInit, Mac};
use http::HeaderMap;
use serde_json::{Value, json};
use sha2::Sha256;

// ---------------------------------------------------------------------------
// Test doubles and fixtures

const NOW: i64 = 1_790_000_000;
const TOKEN: &str = "polar_oat_test_dummy_not_a_real_token";
/// A Standard Webhooks secret: `whsec_` + base64 of the key bytes. A dummy.
const STANDARD_SECRET: &str = "whsec_ZHVtbXktc3RhbmRhcmQta2V5LW5vdC1yZWFs";
/// An older, pre-2026-09-08 Polar secret: keyed by its own UTF-8 bytes.
const LEGACY_SECRET: &str = "whsec_legacy-dummy-secret-not-real";

struct FixedClock(i64);
impl Clock for FixedClock {
    fn now(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(self.0).unwrap()
    }
}

/// Answers each request with the next scripted `(status, body)` and records
/// the request.
struct Scripted {
    replies: Mutex<VecDeque<(u16, String)>>,
    requests: Mutex<Vec<http::Request<Bytes>>>,
}

impl Scripted {
    fn new(replies: Vec<(u16, String)>) -> Arc<Self> {
        Arc::new(Self {
            replies: Mutex::new(replies.into()),
            requests: Mutex::new(Vec::new()),
        })
    }
    fn none() -> Arc<Self> {
        Self::new(Vec::new())
    }
    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
    fn request(&self, index: usize) -> (String, String, Value) {
        let requests = self.requests.lock().unwrap();
        let request = &requests[index];
        let body = if request.body().is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(request.body()).unwrap()
        };
        (
            request.method().to_string(),
            request.uri().to_string(),
            body,
        )
    }
    fn header(&self, index: usize, name: &str) -> Option<String> {
        self.requests.lock().unwrap()[index]
            .headers()
            .get(name)
            .map(|v| v.to_str().unwrap().to_owned())
    }
}

#[async_trait::async_trait]
impl HttpClient for Scripted {
    async fn send(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        self.requests.lock().unwrap().push(request);
        let (status, body) = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("an unscripted request was made");
        Ok(http::Response::builder()
            .status(status)
            .body(Bytes::from(body))
            .unwrap())
    }
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn fixture_json(name: &str) -> Value {
    serde_json::from_str(&fixture(name)).unwrap()
}

fn polar(http: Arc<Scripted>) -> Polar {
    Polar::new(
        http,
        Arc::new(FixedClock(NOW)),
        Environment::Sandbox,
        TOKEN,
        STANDARD_SECRET,
    )
}

fn meta() -> BTreeMap<String, String> {
    BTreeMap::from([("account_id".to_owned(), "acct_42".to_owned())])
}

fn subscription_request(product: &str) -> SubscriptionCheckoutRequest {
    SubscriptionCheckoutRequest {
        customer_ref: None,
        customer_email: Some("buyer@example.test".to_owned()),
        price_ref: product.to_owned(),
        trial_days: None,
        success_url: "https://acme.example/billing/ok".to_owned(),
        cancel_url: "https://acme.example/billing/cancel".to_owned(),
        metadata: meta(),
        idempotency_key: "idem-sub".to_owned(),
    }
}

fn block<F: std::future::Future>(future: F) -> F::Output {
    pollster::block_on(future)
}

// ---------------------------------------------------------------------------
// Configuration

#[test]
fn sandbox_and_production_hosts() {
    assert_eq!(
        Environment::Sandbox.base_url(),
        "https://sandbox-api.polar.sh"
    );
    assert_eq!(Environment::Production.base_url(), "https://api.polar.sh");
    assert_eq!(Environment::parse(None), Environment::Sandbox);
    assert_eq!(Environment::parse(Some("garbage")), Environment::Sandbox);
    assert_eq!(
        Environment::parse(Some(" Production ")),
        Environment::Production
    );

    let http = Scripted::new(vec![(201, fixture("checkout.json"))]);
    let adapter = Polar::new(
        http.clone(),
        Arc::new(FixedClock(NOW)),
        Environment::Production,
        TOKEN,
        "",
    );
    block(adapter.create_subscription_checkout(&subscription_request("prod_monthly"))).unwrap();
    assert!(
        http.request(0)
            .1
            .starts_with("https://api.polar.sh/v1/checkouts/")
    );
}

#[test]
fn from_config_reads_the_token_secret_and_environment() {
    let config = MapConfig::from_pairs([
        ("POLAR_ACCESS_TOKEN", TOKEN),
        ("POLAR_WEBHOOK_SECRET", STANDARD_SECRET),
        ("POLAR_ENVIRONMENT", "sandbox"),
    ]);
    let http = Scripted::new(vec![(201, fixture("checkout.json"))]);
    let adapter = Polar::from_config(http.clone(), Arc::new(FixedClock(NOW)), &config);
    block(adapter.create_subscription_checkout(&subscription_request("prod_monthly"))).unwrap();
    assert!(
        http.request(0)
            .1
            .starts_with("https://sandbox-api.polar.sh/")
    );

    // No token: degraded, and no network call.
    let empty = Polar::from_config(
        Scripted::none(),
        Arc::new(FixedClock(NOW)),
        &MapConfig::from_pairs(Vec::<(String, String)>::new()),
    );
    let err = block(empty.create_subscription_checkout(&subscription_request("p"))).unwrap_err();
    assert!(matches!(err, PaymentsError::NotConfigured));
}

#[test]
fn blank_token_is_not_configured_with_no_network_call() {
    let http = Scripted::none();
    let adapter = Polar::new(
        http.clone(),
        Arc::new(FixedClock(NOW)),
        Environment::Sandbox,
        "   ",
        STANDARD_SECRET,
    );
    assert!(matches!(
        block(adapter.create_subscription_checkout(&subscription_request("p"))).unwrap_err(),
        PaymentsError::NotConfigured
    ));
    assert!(matches!(
        block(adapter.verify_webhook("", b"{}")).unwrap_err(),
        PaymentsError::NotConfigured
    ));
    assert_eq!(http.count(), 0);
}

#[test]
fn the_token_never_appears_in_debug_or_errors() {
    let http = Scripted::new(vec![(
        401,
        r#"{"error":"Unauthorized","detail":"Invalid token"}"#.to_owned(),
    )]);
    let adapter = polar(http.clone());
    let shown = format!("{adapter:?}");
    assert!(!shown.contains(TOKEN) && !shown.contains(STANDARD_SECRET));
    let err = block(adapter.create_subscription_checkout(&subscription_request("p"))).unwrap_err();
    assert!(!err.to_string().contains(TOKEN));
    assert!(matches!(err, PaymentsError::Rejected(_)));
    // …while the request itself does carry it, as a bearer token.
    assert_eq!(
        http.header(0, "authorization").unwrap(),
        format!("Bearer {TOKEN}")
    );
}

// ---------------------------------------------------------------------------
// Checkout

#[test]
fn subscription_checkout_monthly_and_annual() {
    for product in ["prod_monthly", "prod_annual"] {
        let http = Scripted::new(vec![(201, fixture("checkout.json"))]);
        let session =
            block(polar(http.clone()).create_subscription_checkout(&subscription_request(product)))
                .unwrap();
        assert_eq!(session.id, "8f1a2b3c-0000-4000-8000-00000000c0c0");
        assert_eq!(
            session.url,
            "https://sandbox.polar.sh/checkout/polar_c_dummy"
        );

        let (method, uri, body) = http.request(0);
        assert_eq!(method, "POST");
        assert_eq!(uri, "https://sandbox-api.polar.sh/v1/checkouts/");
        assert_eq!(body["products"], json!([product]));
        assert_eq!(body["customer_email"], "buyer@example.test");
        assert_eq!(body["metadata"], json!({ "account_id": "acct_42" }));
        assert_eq!(body["success_url"], "https://acme.example/billing/ok");
        assert_eq!(body["return_url"], "https://acme.example/billing/cancel");
        assert!(body.get("allow_trial").is_none());
        assert_eq!(
            http.header(0, "content-type").as_deref(),
            Some("application/json")
        );
    }
}

#[test]
fn subscription_checkout_with_a_trial_and_a_known_customer() {
    let http = Scripted::new(vec![(201, fixture("checkout.json"))]);
    let mut request = subscription_request("prod_monthly");
    request.trial_days = Some(14);
    request.customer_ref = Some("cus_polar_1".to_owned());
    block(polar(http.clone()).create_subscription_checkout(&request)).unwrap();
    let body = http.request(0).2;
    assert_eq!(body["allow_trial"], true);
    assert_eq!(body["trial_interval"], "day");
    assert_eq!(body["trial_interval_count"], 14);
    assert_eq!(body["customer_id"], "cus_polar_1");
    assert!(body.get("external_customer_id").is_none());
}

#[test]
fn external_customer_ids_name_the_venture_account() {
    let http = Scripted::new(vec![(201, fixture("checkout.json"))]);
    let adapter = polar(http.clone()).with_customer_ids(CustomerIds::External);
    let mut request = subscription_request("prod_monthly");
    request.customer_ref = Some("acct_42".to_owned());
    block(adapter.create_subscription_checkout(&request)).unwrap();
    let body = http.request(0).2;
    assert_eq!(body["external_customer_id"], "acct_42");
    assert!(body.get("customer_id").is_none());
}

fn one_off() -> CheckoutRequest {
    CheckoutRequest {
        customer_ref: None,
        customer_email: Some("buyer@example.test".to_owned()),
        line: LineItem {
            name: "Credits pack".to_owned(),
            amount: Money::new(500, "USD"),
            quantity: 3,
        },
        success_url: "https://acme.example/ok".to_owned(),
        cancel_url: "https://acme.example/no".to_owned(),
        metadata: meta(),
        idempotency_key: "idem-once".to_owned(),
    }
}

#[test]
fn one_off_checkout_is_an_ad_hoc_price_on_the_configured_product() {
    let http = Scripted::new(vec![(201, fixture("checkout.json"))]);
    let adapter = polar(http.clone()).with_one_off_product("prod_credits");
    block(adapter.create_checkout(&one_off())).unwrap();
    let body = http.request(0).2;
    assert_eq!(body["products"], json!(["prod_credits"]));
    assert_eq!(
        body["prices"],
        json!({ "prod_credits": [{
            "amount_type": "fixed",
            "price_amount": 1500,
            "price_currency": "usd",
        }] })
    );
}

#[test]
fn one_off_checkout_without_a_product_is_unsupported() {
    let http = Scripted::none();
    let err = block(polar(http.clone()).create_checkout(&one_off())).unwrap_err();
    assert!(matches!(err, PaymentsError::Unsupported(_)));
    assert_eq!(http.count(), 0);
}

// ---------------------------------------------------------------------------
// Unsupported operations

#[test]
fn charge_and_connect_are_unsupported_and_never_call_out() {
    let http = Scripted::none();
    let adapter = polar(http.clone());
    let charge = block(adapter.charge_with_transfer(&TransferCharge {
        customer_ref: None,
        amount: Money::new(1000, "usd"),
        destination_account: "acct_x".to_owned(),
        application_fee: Money::new(100, "usd"),
        metadata: BTreeMap::new(),
        idempotency_key: "k".to_owned(),
    }))
    .unwrap_err();
    assert!(matches!(charge, PaymentsError::Unsupported(_)));
    let connect = block(
        adapter.create_connect_account_link(&ConnectAccountLinkRequest {
            account_ref: None,
            refresh_url: "https://x/r".to_owned(),
            return_url: "https://x/b".to_owned(),
            idempotency_key: "k".to_owned(),
        }),
    )
    .unwrap_err();
    assert!(matches!(connect, PaymentsError::Unsupported(_)));
    assert_eq!(http.count(), 0);
}

// ---------------------------------------------------------------------------
// Customer portal

#[test]
fn portal_session_returns_the_customer_portal_url() {
    let http = Scripted::new(vec![(201, fixture("customer_session.json"))]);
    let session = block(
        polar(http.clone()).create_portal_session(&PortalSessionRequest {
            customer_ref: "cus_polar_1".to_owned(),
            return_url: "https://acme.example/account".to_owned(),
            idempotency_key: "idem-portal".to_owned(),
        }),
    )
    .unwrap();
    assert_eq!(
        session.url,
        "https://sandbox.polar.sh/acme/portal?customer_session_token=polar_cst_dummy"
    );
    let (method, uri, body) = http.request(0);
    assert_eq!(method, "POST");
    assert_eq!(uri, "https://sandbox-api.polar.sh/v1/customer-sessions/");
    assert_eq!(
        body,
        json!({ "customer_id": "cus_polar_1", "return_url": "https://acme.example/account" })
    );
}

#[test]
fn portal_session_by_external_id() {
    let http = Scripted::new(vec![(201, fixture("customer_session.json"))]);
    block(
        polar(http.clone())
            .with_customer_ids(CustomerIds::External)
            .create_portal_session(&PortalSessionRequest {
                customer_ref: "acct_42".to_owned(),
                return_url: "https://acme.example/account".to_owned(),
                idempotency_key: "k".to_owned(),
            }),
    )
    .unwrap();
    assert_eq!(http.request(0).2["external_customer_id"], "acct_42");
}

// ---------------------------------------------------------------------------
// Refunds

fn empty_list() -> String {
    r#"{"items":[],"pagination":{"total_count":0,"max_page":1}}"#.to_owned()
}

#[test]
fn full_refund_reads_the_refundable_amount_first() {
    let order = fixture_json("order.json");
    let order_id = order["id"].as_str().unwrap().to_owned();
    let http = Scripted::new(vec![
        (200, empty_list()),
        (200, fixture("order.json")),
        (201, fixture("refund.json")),
    ]);
    let refund = block(polar(http.clone()).refund(&RefundRequest {
        payment_ref: order_id.clone(),
        amount: None,
        idempotency_key: "idem-refund-1".to_owned(),
    }))
    .unwrap();
    assert_eq!(refund.id, "4ef00000-0000-4000-8000-00000000ref1");

    let (_, list_uri, _) = http.request(0);
    assert_eq!(
        list_uri,
        format!("https://sandbox-api.polar.sh/v1/refunds/?order_id={order_id}&limit=100")
    );
    let (method, uri, _) = http.request(1);
    assert_eq!(
        (method.as_str(), uri.as_str()),
        (
            "GET",
            format!("https://sandbox-api.polar.sh/v1/orders/{order_id}").as_str()
        )
    );
    let (method, uri, body) = http.request(2);
    assert_eq!(method, "POST");
    assert_eq!(uri, "https://sandbox-api.polar.sh/v1/refunds/");
    assert_eq!(
        body,
        json!({
            "order_id": order_id,
            "reason": "customer_request",
            "amount": 1500,
            "metadata": { "cratefield_idempotency_key": "idem-refund-1" },
        })
    );
}

#[test]
fn partial_refund_with_a_reason_skips_the_order_lookup() {
    let http = Scripted::new(vec![(200, empty_list()), (201, fixture("refund.json"))]);
    block(polar(http.clone()).refund_with_reason(
        &RefundRequest {
            payment_ref: "57107b74-8400-4d80-a2fc-54c2b4239cb3".to_owned(),
            amount: Some(Money::new(400, "usd")),
            idempotency_key: "idem-partial".to_owned(),
        },
        RefundReason::ServiceDisruption,
    ))
    .unwrap();
    assert_eq!(http.count(), 2);
    let body = http.request(1).2;
    assert_eq!(body["amount"], 400);
    assert_eq!(body["reason"], "service_disruption");
}

#[test]
fn a_retried_refund_returns_the_first_one() {
    let mut existing = fixture_json("refund.json");
    existing["metadata"] = json!({ "cratefield_idempotency_key": "idem-refund-1" });
    let list = json!({ "items": [existing], "pagination": { "total_count": 1, "max_page": 1 } });
    let http = Scripted::new(vec![(200, list.to_string())]);
    let refund = block(polar(http.clone()).refund(&RefundRequest {
        payment_ref: "57107b74-8400-4d80-a2fc-54c2b4239cb3".to_owned(),
        amount: None,
        idempotency_key: "idem-refund-1".to_owned(),
    }))
    .unwrap();
    assert_eq!(refund.id, "4ef00000-0000-4000-8000-00000000ref1");
    assert_eq!(http.count(), 1, "no second refund is created");
}

#[test]
fn refund_of_a_fully_refunded_order_is_rejected() {
    let mut order = fixture_json("order.json");
    order["refundable_amount"] = json!(0);
    let http = Scripted::new(vec![(200, empty_list()), (200, order.to_string())]);
    let err = block(polar(http.clone()).refund(&RefundRequest {
        payment_ref: "57107b74-8400-4d80-a2fc-54c2b4239cb3".to_owned(),
        amount: None,
        idempotency_key: "k".to_owned(),
    }))
    .unwrap_err();
    assert!(matches!(err, PaymentsError::Rejected(_)));
    assert_eq!(http.count(), 2);

    // Polar's own refusal (`403 RefundedAlready`) maps the same way.
    let http = Scripted::new(vec![
        (200, empty_list()),
        (
            403,
            r#"{"error":"RefundedAlready","detail":"Order is already fully refunded."}"#.to_owned(),
        ),
    ]);
    let err = block(polar(http).refund(&RefundRequest {
        payment_ref: "57107b74-8400-4d80-a2fc-54c2b4239cb3".to_owned(),
        amount: Some(Money::new(1, "usd")),
        idempotency_key: "k".to_owned(),
    }))
    .unwrap_err();
    let PaymentsError::Rejected(message) = err else {
        panic!("expected Rejected")
    };
    assert!(message.contains("RefundedAlready"));
}

#[test]
fn an_id_that_would_change_the_path_is_refused() {
    let http = Scripted::none();
    let err = block(polar(http.clone()).refund(&RefundRequest {
        payment_ref: "../organizations".to_owned(),
        amount: None,
        idempotency_key: "k".to_owned(),
    }))
    .unwrap_err();
    assert!(matches!(err, PaymentsError::Rejected(_)));
    assert!(block(polar(http.clone()).get_dispute("a/b")).is_err());
    assert_eq!(http.count(), 0);
}

// ---------------------------------------------------------------------------
// Usage-based billing

fn hourly() -> UsageReport {
    UsageReport::hourly(
        "acct_42",
        "emails.accepted",
        "cus_polar_1",
        37,
        time::OffsetDateTime::from_unix_timestamp(1_790_003_725).unwrap(),
    )
}

#[test]
fn usage_is_ingested_as_an_event_keyed_by_its_identifier() {
    let http = Scripted::new(vec![(200, r#"{"inserted":1,"duplicates":0}"#.to_owned())]);
    let report = hourly();
    let reported = block(polar(http.clone()).report_usage(&report)).unwrap();
    assert_eq!(reported.identifier, report.identifier);
    assert!(!reported.already_reported);

    let (method, uri, body) = http.request(0);
    assert_eq!(method, "POST");
    assert_eq!(uri, "https://sandbox-api.polar.sh/v1/events/ingest");
    assert_eq!(
        body,
        json!({ "events": [{
            "name": "emails.accepted",
            "customer_id": "cus_polar_1",
            "external_id": report.identifier,
            "timestamp": "2026-09-21T15:00:00Z",
            "metadata": { "value": 37 },
        }] })
    );
}

#[test]
fn re_sending_the_same_identifier_is_a_duplicate_not_a_second_count() {
    // Polar dedups on `external_id`: the first send inserts, the second is
    // counted as a duplicate and the adapter reports it as already reported.
    let http = Scripted::new(vec![
        (200, r#"{"inserted":1,"duplicates":0}"#.to_owned()),
        (200, r#"{"inserted":0,"duplicates":1}"#.to_owned()),
    ]);
    let adapter = polar(http.clone());
    let report = hourly();
    assert!(
        !block(adapter.report_usage(&report))
            .unwrap()
            .already_reported
    );
    assert!(
        block(adapter.report_usage(&report))
            .unwrap()
            .already_reported
    );
    // Both sends carried the same external id: the hour's identifier.
    assert_eq!(
        http.request(0).2["events"][0]["external_id"],
        http.request(1).2["events"][0]["external_id"]
    );
}

#[test]
fn usage_by_external_customer_and_custom_value_key() {
    let http = Scripted::new(vec![(200, r#"{"inserted":1}"#.to_owned())]);
    let adapter = polar(http.clone())
        .with_customer_ids(CustomerIds::External)
        .with_usage_value_key("gb");
    let mut report = hourly();
    report.customer_ref = "acct_42".to_owned();
    block(adapter.report_usage(&report)).unwrap();
    let event = &http.request(0).2["events"][0];
    assert_eq!(event["external_customer_id"], "acct_42");
    assert!(event.get("customer_id").is_none());
    assert_eq!(event["metadata"], json!({ "gb": 37 }));
}

#[test]
fn usage_batches_are_chunked_and_counted() {
    let http = Scripted::new(vec![
        (200, r#"{"inserted":100,"duplicates":0}"#.to_owned()),
        (200, r#"{"inserted":98,"duplicates":2}"#.to_owned()),
        (200, r#"{"inserted":50,"duplicates":0}"#.to_owned()),
    ]);
    let reports: Vec<UsageReport> = (0..250)
        .map(|n| {
            let mut report = hourly();
            report.identifier = format!("acct_42:emails.accepted:{n}");
            report
        })
        .collect();
    let counts = block(polar(http.clone()).report_usage_batch(&reports)).unwrap();
    assert_eq!((counts.inserted, counts.duplicates), (248, 2));
    assert_eq!(http.count(), 3);
    assert_eq!(http.request(0).2["events"].as_array().unwrap().len(), 100);
    assert_eq!(http.request(2).2["events"].as_array().unwrap().len(), 50);
}

#[test]
fn a_malformed_usage_report_never_calls_out() {
    let http = Scripted::none();
    let mut report = hourly();
    report.identifier = String::new();
    assert!(matches!(
        block(polar(http.clone()).report_usage(&report)).unwrap_err(),
        PaymentsError::Rejected(_)
    ));
    assert!(block(polar(http.clone()).report_usage_batch(&[hourly(), report])).is_err());
    assert_eq!(http.count(), 0);
}

#[test]
fn rate_limits_and_server_errors_are_transient_validation_is_not() {
    for (status, transient) in [(429, true), (502, true), (422, false), (404, false)] {
        let body = if status == 422 {
            r#"{"detail":[{"loc":["body","events",0,"name"],"msg":"Field required","type":"missing"}]}"#
        } else {
            "{}"
        };
        let http = Scripted::new(vec![(status, body.to_owned())]);
        let err = block(polar(http).report_usage(&hourly())).unwrap_err();
        assert_eq!(
            matches!(err, PaymentsError::Transient(_)),
            transient,
            "{status}"
        );
        if status == 422 {
            assert!(err.to_string().contains("Field required"));
        }
    }
}

// ---------------------------------------------------------------------------
// Disputes

#[test]
fn get_dispute_maps_polar_onto_the_port() {
    let http = Scripted::new(vec![(200, fixture("dispute_needs_response.json"))]);
    let dispute =
        block(polar(http.clone()).get_dispute("d15b0000-0000-4000-8000-0000000d1590")).unwrap();
    assert_eq!(
        http.request(0).1,
        "https://sandbox-api.polar.sh/v1/disputes/d15b0000-0000-4000-8000-0000000d1590"
    );
    assert_eq!(dispute.status, DisputeStatus::NeedsResponse);
    assert_eq!(dispute.status.phase(), DisputePhase::Open);
    assert_eq!(dispute.provider_status, "needs_response");
    assert_eq!(dispute.payment_ref, "57107b74-8400-4d80-a2fc-54c2b4239cb3");
    assert_eq!(
        dispute.charge_ref.as_deref(),
        Some("42b94870-36b9-4573-96b6-b90b1c99a353")
    );
    assert_eq!(dispute.amount, Money::new(1500, "usd"));
    assert_eq!(dispute.reason.as_deref(), Some("fraudulent"));
    assert_eq!(
        dispute.customer_ref.as_deref(),
        Some("5c2e5c5a-1f3b-4c8e-9a51-0f6c1f9f0a01")
    );
    assert!(dispute.evidence_due_by.is_some());
    assert_eq!(dispute.is_charge_refundable, None);
}

/// The lifecycle a venture's dispute poll sees, and what it does: flag the
/// account on open, and restore it (won) or keep it revoked (lost). Each
/// transition has its own `event_key`, so the Inbox acts on each once.
fn lifecycle(final_fixture: &str, final_phase: DisputePhase) {
    let http = Scripted::new(vec![
        (200, fixture("dispute_needs_response.json")),
        (200, fixture("dispute_under_review.json")),
        (200, fixture(final_fixture)),
    ]);
    let adapter = polar(http).with_customer_ids(CustomerIds::External);
    let mut flagged: BTreeMap<String, bool> = BTreeMap::new();
    let mut seen = Vec::new();
    for _ in 0..3 {
        let dispute = block(adapter.get_dispute("d15b0000-0000-4000-8000-0000000d1590")).unwrap();
        let account = dispute.customer_ref.clone().unwrap();
        assert_eq!(account, "acct_42", "external ids name the venture account");
        seen.push(dispute.event_key());
        match dispute.status.phase() {
            DisputePhase::Open => {
                flagged.insert(account, true);
            }
            DisputePhase::Won | DisputePhase::Closed => {
                flagged.insert(account, false);
            }
            DisputePhase::Lost => {} // stays flagged; grants are revoked
        }
        if seen.len() == 3 {
            assert_eq!(dispute.status.phase(), final_phase);
        }
    }
    seen.dedup();
    assert_eq!(seen.len(), 3, "every transition has its own dedup key");
    assert_eq!(flagged["acct_42"], final_phase == DisputePhase::Lost);
}

#[test]
fn dispute_lifecycle_opened_then_lost() {
    lifecycle("dispute_lost.json", DisputePhase::Lost);
}

#[test]
fn dispute_lifecycle_opened_then_won() {
    lifecycle("dispute_won.json", DisputePhase::Won);
}

#[test]
fn list_open_disputes_filters_sorts_and_pages() {
    let page = json!({
        "items": [fixture_json("dispute_needs_response.json")],
        "pagination": { "total_count": 101, "max_page": 2 },
    });
    let http = Scripted::new(vec![(200, page.to_string())]);
    let result = block(polar(http.clone()).list_disputes(&DisputeListRequest {
        open_only: true,
        cursor: None,
    }))
    .unwrap();
    assert_eq!(result.disputes.len(), 1);
    assert_eq!(result.next.as_deref(), Some("2"));
    assert_eq!(
        http.request(0).1,
        "https://sandbox-api.polar.sh/v1/disputes/?page=1&limit=100&sorting=-created_at\
         &status=early_warning&status=needs_response&status=under_review"
    );

    let last = json!({ "items": [], "pagination": { "total_count": 101, "max_page": 2 } });
    let http = Scripted::new(vec![(200, last.to_string())]);
    let result = block(polar(http.clone()).list_disputes(&DisputeListRequest {
        open_only: false,
        cursor: Some("2".to_owned()),
    }))
    .unwrap();
    assert_eq!(result.next, None);
    assert_eq!(
        http.request(0).1,
        "https://sandbox-api.polar.sh/v1/disputes/?page=2&limit=100&sorting=-created_at"
    );
}

#[test]
fn close_dispute_accepts_it_and_a_closed_one_is_rejected() {
    let http = Scripted::new(vec![(200, fixture("dispute_lost.json"))]);
    let dispute =
        block(polar(http.clone()).close_dispute("d15b0000-0000-4000-8000-0000000d1590", "k"))
            .unwrap();
    assert_eq!(dispute.status, DisputeStatus::Lost);
    let (method, uri, _) = http.request(0);
    assert_eq!(method, "POST");
    assert_eq!(
        uri,
        "https://sandbox-api.polar.sh/v1/disputes/d15b0000-0000-4000-8000-0000000d1590/accept"
    );

    let http = Scripted::new(vec![(
        409,
        r#"{"error":"DisputeNotOpenError","detail":"Dispute is not open."}"#.to_owned(),
    )]);
    let err =
        block(polar(http).close_dispute("d15b0000-0000-4000-8000-0000000d1590", "k")).unwrap_err();
    assert!(matches!(err, PaymentsError::Rejected(_)));
}

#[test]
fn dispute_status_spellings_and_phases() {
    for (raw, phase) in [
        ("early_warning", DisputePhase::Open),
        ("needs_response", DisputePhase::Open),
        ("under_review", DisputePhase::Open),
        ("won", DisputePhase::Won),
        ("lost", DisputePhase::Lost),
        ("prevented", DisputePhase::Closed),
        ("warning_closed", DisputePhase::Closed),
        ("something_new", DisputePhase::Open),
    ] {
        assert_eq!(DisputeStatus::from_provider(raw).phase(), phase, "{raw}");
    }
    assert_eq!(
        DisputeStatus::from_provider("something_new"),
        DisputeStatus::Other("something_new".to_owned())
    );
}

// ---------------------------------------------------------------------------
// Webhook signatures

fn sign(key: &[u8], id: &str, timestamp: i64, body: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
    mac.update(format!("{id}.{timestamp}.").as_bytes());
    mac.update(body);
    format!("v1,{}", STANDARD.encode(mac.finalize().into_bytes()))
}

fn standard_key(secret: &str) -> Vec<u8> {
    STANDARD
        .decode(secret.strip_prefix("whsec_").unwrap())
        .unwrap()
}

fn delivery(signature: &str, id: &str, timestamp: i64) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("webhook-id", id.parse().unwrap());
    headers.insert("webhook-timestamp", timestamp.to_string().parse().unwrap());
    headers.insert("webhook-signature", signature.parse().unwrap());
    headers
}

fn payload(kind: &str, data: &Value) -> Vec<u8> {
    json!({
        "type": kind,
        "timestamp": "2026-10-01T09:30:00.000000Z",
        "api_version": "2026-04",
        "data": data,
    })
    .to_string()
    .into_bytes()
}

fn adapter_with_secret(secret: &str) -> Polar {
    Polar::new(
        Scripted::none(),
        Arc::new(FixedClock(NOW)),
        Environment::Sandbox,
        TOKEN,
        secret,
    )
}

#[test]
fn a_standard_webhooks_signature_verifies() {
    let body = payload("order.paid", &fixture_json("order.json"));
    let sig = sign(&standard_key(STANDARD_SECRET), "msg_1", NOW, &body);
    let event = block(
        adapter_with_secret(STANDARD_SECRET)
            .verify_webhook_request(&delivery(&sig, "msg_1", NOW), &body),
    )
    .unwrap();
    assert_eq!(event.id, "msg_1");
    assert_eq!(event.kind, "order.paid");
    assert_eq!(event.data["id"], "57107b74-8400-4d80-a2fc-54c2b4239cb3");
}

#[test]
fn an_older_polar_hmac_secret_verifies_too() {
    // Secrets made before 2026-09-08 key the HMAC with their UTF-8 bytes.
    let body = payload("order.paid", &fixture_json("order.json"));
    let sig = sign(LEGACY_SECRET.as_bytes(), "msg_2", NOW, &body);
    let event = block(
        adapter_with_secret(LEGACY_SECRET)
            .verify_webhook_request(&delivery(&sig, "msg_2", NOW), &body),
    )
    .unwrap();
    assert_eq!(event.id, "msg_2");
}

#[test]
fn a_rotated_header_with_several_signatures_verifies() {
    let body = payload("order.paid", &fixture_json("order.json"));
    let good = sign(&standard_key(STANDARD_SECRET), "msg_3", NOW, &body);
    let header = format!("v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= {good}");
    assert!(
        block(
            adapter_with_secret(STANDARD_SECRET)
                .verify_webhook_request(&delivery(&header, "msg_3", NOW), &body)
        )
        .is_ok()
    );
}

#[test]
fn the_wrong_secret_is_refused() {
    let body = payload("order.paid", &fixture_json("order.json"));
    let sig = sign(b"some-other-endpoint-secret", "msg_4", NOW, &body);
    let err = block(
        adapter_with_secret(STANDARD_SECRET)
            .verify_webhook_request(&delivery(&sig, "msg_4", NOW), &body),
    )
    .unwrap_err();
    assert!(matches!(err, PaymentsError::SignatureInvalid(_)));
}

#[test]
fn a_stale_or_future_timestamp_is_refused() {
    let body = payload("order.paid", &fixture_json("order.json"));
    for sent in [NOW - 301, NOW + 301] {
        let sig = sign(&standard_key(STANDARD_SECRET), "msg_5", sent, &body);
        let err = block(
            adapter_with_secret(STANDARD_SECRET)
                .verify_webhook_request(&delivery(&sig, "msg_5", sent), &body),
        )
        .unwrap_err();
        assert!(matches!(err, PaymentsError::SignatureInvalid(_)), "{sent}");
    }
    // Inside the tolerance it verifies.
    let sig = sign(&standard_key(STANDARD_SECRET), "msg_5", NOW - 299, &body);
    assert!(
        block(
            adapter_with_secret(STANDARD_SECRET)
                .verify_webhook_request(&delivery(&sig, "msg_5", NOW - 299), &body)
        )
        .is_ok()
    );
}

#[test]
fn a_tampered_body_or_id_is_refused() {
    let body = payload("order.paid", &fixture_json("order.json"));
    let sig = sign(&standard_key(STANDARD_SECRET), "msg_6", NOW, &body);
    let mut tampered = body.clone();
    tampered.extend_from_slice(b" ");
    let adapter = adapter_with_secret(STANDARD_SECRET);
    assert!(
        block(adapter.verify_webhook_request(&delivery(&sig, "msg_6", NOW), &tampered)).is_err()
    );
    // The id is signed too: a replay under a fresh id does not verify.
    assert!(block(adapter.verify_webhook_request(&delivery(&sig, "msg_7", NOW), &body)).is_err());
    // Missing headers fail closed.
    assert!(block(adapter.verify_webhook_request(&HeaderMap::new(), &body)).is_err());
}

#[test]
fn the_packed_signature_header_goes_through_verify_webhook() {
    let body = payload("subscription.active", &fixture_json("subscription.json"));
    let sig = sign(&standard_key(STANDARD_SECRET), "msg_8", NOW, &body);
    let packed = signature_header(&delivery(&sig, "msg_8", NOW)).unwrap();
    let event = block(adapter_with_secret(STANDARD_SECRET).verify_webhook(&packed, &body)).unwrap();
    assert_eq!(event.kind, "subscription.active");
    assert!(signature_header(&HeaderMap::new()).is_none());
}

#[test]
fn no_webhook_secret_is_not_configured() {
    let body = payload("order.paid", &json!({}));
    let err = block(
        adapter_with_secret("").verify_webhook_request(&delivery("v1,AAAA", "msg_9", NOW), &body),
    )
    .unwrap_err();
    assert!(matches!(err, PaymentsError::NotConfigured));
}

#[test]
fn a_replayed_delivery_is_applied_once() {
    // Polar retries a delivery under the same `webhook-id`; the event id the
    // adapter returns is that header, so the Inbox claims it exactly once.
    let db = cratefield_adapter_sqlite::SqliteDatabase::in_memory().unwrap();
    let inbox = Inbox::new("billing_inbox");
    block(db.execute(&Statement::new(inbox.create_table_sql()))).unwrap();

    let adapter = adapter_with_secret(STANDARD_SECRET);
    let body = payload("order.paid", &fixture_json("order.json"));
    let sig = sign(&standard_key(STANDARD_SECRET), "msg_replay", NOW, &body);
    let mut applied = 0;
    for _ in 0..3 {
        let event =
            block(adapter.verify_webhook_request(&delivery(&sig, "msg_replay", NOW), &body))
                .unwrap();
        if block(inbox.claim(&db, &event.id, "2026-10-01T09:30:00Z")).unwrap() {
            applied += 1;
        }
    }
    assert_eq!(applied, 1);
}

// ---------------------------------------------------------------------------
// Event mapping (every webhook type)

fn event(kind: &str, data: Value) -> WebhookEvent {
    WebhookEvent {
        id: format!("msg_{kind}"),
        kind: kind.to_owned(),
        data,
    }
}

#[test]
fn checkout_events() {
    for (kind, change) in [
        ("checkout.created", CheckoutChange::Created),
        ("checkout.updated", CheckoutChange::Updated),
        ("checkout.expired", CheckoutChange::Expired),
    ] {
        let events = normalize(
            &event(kind, fixture_json("checkout.json")),
            CustomerIds::Polar,
        );
        let [PolarEvent::Checkout(checkout)] = events.as_slice() else {
            panic!("{kind}: {events:?}")
        };
        assert_eq!(checkout.change, change);
        assert_eq!(checkout.status, "open");
        assert_eq!(checkout.external_customer_id.as_deref(), Some("acct_42"));
        assert_eq!(checkout.metadata["account_id"], "acct_42");
    }
}

#[test]
fn subscription_events() {
    for (kind, change) in [
        ("subscription.created", SubscriptionChange::Created),
        ("subscription.active", SubscriptionChange::Active),
        ("subscription.updated", SubscriptionChange::Updated),
        ("subscription.canceled", SubscriptionChange::Canceled),
        ("subscription.uncanceled", SubscriptionChange::Uncanceled),
        ("subscription.revoked", SubscriptionChange::Revoked),
        ("subscription.past_due", SubscriptionChange::PastDue),
        ("subscription.paused", SubscriptionChange::Paused),
        ("subscription.resumed", SubscriptionChange::Resumed),
        ("subscription.cycled", SubscriptionChange::Cycled),
        ("subscription.migrated", SubscriptionChange::Migrated),
    ] {
        let events = normalize(
            &event(kind, fixture_json("subscription.json")),
            CustomerIds::Polar,
        );
        let [PolarEvent::Subscription(sub)] = events.as_slice() else {
            panic!("{kind}: {events:?}")
        };
        assert_eq!(sub.change, change, "{kind}");
        assert_eq!(sub.status, "active");
        assert_eq!(sub.product_id, "0d9c8a7b-0000-4000-8000-0000000000aa");
        assert_eq!(sub.external_customer_id.as_deref(), Some("acct_42"));
        assert!(sub.current_period_end.is_some());
        assert!(!sub.cancel_at_period_end);
    }
}

#[test]
fn order_events() {
    for (kind, change) in [
        ("order.created", OrderChange::Created),
        ("order.paid", OrderChange::Paid),
        ("order.updated", OrderChange::Updated),
        ("order.refunded", OrderChange::Refunded),
    ] {
        let events = normalize(&event(kind, fixture_json("order.json")), CustomerIds::Polar);
        let [PolarEvent::Order(order)] = events.as_slice() else {
            panic!("{kind}: {events:?}")
        };
        assert_eq!(order.change, change);
        assert_eq!(order.total, Money::new(1800, "usd"));
        assert_eq!(order.refunded, Money::new(0, "usd"));
        assert_eq!(order.billing_reason.as_deref(), Some("subscription_create"));
        assert_eq!(
            order.subscription_id.as_deref(),
            Some("e3f1a2b3-0000-4000-8000-00000000s0b1")
        );
    }
}

#[test]
fn refund_events() {
    for (kind, change) in [
        ("refund.created", RefundChange::Created),
        ("refund.updated", RefundChange::Updated),
    ] {
        let events = normalize(
            &event(kind, fixture_json("refund.json")),
            CustomerIds::Polar,
        );
        let [PolarEvent::Refund(refund)] = events.as_slice() else {
            panic!("{kind}: {events:?}")
        };
        assert_eq!(refund.change, change);
        assert_eq!(refund.payment_ref, "57107b74-8400-4d80-a2fc-54c2b4239cb3");
        assert_eq!(refund.amount, Money::new(1500, "usd"));
        assert_eq!(refund.status, "succeeded");
    }
}

#[test]
fn a_refund_that_prevented_a_dispute_also_yields_the_dispute() {
    let events = normalize(
        &event(
            "refund.created",
            fixture_json("refund_prevented_dispute.json"),
        ),
        CustomerIds::Polar,
    );
    let [PolarEvent::Refund(refund), PolarEvent::Dispute(dispute)] = events.as_slice() else {
        panic!("{events:?}")
    };
    assert_eq!(refund.reason, "dispute_prevention");
    assert_eq!(dispute.status, DisputeStatus::Prevented);
    assert_eq!(dispute.status.phase(), DisputePhase::Closed);
    assert_eq!(dispute.payment_ref, refund.payment_ref);
    assert_eq!(
        dispute.customer_ref.as_deref(),
        Some(refund.customer_id.as_str())
    );
}

#[test]
/// The nested `dispute` is enrichment on top of a refund that is already
/// complete. A dispute object this crate cannot read — a field Polar dropped,
/// renamed, or a shape this version does not know — must cost the dispute
/// alone: the refund Polar really did issue is money moving back to a
/// customer, and dropping it over an optional extra leaves the venture's
/// books wrong with nothing in the log but a generic "incomplete".
fn a_malformed_nested_dispute_does_not_take_the_refund_with_it() {
    let mut data = fixture_json("refund_prevented_dispute.json");
    data["dispute"]["order_id"] = Value::Null;
    let events = normalize(&event("refund.created", data), CustomerIds::Polar);
    let [PolarEvent::Refund(refund)] = events.as_slice() else {
        panic!("the refund survived: {events:?}")
    };
    assert_eq!(refund.reason, "dispute_prevention");
    assert_eq!(refund.amount, Money::new(1500, "usd"));
}

#[test]
fn customer_events() {
    for (kind, change) in [
        ("customer.created", CustomerChange::Created),
        ("customer.updated", CustomerChange::Updated),
        ("customer.deleted", CustomerChange::Deleted),
        ("customer.state_changed", CustomerChange::StateChanged),
    ] {
        let events = normalize(
            &event(kind, fixture_json("customer.json")),
            CustomerIds::Polar,
        );
        let [PolarEvent::Customer(customer)] = events.as_slice() else {
            panic!("{kind}: {events:?}")
        };
        assert_eq!(customer.change, change);
        assert_eq!(customer.external_id.as_deref(), Some("acct_42"));
        assert_eq!(customer.email.as_deref(), Some("buyer@example.test"));
    }
}

#[test]
fn unknown_unused_and_incomplete_events_are_ignored_not_errors() {
    for kind in [
        "benefit_grant.created",
        "product.updated",
        "customer_seat.claimed",
        "organization.updated",
        "something.polar.adds.later",
    ] {
        assert!(normalize(&event(kind, json!({ "id": "x" })), CustomerIds::Polar).is_empty());
    }
    // A known type with a payload missing what we need is skipped, too.
    assert!(
        normalize(
            &event("order.paid", json!({ "id": "x" })),
            CustomerIds::Polar
        )
        .is_empty()
    );
}

#[test]
fn the_adapter_normalizes_with_its_own_customer_naming() {
    let adapter = adapter_with_secret(STANDARD_SECRET).with_customer_ids(CustomerIds::External);
    let events = adapter.normalize(&event(
        "refund.created",
        fixture_json("refund_prevented_dispute.json"),
    ));
    let PolarEvent::Dispute(dispute) = &events[1] else {
        panic!("{events:?}")
    };
    // `RefundDispute` carries no customer, so no external id to name.
    assert_eq!(dispute.customer_ref, None);
}

// ---------------------------------------------------------------------------
// Switching providers by composition only (issue #690 acceptance)

/// Venture code that only knows the port: identical for Stripe and Polar.
async fn start_plan(payments: &dyn Payments, plan: &str) -> Result<String, PaymentsError> {
    Ok(payments
        .create_subscription_checkout(&subscription_request(plan))
        .await?
        .url)
}

struct StripeReply;
#[async_trait::async_trait]
impl HttpClient for StripeReply {
    async fn send(
        &self,
        _request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        Ok(http::Response::builder()
            .status(200)
            .body(Bytes::from_static(
                br#"{"id":"cs_1","url":"https://checkout.stripe.com/c/cs_1"}"#,
            ))
            .unwrap())
    }
}

#[test]
fn a_venture_switches_between_stripe_and_polar_by_composition_only() {
    let clock: Arc<dyn Clock> = Arc::new(FixedClock(NOW));
    let stripe: Arc<dyn Payments> = Arc::new(cratefield_adapter_stripe::Stripe::new(
        Arc::new(StripeReply),
        clock.clone(),
        "sk_test_dummy",
        "whsec_dummy",
    ));
    let polar: Arc<dyn Payments> =
        Arc::new(polar(Scripted::new(vec![(201, fixture("checkout.json"))])));
    assert_eq!(
        block(start_plan(stripe.as_ref(), "price_monthly")).unwrap(),
        "https://checkout.stripe.com/c/cs_1"
    );
    assert_eq!(
        block(start_plan(polar.as_ref(), "prod_monthly")).unwrap(),
        "https://sandbox.polar.sh/checkout/polar_c_dummy"
    );
}
