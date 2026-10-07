//! `cratefield-adapter-stripe`: the [`Payments`] port over the Stripe REST API
//! (issue #102). Uses the runtime's [`HttpClient`] and [`Clock`] ports — no
//! vendor SDK — so the same adapter runs on Workers and natively.
//!
//! **Card data never crosses this adapter.** Every call creates or reads a
//! Stripe object by id, or returns a hosted Stripe URL the browser is
//! redirected to; card numbers are entered on Stripe's own pages. The harness
//! holds Stripe identifiers, nothing more (see `docs/PAYMENTS.md`).
//!
//! **Degraded mode.** [`Stripe::not_configured`] reports
//! [`PaymentsError::NotConfigured`] without any network call, so a venture with
//! no Stripe keys still builds and runs.
//!
//! **Verification.** Request shaping, error mapping, and webhook signature
//! verification (including a tampered signature and a stale timestamp) are unit
//! tested here against a scripted `HttpClient`. The live path against Stripe is
//! `needs-human` (issue #102 acceptance): it needs real test-mode keys, which
//! do not live in the repo.
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{
    Charge, CheckoutRequest, CheckoutSession, Clock, ConnectAccountLink, ConnectAccountLinkRequest,
    HttpClient, Money, Payments, PaymentsError, PortalSession, PortalSessionRequest, Refund,
    RefundRequest, Subscription, SubscriptionCheckoutRequest, SubscriptionStatus, TransferCharge,
    UsageReport, UsageReported, WebhookEvent,
};
use hmac::{Hmac, KeyInit, Mac};
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{Request, StatusCode};
use serde_json::Value;
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq};
use time::OffsetDateTime;

const STRIPE_API_BASE: &str = "https://api.stripe.com";

/// How much clock skew a webhook timestamp may have before it is rejected.
/// Stripe recommends five minutes.
pub const WEBHOOK_TOLERANCE: Duration = Duration::from_secs(300);

/// [`Payments`] over the Stripe REST API.
pub struct Stripe {
    inner: Inner,
}

enum Inner {
    Live(Box<Live>),
    NotConfigured,
}

struct Live {
    http: Arc<dyn HttpClient>,
    clock: Arc<dyn Clock>,
    secret_key: String,
    /// The `whsec_...` signing secret for webhook verification; may be empty
    /// when webhooks are not yet configured (then [`Payments::verify_webhook`]
    /// reports `NotConfigured`).
    webhook_secret: String,
    base_url: String,
}

impl Stripe {
    /// A live adapter. `secret_key` is the `sk_...` API key; `webhook_secret`
    /// is the `whsec_...` endpoint signing secret (pass an empty string if
    /// webhooks are not configured yet).
    #[must_use]
    pub fn new(
        http: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
        secret_key: impl Into<String>,
        webhook_secret: impl Into<String>,
    ) -> Self {
        Self {
            inner: Inner::Live(Box::new(Live {
                http,
                clock,
                secret_key: secret_key.into(),
                webhook_secret: webhook_secret.into(),
                base_url: STRIPE_API_BASE.to_owned(),
            })),
        }
    }

    /// A degraded adapter that reports [`PaymentsError::NotConfigured`] without
    /// any network call — for a venture with no Stripe keys set.
    #[must_use]
    pub fn not_configured() -> Self {
        Self {
            inner: Inner::NotConfigured,
        }
    }

    /// Overrides the API base URL (tests point this at a scripted client's
    /// expected host; production uses `https://api.stripe.com`).
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        if let Inner::Live(live) = &mut self.inner {
            live.base_url = base_url.into();
        }
        self
    }

    fn live(&self) -> Result<&Live, PaymentsError> {
        match &self.inner {
            Inner::Live(live) => Ok(live),
            Inner::NotConfigured => Err(PaymentsError::NotConfigured),
        }
    }
}

/// Accumulates `application/x-www-form-urlencoded` fields, Stripe's request
/// encoding, with the bracket notation Stripe uses for nested objects.
#[derive(Default)]
struct Form {
    pairs: Vec<(String, String)>,
}

impl Form {
    fn field(&mut self, key: &str, value: impl Into<String>) -> &mut Self {
        self.pairs.push((key.to_owned(), value.into()));
        self
    }

    fn field_opt(&mut self, key: &str, value: Option<&str>) -> &mut Self {
        if let Some(value) = value {
            self.field(key, value.to_owned());
        }
        self
    }

    fn metadata(&mut self, metadata: &std::collections::BTreeMap<String, String>) -> &mut Self {
        for (key, value) in metadata {
            self.field(&format!("metadata[{key}]"), value.clone());
        }
        self
    }

    fn encode(&self) -> String {
        self.pairs
            .iter()
            .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
            .collect::<Vec<_>>()
            .join("&")
    }
}

/// Percent-encodes for `application/x-www-form-urlencoded`: unreserved bytes
/// pass through, everything else (space included, as `%20`) is escaped.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &byte in input.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

impl Live {
    /// `POST {base}/v1/{path}` with the API key, an idempotency key, and a
    /// form body; returns the parsed JSON on `2xx`, else a mapped error.
    async fn post(
        &self,
        path: &str,
        idempotency_key: &str,
        form: &Form,
    ) -> Result<Value, PaymentsError> {
        let (status, body) = self.post_raw(path, idempotency_key, form).await?;
        if status.is_success() {
            return serde_json::from_slice(&body).map_err(|err| {
                PaymentsError::Rejected(format!("unparseable Stripe response: {err}"))
            });
        }
        Err(map_error(status, &body))
    }

    /// The raw `POST` above with no error mapping: the caller inspects the
    /// status and body itself. Used where a specific non-`2xx` is not an
    /// error — Stripe's duplicate meter event is a success in disguise.
    async fn post_raw(
        &self,
        path: &str,
        idempotency_key: &str,
        form: &Form,
    ) -> Result<(StatusCode, Bytes), PaymentsError> {
        let url = format!("{}/v1/{path}", self.base_url);
        let request = Request::builder()
            .method("POST")
            .uri(&url)
            .header(AUTHORIZATION, format!("Bearer {}", self.secret_key))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("Idempotency-Key", idempotency_key)
            .header("Stripe-Version", "2024-06-20")
            .body(Bytes::from(form.encode()))
            .map_err(|err| PaymentsError::Rejected(format!("could not build request: {err}")))?;

        let response = self
            .http
            .send(request)
            .await
            .map_err(|err| PaymentsError::Transient(err.to_string()))?;

        Ok((response.status(), response.into_body()))
    }

    /// `GET {base}/v1/{path}` with the API key and any query parameters; the
    /// query values are percent-encoded. Returns the parsed JSON on `2xx`,
    /// else a mapped error.
    async fn get(&self, path: &str, query: &[(&str, String)]) -> Result<Value, PaymentsError> {
        let mut url = format!("{}/v1/{path}", self.base_url);
        for (index, (key, value)) in query.iter().enumerate() {
            url.push(if index == 0 { '?' } else { '&' });
            url.push_str(&percent_encode(key));
            url.push('=');
            url.push_str(&percent_encode(value));
        }

        let request = Request::builder()
            .method("GET")
            .uri(&url)
            .header(AUTHORIZATION, format!("Bearer {}", self.secret_key))
            .header("Stripe-Version", "2024-06-20")
            .body(Bytes::new())
            .map_err(|err| PaymentsError::Rejected(format!("could not build request: {err}")))?;

        let response = self
            .http
            .send(request)
            .await
            .map_err(|err| PaymentsError::Transient(err.to_string()))?;

        let status = response.status();
        let body = response.into_body();
        if status.is_success() {
            return serde_json::from_slice(&body).map_err(|err| {
                PaymentsError::Rejected(format!("unparseable Stripe response: {err}"))
            });
        }
        Err(map_error(status, &body))
    }
}

/// Stripe's `error.code` and `error.message` from an error body, either of
/// which may be absent.
fn error_fields(body: &[u8]) -> (Option<String>, Option<String>) {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return (None, None);
    };
    let error = value.get("error");
    let string = |key: &str| {
        error
            .and_then(|error| error.get(key))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    (string("code"), string("message"))
}

/// Maps a non-2xx Stripe response to a [`PaymentsError`]: `429`/`5xx` are
/// retryable, everything else is a request that will not succeed unchanged.
/// The detail carries Stripe's `error.code` and `error.message` when present.
fn map_error(status: StatusCode, body: &[u8]) -> PaymentsError {
    let (code, message) = error_fields(body);
    let detail = match (code, message) {
        (Some(code), Some(message)) => format!("{code}: {message}"),
        (Some(code), None) => code,
        (None, Some(message)) => message,
        (None, None) => status.as_u16().to_string(),
    };

    if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        PaymentsError::Transient(format!("stripe {}: {detail}", status.as_u16()))
    } else {
        PaymentsError::Rejected(format!("stripe {}: {detail}", status.as_u16()))
    }
}

/// Reads a required string field from a Stripe object.
fn field<'a>(object: &'a Value, key: &str) -> Result<&'a str, PaymentsError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| PaymentsError::Rejected(format!("Stripe response missing `{key}`")))
}

/// A Stripe id used as a URL path segment (a `sub_...`/`cus_...` id: ASCII
/// alphanumerics and `_`). Anything else — an empty string, a `/`, `?`, `#`,
/// whitespace — is refused rather than allowed to change the path.
fn path_segment(id: &str) -> Result<&str, PaymentsError> {
    if !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        Ok(id)
    } else {
        Err(PaymentsError::Rejected("not a Stripe id".to_owned()))
    }
}

/// The customer id from a subscription's `customer` field, which Stripe
/// returns as a bare id string unless it was expanded into an object.
fn customer_ref(object: &Value) -> Result<String, PaymentsError> {
    match object.get("customer") {
        Some(Value::String(id)) => Ok(id.clone()),
        Some(customer) => customer
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| {
                PaymentsError::Rejected("Stripe customer object missing `id`".to_owned())
            }),
        None => Err(PaymentsError::Rejected(
            "Stripe response missing `customer`".to_owned(),
        )),
    }
}

/// The string metadata a Stripe object carries, as a `BTreeMap`; absent
/// metadata is empty, and a non-string value is skipped rather than failing
/// the whole object.
fn metadata_from(object: &Value) -> BTreeMap<String, String> {
    object
        .get("metadata")
        .and_then(Value::as_object)
        .map(|metadata| {
            metadata
                .iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|value| (key.clone(), value.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Reads a Stripe `subscription` object into the port's [`Subscription`].
fn subscription_from(object: &Value) -> Result<Subscription, PaymentsError> {
    let item = object
        .get("items")
        .and_then(|items| items.get("data"))
        .and_then(Value::as_array)
        .and_then(|items| items.first());

    let price_ref = item
        .and_then(|item| item.get("price"))
        .and_then(|price| match price {
            Value::String(id) => Some(id.clone()),
            price => price.get("id").and_then(Value::as_str).map(str::to_owned),
        });

    let quantity = item
        .and_then(|item| item.get("quantity"))
        .and_then(Value::as_u64)
        .and_then(|quantity| u32::try_from(quantity).ok())
        .unwrap_or(1);

    // Stripe moved `current_period_end` from the subscription onto its items
    // in API version 2025-03-31 ("basil"). Read the top level first and fall
    // back to the first item, so either shape parses without repinning.
    let current_period_end = object
        .get("current_period_end")
        .and_then(Value::as_i64)
        .or_else(|| {
            item.and_then(|item| item.get("current_period_end"))
                .and_then(Value::as_i64)
        })
        .and_then(|unix| OffsetDateTime::from_unix_timestamp(unix).ok());

    Ok(Subscription {
        id: field(object, "id")?.to_owned(),
        customer_ref: customer_ref(object)?,
        status: SubscriptionStatus::from_provider(field(object, "status")?),
        price_ref,
        quantity,
        current_period_end,
        cancel_at_period_end: object
            .get("cancel_at_period_end")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        metadata: metadata_from(object),
    })
}

#[async_trait]
impl Payments for Stripe {
    async fn create_checkout(
        &self,
        request: &CheckoutRequest,
    ) -> Result<CheckoutSession, PaymentsError> {
        let live = self.live()?;
        let mut form = Form::default();
        form.field("mode", "payment")
            .field("success_url", request.success_url.clone())
            .field("cancel_url", request.cancel_url.clone())
            .field_opt("customer", request.customer_ref.as_deref())
            .field_opt("customer_email", request.customer_email.as_deref())
            .field("line_items[0][quantity]", request.line.quantity.to_string())
            .field(
                "line_items[0][price_data][currency]",
                request.line.amount.currency.clone(),
            )
            .field(
                "line_items[0][price_data][unit_amount]",
                request.line.amount.minor_units.to_string(),
            )
            .field(
                "line_items[0][price_data][product_data][name]",
                request.line.name.clone(),
            )
            .metadata(&request.metadata);

        let object = live
            .post("checkout/sessions", &request.idempotency_key, &form)
            .await?;
        Ok(CheckoutSession {
            id: field(&object, "id")?.to_owned(),
            url: field(&object, "url")?.to_owned(),
        })
    }

    async fn create_subscription_checkout(
        &self,
        request: &SubscriptionCheckoutRequest,
    ) -> Result<CheckoutSession, PaymentsError> {
        let live = self.live()?;
        let mut form = Form::default();
        form.field("mode", "subscription")
            .field("success_url", request.success_url.clone())
            .field("cancel_url", request.cancel_url.clone())
            .field_opt("customer", request.customer_ref.as_deref())
            .field_opt("customer_email", request.customer_email.as_deref())
            .field("line_items[0][price]", request.price_ref.clone())
            .field("line_items[0][quantity]", "1");
        if let Some(days) = request.trial_days {
            form.field("subscription_data[trial_period_days]", days.to_string());
        }
        form.metadata(&request.metadata);

        let object = live
            .post("checkout/sessions", &request.idempotency_key, &form)
            .await?;
        Ok(CheckoutSession {
            id: field(&object, "id")?.to_owned(),
            url: field(&object, "url")?.to_owned(),
        })
    }

    async fn create_portal_session(
        &self,
        request: &PortalSessionRequest,
    ) -> Result<PortalSession, PaymentsError> {
        let live = self.live()?;
        let mut form = Form::default();
        form.field("customer", request.customer_ref.clone())
            .field("return_url", request.return_url.clone());

        let object = live
            .post("billing_portal/sessions", &request.idempotency_key, &form)
            .await?;
        Ok(PortalSession {
            url: field(&object, "url")?.to_owned(),
        })
    }

    async fn get_subscription(
        &self,
        subscription_ref: &str,
    ) -> Result<Subscription, PaymentsError> {
        let live = self.live()?;
        let id = path_segment(subscription_ref)?;
        let object = live.get(&format!("subscriptions/{id}"), &[]).await?;
        subscription_from(&object)
    }

    async fn list_subscriptions(
        &self,
        customer_ref: &str,
    ) -> Result<Vec<Subscription>, PaymentsError> {
        let live = self.live()?;
        // `status=all` includes canceled subscriptions, which Stripe's list
        // omits by default — a reconciliation poll must see ended ones too.
        // `limit=100` is Stripe's maximum page; follow `has_more` with
        // `starting_after` until the list is exhausted.
        let mut subscriptions = Vec::new();
        let mut starting_after: Option<String> = None;
        loop {
            let mut query = vec![
                ("customer", customer_ref.to_owned()),
                ("status", "all".to_owned()),
                ("limit", "100".to_owned()),
            ];
            if let Some(after) = &starting_after {
                query.push(("starting_after", after.clone()));
            }
            let page = live.get("subscriptions", &query).await?;
            let data = page.get("data").and_then(Value::as_array).ok_or_else(|| {
                PaymentsError::Rejected("Stripe response missing `data`".to_owned())
            })?;
            for object in data {
                subscriptions.push(subscription_from(object)?);
            }

            let has_more = page
                .get("has_more")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let last_id = data
                .last()
                .and_then(|object| object.get("id"))
                .and_then(Value::as_str);
            match (has_more, last_id) {
                // A page that hands back the cursor it was given is not
                // progress: re-sending it would repeat one request forever and
                // `list_subscriptions` would never return.
                (true, Some(id)) if Some(id) == starting_after.as_deref() => {
                    tracing::warn!(
                        customer = %customer_ref,
                        cursor = %id,
                        "stripe page did not advance the pagination cursor; stopping"
                    );
                    break;
                }
                (true, Some(id)) => starting_after = Some(id.to_owned()),
                _ => break,
            }
        }
        Ok(subscriptions)
    }

    async fn create_connect_account_link(
        &self,
        request: &ConnectAccountLinkRequest,
    ) -> Result<ConnectAccountLink, PaymentsError> {
        let live = self.live()?;
        // Reuse an existing account, or create an Express account first.
        let account_id = if let Some(account_id) = &request.account_ref {
            account_id.clone()
        } else {
            let mut form = Form::default();
            form.field("type", "express");
            let object = live
                .post(
                    "accounts",
                    &format!("{}-acct", request.idempotency_key),
                    &form,
                )
                .await?;
            field(&object, "id")?.to_owned()
        };

        let mut form = Form::default();
        form.field("account", account_id.clone())
            .field("refresh_url", request.refresh_url.clone())
            .field("return_url", request.return_url.clone())
            .field("type", "account_onboarding");
        let object = live
            .post(
                "account_links",
                &format!("{}-link", request.idempotency_key),
                &form,
            )
            .await?;
        Ok(ConnectAccountLink {
            account_id,
            url: field(&object, "url")?.to_owned(),
        })
    }

    async fn charge_with_transfer(
        &self,
        request: &TransferCharge,
    ) -> Result<Charge, PaymentsError> {
        let live = self.live()?;
        let mut form = Form::default();
        form.field("amount", request.amount.minor_units.to_string())
            .field("currency", request.amount.currency.clone())
            .field_opt("customer", request.customer_ref.as_deref())
            .field(
                "application_fee_amount",
                request.application_fee.minor_units.to_string(),
            )
            .field(
                "transfer_data[destination]",
                request.destination_account.clone(),
            )
            .metadata(&request.metadata);

        let object = live
            .post("payment_intents", &request.idempotency_key, &form)
            .await?;
        Ok(Charge {
            id: field(&object, "id")?.to_owned(),
            status: field(&object, "status")?.to_owned(),
        })
    }

    async fn refund(&self, request: &RefundRequest) -> Result<Refund, PaymentsError> {
        let live = self.live()?;
        let mut form = Form::default();
        form.field("payment_intent", request.payment_ref.clone());
        if let Some(Money { minor_units, .. }) = &request.amount {
            form.field("amount", minor_units.to_string());
        }

        let object = live
            .post("refunds", &request.idempotency_key, &form)
            .await?;
        Ok(Refund {
            id: field(&object, "id")?.to_owned(),
        })
    }

    async fn verify_webhook(
        &self,
        signature_header: &str,
        body: &[u8],
    ) -> Result<WebhookEvent, PaymentsError> {
        let live = self.live()?;
        if live.webhook_secret.is_empty() {
            return Err(PaymentsError::NotConfigured);
        }

        let (timestamp, signatures) = parse_signature_header(signature_header)?;

        // Reject a stale (or future) timestamp before the constant-time check.
        let now = live.clock.now().unix_timestamp();
        if now.saturating_sub(timestamp).unsigned_abs() > WEBHOOK_TOLERANCE.as_secs() {
            return Err(PaymentsError::SignatureInvalid(
                "timestamp outside tolerance".to_owned(),
            ));
        }

        // HMAC-SHA256 over `{timestamp}.{body}`, compared constant-time against
        // each `v1` the header carried. No early exit: every candidate is
        // decoded and compared, the `Choice`s are OR-ed, and the verdict is
        // converted only once at the end — so how long this takes says nothing
        // about how much of a wrong signature was right, nor which candidate
        // (if any) matched. A candidate of the wrong length simply compares
        // unequal (`ct_eq` is false on a length mismatch).
        let mut mac = Hmac::<Sha256>::new_from_slice(live.webhook_secret.as_bytes())
            .map_err(|err| PaymentsError::SignatureInvalid(err.to_string()))?;
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(body);
        let expected = mac.finalize().into_bytes();

        let mut matched = Choice::from(0u8);
        for candidate in &signatures {
            if let Some(bytes) = hex_decode(candidate) {
                matched |= bytes.ct_eq(expected.as_slice());
            }
        }
        if !bool::from(matched) {
            return Err(PaymentsError::SignatureInvalid(
                "no signature matched".to_owned(),
            ));
        }

        let event: Value = serde_json::from_slice(body)
            .map_err(|err| PaymentsError::SignatureInvalid(format!("unparseable event: {err}")))?;
        Ok(WebhookEvent {
            id: field(&event, "id")?.to_owned(),
            kind: field(&event, "type")?.to_owned(),
            data: event
                .get("data")
                .and_then(|data| data.get("object"))
                .cloned()
                .unwrap_or(Value::Null),
        })
    }

    async fn report_usage(&self, report: &UsageReport) -> Result<UsageReported, PaymentsError> {
        let live = self.live()?;
        // A shape error is the caller's, not Stripe's: reject before any
        // network call, so a misconfigured tick cannot spray requests.
        if report.identifier.is_empty()
            || report.meter_event_name.is_empty()
            || report.customer_ref.is_empty()
        {
            return Err(PaymentsError::Rejected(
                "usage report needs a non-empty identifier, meter event name and customer"
                    .to_owned(),
            ));
        }

        let mut form = Form::default();
        form.field("event_name", report.meter_event_name.clone())
            .field("payload[stripe_customer_id]", report.customer_ref.clone())
            .field("payload[value]", report.value.to_string())
            .field("identifier", report.identifier.clone())
            .field("timestamp", report.timestamp.unix_timestamp().to_string());

        // The identifier is also the Idempotency-Key: an exact retry within
        // Stripe's 24-hour idempotency window returns the first response.
        let (status, body) = live
            .post_raw("billing/meter_events", &report.identifier, &form)
            .await?;

        if status.is_success() {
            return Ok(UsageReported {
                identifier: report.identifier.clone(),
                already_reported: false,
            });
        }

        let (code, message) = error_fields(&body);

        // Stripe documents a duplicate identifier as `400 duplicate_meter_event`
        // only; `409` is never a duplicate, just a concurrency conflict on the
        // customer+meter, so a retry is safe rather than dead-lettering.
        if status == StatusCode::CONFLICT {
            return Err(PaymentsError::Transient(format!(
                "stripe 409: {}",
                message.as_deref().unwrap_or("too many concurrent requests")
            )));
        }

        // A duplicate identifier is success, not failure: the window is
        // already counted. Stripe answers `400 duplicate_meter_event`; when
        // the body carries no code, fall back to a message that names both a
        // duplicate and an identifier, so an unrelated `400` never becomes a
        // silent success.
        let duplicate = match code.as_deref() {
            Some(code) => code == "duplicate_meter_event",
            None => message.as_deref().is_some_and(|message| {
                let message = message.to_ascii_lowercase();
                message.contains("duplicate") && message.contains("identifier")
            }),
        };
        if status == StatusCode::BAD_REQUEST && duplicate {
            return Ok(UsageReported {
                identifier: report.identifier.clone(),
                already_reported: true,
            });
        }

        Err(map_error(status, &body))
    }
}

/// Parses `Stripe-Signature: t=<unix>,v1=<hex>[,v1=<hex>]` into the timestamp
/// and every `v1` scheme signature.
fn parse_signature_header(header: &str) -> Result<(i64, Vec<String>), PaymentsError> {
    let mut timestamp = None;
    let mut signatures = Vec::new();
    for part in header.split(',') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        match key.trim() {
            "t" => timestamp = value.trim().parse::<i64>().ok(),
            "v1" => signatures.push(value.trim().to_owned()),
            _ => {}
        }
    }
    let timestamp = timestamp
        .ok_or_else(|| PaymentsError::SignatureInvalid("no timestamp in header".to_owned()))?;
    if signatures.is_empty() {
        return Err(PaymentsError::SignatureInvalid(
            "no v1 signature in header".to_owned(),
        ));
    }
    Ok((timestamp, signatures))
}

/// Decodes a lowercase/uppercase hex string to bytes; `None` on any non-hex.
fn hex_decode(input: &str) -> Option<Vec<u8>> {
    if !input.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let high = (bytes[index] as char).to_digit(16)?;
        let low = (bytes[index + 1] as char).to_digit(16)?;
        out.push(u8::try_from(high * 16 + low).ok()?);
        index += 2;
    }
    Some(out)
}
