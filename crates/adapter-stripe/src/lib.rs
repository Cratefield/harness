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

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{
    Charge, CheckoutRequest, CheckoutSession, Clock, ConnectAccountLink, ConnectAccountLinkRequest,
    HttpClient, Money, Payments, PaymentsError, Refund, RefundRequest, SubscriptionCheckoutRequest,
    TransferCharge, WebhookEvent,
};
use hmac::{Hmac, KeyInit, Mac};
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{Request, StatusCode};
use serde_json::Value;
use sha2::Sha256;

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

/// Maps a non-2xx Stripe response to a [`PaymentsError`]: `429`/`5xx` are
/// retryable, everything else is a request that will not succeed unchanged.
fn map_error(status: StatusCode, body: &[u8]) -> PaymentsError {
    let detail = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("error")
                .and_then(|error| error.get("message"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| status.as_u16().to_string());

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
        // each `v1` the header carried.
        let mut mac = Hmac::<Sha256>::new_from_slice(live.webhook_secret.as_bytes())
            .map_err(|err| PaymentsError::SignatureInvalid(err.to_string()))?;
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(body);
        let expected = mac.finalize().into_bytes();

        let matched = signatures.iter().any(|candidate| {
            hex_decode(candidate).is_some_and(|bytes| bytes.as_slice() == expected.as_slice())
        });
        if !matched {
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
