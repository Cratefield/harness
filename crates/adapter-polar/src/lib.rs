//! `cratefield-adapter-polar`: the [`Payments`] port over the
//! [Polar](https://polar.sh) API, a Merchant of Record (issue #690). Polar is
//! the legal seller: it collects the payment, handles VAT, GST and sales tax,
//! and pays the founder out, so a venture with no company yet can sell
//! worldwide. Switching to `cratefield-adapter-stripe` later is a change of
//! composition, not of module code (ADR 0027).
//!
//! It uses the runtime's [`HttpClient`] and [`Clock`] ports, no vendor SDK and
//! no `reqwest`, so the same adapter runs on Workers and natively.
//!
//! **What maps and what does not.**
//!
//! | `Payments` | Polar |
//! |---|---|
//! | `create_subscription_checkout` | `POST /v1/checkouts/` for one product (monthly or annual) |
//! | `create_checkout` | `POST /v1/checkouts/` with an ad-hoc price on the configured one-off product |
//! | `create_portal_session` | `POST /v1/customer-sessions/` → `customer_portal_url` |
//! | `refund` | `POST /v1/refunds/` (full or partial, with a reason), idempotent by metadata |
//! | `report_usage` | `POST /v1/events/ingest`, deduplicated on `external_id` |
//! | `get_dispute` / `list_disputes` / `close_dispute` | `/v1/disputes/` |
//! | `verify_webhook` / `verify_webhook_request` | Standard Webhooks, both of Polar's key derivations |
//! | `create_connect_account_link`, `charge_with_transfer` | [`PaymentsError::Unsupported`] |
//!
//! **Card data never crosses this adapter**: every call names a Polar object
//! by id or returns a hosted Polar URL.
//!
//! **Secrets.** The organization access token and the webhook secret come in
//! through [`Polar::new`] (read them from the Workers `Env` or the secrets
//! layer), [`Polar::from_config`] or [`Polar::from_env`]. Neither is ever
//! logged, formatted by `Debug`, or put in an error.
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{
    Charge, CheckoutRequest, CheckoutSession, Clock, Config, ConnectAccountLink,
    ConnectAccountLinkRequest, Dispute, DisputeListRequest, DisputePage, DisputeStatus, HttpClient,
    Money, Payments, PaymentsError, PortalSession, PortalSessionRequest, Refund, RefundRequest,
    SignatureScheme, SignedDelivery, SubscriptionCheckoutRequest, Svix, TransferCharge,
    UsageReport, UsageReported, WebhookEvent, WebhookVerifier,
};
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

mod normalize;

pub use normalize::{
    CheckoutChange, CheckoutEvent, CustomerChange, CustomerEvent, OrderChange, OrderEvent,
    PolarEvent, RefundChange, RefundEvent, SubscriptionChange, SubscriptionEvent, normalize,
};

/// Polar's production API host.
pub const PRODUCTION_BASE_URL: &str = "https://api.polar.sh";
/// Polar's sandbox API host: isolated data, users, tokens and organizations.
pub const SANDBOX_BASE_URL: &str = "https://sandbox-api.polar.sh";

/// The webhook replay tolerance in seconds, either way: the Standard Webhooks
/// recommendation and the harness default.
pub const WEBHOOK_TOLERANCE_SECS: i64 = cratefield_core::DEFAULT_TOLERANCE_SECS;

/// How many usage events go in one `POST /v1/events/ingest`. Polar documents
/// no batch ceiling; this is our own bound on one request's size.
pub const MAX_INGEST_BATCH: usize = 100;

/// The metadata key a refund's idempotency key is stored under, so a retried
/// [`Payments::refund`] finds the refund it already made instead of making a
/// second one (Polar's API takes no `Idempotency-Key`).
pub const REFUND_IDEMPOTENCY_KEY: &str = "cratefield_idempotency_key";

/// Which Polar environment the adapter talks to. The two are fully isolated:
/// a sandbox token does not work in production, and vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Environment {
    /// `https://sandbox-api.polar.sh`, the default: a missing setting can
    /// never move real money.
    #[default]
    Sandbox,
    /// `https://api.polar.sh`.
    Production,
}

impl Environment {
    /// The API host for this environment.
    #[must_use]
    pub const fn base_url(self) -> &'static str {
        match self {
            Self::Sandbox => SANDBOX_BASE_URL,
            Self::Production => PRODUCTION_BASE_URL,
        }
    }

    /// Reads `production` or `sandbox` (case-insensitive); anything else,
    /// including nothing, is the sandbox.
    #[must_use]
    pub fn parse(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            Some(v) if v.eq_ignore_ascii_case("production") => Self::Production,
            _ => Self::Sandbox,
        }
    }
}

/// What a `customer_ref` names, everywhere the port takes or returns one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CustomerIds {
    /// Polar's own customer id, the same meaning `adapter-stripe` gives a
    /// Stripe customer id.
    #[default]
    Polar,
    /// The venture's own id (Polar's `external_customer_id`), typically the
    /// account id: the venture never has to store a Polar customer id, and
    /// a checkout creates the Polar customer with that external id.
    External,
}

/// The reason Polar records on a refund (`RefundCreate.reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RefundReason {
    Duplicate,
    Fraudulent,
    #[default]
    CustomerRequest,
    ServiceDisruption,
    SatisfactionGuarantee,
    Other,
}

impl RefundReason {
    /// Polar's spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Duplicate => "duplicate",
            Self::Fraudulent => "fraudulent",
            Self::CustomerRequest => "customer_request",
            Self::ServiceDisruption => "service_disruption",
            Self::SatisfactionGuarantee => "satisfaction_guarantee",
            Self::Other => "other",
        }
    }
}

/// The outcome of [`Polar::report_usage_batch`]: Polar answers counts, not
/// per-event results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UsageBatchReported {
    /// Events Polar stored.
    pub inserted: u64,
    /// Events Polar skipped because their `external_id` was already ingested.
    pub duplicates: u64,
}

/// [`Payments`] over the Polar API.
pub struct Polar {
    inner: Inner,
}

enum Inner {
    Live(Box<Live>),
    NotConfigured,
}

struct Live {
    http: Arc<dyn HttpClient>,
    clock: Arc<dyn Clock>,
    /// The organization access token (`polar_oat_…`). Never logged.
    token: String,
    /// The webhook endpoint secret. Never logged; may be empty when webhooks
    /// are not set up yet (then verification reports `NotConfigured`).
    webhook_secret: String,
    base_url: String,
    customers: CustomerIds,
    one_off_product: Option<String>,
    usage_value_key: String,
    refund_reason: RefundReason,
}

impl fmt::Debug for Polar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            Inner::Live(live) => f
                .debug_struct("Polar")
                .field("base_url", &live.base_url)
                .field("customers", &live.customers)
                .field("one_off_product", &live.one_off_product)
                .field("token", &"<redacted>")
                .field("webhook_secret", &"<redacted>")
                .finish_non_exhaustive(),
            Inner::NotConfigured => f.write_str("Polar(NotConfigured)"),
        }
    }
}

impl Polar {
    /// A live adapter against `environment`. `access_token` is an
    /// organization access token; a blank one makes the adapter
    /// [`NotConfigured`](PaymentsError::NotConfigured) with no network call.
    /// `webhook_secret` is the endpoint secret from the Polar dashboard (pass
    /// an empty string while webhooks are not set up).
    #[must_use]
    pub fn new(
        http: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
        environment: Environment,
        access_token: impl Into<String>,
        webhook_secret: impl Into<String>,
    ) -> Self {
        let token = access_token.into();
        if token.trim().is_empty() {
            return Self::not_configured();
        }
        Self {
            inner: Inner::Live(Box::new(Live {
                http,
                clock,
                token: token.trim().to_owned(),
                webhook_secret: webhook_secret.into(),
                base_url: environment.base_url().to_owned(),
                customers: CustomerIds::default(),
                one_off_product: None,
                usage_value_key: "value".to_owned(),
                refund_reason: RefundReason::default(),
            })),
        }
    }

    /// A degraded adapter that reports [`PaymentsError::NotConfigured`]
    /// without any network call.
    #[must_use]
    pub fn not_configured() -> Self {
        Self {
            inner: Inner::NotConfigured,
        }
    }

    /// Reads `POLAR_ACCESS_TOKEN`, `POLAR_WEBHOOK_SECRET` and
    /// `POLAR_ENVIRONMENT` (`production` or `sandbox`, default sandbox) from
    /// `config` — the harness config, which the runtimes fill from secrets.
    #[must_use]
    pub fn from_config(
        http: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
        config: &dyn Config,
    ) -> Self {
        Self::new(
            http,
            clock,
            Environment::parse(config.get("POLAR_ENVIRONMENT").as_deref()),
            config.get("POLAR_ACCESS_TOKEN").unwrap_or_default(),
            config.get("POLAR_WEBHOOK_SECRET").unwrap_or_default(),
        )
    }

    /// [`Polar::from_config`] over the process environment (the native
    /// runtime). On Workers read the secrets from the `Env` and use
    /// [`Polar::new`].
    #[must_use]
    pub fn from_env(http: Arc<dyn HttpClient>, clock: Arc<dyn Clock>) -> Self {
        Self::new(
            http,
            clock,
            Environment::parse(std::env::var("POLAR_ENVIRONMENT").ok().as_deref()),
            std::env::var("POLAR_ACCESS_TOKEN").unwrap_or_default(),
            std::env::var("POLAR_WEBHOOK_SECRET").unwrap_or_default(),
        )
    }

    /// Overrides the API host (a proxy, or a test double's expected host).
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        if let Inner::Live(live) = &mut self.inner {
            base_url
                .into()
                .trim_end_matches('/')
                .clone_into(&mut live.base_url);
        }
        self
    }

    /// What a `customer_ref` names (default: Polar's customer id).
    #[must_use]
    pub fn with_customer_ids(mut self, customers: CustomerIds) -> Self {
        if let Inner::Live(live) = &mut self.inner {
            live.customers = customers;
        }
        self
    }

    /// The Polar product a one-off [`Payments::create_checkout`] charges
    /// against, with the request's amount as an ad-hoc price. Polar has no
    /// checkout without a product; without this, one-off checkout is
    /// [`PaymentsError::Unsupported`].
    #[must_use]
    pub fn with_one_off_product(mut self, product_id: impl Into<String>) -> Self {
        if let Inner::Live(live) = &mut self.inner {
            live.one_off_product = Some(product_id.into());
        }
        self
    }

    /// The event-metadata key [`UsageReport::value`] is ingested under
    /// (default `value`). The Polar meter must sum this property.
    #[must_use]
    pub fn with_usage_value_key(mut self, key: impl Into<String>) -> Self {
        if let Inner::Live(live) = &mut self.inner {
            live.usage_value_key = key.into();
        }
        self
    }

    /// The reason [`Payments::refund`] records (default `customer_request`).
    #[must_use]
    pub fn with_refund_reason(mut self, reason: RefundReason) -> Self {
        if let Inner::Live(live) = &mut self.inner {
            live.refund_reason = reason;
        }
        self
    }

    fn live(&self) -> Result<&Live, PaymentsError> {
        match &self.inner {
            Inner::Live(live) => Ok(live),
            Inner::NotConfigured => Err(PaymentsError::NotConfigured),
        }
    }

    /// Maps a verified event onto [`PolarEvent`]s, naming customers the way
    /// this adapter is configured to ([`Polar::with_customer_ids`]).
    #[must_use]
    pub fn normalize(&self, event: &WebhookEvent) -> Vec<PolarEvent> {
        let customers = match &self.inner {
            Inner::Live(live) => live.customers,
            Inner::NotConfigured => CustomerIds::default(),
        };
        normalize(event, customers)
    }

    /// [`Payments::refund`] with an explicit reason. `request.amount` is the
    /// **net** amount (before tax), as Polar refunds it; Polar refunds the
    /// matching tax itself. `None` refunds the order's whole
    /// `refundable_amount`.
    ///
    /// Idempotent on `request.idempotency_key`: the key is stored in the
    /// refund's metadata and looked up first, so a retry returns the refund
    /// already made.
    ///
    /// # Errors
    ///
    /// [`PaymentsError::Rejected`] for an order that has nothing left to
    /// refund or a refusal; [`PaymentsError::Transient`] for `429`/`5xx`.
    pub async fn refund_with_reason(
        &self,
        request: &RefundRequest,
        reason: RefundReason,
    ) -> Result<Refund, PaymentsError> {
        let live = self.live()?;
        let order_id = path_segment(&request.payment_ref)?;

        // A retry after a success: the refund is already there.
        let existing = live
            .get_json(
                "/v1/refunds/",
                &[
                    ("order_id", order_id.to_owned()),
                    ("limit", "100".to_owned()),
                ],
            )
            .await?;
        if let Some(found) = items(&existing).iter().find(|refund| {
            refund
                .get("metadata")
                .and_then(|m| m.get(REFUND_IDEMPOTENCY_KEY))
                .and_then(Value::as_str)
                == Some(request.idempotency_key.as_str())
        }) {
            return Ok(Refund {
                id: string(found, "id")?.to_owned(),
            });
        }

        let amount = if let Some(money) = &request.amount {
            money.minor_units
        } else {
            let order = live
                .get_json(&format!("/v1/orders/{order_id}"), &[])
                .await?;
            order
                .get("refundable_amount")
                .and_then(Value::as_i64)
                .ok_or_else(|| missing("refundable_amount"))?
        };
        if amount <= 0 {
            return Err(PaymentsError::Rejected(
                "polar: the order has nothing left to refund".to_owned(),
            ));
        }

        let body = json!({
            "order_id": order_id,
            "reason": reason.as_str(),
            "amount": amount,
            "metadata": { REFUND_IDEMPOTENCY_KEY: request.idempotency_key },
        });
        let refund = live
            .send_json(Method::POST, "/v1/refunds/", &[], Some(&body))
            .await?;
        Ok(Refund {
            id: string(&refund, "id")?.to_owned(),
        })
    }

    /// Ingests many usage reports, in requests of at most
    /// [`MAX_INGEST_BATCH`] events. Each report's `identifier` is the event's
    /// `external_id`, so re-sending a report Polar has already counted is a
    /// duplicate, not a second count.
    ///
    /// # Errors
    ///
    /// As [`Payments::report_usage`]. A failure part-way leaves the earlier
    /// chunks ingested; re-sending the whole batch is safe.
    pub async fn report_usage_batch(
        &self,
        reports: &[UsageReport],
    ) -> Result<UsageBatchReported, PaymentsError> {
        let live = self.live()?;
        for report in reports {
            validate_usage(report)?;
        }
        let mut total = UsageBatchReported::default();
        for chunk in reports.chunks(MAX_INGEST_BATCH) {
            let counts = live.ingest(chunk).await?;
            total.inserted += counts.inserted;
            total.duplicates += counts.duplicates;
        }
        Ok(total)
    }
}

impl Live {
    fn url(&self, path: &str, query: &[(&str, String)]) -> String {
        let mut url = format!("{}{path}", self.base_url);
        for (index, (key, value)) in query.iter().enumerate() {
            url.push(if index == 0 { '?' } else { '&' });
            url.push_str(&percent_encode(key));
            url.push('=');
            url.push_str(&percent_encode(value));
        }
        url
    }

    /// One request; returns the parsed JSON on `2xx`, else a mapped error.
    async fn send_json(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
    ) -> Result<Value, PaymentsError> {
        let (status, bytes) = self.send_raw(method, path, query, body).await?;
        if !status.is_success() {
            return Err(map_error(status, &bytes));
        }
        serde_json::from_slice(&bytes)
            .map_err(|err| PaymentsError::Rejected(format!("unparseable Polar response: {err}")))
    }

    async fn get_json(&self, path: &str, query: &[(&str, String)]) -> Result<Value, PaymentsError> {
        self.send_json(Method::GET, path, query, None).await
    }

    async fn send_raw(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
    ) -> Result<(StatusCode, Bytes), PaymentsError> {
        let mut builder = Request::builder()
            .method(method)
            .uri(self.url(path, query))
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .header(ACCEPT, "application/json");
        let payload = match body {
            Some(body) => {
                builder = builder.header(CONTENT_TYPE, "application/json");
                Bytes::from(body.to_string())
            }
            None => Bytes::new(),
        };
        // The builder error names the URI or a header; never the token.
        let request = builder
            .body(payload)
            .map_err(|_| PaymentsError::Rejected("could not build the Polar request".to_owned()))?;
        let response = self
            .http
            .send(request)
            .await
            .map_err(|err| PaymentsError::Transient(err.to_string()))?;
        Ok((response.status(), response.into_body()))
    }

    fn customer_field(&self) -> &'static str {
        match self.customers {
            CustomerIds::Polar => "customer_id",
            CustomerIds::External => "external_customer_id",
        }
    }

    async fn ingest(&self, reports: &[UsageReport]) -> Result<UsageBatchReported, PaymentsError> {
        let customer_field = self.customer_field();
        let events: Vec<Value> = reports
            .iter()
            .map(|report| {
                let mut event = Map::new();
                event.insert("name".to_owned(), json!(report.meter_event_name));
                event.insert(customer_field.to_owned(), json!(report.customer_ref));
                event.insert("external_id".to_owned(), json!(report.identifier));
                event.insert("timestamp".to_owned(), json!(rfc3339(report.timestamp)));
                event.insert(
                    "metadata".to_owned(),
                    json!({ self.usage_value_key.as_str(): report.value }),
                );
                Value::Object(event)
            })
            .collect();
        let response = self
            .send_json(
                Method::POST,
                "/v1/events/ingest",
                &[],
                Some(&json!({ "events": events })),
            )
            .await?;
        Ok(UsageBatchReported {
            inserted: response
                .get("inserted")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            duplicates: response
                .get("duplicates")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        })
    }

    async fn checkout(&self, body: Value) -> Result<CheckoutSession, PaymentsError> {
        let object = self
            .send_json(Method::POST, "/v1/checkouts/", &[], Some(&body))
            .await?;
        Ok(CheckoutSession {
            id: string(&object, "id")?.to_owned(),
            url: string(&object, "url")?.to_owned(),
        })
    }

    /// The fields every checkout shares: who, where to, and the metadata.
    fn checkout_base(
        &self,
        product_id: &str,
        customer_ref: Option<&str>,
        customer_email: Option<&str>,
        success_url: &str,
        cancel_url: &str,
        metadata: &BTreeMap<String, String>,
    ) -> Map<String, Value> {
        let mut body = Map::new();
        body.insert("products".to_owned(), json!([product_id]));
        if let Some(customer) = customer_ref {
            body.insert(self.customer_field().to_owned(), json!(customer));
        }
        if let Some(email) = customer_email {
            body.insert("customer_email".to_owned(), json!(email));
        }
        body.insert("success_url".to_owned(), json!(success_url));
        // Polar shows a back button to `return_url`: the cancel path.
        body.insert("return_url".to_owned(), json!(cancel_url));
        // Copied by Polar onto the resulting order and subscription, so it
        // comes back on their webhooks.
        body.insert("metadata".to_owned(), json!(metadata));
        body
    }
}

#[async_trait]
impl Payments for Polar {
    async fn create_checkout(
        &self,
        request: &CheckoutRequest,
    ) -> Result<CheckoutSession, PaymentsError> {
        let live = self.live()?;
        let Some(product) = live.one_off_product.as_deref() else {
            return Err(PaymentsError::Unsupported(
                "one-off checkout on Polar without a configured product (with_one_off_product)",
            ));
        };
        let total = request
            .line
            .amount
            .minor_units
            .checked_mul(i64::from(request.line.quantity))
            .ok_or_else(|| PaymentsError::Rejected("checkout amount overflows".to_owned()))?;
        let mut body = live.checkout_base(
            product,
            request.customer_ref.as_deref(),
            request.customer_email.as_deref(),
            &request.success_url,
            &request.cancel_url,
            &request.metadata,
        );
        // Polar has no free-form line items: the line becomes an ad-hoc fixed
        // price on the one-off product, for this checkout only.
        body.insert(
            "prices".to_owned(),
            json!({ product: [{
                "amount_type": "fixed",
                "price_amount": total,
                "price_currency": request.line.amount.currency.to_ascii_lowercase(),
            }] }),
        );
        live.checkout(Value::Object(body)).await
    }

    async fn create_subscription_checkout(
        &self,
        request: &SubscriptionCheckoutRequest,
    ) -> Result<CheckoutSession, PaymentsError> {
        let live = self.live()?;
        // A Polar product carries one recurring interval, so a monthly and an
        // annual plan are two products: `price_ref` is the product id.
        let mut body = live.checkout_base(
            &request.price_ref,
            request.customer_ref.as_deref(),
            request.customer_email.as_deref(),
            &request.success_url,
            &request.cancel_url,
            &request.metadata,
        );
        if let Some(days) = request.trial_days {
            body.insert("allow_trial".to_owned(), json!(true));
            body.insert("trial_interval".to_owned(), json!("day"));
            body.insert("trial_interval_count".to_owned(), json!(days));
        }
        live.checkout(Value::Object(body)).await
    }

    async fn create_connect_account_link(
        &self,
        _request: &ConnectAccountLinkRequest,
    ) -> Result<ConnectAccountLink, PaymentsError> {
        self.live()?;
        Err(PaymentsError::Unsupported(
            "Connect onboarding: Polar is the merchant of record and pays out the seller itself",
        ))
    }

    async fn charge_with_transfer(
        &self,
        _request: &TransferCharge,
    ) -> Result<Charge, PaymentsError> {
        self.live()?;
        Err(PaymentsError::Unsupported(
            "destination charges: Polar has no server-side charge or transfer API",
        ))
    }

    async fn refund(&self, request: &RefundRequest) -> Result<Refund, PaymentsError> {
        let reason = self.live()?.refund_reason;
        self.refund_with_reason(request, reason).await
    }

    /// `signature_header` is the three Standard Webhooks headers packed one
    /// per line as `name: value` — what [`signature_header`] builds from a
    /// request. Prefer [`Payments::verify_webhook_request`], which takes the
    /// headers directly.
    async fn verify_webhook(
        &self,
        signature_header: &str,
        body: &[u8],
    ) -> Result<WebhookEvent, PaymentsError> {
        let headers = unpack_signature_header(signature_header);
        self.verify_webhook_request(&headers, body).await
    }

    async fn verify_webhook_request(
        &self,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<WebhookEvent, PaymentsError> {
        let live = self.live()?;
        if live.webhook_secret.trim().is_empty() {
            return Err(PaymentsError::NotConfigured);
        }
        let now = live.clock.now().unix_timestamp();
        // Both of Polar's key derivations are tried, the way Polar's own SDKs
        // do: a secret made before 2026-09-08 keys the HMAC with its UTF-8
        // bytes ("Polar HMAC"), a newer one is a Standard Webhooks secret
        // (base64 after `whsec_`). Each check is constant-time; both always
        // run, so timing does not say which key a secret is.
        let standard = WebhookVerifier::new(Svix).verify(&live.webhook_secret, headers, body, now);
        let legacy =
            WebhookVerifier::new(PolarHmac).verify(&live.webhook_secret, headers, body, now);
        if !(standard | legacy) {
            return Err(PaymentsError::SignatureInvalid(
                "no signature matched, or the timestamp is outside tolerance".to_owned(),
            ));
        }

        // Standard Webhooks: the message id is the header, stable across
        // Polar's retries, and the dedup key for the `Inbox`.
        let id = headers
            .get("webhook-id")
            .or_else(|| headers.get("svix-id"))
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| PaymentsError::SignatureInvalid("no webhook-id header".to_owned()))?;
        let event: Value = serde_json::from_slice(body)
            .map_err(|err| PaymentsError::SignatureInvalid(format!("unparseable event: {err}")))?;
        let kind = event
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| PaymentsError::SignatureInvalid("event has no `type`".to_owned()))?;
        Ok(WebhookEvent {
            id: id.to_owned(),
            kind: kind.to_owned(),
            data: event.get("data").cloned().unwrap_or(Value::Null),
        })
    }

    async fn report_usage(&self, report: &UsageReport) -> Result<UsageReported, PaymentsError> {
        let live = self.live()?;
        validate_usage(report)?;
        let counts = live.ingest(std::slice::from_ref(report)).await?;
        if counts.inserted == 0 && counts.duplicates == 0 {
            return Err(PaymentsError::Rejected(
                "polar ingested neither the event nor a duplicate of it".to_owned(),
            ));
        }
        Ok(UsageReported {
            identifier: report.identifier.clone(),
            already_reported: counts.inserted == 0,
        })
    }

    async fn create_portal_session(
        &self,
        request: &PortalSessionRequest,
    ) -> Result<PortalSession, PaymentsError> {
        let live = self.live()?;
        if request.customer_ref.trim().is_empty() {
            return Err(PaymentsError::Rejected(
                "a portal session needs a customer".to_owned(),
            ));
        }
        let body = json!({
            live.customer_field(): request.customer_ref,
            "return_url": request.return_url,
        });
        let session = live
            .send_json(Method::POST, "/v1/customer-sessions/", &[], Some(&body))
            .await?;
        Ok(PortalSession {
            url: string(&session, "customer_portal_url")?.to_owned(),
        })
    }

    async fn get_dispute(&self, dispute_ref: &str) -> Result<Dispute, PaymentsError> {
        let live = self.live()?;
        let id = path_segment(dispute_ref)?;
        let object = live.get_json(&format!("/v1/disputes/{id}"), &[]).await?;
        dispute_from(&object, live.customers)
    }

    async fn list_disputes(
        &self,
        request: &DisputeListRequest,
    ) -> Result<DisputePage, PaymentsError> {
        let live = self.live()?;
        let page: u64 = match &request.cursor {
            Some(cursor) => cursor
                .parse()
                .map_err(|_| PaymentsError::Rejected("not a Polar dispute cursor".to_owned()))?,
            None => 1,
        };
        let mut query = vec![
            ("page", page.to_string()),
            ("limit", "100".to_owned()),
            ("sorting", "-created_at".to_owned()),
        ];
        if request.open_only {
            for status in ["early_warning", "needs_response", "under_review"] {
                query.push(("status", status.to_owned()));
            }
        }
        let list = live.get_json("/v1/disputes/", &query).await?;
        let disputes = items(&list)
            .iter()
            .map(|object| dispute_from(object, live.customers))
            .collect::<Result<Vec<_>, _>>()?;
        let max_page = list
            .get("pagination")
            .and_then(|p| p.get("max_page"))
            .and_then(Value::as_u64)
            .unwrap_or(page);
        Ok(DisputePage {
            disputes,
            next: (page < max_page).then(|| (page + 1).to_string()),
        })
    }

    /// Polar's "accept": concedes the chargeback, settling it as lost. Polar
    /// takes no idempotency key; accepting a dispute that is no longer open
    /// is a `409`, reported as [`PaymentsError::Rejected`].
    async fn close_dispute(
        &self,
        dispute_ref: &str,
        _idempotency_key: &str,
    ) -> Result<Dispute, PaymentsError> {
        let live = self.live()?;
        let id = path_segment(dispute_ref)?;
        let object = live
            .send_json(
                Method::POST,
                &format!("/v1/disputes/{id}/accept"),
                &[],
                None,
            )
            .await?;
        dispute_from(&object, live.customers)
    }
}

/// The older "Polar HMAC" key derivation: the Standard Webhooks layout
/// (`{id}.{timestamp}.{body}`, `v1,<base64>`), keyed with the secret's own
/// UTF-8 bytes instead of its base64 decoding.
struct PolarHmac;

impl SignatureScheme for PolarHmac {
    fn extract(&self, headers: &HeaderMap, body: &[u8]) -> Option<SignedDelivery> {
        Svix.extract(headers, body)
    }

    fn secret_key<'a>(&self, secret: &'a str) -> Option<Cow<'a, [u8]>> {
        let trimmed = secret.trim();
        (!trimmed.is_empty()).then_some(Cow::Borrowed(trimmed.as_bytes()))
    }
}

/// The three Standard Webhooks headers a Polar delivery carries.
const SIGNATURE_HEADERS: [&str; 3] = ["webhook-id", "webhook-timestamp", "webhook-signature"];

/// Packs a delivery's `webhook-id`, `webhook-timestamp` and
/// `webhook-signature` into the one string [`Payments::verify_webhook`]
/// takes, one `name: value` per line (header values cannot hold a newline,
/// so the packing is unambiguous). `None` when one is missing.
#[must_use]
pub fn signature_header(headers: &HeaderMap) -> Option<String> {
    let mut lines = Vec::with_capacity(SIGNATURE_HEADERS.len());
    for name in SIGNATURE_HEADERS {
        let value = headers.get(name)?.to_str().ok()?;
        lines.push(format!("{name}: {value}"));
    }
    Some(lines.join("\n"))
}

fn unpack_signature_header(packed: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for line in packed.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        if !SIGNATURE_HEADERS.contains(&name.as_str()) {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value.trim()),
        ) {
            headers.insert(name, value);
        }
    }
    headers
}

/// Maps one Polar dispute object onto the port's [`Dispute`].
pub(crate) fn dispute_from(
    object: &Value,
    customers: CustomerIds,
) -> Result<Dispute, PaymentsError> {
    let provider_status = string(object, "status")?.to_owned();
    let customer = object.get("customer");
    let customer_ref = match customers {
        CustomerIds::Polar => customer
            .and_then(|c| c.get("id"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        CustomerIds::External => customer
            .and_then(|c| c.get("external_id"))
            .and_then(Value::as_str)
            .map(str::to_owned),
    };
    Ok(Dispute {
        id: string(object, "id")?.to_owned(),
        charge_ref: optional_string(object, "payment_id"),
        payment_ref: string(object, "order_id")?.to_owned(),
        customer_ref,
        amount: Money::new(
            object
                .get("amount")
                .and_then(Value::as_i64)
                .ok_or_else(|| missing("amount"))?,
            string(object, "currency")?,
        ),
        reason: optional_string(object, "reason"),
        status: DisputeStatus::from_provider(&provider_status),
        provider_status,
        evidence_due_by: optional_time(object, "evidence_due_by"),
        is_charge_refundable: None,
        balance_transactions: Vec::new(),
    })
}

fn validate_usage(report: &UsageReport) -> Result<(), PaymentsError> {
    // A shape error is the caller's: refuse before any network call.
    if report.identifier.is_empty()
        || report.meter_event_name.is_empty()
        || report.customer_ref.is_empty()
    {
        return Err(PaymentsError::Rejected(
            "usage report needs a non-empty identifier, meter event name and customer".to_owned(),
        ));
    }
    Ok(())
}

/// Polar's error detail: `detail` as a string, or the first validation
/// message of a `422`; the response body never contains our token.
fn error_detail(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let error = value.get("error").and_then(Value::as_str);
    let detail = match value.get("detail") {
        Some(Value::String(detail)) => Some(detail.clone()),
        Some(Value::Array(list)) => list
            .first()
            .and_then(|first| first.get("msg"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        _ => None,
    };
    match (error, detail) {
        (Some(error), Some(detail)) => Some(format!("{error}: {detail}")),
        (Some(error), None) => Some(error.to_owned()),
        (None, detail) => detail,
    }
}

/// `429`/`5xx` are retryable; everything else will not succeed unchanged.
fn map_error(status: StatusCode, body: &[u8]) -> PaymentsError {
    let detail = error_detail(body).unwrap_or_else(|| status.as_u16().to_string());
    let message = format!("polar {}: {detail}", status.as_u16());
    if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        PaymentsError::Transient(message)
    } else {
        PaymentsError::Rejected(message)
    }
}

fn missing(key: &str) -> PaymentsError {
    PaymentsError::Rejected(format!("Polar response missing `{key}`"))
}

pub(crate) fn string<'a>(object: &'a Value, key: &str) -> Result<&'a str, PaymentsError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| missing(key))
}

pub(crate) fn optional_string(object: &Value, key: &str) -> Option<String> {
    object.get(key).and_then(Value::as_str).map(str::to_owned)
}

pub(crate) fn optional_time(object: &Value, key: &str) -> Option<OffsetDateTime> {
    object
        .get(key)
        .and_then(Value::as_str)
        .and_then(|text| OffsetDateTime::parse(text, &Rfc3339).ok())
}

fn items(list: &Value) -> &[Value] {
    list.get("items")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn rfc3339(at: OffsetDateTime) -> String {
    at.to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// An id that goes into a URL path: Polar ids are UUIDs, so anything outside
/// `[A-Za-z0-9_-]` is refused rather than allowed to change the path.
fn path_segment(id: &str) -> Result<&str, PaymentsError> {
    if !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        Ok(id)
    } else {
        Err(PaymentsError::Rejected("not a Polar id".to_owned()))
    }
}

/// Percent-encodes a query component: unreserved bytes pass through.
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
