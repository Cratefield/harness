//! The `Payments` port (issue #102): the first thing in the harness that moves
//! money. Stripe today, over the runtime's `HttpClient`.
//!
//! **Card data never crosses the harness.** Every method here names a Stripe
//! identifier or a hosted URL — a checkout session the browser is redirected
//! to, a customer/account/payment id — never a card number, CVC, or expiry.
//! The card details are entered on Stripe's own hosted pages; the harness only
//! ever holds Stripe's identifiers for them (see `docs/PAYMENTS.md`).
//!
//! The trait names only what a billing module needs. [`verify_webhook`]
//! returns a verified [`WebhookEvent`] and the module decides what it means.
//! The billing *lifecycle* — trials, entitlements, renewals, disputes — is
//! no longer venture code: it lives in `cratefield-module-billing` (ADR
//! 0025). A store-billing aggregator such as `RevenueCat` is the separate
//! `InAppPurchases` port, not this one, because it reports purchases the
//! stores made rather than moving money. Payout schedules stay venture
//! code where they are a venture's own policy.
//!
//! [`verify_webhook`]: Payments::verify_webhook

use async_trait::async_trait;
use serde_json::Value;
use std::collections::BTreeMap;
use thiserror::Error;
use time::{OffsetDateTime, UtcOffset};

/// An amount in a currency's minor units (cents), the way Stripe takes and
/// reports money. `currency` is a lowercase ISO-4217 code (`"usd"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Money {
    pub minor_units: i64,
    pub currency: String,
}

impl Money {
    #[must_use]
    pub fn new(minor_units: i64, currency: impl Into<String>) -> Self {
        Self {
            minor_units,
            currency: currency.into(),
        }
    }
}

/// One line on a checkout: a name shown to the buyer and its price.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineItem {
    pub name: String,
    pub amount: Money,
    pub quantity: u32,
}

/// A one-time hosted checkout (Stripe Checkout in `payment` mode).
#[derive(Debug, Clone)]
pub struct CheckoutRequest {
    /// A known Stripe customer id, if the venture has one for this buyer.
    pub customer_ref: Option<String>,
    /// The buyer's email, so Stripe can create/attach a customer.
    pub customer_email: Option<String>,
    pub line: LineItem,
    pub success_url: String,
    pub cancel_url: String,
    /// Copied onto the resulting objects, echoed back on the webhook.
    pub metadata: BTreeMap<String, String>,
    /// Makes the create idempotent under retries; the caller owns its shape.
    pub idempotency_key: String,
}

/// A recurring hosted checkout (Stripe Checkout in `subscription` mode) against
/// a Stripe Price the venture configured (e.g. `$15/mo` with a trial).
#[derive(Debug, Clone)]
pub struct SubscriptionCheckoutRequest {
    pub customer_ref: Option<String>,
    pub customer_email: Option<String>,
    /// The Stripe Price id to subscribe to.
    pub price_ref: String,
    /// Free-trial length in days, if any.
    pub trial_days: Option<u32>,
    pub success_url: String,
    pub cancel_url: String,
    pub metadata: BTreeMap<String, String>,
    pub idempotency_key: String,
}

/// The hosted page to send the browser to, and the session id to reconcile on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutSession {
    pub id: String,
    pub url: String,
}

/// Onboards a Connect account (a coach) and returns a hosted onboarding link.
#[derive(Debug, Clone)]
pub struct ConnectAccountLinkRequest {
    /// An existing Connect account id to refresh, or `None` to create one.
    pub account_ref: Option<String>,
    pub refresh_url: String,
    pub return_url: String,
    pub idempotency_key: String,
}

/// The Connect account id (persist it) and the hosted onboarding URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectAccountLink {
    pub account_id: String,
    pub url: String,
}

/// A destination charge with an application fee: the buyer is charged
/// `amount`, `application_fee` is kept by the platform, and the remainder is
/// transferred to `destination_account` (the coach's Connect account).
#[derive(Debug, Clone)]
pub struct TransferCharge {
    pub customer_ref: Option<String>,
    pub amount: Money,
    pub destination_account: String,
    pub application_fee: Money,
    pub metadata: BTreeMap<String, String>,
    pub idempotency_key: String,
}

/// A created charge/payment-intent and its status as Stripe reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Charge {
    pub id: String,
    pub status: String,
}

/// A refund of a prior payment: the whole amount when `amount` is `None`, else
/// a partial refund.
#[derive(Debug, Clone)]
pub struct RefundRequest {
    /// The payment-intent (or charge) id to refund.
    pub payment_ref: String,
    pub amount: Option<Money>,
    pub idempotency_key: String,
}

/// A created refund.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refund {
    pub id: String,
}

/// A metered usage amount to report to the billing provider (Stripe Billing
/// Meters). `meter_event_name` names a meter the venture configured;
/// `customer_ref` is the provider customer id the meter maps the event to;
/// `value` is the amount counted, in the meter's own unit; `identifier` is the
/// caller-chosen exactly-once key; `timestamp` is when the usage happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageReport {
    pub meter_event_name: String,
    pub customer_ref: String,
    pub value: u64,
    pub identifier: String,
    pub timestamp: OffsetDateTime,
}

impl UsageReport {
    /// A report for one **UTC hour**: `timestamp` is the start of the hour
    /// containing `at`, and `identifier` is
    /// `{subject}:{meter_event_name}:{start unix seconds}`. Every report for
    /// the same subject, meter and hour therefore carries the same identifier,
    /// so a retry, a re-delivery, or a concurrent drainer reports that window
    /// once. The identifier is only safe when the window's `value` is **final**
    /// — report a window once it has closed (see `docs/PAYMENTS.md`); two
    /// reports for the same open hour with different values would collide, and
    /// the provider would count only the first. The next hour is a new window
    /// and a new identifier.
    #[must_use]
    pub fn hourly(
        subject: &str,
        meter_event_name: &str,
        customer_ref: &str,
        value: u64,
        at: OffsetDateTime,
    ) -> Self {
        let at = at.to_offset(UtcOffset::UTC);
        let start = at
            .replace_minute(0)
            .and_then(|t| t.replace_second(0))
            .and_then(|t| t.replace_nanosecond(0))
            .unwrap_or(at);
        Self {
            meter_event_name: meter_event_name.to_owned(),
            customer_ref: customer_ref.to_owned(),
            value,
            identifier: format!("{subject}:{meter_event_name}:{}", start.unix_timestamp()),
            timestamp: start,
        }
    }
}

/// The outcome of a [`report_usage`](Payments::report_usage): the identifier
/// that was reported and whether the provider said it had **already** been
/// reported. A duplicate is success, not failure — the window was counted
/// exactly once — so a caller completes the work either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageReported {
    pub identifier: String,
    pub already_reported: bool,
}

/// A webhook event the adapter has **verified** (signature + timestamp) before
/// returning. `kind` is Stripe's event type (`"checkout.session.completed"`);
/// `data` is the event's `data.object` for the module to interpret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookEvent {
    pub id: String,
    pub kind: String,
    pub data: Value,
}

/// Payment failures. `NotConfigured` lets a venture build and run without
/// Stripe (the port reports it rather than erroring); the rest map an upstream
/// failure. `SignatureInvalid` is separated so a webhook handler answers `400`
/// and never processes an unverified event.
#[derive(Debug, Clone, Error)]
pub enum PaymentsError {
    /// No Stripe key configured: the caller should degrade, not fail.
    #[error("payments are not configured")]
    NotConfigured,
    /// A webhook signature or timestamp did not verify: reject the request,
    /// do not process the event.
    #[error("webhook signature verification failed: {0}")]
    SignatureInvalid(String),
    /// Stripe rejected the request (a `4xx` that is not auth): not retryable
    /// without a change.
    #[error("payments request rejected: {0}")]
    Rejected(String),
    /// A transient failure (a `5xx`, a transport error): retry later.
    #[error("payments request failed, retryable: {0}")]
    Transient(String),
    /// This adapter does not implement the operation — e.g. usage reporting
    /// on an adapter that does not do metered billing. Not retryable: a
    /// caller that needs it must select an adapter that supports it.
    #[error("not supported by this payments adapter: {0}")]
    Unsupported(&'static str),
}

/// Moves money for a venture. Stripe today; the trait names only Stripe
/// identifiers and hosted URLs, never card data.
#[async_trait]
pub trait Payments: Send + Sync {
    /// A one-time hosted checkout. Returns the URL to redirect the browser to.
    async fn create_checkout(
        &self,
        request: &CheckoutRequest,
    ) -> Result<CheckoutSession, PaymentsError>;

    /// A recurring hosted checkout against a configured Stripe Price.
    async fn create_subscription_checkout(
        &self,
        request: &SubscriptionCheckoutRequest,
    ) -> Result<CheckoutSession, PaymentsError>;

    /// A Connect onboarding link for a coach's account.
    async fn create_connect_account_link(
        &self,
        request: &ConnectAccountLinkRequest,
    ) -> Result<ConnectAccountLink, PaymentsError>;

    /// A destination charge with an application fee (the platform's cut).
    async fn charge_with_transfer(&self, request: &TransferCharge)
    -> Result<Charge, PaymentsError>;

    /// Refunds a prior payment, in whole or in part.
    async fn refund(&self, request: &RefundRequest) -> Result<Refund, PaymentsError>;

    /// Verifies a webhook's signature and timestamp and returns the event.
    /// `signature_header` is the raw `Stripe-Signature` header; `body` is the
    /// exact bytes received (verification is over the raw body). Returns
    /// [`PaymentsError::SignatureInvalid`] if verification fails.
    async fn verify_webhook(
        &self,
        signature_header: &str,
        body: &[u8],
    ) -> Result<WebhookEvent, PaymentsError>;

    /// Reports a metered usage amount to the billing provider (Stripe Billing
    /// Meters) **idempotently**: the [`UsageReport::identifier`] makes a
    /// repeated report a no-op at the provider, so retrying is safe and a
    /// second report of the same window comes back as
    /// [`UsageReported::already_reported`] rather than an error.
    ///
    /// The default reports [`PaymentsError::Unsupported`], so an adapter that
    /// does not do metered billing compiles and runs unchanged.
    async fn report_usage(&self, _report: &UsageReport) -> Result<UsageReported, PaymentsError> {
        Err(PaymentsError::Unsupported("usage reporting"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::format_description::well_known::Rfc3339;

    fn at(text: &str) -> OffsetDateTime {
        OffsetDateTime::parse(text, &Rfc3339).expect("test instant parses")
    }

    #[test]
    fn hourly_identifier_names_the_utc_hour() {
        let report = UsageReport::hourly(
            "sub_1",
            "extra_avatar_minutes",
            "cus_1",
            5,
            at("2026-05-04T13:59:59Z"),
        );
        assert_eq!(report.timestamp, at("2026-05-04T13:00:00Z"));
        assert_eq!(
            report.identifier,
            format!(
                "sub_1:extra_avatar_minutes:{}",
                report.timestamp.unix_timestamp()
            )
        );

        // Any instant in the hour, and any value, name the same window.
        let same_hour = UsageReport::hourly(
            "sub_1",
            "extra_avatar_minutes",
            "cus_1",
            9,
            at("2026-05-04T13:00:01Z"),
        );
        assert_eq!(report.identifier, same_hour.identifier);
        assert_eq!(report.timestamp, same_hour.timestamp);

        // A non-UTC spelling of an instant names the same UTC hour:
        // 18:45 +05:30 is 13:15 UTC, the same window as 13:59:59Z above.
        let local = UsageReport::hourly(
            "sub_1",
            "extra_avatar_minutes",
            "cus_1",
            5,
            at("2026-05-04T18:45:00+05:30"),
        );
        assert_eq!(report.timestamp, local.timestamp);
        assert_eq!(report.identifier, local.identifier);

        // The next hour is a new window and a new identifier.
        let next_hour = UsageReport::hourly(
            "sub_1",
            "extra_avatar_minutes",
            "cus_1",
            5,
            at("2026-05-04T14:00:00Z"),
        );
        assert_ne!(report.identifier, next_hour.identifier);
        assert_ne!(report.timestamp, next_hour.timestamp);
    }
}
