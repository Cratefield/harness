//! Verified Polar webhook events mapped onto typed [`PolarEvent`]s.
//!
//! A free function, not a `Payments` method, the way issue #601 shapes
//! Stripe's `normalize`: the port hands over a verified [`WebhookEvent`] and
//! each adapter says what its vendor's events mean. When the provider-neutral
//! `LifecycleEvent` of issue #593 lands, this is where Polar's mapping onto it
//! goes. Disputes already map onto the port's own [`Dispute`], so code that
//! reacts to a dispute is the same for every adapter.
//!
//! Unknown event types, and the ones Polar sends that billing does not need
//! (benefits, products, seats, members, discounts, the organization), map to
//! no event and a log line, never an error: Polar adds event types, and a
//! handler must keep answering `2xx` when it does.

use std::collections::BTreeMap;

use cratefield_core::{Dispute, Money, WebhookEvent};
use serde_json::Value;
use time::OffsetDateTime;

use crate::{CustomerIds, dispute_from, optional_string, optional_time};

/// One billing-relevant fact from a verified Polar webhook.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolarEvent {
    Checkout(CheckoutEvent),
    Subscription(SubscriptionEvent),
    Order(OrderEvent),
    Refund(RefundEvent),
    Customer(CustomerEvent),
    /// A dispute changed. Polar sends no dispute webhook today; this comes
    /// from a refund Polar issued to **prevent** one (`refund.dispute`, with
    /// `status: prevented`). Open, won and lost disputes are read with
    /// [`Payments::list_disputes`](cratefield_core::Payments::list_disputes).
    Dispute(Dispute),
}

/// `checkout.created` / `checkout.updated` / `checkout.expired`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckoutChange {
    Created,
    Updated,
    Expired,
}

/// A checkout session's state. `status` is Polar's (`open`, `expired`,
/// `confirmed`, `succeeded`, `failed`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutEvent {
    pub change: CheckoutChange,
    pub id: String,
    pub status: String,
    pub customer_id: Option<String>,
    pub external_customer_id: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

/// Which `subscription.*` event it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionChange {
    Created,
    /// Became active: new and paid, or payment recovered.
    Active,
    /// Any change, renewals included.
    Updated,
    /// Will end at the period end; access continues until then.
    Canceled,
    /// A pending cancellation was taken back.
    Uncanceled,
    /// Ended now: access is gone (canceled immediately, or retries
    /// exhausted).
    Revoked,
    /// A renewal payment failed.
    PastDue,
    Paused,
    Resumed,
    /// A new billing period started.
    Cycled,
    /// Polar took over billing from another provider.
    Migrated,
}

/// A subscription's state after the change. `status` is Polar's
/// (`incomplete`, `incomplete_expired`, `trialing`, `active`, `past_due`,
/// `canceled`, `unpaid`, `paused`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionEvent {
    pub change: SubscriptionChange,
    pub id: String,
    pub status: String,
    pub customer_id: String,
    pub external_customer_id: Option<String>,
    /// The product (the plan: monthly or annual) subscribed to.
    pub product_id: String,
    pub cancel_at_period_end: bool,
    pub current_period_end: Option<OffsetDateTime>,
    pub metadata: BTreeMap<String, String>,
}

/// Which `order.*` event it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderChange {
    Created,
    /// Paid in full: the order is processed and the money received.
    Paid,
    Updated,
    /// Refunded in full or in part.
    Refunded,
}

/// An order (every paid transaction on Polar is one). `status` is Polar's
/// (`pending`, `paid`, `refunded`, `partially_refunded`, …);
/// `billing_reason` says why it exists (`purchase`, `subscription_create`,
/// `subscription_cycle`, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderEvent {
    pub change: OrderChange,
    pub id: String,
    pub status: String,
    pub billing_reason: Option<String>,
    pub customer_id: String,
    pub external_customer_id: Option<String>,
    pub subscription_id: Option<String>,
    /// After discounts and taxes.
    pub total: Money,
    pub refunded: Money,
    pub metadata: BTreeMap<String, String>,
}

/// `refund.created` / `refund.updated`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefundChange {
    Created,
    Updated,
}

/// A refund. `payment_ref` is the order id, what `Payments::refund` takes;
/// `status` is Polar's (`pending`, `succeeded`, `failed`, `canceled`), and
/// `reason` includes Polar's own `dispute_prevention`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefundEvent {
    pub change: RefundChange,
    pub id: String,
    pub payment_ref: String,
    pub subscription_id: Option<String>,
    pub customer_id: String,
    pub status: String,
    pub reason: String,
    /// The net amount refunded (tax is refunded on top, as `tax_amount`).
    pub amount: Money,
    pub metadata: BTreeMap<String, String>,
}

/// Which `customer.*` event it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustomerChange {
    Created,
    Updated,
    Deleted,
    /// Anything about the customer's state: subscriptions, benefits, meters.
    StateChanged,
}

/// A customer, with the venture's own id when it was set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomerEvent {
    pub change: CustomerChange,
    pub id: String,
    pub external_id: Option<String>,
    pub email: Option<String>,
}

/// The event types Polar sends that billing has no use for: ignored quietly.
const IGNORED_PREFIXES: [&str; 6] = [
    "benefit",
    "product.",
    "member.",
    "customer_seat.",
    "discount.",
    "organization.",
];

/// Maps one verified event onto zero or more [`PolarEvent`]s. A refund that
/// prevented a dispute yields both the refund and the dispute. `customers`
/// decides what a dispute's `customer_ref` names, as on the adapter.
#[must_use]
pub fn normalize(event: &WebhookEvent, customers: CustomerIds) -> Vec<PolarEvent> {
    let data = &event.data;
    let mapped = match event.kind.as_str() {
        "checkout.created" => checkout(data, CheckoutChange::Created),
        "checkout.updated" => checkout(data, CheckoutChange::Updated),
        "checkout.expired" => checkout(data, CheckoutChange::Expired),
        "subscription.created" => subscription(data, SubscriptionChange::Created),
        "subscription.active" => subscription(data, SubscriptionChange::Active),
        "subscription.updated" => subscription(data, SubscriptionChange::Updated),
        "subscription.canceled" => subscription(data, SubscriptionChange::Canceled),
        "subscription.uncanceled" => subscription(data, SubscriptionChange::Uncanceled),
        "subscription.revoked" => subscription(data, SubscriptionChange::Revoked),
        "subscription.past_due" => subscription(data, SubscriptionChange::PastDue),
        "subscription.paused" => subscription(data, SubscriptionChange::Paused),
        "subscription.resumed" => subscription(data, SubscriptionChange::Resumed),
        "subscription.cycled" => subscription(data, SubscriptionChange::Cycled),
        "subscription.migrated" => subscription(data, SubscriptionChange::Migrated),
        "order.created" => order(data, OrderChange::Created),
        "order.paid" => order(data, OrderChange::Paid),
        "order.updated" => order(data, OrderChange::Updated),
        "order.refunded" => order(data, OrderChange::Refunded),
        "refund.created" => refund(data, RefundChange::Created, customers),
        "refund.updated" => refund(data, RefundChange::Updated, customers),
        "customer.created" => customer(data, CustomerChange::Created),
        "customer.updated" => customer(data, CustomerChange::Updated),
        "customer.deleted" => customer(data, CustomerChange::Deleted),
        "customer.state_changed" => customer(data, CustomerChange::StateChanged),
        kind if IGNORED_PREFIXES
            .iter()
            .any(|prefix| kind.starts_with(prefix)) =>
        {
            tracing::debug!(event_id = %event.id, kind, "polar event not used by billing");
            return Vec::new();
        }
        kind => {
            tracing::info!(event_id = %event.id, kind, "ignoring unknown polar event type");
            return Vec::new();
        }
    };
    if mapped.is_none() {
        // A known type whose payload lacked a field we need: logged and
        // skipped, never an error the provider would retry forever.
        tracing::warn!(event_id = %event.id, kind = %event.kind, "polar event payload incomplete, ignored");
    }
    mapped.unwrap_or_default()
}

fn text(object: &Value, key: &str) -> Option<String> {
    optional_string(object, key)
}

fn metadata(object: &Value) -> BTreeMap<String, String> {
    object
        .get("metadata")
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .map(|(key, value)| {
                    let value = match value {
                        Value::String(text) => text.clone(),
                        other => other.to_string(),
                    };
                    (key.clone(), value)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn money(object: &Value, amount_key: &str) -> Option<Money> {
    Some(Money::new(
        object.get(amount_key)?.as_i64()?,
        object.get("currency")?.as_str()?,
    ))
}

/// The venture's id for the customer embedded in an order or subscription.
fn embedded_external_id(object: &Value) -> Option<String> {
    object.get("customer").and_then(|c| text(c, "external_id"))
}

fn checkout(data: &Value, change: CheckoutChange) -> Option<Vec<PolarEvent>> {
    Some(vec![PolarEvent::Checkout(CheckoutEvent {
        change,
        id: text(data, "id")?,
        status: text(data, "status")?,
        customer_id: text(data, "customer_id"),
        external_customer_id: text(data, "external_customer_id"),
        metadata: metadata(data),
    })])
}

fn subscription(data: &Value, change: SubscriptionChange) -> Option<Vec<PolarEvent>> {
    Some(vec![PolarEvent::Subscription(SubscriptionEvent {
        change,
        id: text(data, "id")?,
        status: text(data, "status")?,
        customer_id: text(data, "customer_id")?,
        external_customer_id: embedded_external_id(data),
        product_id: text(data, "product_id")?,
        cancel_at_period_end: data
            .get("cancel_at_period_end")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        current_period_end: optional_time(data, "current_period_end"),
        metadata: metadata(data),
    })])
}

fn order(data: &Value, change: OrderChange) -> Option<Vec<PolarEvent>> {
    Some(vec![PolarEvent::Order(OrderEvent {
        change,
        id: text(data, "id")?,
        status: text(data, "status")?,
        billing_reason: text(data, "billing_reason"),
        customer_id: text(data, "customer_id")?,
        external_customer_id: embedded_external_id(data),
        subscription_id: text(data, "subscription_id"),
        total: money(data, "total_amount")?,
        refunded: money(data, "refunded_amount")?,
        metadata: metadata(data),
    })])
}

fn refund(data: &Value, change: RefundChange, customers: CustomerIds) -> Option<Vec<PolarEvent>> {
    let event = RefundEvent {
        change,
        id: text(data, "id")?,
        payment_ref: text(data, "order_id")?,
        subscription_id: text(data, "subscription_id"),
        customer_id: text(data, "customer_id")?,
        status: text(data, "status")?,
        reason: text(data, "reason")?,
        amount: money(data, "amount")?,
        metadata: metadata(data),
    };
    let mut events = Vec::with_capacity(2);
    if let Some(dispute) = data.get("dispute").filter(|d| !d.is_null()) {
        // `RefundDispute` carries no customer object; the refund names the
        // Polar customer, which is only the right `customer_ref` when the
        // adapter names customers by Polar id.
        let mut dispute = dispute_from(dispute, customers).ok()?;
        if customers == CustomerIds::Polar {
            dispute.customer_ref = Some(event.customer_id.clone());
        }
        events.push(PolarEvent::Dispute(dispute));
    }
    events.insert(0, PolarEvent::Refund(event));
    Some(events)
}

fn customer(data: &Value, change: CustomerChange) -> Option<Vec<PolarEvent>> {
    Some(vec![PolarEvent::Customer(CustomerEvent {
        change,
        id: text(data, "id")?,
        external_id: text(data, "external_id"),
        email: text(data, "email"),
    })])
}
