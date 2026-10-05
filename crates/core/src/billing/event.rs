//! The provider-neutral lifecycle event (ADR 0025 decision 2, issue #593).
//!
//! An adapter (Stripe, issue #600; `RevenueCat`, issue #601) maps one verified
//! vendor payload onto one [`LifecycleEvent`]. No vendor name reaches the state
//! machine except [`Provider::Stripe`], which the past-due default keys off.

use time::OffsetDateTime;

/// Which billing provider delivered the event.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Provider {
    /// Stripe, over the `Payments` port: the `customer.subscription.*`,
    /// `invoice.*` and `charge.dispute.*` events.
    Stripe,
    /// `RevenueCat`, over the `InAppPurchases` port: its webhook `type`, or a
    /// v2 subscription `status`.
    RevenueCat,
    /// A provider this version does not know; the raw value is kept.
    Other(String),
}

/// The store a purchase came from (`RevenueCat` `store`; a Stripe purchase is
/// [`Store::Stripe`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Store {
    /// Apple App Store (`APP_STORE`).
    AppStore,
    /// Apple Mac App Store (`MAC_APP_STORE`).
    MacAppStore,
    /// Google Play (`PLAY_STORE`).
    PlayStore,
    /// Amazon Appstore (`AMAZON`).
    Amazon,
    /// A Stripe subscription or charge (`STRIPE`).
    Stripe,
    /// `RevenueCat` Billing, its own processor (`RC_BILLING`).
    RcBilling,
    /// Paddle, a Merchant of Record (`PADDLE`).
    Paddle,
    /// Roku (`ROKU`).
    Roku,
    /// A promotional grant, not a purchase (`PROMOTIONAL`).
    Promotional,
    /// `RevenueCat`'s test store (`TEST_STORE`).
    TestStore,
    /// A store this version does not know; the raw value is kept.
    Other(String),
}

/// Which environment the event happened in (`RevenueCat` reports `SANDBOX`;
/// Stripe sends both from one live account).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Environment {
    /// Real money and real customers.
    Production,
    /// Sandbox or test traffic: stored but never grants in production
    /// (ADR 0025 decision 10).
    Sandbox,
}

/// Whether the customer bought the subscription themselves or receives it from
/// a family plan (`RevenueCat` `PURCHASED` / `FAMILY_SHARED`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ownership {
    /// The customer purchased it.
    Purchased,
    /// A family member shared it with the customer.
    FamilyShared,
}

/// What kind of period a subscription is in (`RevenueCat` `period_type`; a
/// Stripe subscription with `status=trialing` is [`PeriodType::Trial`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeriodType {
    /// A free trial (`TRIAL`).
    Trial,
    /// An introductory paid period (`INTRO`).
    Intro,
    /// A normal paid period (`NORMAL`).
    Normal,
    /// A promotional period (`PROMOTIONAL`).
    Promotional,
    /// A prepaid period, e.g. a multi-month top-up (`PREPAID`).
    Prepaid,
}

/// The customer at the provider (ADR 0025 decision 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderCustomer {
    /// The current id (`RevenueCat` `app_user_id`; the Stripe customer id).
    pub id: String,
    /// The first id ever seen for this customer, when the provider reports one
    /// (`RevenueCat` `original_app_user_id`).
    pub original_id: Option<String>,
    /// Every other id that has resolved to this customer (`RevenueCat`
    /// `aliases`), so an alias or transfer can be followed to the same account.
    pub aliases: Vec<String>,
}

/// The provider's id for what the event is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceRef {
    /// A subscription (`RevenueCat` `subscription_id`; a Stripe `sub_…`).
    Subscription(String),
    /// A one-time purchase or transaction (`RevenueCat` `transaction_id`; a
    /// Stripe payment intent or charge).
    OneTimePurchase(String),
}

/// One billing period as the provider reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Period {
    /// When the period began.
    pub starts_at: OffsetDateTime,
    /// When the period ends (`RevenueCat` `expiration_at_ms`; Stripe
    /// `current_period_end`).
    pub ends_at: OffsetDateTime,
}

/// Why a subscription stopped auto-renewing or ended (`RevenueCat`
/// `cancel_reason`; Stripe `cancellation_details.reason`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CancelReason {
    /// The customer turned auto-renew off (`UNSUBSCRIBE`; Stripe
    /// `cancellation_requested`).
    Unsubscribe,
    /// The renewal charge failed (`BILLING_ERROR`; Stripe `payment_failed`).
    BillingError,
    /// The venture cancelled it (`DEVELOPER_INITIATED`).
    DeveloperInitiated,
    /// A price increase the customer did not consent to (`PRICE_INCREASE`).
    PriceIncrease,
    /// Support cancelled on the customer's behalf (`CUSTOMER_SUPPORT`, also
    /// the reason `RevenueCat` reports for a store refund).
    CustomerSupport,
    /// The charge was disputed (Stripe `payment_disputed`).
    PaymentDisputed,
    /// The provider reports no reason (`UNKNOWN`).
    Unknown,
    /// A reason this version does not know; the raw value is kept.
    Other(String),
}

/// Why a subscription expired: [`CancelReason`]'s variants plus
/// [`ExpirationReason::SubscriptionPaused`] (`RevenueCat` `expiration_reason`
/// `SUBSCRIPTION_PAUSED`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExpirationReason {
    /// The customer turned auto-renew off (`UNSUBSCRIBE`).
    Unsubscribe,
    /// The renewal charge failed (`BILLING_ERROR`).
    BillingError,
    /// The venture ended it (`DEVELOPER_INITIATED`).
    DeveloperInitiated,
    /// A price increase the customer did not consent to (`PRICE_INCREASE`).
    PriceIncrease,
    /// Support ended it (`CUSTOMER_SUPPORT`; a store refund).
    CustomerSupport,
    /// The charge was disputed (Stripe `payment_disputed`).
    PaymentDisputed,
    /// The provider reports no reason (`UNKNOWN`).
    Unknown,
    /// The subscription paused for long enough to expire
    /// (`SUBSCRIPTION_PAUSED`).
    SubscriptionPaused,
    /// A reason this version does not know; the raw value is kept.
    Other(String),
}

/// When a product or price change takes effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChangeTiming {
    /// Now, mid-period (a Stripe price change on the subscription).
    Immediate,
    /// At the next renewal (`RevenueCat` `PRODUCT_CHANGE` for a scheduled
    /// change; a Stripe subscription schedule).
    NextRenewal,
}

/// Who issued a refund.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefundOrigin {
    /// The store issued it: an Apple or Google refund, or a store-side
    /// chargeback, which `RevenueCat` reports as a `CANCELLATION` with
    /// `cancel_reason=CUSTOMER_SUPPORT`.
    Store,
    /// The merchant issued it through the provider's dashboard or API (Stripe
    /// `charge.refunded`).
    Merchant,
    /// An origin this version does not know; the raw value is kept.
    Other(String),
}

/// How a dispute ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DisputeOutcome {
    /// The merchant won: the funds come back (Stripe `won`).
    Won,
    /// The cardholder won: the funds stay withdrawn (Stripe `lost`).
    Lost,
    /// An outcome this version does not know, e.g. Stripe `warning_closed`;
    /// the raw value is kept.
    Other(String),
}

/// What happened, in the provider-neutral vocabulary of ADR 0025 decision 2.
/// Each variant names the vendor values an adapter maps onto it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LifecycleKind {
    /// A subscription began: `RevenueCat` `INITIAL_PURCHASE`; Stripe `customer.subscription.created`.
    Started,
    /// A period renewed: `RevenueCat` `RENEWAL`; Stripe `invoice.paid` `billing_reason=subscription_cycle`.
    Renewed {
        /// Whether this renewal ended a trial (`RevenueCat` `is_trial_conversion`).
        trial_conversion: bool,
    },
    /// Auto-renew off, access to the period end: RC `CANCELLATION`; Stripe `cancel_at_period_end=true`.
    CancellationScheduled {
        /// Why: RC `cancel_reason`; Stripe `cancellation_details.reason`.
        reason: CancelReason,
    },
    /// Auto-renew back on: RC `UNCANCELLATION`; Stripe `cancel_at_period_end=false`.
    Uncancelled,
    /// A renewal charge failed: RC `BILLING_ISSUE`; Stripe `invoice.payment_failed`, `status=past_due`.
    BillingIssue {
        /// When a grace period ends (RC `grace_period_expiration_at_ms`), if one runs.
        grace_until: Option<OffsetDateTime>,
    },
    /// Billing recovered: Stripe `past_due`/`unpaid` to `active`; RC `RENEWAL` after a billing issue.
    Recovered,
    /// A pause was scheduled: RC `SUBSCRIPTION_PAUSED`; Stripe `pause_collection` set.
    PauseScheduled {
        /// When the pause lifts itself (Stripe `resumes_at`), if it does.
        resumes_at: Option<OffsetDateTime>,
    },
    /// The subscription is paused: Stripe `customer.subscription.paused`; RC `status=paused`.
    Paused,
    /// A pause ended: Stripe `customer.subscription.resumed`.
    Resumed,
    /// Access ended: RC `EXPIRATION`; Stripe `customer.subscription.deleted` with `canceled`.
    Expired {
        /// Why (RC `expiration_reason`).
        reason: ExpirationReason,
    },
    /// The period's end moved later without money: RC `SUBSCRIPTION_EXTENDED`.
    Extended {
        /// The new end of access.
        new_ends_at: OffsetDateTime,
    },
    /// The product changed: RC `PRODUCT_CHANGE`; Stripe a price change or schedule.
    ProductChanged {
        /// The product (or price) the customer moves to.
        to_product: String,
        /// When the change takes effect.
        effective: ChangeTiming,
    },
    /// A payment was refunded: Stripe `charge.refunded`; RC `CANCELLATION` with `CUSTOMER_SUPPORT`.
    Refunded {
        /// Whether only part of the amount came back.
        partial: bool,
        /// Who issued it.
        origin: RefundOrigin,
    },
    /// A refund was reversed (App Store): RC `REFUND_REVERSED`.
    RefundReversed,
    /// A dispute opened: Stripe `charge.dispute.created`.
    DisputeOpened,
    /// A dispute's status changed: Stripe `charge.dispute.updated`.
    DisputeUpdated,
    /// A dispute closed: Stripe `charge.dispute.closed`.
    DisputeClosed {
        /// Who the decision favoured.
        outcome: DisputeOutcome,
    },
    /// Disputed funds were withdrawn: Stripe `charge.dispute.funds_withdrawn`.
    DisputeFundsWithdrawn,
    /// Disputed funds came back: Stripe `charge.dispute.funds_reinstated`.
    DisputeFundsReinstated,
    /// A non-renewing purchase: RC `NON_RENEWING_PURCHASE`; Stripe `mode=payment` checkout.
    OneTimePurchase {
        /// Whether it is consumable (RC `is_consumable`), when the provider says.
        consumable: Option<bool>,
    },
    /// A purchase moved between customers: RC `TRANSFER` (`transferred_from`, `transferred_to`).
    Transferred {
        /// The customer ids it moved from.
        from: Vec<String>,
        /// The customer ids it moved to.
        to: Vec<String>,
    },
    /// A temporary entitlement grant: RC `TEMPORARY_ENTITLEMENT_GRANT`.
    TemporaryGrant {
        /// When the grant lapses.
        until: OffsetDateTime,
    },
    /// A price increase needs consent: RC `auto_renewal_status=requires_price_increase_consent`.
    PriceChangeConsentRequired,
    /// The price increase was consented to: RC `auto_renewal_status=will_renew`.
    PriceChangeConsentApproved,
    /// An unpaid invoice was issued: RC Billing `INVOICE_ISSUANCE`; Stripe `invoice.finalized`.
    InvoiceIssued,
    /// RC's test event (`TEST`): a no-op that proves the route is wired.
    Test,
    /// An unknown event; `raw_kind` keeps the vendor string, e.g. RC `SUBSCRIBER_ALIAS`.
    Unrecognized,
}

impl LifecycleKind {
    /// Whether applying this event can *never restore or extend access*.
    ///
    /// Out-of-order deliveries are ignored when they are older than the state
    /// they would move (ADR 0025 decision 2). The exceptions are the kinds
    /// that only ever take access away — a refund, a dispute that is still
    /// open or was lost, a funds withdrawal, a transfer — because a late one
    /// must still apply: a revocation is not made true again by a newer
    /// renewal that arrived first.
    ///
    /// An exhaustive match, so a new variant has to decide.
    #[must_use]
    pub fn is_monotonic_safe(&self) -> bool {
        match self {
            Self::Refunded { .. }
            | Self::DisputeOpened
            | Self::DisputeUpdated
            | Self::DisputeFundsWithdrawn
            | Self::Transferred { .. } => true,
            Self::DisputeClosed { outcome } => !matches!(outcome, DisputeOutcome::Won),
            Self::Started
            | Self::Renewed { .. }
            | Self::CancellationScheduled { .. }
            | Self::Uncancelled
            | Self::BillingIssue { .. }
            | Self::Recovered
            | Self::PauseScheduled { .. }
            | Self::Paused
            | Self::Resumed
            | Self::Expired { .. }
            | Self::Extended { .. }
            | Self::ProductChanged { .. }
            | Self::RefundReversed
            | Self::DisputeFundsReinstated
            | Self::OneTimePurchase { .. }
            | Self::TemporaryGrant { .. }
            | Self::PriceChangeConsentRequired
            | Self::PriceChangeConsentApproved
            | Self::InvoiceIssued
            | Self::Test
            | Self::Unrecognized => false,
        }
    }
}

/// One billing lifecycle event: what happened to a provider customer's
/// subscription or purchase, in the provider-neutral shape every adapter maps
/// its vendor payloads onto (ADR 0025 decision 2).
///
/// Charge amounts arrive with issue #594, which adds an `amounts` field; this
/// struct is deliberately not `#[non_exhaustive]` so adapters in other crates
/// can build one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleEvent {
    /// Which provider sent the event.
    pub provider: Provider,
    /// Which store the purchase came from.
    pub store: Store,
    /// The provider's id for this delivery, for the `Inbox` dedup ledger.
    pub event_id: String,
    /// When the provider says the event happened.
    pub occurred_at: OffsetDateTime,
    /// Production or sandbox.
    pub environment: Environment,
    /// The customer at the provider.
    pub provider_customer: ProviderCustomer,
    /// The subscription or one-time purchase the event is about.
    pub source: SourceRef,
    /// The product (or store SKU) the event concerns.
    pub product_id: String,
    /// The entitlement keys (ADR 0025 decision 4) this source grants.
    pub entitlement_keys: Vec<String>,
    /// The billing period, when the event carries one.
    pub period: Option<Period>,
    /// What kind of period the customer is in.
    pub period_type: PeriodType,
    /// Whether the customer bought the purchase or a family shared it.
    pub ownership: Ownership,
    /// What happened.
    pub kind: LifecycleKind,
    /// The provider's event type verbatim (`RENEWAL`,
    /// `customer.subscription.created`), kept for audit and for
    /// [`LifecycleKind::Unrecognized`].
    pub raw_kind: String,
}
