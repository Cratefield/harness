//! Provider-neutral billing lifecycle (ADR 0025, issue #593).
//!
//! Adapters map vendor payloads onto a [`LifecycleEvent`] — Stripe in issue
//! #600, `RevenueCat` in issue #601 — and [`transition`] folds those events,
//! out-of-order deliveries included, into a [`SubscriptionState`]. Nothing
//! here touches the network or a database: persistence is issue #603, and the
//! specification is `docs/adr/0025-billing-lifecycle-entitlements-and-ledger.md`.

mod event;
mod money;
mod state;

pub use event::{
    CancelReason, ChangeTiming, DisputeOutcome, Environment, ExpirationReason, LifecycleEvent,
    LifecycleKind, Ownership, Period, PeriodType, Provider, ProviderCustomer, RefundOrigin,
    SourceRef, Store,
};
pub use money::{
    ChargeAmounts, LedgerEntry, LedgerKind, MoneyError, currency_exponent, major_to_minor,
};
pub use state::{
    DisputePolicy, LifecyclePolicy, PastDuePolicy, Status, SubscriptionState, Transition,
    gives_access, transition,
};
