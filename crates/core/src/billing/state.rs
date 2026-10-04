//! The provider-neutral subscription state machine (ADR 0025 decision 2,
//! issue #593): [`transition`] folds [`LifecycleEvent`]s into a
//! [`SubscriptionState`], and [`gives_access`] answers whether that state
//! grants access right now.

use super::event::{
    ChangeTiming, DisputeOutcome, LifecycleEvent, LifecycleKind, PeriodType, Provider,
};
use time::OffsetDateTime;

/// Where a subscription is, provider-neutral.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Status {
    /// The first charge has not succeeded yet (Stripe `incomplete`;
    /// `RevenueCat` `incomplete` and `unknown`).
    Incomplete,
    /// Paying and renewing (Stripe `active` / `trialing`; `RevenueCat`
    /// `active` / `trialing`). A trial is [`PeriodType::Trial`], not a status
    /// of its own.
    Active,
    /// A charge failed and a grace period is running (`RevenueCat`
    /// `in_grace_period`; Stripe `past_due` under the default
    /// [`PastDuePolicy`]).
    InGracePeriod,
    /// A charge failed and the provider is retrying (`RevenueCat`
    /// `in_billing_retry`; Stripe `unpaid`).
    InBillingRetry,
    /// Paused, by the customer or by policy (both providers' `paused`).
    Paused,
    /// Access ended (`RevenueCat` `expired`; Stripe `canceled` and
    /// `incomplete_expired`).
    Expired,
    /// No provider reports this status: a refund or a lost dispute sets it.
    Revoked,
}

/// A subscription's state after folding in every event seen so far.
///
/// [`transition`] maintains the invariant `revoked == (status ==
/// Status::Revoked)`, so code that builds a state by hand must keep it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionState {
    /// Where the subscription is.
    pub status: Status,
    /// What kind of period it is in.
    pub period_type: PeriodType,
    /// Whether it will renew (auto-renew is on).
    pub renews: bool,
    /// When access ends. `None` means no end date, e.g. a lifetime one-time
    /// purchase.
    pub access_until: Option<OffsetDateTime>,
    /// A product change scheduled for the next renewal.
    pub pending_product: Option<String>,
    /// The provider timestamp of the newest event applied.
    pub last_event_at: OffsetDateTime,
    /// Whether a refund or a lost dispute revoked access (ADR 0025
    /// decision 9).
    pub revoked: bool,
}

/// What a Stripe subscription in `past_due` gets by default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum PastDuePolicy {
    /// Keep access while Stripe retries: `past_due` is
    /// [`Status::InGracePeriod`]. The default.
    #[default]
    InGracePeriod,
    /// Drop access while Stripe retries: `past_due` is
    /// [`Status::InBillingRetry`].
    InBillingRetry,
}

/// What a dispute does to access (ADR 0025 decision 9).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum DisputePolicy {
    /// Opening a dispute leaves access alone; losing it revokes, winning it
    /// restores. Flagging the account is the billing module's job, not
    /// `transition`'s (ADR 0025 decision 9). The default.
    #[default]
    RevokeOnLoss,
    /// Opening a dispute revokes access at once.
    RevokeOnOpen,
    /// Disputes never touch access; some other policy owns the flag.
    Ignore,
}

/// The venture-configurable policy [`transition`] reads.
///
/// Issue #612 owns letting a venture configure this; [`Default`] is
/// ADR 0025 decision 9's default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecyclePolicy {
    /// What Stripe `past_due` means for access.
    pub stripe_past_due: PastDuePolicy,
    /// Whether [`Status::InBillingRetry`] still grants access, for a provider
    /// that reports no grace period of its own.
    pub billing_retry_grants_access: bool,
    /// Whether a full refund revokes access.
    pub refund_revokes: bool,
    /// What a dispute does.
    pub dispute: DisputePolicy,
}

impl Default for LifecyclePolicy {
    /// ADR 0025 decision 9's defaults, in
    /// `docs/adr/0025-billing-lifecycle-entitlements-and-ledger.md`: a
    /// Stripe `past_due` keeps access, a billing retry does not, a full
    /// refund revokes, and a dispute flags on open, revokes on loss and
    /// restores on a win.
    fn default() -> Self {
        Self {
            stripe_past_due: PastDuePolicy::InGracePeriod,
            billing_retry_grants_access: false,
            refund_revokes: true,
            dispute: DisputePolicy::RevokeOnLoss,
        }
    }
}

/// What [`transition`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    /// The event applied; this is the state that follows.
    Apply(SubscriptionState),
    /// The event is older than the state it would move and cannot restore
    /// access, so it was dropped. A duplicate delivery is the common case.
    IgnoreStale,
    /// The event cannot apply to this state; the reason is meant for a log.
    Invalid(&'static str),
}

/// Folds one event into the subscription state, purely; `None` for `state`
/// means this is the first event seen. An event older than the state it
/// would move is [`Transition::IgnoreStale`] unless
/// [`LifecycleKind::is_monotonic_safe`]; an event that cannot move an
/// expired or revoked state is [`Transition::Invalid`]. The full rule table
/// is decision 2 of `docs/adr/0025-billing-lifecycle-entitlements-and-ledger.md`,
/// and the arms below are in its order.
///
/// The match over the kind is exhaustive with no wildcard, so a new
/// [`LifecycleKind`] is a compile error here until it has a rule.
#[must_use]
#[allow(clippy::too_many_lines)] // the transition table, one arm per kind
pub fn transition(
    state: Option<&SubscriptionState>,
    event: &LifecycleEvent,
    policy: &LifecyclePolicy,
) -> Transition {
    let fresh = SubscriptionState {
        status: Status::Incomplete,
        period_type: event.period_type,
        renews: false,
        access_until: None,
        pending_product: None,
        last_event_at: event.occurred_at,
        revoked: false,
    };
    let prior = state.unwrap_or(&fresh);
    let t = event.occurred_at;

    // Rule 1.
    if t < prior.last_event_at && !event.kind.is_monotonic_safe() {
        return Transition::IgnoreStale;
    }

    let terminal = matches!(prior.status, Status::Expired | Status::Revoked);
    let ends_at = event.period.as_ref().map(|period| period.ends_at);

    let next = match &event.kind {
        // Rule 3: a newer payment clears an earlier revocation.
        LifecycleKind::Started | LifecycleKind::Renewed { .. } | LifecycleKind::Recovered => {
            Some(paid(event, true, prior.access_until))
        }
        LifecycleKind::OneTimePurchase { .. } => Some(paid(event, false, None)),
        LifecycleKind::TemporaryGrant { until } => Some(SubscriptionState {
            status: Status::Active,
            period_type: event.period_type,
            renews: false,
            access_until: Some(*until),
            pending_product: None,
            last_event_at: t,
            revoked: false,
        }),

        // Rule 4.
        LifecycleKind::CancellationScheduled { .. } => (!terminal).then(|| SubscriptionState {
            renews: false,
            access_until: ends_at.or(prior.access_until),
            ..prior.clone()
        }),
        LifecycleKind::Uncancelled => (!terminal).then(|| SubscriptionState {
            renews: true,
            ..prior.clone()
        }),
        LifecycleKind::PauseScheduled { .. } => (!terminal).then(|| prior.clone()),
        LifecycleKind::ProductChanged {
            to_product,
            effective,
        } => (!terminal).then(|| SubscriptionState {
            pending_product: match effective {
                ChangeTiming::Immediate => None,
                ChangeTiming::NextRenewal => Some(to_product.clone()),
            },
            ..prior.clone()
        }),

        // Rule 5.
        LifecycleKind::BillingIssue { grace_until } => {
            if terminal {
                None
            } else if prior.status == Status::Incomplete {
                Some(prior.clone())
            } else if let Some(grace) = grace_until {
                Some(SubscriptionState {
                    status: Status::InGracePeriod,
                    access_until: Some(*grace),
                    ..prior.clone()
                })
            } else if (event.provider == Provider::Stripe
                && policy.stripe_past_due == PastDuePolicy::InGracePeriod)
                || policy.billing_retry_grants_access
            {
                Some(SubscriptionState {
                    status: Status::InGracePeriod,
                    access_until: ends_at.or(prior.access_until),
                    ..prior.clone()
                })
            } else {
                Some(SubscriptionState {
                    status: Status::InBillingRetry,
                    ..prior.clone()
                })
            }
        }

        // Rule 6.
        LifecycleKind::Paused => (!terminal).then(|| SubscriptionState {
            status: Status::Paused,
            ..prior.clone()
        }),
        LifecycleKind::Resumed => {
            if terminal {
                None
            } else if prior.status == Status::Paused {
                Some(SubscriptionState {
                    status: Status::Active,
                    renews: true,
                    access_until: ends_at.or(prior.access_until),
                    ..prior.clone()
                })
            } else {
                Some(prior.clone())
            }
        }

        // Rule 7: revocation is sticky.
        LifecycleKind::Expired { .. } => Some(if prior.status == Status::Revoked {
            prior.clone()
        } else {
            SubscriptionState {
                status: Status::Expired,
                renews: false,
                ..prior.clone()
            }
        }),

        // Rule 8.
        LifecycleKind::Extended { new_ends_at } => {
            if prior.status == Status::Revoked {
                None
            } else {
                Some(SubscriptionState {
                    status: if prior.status == Status::Expired {
                        Status::Active
                    } else {
                        prior.status
                    },
                    access_until: Some(*new_ends_at),
                    ..prior.clone()
                })
            }
        }

        // Rule 9.
        LifecycleKind::Refunded { partial, .. } => {
            if policy.refund_revokes && !partial {
                Some(revoke(prior))
            } else {
                Some(prior.clone())
            }
        }
        LifecycleKind::RefundReversed => Some(restore(prior)),

        // Rule 10.
        LifecycleKind::DisputeOpened
        | LifecycleKind::DisputeUpdated
        | LifecycleKind::DisputeFundsWithdrawn => {
            if policy.dispute == DisputePolicy::RevokeOnOpen {
                Some(revoke(prior))
            } else {
                Some(prior.clone())
            }
        }
        LifecycleKind::DisputeClosed { outcome } => match outcome {
            DisputeOutcome::Lost => {
                if policy.dispute == DisputePolicy::Ignore {
                    Some(prior.clone())
                } else {
                    Some(revoke(prior))
                }
            }
            DisputeOutcome::Won => Some(restorable(prior, policy)),
            DisputeOutcome::Other(_) => Some(prior.clone()),
        },
        LifecycleKind::DisputeFundsReinstated => Some(restorable(prior, policy)),

        // Rule 11: observations. A transfer re-keys the customers, which is
        // the billing module's job, not this function's.
        LifecycleKind::Transferred { .. }
        | LifecycleKind::PriceChangeConsentRequired
        | LifecycleKind::PriceChangeConsentApproved
        | LifecycleKind::InvoiceIssued
        | LifecycleKind::Test
        | LifecycleKind::Unrecognized => Some(prior.clone()),
    };

    match next {
        None => Transition::Invalid("event cannot move an expired or revoked subscription"),
        Some(mut next) => {
            // Rule 2, and the `revoked` invariant.
            next.last_event_at = prior.last_event_at.max(t);
            next.revoked = next.status == Status::Revoked;
            Transition::Apply(next)
        }
    }
}

/// Whether this state grants access at `now`.
///
/// A revoked state never does. Otherwise [`Status::Active`] and
/// [`Status::InGracePeriod`] do, until `access_until` passes if it is set.
#[must_use]
pub fn gives_access(state: &SubscriptionState, now: OffsetDateTime) -> bool {
    if state.revoked {
        return false;
    }
    matches!(state.status, Status::Active | Status::InGracePeriod)
        && state.access_until.is_none_or(|until| now < until)
}

/// The state an activation leaves behind (rule 3): active, no pending
/// product, access to the paid period's end, or `fallback` when the event
/// carries no period.
fn paid(
    event: &LifecycleEvent,
    renews: bool,
    fallback: Option<OffsetDateTime>,
) -> SubscriptionState {
    SubscriptionState {
        status: Status::Active,
        period_type: event.period_type,
        renews,
        access_until: event
            .period
            .as_ref()
            .map(|period| period.ends_at)
            .or(fallback),
        pending_product: None,
        last_event_at: event.occurred_at,
        revoked: false,
    }
}

/// The state a revocation leaves behind (rules 9 and 10): no renewal, no
/// access, and the invariant's `revoked` set.
fn revoke(prior: &SubscriptionState) -> SubscriptionState {
    SubscriptionState {
        status: Status::Revoked,
        renews: false,
        revoked: true,
        ..prior.clone()
    }
}

/// Undo a revocation when a dispute is won or the disputed funds come back
/// (ADR 0025 decision 9). `access_until` still bounds access, so a restored
/// subscription whose period has passed grants nothing. Under
/// [`DisputePolicy::Ignore`] the policy does not own this, so nothing
/// changes.
fn restorable(prior: &SubscriptionState, policy: &LifecyclePolicy) -> SubscriptionState {
    if prior.revoked && policy.dispute != DisputePolicy::Ignore {
        SubscriptionState {
            status: Status::Active,
            revoked: false,
            ..prior.clone()
        }
    } else {
        prior.clone()
    }
}

/// Undo a revocation (rule 9): a reversed refund restores access, but any
/// other state is unchanged.
fn restore(prior: &SubscriptionState) -> SubscriptionState {
    if prior.revoked {
        SubscriptionState {
            status: Status::Active,
            revoked: false,
            ..prior.clone()
        }
    } else {
        prior.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::event::{
        CancelReason, DisputeOutcome, Environment, ExpirationReason, LifecycleEvent, Ownership,
        Period, ProviderCustomer, RefundOrigin, SourceRef, Store,
    };
    use time::Duration;
    use time::format_description::well_known::Rfc3339;

    /// Every [`Status`]. The `match` is the point: a variant missing from the
    /// list is a compile error here.
    fn all_statuses() -> Vec<Status> {
        let all = vec![
            Status::Incomplete,
            Status::Active,
            Status::InGracePeriod,
            Status::InBillingRetry,
            Status::Paused,
            Status::Expired,
            Status::Revoked,
        ];
        for status in &all {
            match status {
                Status::Incomplete
                | Status::Active
                | Status::InGracePeriod
                | Status::InBillingRetry
                | Status::Paused
                | Status::Expired
                | Status::Revoked => {}
            }
        }
        all
    }

    /// Declares one sample per [`LifecycleKind`] and, from that same list, a
    /// match that must be exhaustive: a new variant with no sample is a
    /// compile error.
    macro_rules! kind_samples {
        ($($pattern:pat => $sample:expr),+ $(,)?) => {
            /// One representative sample of every kind.
            fn kind_samples() -> Vec<(&'static str, LifecycleKind)> {
                vec![$((stringify!($pattern), $sample)),+]
            }

            /// Never called: a kind absent from the list above is a compile
            /// error here.
            #[expect(dead_code, reason = "its only job is to be exhaustive")]
            fn every_kind_is_sampled(kind: LifecycleKind) {
                match kind {
                    $($pattern => {}),+
                }
            }
        };
    }

    kind_samples! {
        LifecycleKind::Started => LifecycleKind::Started,
        LifecycleKind::Renewed { .. } => LifecycleKind::Renewed { trial_conversion: false },
        LifecycleKind::CancellationScheduled { .. } => LifecycleKind::CancellationScheduled {
            reason: CancelReason::Unsubscribe,
        },
        LifecycleKind::Uncancelled => LifecycleKind::Uncancelled,
        LifecycleKind::BillingIssue { .. } => LifecycleKind::BillingIssue { grace_until: None },
        LifecycleKind::Recovered => LifecycleKind::Recovered,
        LifecycleKind::PauseScheduled { .. } => LifecycleKind::PauseScheduled { resumes_at: None },
        LifecycleKind::Paused => LifecycleKind::Paused,
        LifecycleKind::Resumed => LifecycleKind::Resumed,
        LifecycleKind::Expired { .. } => LifecycleKind::Expired { reason: ExpirationReason::Unknown },
        LifecycleKind::Extended { .. } => LifecycleKind::Extended { new_ends_at: instant("2026-07-01T00:00:00Z") },
        LifecycleKind::ProductChanged { .. } => LifecycleKind::ProductChanged {
            to_product: "pro_annual".to_owned(),
            effective: ChangeTiming::NextRenewal,
        },
        LifecycleKind::Refunded { .. } => LifecycleKind::Refunded {
            partial: false,
            origin: RefundOrigin::Store,
        },
        LifecycleKind::RefundReversed => LifecycleKind::RefundReversed,
        LifecycleKind::DisputeOpened => LifecycleKind::DisputeOpened,
        LifecycleKind::DisputeUpdated => LifecycleKind::DisputeUpdated,
        LifecycleKind::DisputeClosed { .. } => LifecycleKind::DisputeClosed {
            outcome: DisputeOutcome::Won,
        },
        LifecycleKind::DisputeFundsWithdrawn => LifecycleKind::DisputeFundsWithdrawn,
        LifecycleKind::DisputeFundsReinstated => LifecycleKind::DisputeFundsReinstated,
        LifecycleKind::OneTimePurchase { .. } => LifecycleKind::OneTimePurchase { consumable: None },
        LifecycleKind::Transferred { .. } => LifecycleKind::Transferred {
            from: vec!["u_old".to_owned()],
            to: vec!["u_1".to_owned()],
        },
        LifecycleKind::TemporaryGrant { .. } => LifecycleKind::TemporaryGrant {
            until: instant("2026-06-01T00:00:00Z"),
        },
        LifecycleKind::PriceChangeConsentRequired => LifecycleKind::PriceChangeConsentRequired,
        LifecycleKind::PriceChangeConsentApproved => LifecycleKind::PriceChangeConsentApproved,
        LifecycleKind::InvoiceIssued => LifecycleKind::InvoiceIssued,
        LifecycleKind::Test => LifecycleKind::Test,
        LifecycleKind::Unrecognized => LifecycleKind::Unrecognized,
    }

    /// The instant every scenario's subscription starts at.
    const START: &str = "2026-05-01T00:00:00Z";
    /// The free trial's end.
    const TRIAL_END: &str = "2026-05-15T00:00:00Z";
    /// The first paid period's end.
    const PAID_END: &str = "2026-06-15T00:00:00Z";

    fn instant(text: &str) -> OffsetDateTime {
        OffsetDateTime::parse(text, &Rfc3339).expect("test instant parses")
    }

    fn period(starts_at: OffsetDateTime, ends_at: OffsetDateTime) -> Period {
        Period { starts_at, ends_at }
    }

    /// A `RevenueCat` event, production, one subscription, normal period
    /// type and no period until a test sets one.
    fn rc_event(kind: LifecycleKind, at: OffsetDateTime) -> LifecycleEvent {
        LifecycleEvent {
            provider: Provider::RevenueCat,
            store: Store::AppStore,
            event_id: format!("evt-{}", at.unix_timestamp()),
            occurred_at: at,
            environment: Environment::Production,
            provider_customer: ProviderCustomer {
                id: "u_1".to_owned(),
                original_id: None,
                aliases: Vec::new(),
            },
            source: SourceRef::Subscription("sub_1".to_owned()),
            product_id: "pro".to_owned(),
            entitlement_keys: vec!["pro".to_owned()],
            period: None,
            period_type: PeriodType::Normal,
            ownership: Ownership::Purchased,
            kind,
            raw_kind: "TEST".to_owned(),
        }
    }

    /// A whole refund at `at`, in the store's ledger.
    fn whole_refund(at: OffsetDateTime) -> LifecycleEvent {
        rc_event(
            LifecycleKind::Refunded {
                partial: false,
                origin: RefundOrigin::Store,
            },
            at,
        )
    }

    /// A prior state for every status, with access in the future and no
    /// pending product.
    fn representative(status: Status, at: OffsetDateTime) -> SubscriptionState {
        SubscriptionState {
            status,
            period_type: PeriodType::Normal,
            renews: true,
            access_until: Some(at + Duration::days(30)),
            pending_product: None,
            last_event_at: at,
            revoked: status == Status::Revoked,
        }
    }

    /// A subscription that started in a free trial at [`START`] ending at
    /// `trial_end`.
    fn trial_started(trial_end: OffsetDateTime) -> SubscriptionState {
        let mut started = rc_event(LifecycleKind::Started, instant(START));
        started.period_type = PeriodType::Trial;
        started.period = Some(period(instant(START), trial_end));
        applied(transition(None, &started, &LifecyclePolicy::default()))
    }

    /// [`transition`] from `prior` under the default policy.
    fn step(prior: &SubscriptionState, event: &LifecycleEvent) -> SubscriptionState {
        applied(transition(Some(prior), event, &LifecyclePolicy::default()))
    }

    fn applied(outcome: Transition) -> SubscriptionState {
        match outcome {
            Transition::Apply(state) => state,
            other => panic!("expected Apply, got {other:?}"),
        }
    }

    /// A rule that leaves the status alone, unless the prior state was
    /// terminal.
    fn stay(status: Status, terminal: bool) -> Option<Status> {
        (!terminal).then_some(status)
    }

    /// An undo: a revoked prior state becomes active, anything else is
    /// unchanged.
    fn restored(status: Status) -> Status {
        if status == Status::Revoked {
            Status::Active
        } else {
            status
        }
    }

    /// The transition table, written out: the status `transition` lands on
    /// for a prior status and a kind under [`LifecyclePolicy::default`] and
    /// the samples above. `None` is [`Transition::Invalid`].
    ///
    /// The samples matter: the billing issue is a `RevenueCat` event with no
    /// grace period (so it lands in billing retry), the refund is not
    /// partial, the product change is next renewal, and the closed dispute
    /// was won.
    ///
    /// The arms are in `transition`'s order, one per rule.
    fn expected(status: Status, kind: &LifecycleKind) -> Option<Status> {
        let terminal = matches!(status, Status::Expired | Status::Revoked);
        match kind {
            // Rule 3: a payment lands the subscription in force.
            LifecycleKind::Started
            | LifecycleKind::Renewed { .. }
            | LifecycleKind::Recovered
            | LifecycleKind::OneTimePurchase { .. }
            | LifecycleKind::TemporaryGrant { .. } => Some(Status::Active),

            // Rule 4: flags on the subscription, no status change.
            LifecycleKind::CancellationScheduled { .. }
            | LifecycleKind::Uncancelled
            | LifecycleKind::PauseScheduled { .. }
            | LifecycleKind::ProductChanged { .. } => stay(status, terminal),

            // Rule 5: the sample is RevenueCat with no grace period.
            LifecycleKind::BillingIssue { .. } => {
                if status == Status::Incomplete {
                    Some(Status::Incomplete)
                } else {
                    stay(Status::InBillingRetry, terminal)
                }
            }

            // Rule 6.
            LifecycleKind::Paused => stay(Status::Paused, terminal),
            LifecycleKind::Resumed => {
                if status == Status::Paused {
                    Some(Status::Active)
                } else {
                    stay(status, terminal)
                }
            }

            // Rule 7: revocation is sticky, expiration never revives it.
            LifecycleKind::Expired { .. } => Some(if status == Status::Revoked {
                Status::Revoked
            } else {
                Status::Expired
            }),

            // Rule 8: an extension revives an expired subscription.
            LifecycleKind::Extended { .. } => {
                if status == Status::Revoked {
                    None
                } else if status == Status::Expired {
                    Some(Status::Active)
                } else {
                    Some(status)
                }
            }

            // Rule 9, and the loss half of rule 10: the money is gone for
            // good.
            LifecycleKind::Refunded { .. }
            | LifecycleKind::DisputeClosed {
                outcome: DisputeOutcome::Lost,
            } => Some(Status::Revoked),
            LifecycleKind::RefundReversed
            | LifecycleKind::DisputeClosed {
                outcome: DisputeOutcome::Won,
            }
            | LifecycleKind::DisputeFundsReinstated => Some(restored(status)),

            // Rules 10 and 11: events that leave the status alone.
            LifecycleKind::DisputeOpened
            | LifecycleKind::DisputeUpdated
            | LifecycleKind::DisputeFundsWithdrawn
            | LifecycleKind::DisputeClosed {
                outcome: DisputeOutcome::Other(_),
            }
            | LifecycleKind::Transferred { .. }
            | LifecycleKind::PriceChangeConsentRequired
            | LifecycleKind::PriceChangeConsentApproved
            | LifecycleKind::InvoiceIssued
            | LifecycleKind::Test
            | LifecycleKind::Unrecognized => Some(status),
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one row per status × kind, by design
    fn the_table_holds_for_every_status_and_kind() {
        let prior_at = instant("2026-05-01T00:00:00Z");
        let event_at = instant("2026-05-02T00:00:00Z");
        let mut samples = kind_samples();
        // A second sample for the one kind whose outcome depends on its
        // payload: a lost dispute revokes.
        samples.push((
            "DisputeClosed { outcome: Lost }",
            LifecycleKind::DisputeClosed {
                outcome: DisputeOutcome::Lost,
            },
        ));
        for status in all_statuses() {
            let prior = representative(status, prior_at);
            for (name, kind) in &samples {
                let event = rc_event((*kind).clone(), event_at);
                let outcome = transition(Some(&prior), &event, &LifecyclePolicy::default());
                match expected(status, kind) {
                    None => assert!(
                        matches!(outcome, Transition::Invalid(_)),
                        "{status:?} + {name}: expected Invalid, got {outcome:?}"
                    ),
                    Some(want) => match outcome {
                        Transition::Apply(next) => {
                            assert_eq!(next.status, want, "{status:?} + {name}");
                            assert_eq!(
                                next.revoked,
                                next.status == Status::Revoked,
                                "the revoked invariant after {status:?} + {name}"
                            );
                        }
                        other => panic!("{status:?} + {name}: expected Apply, got {other:?}"),
                    },
                }
            }
        }
    }

    #[test]
    fn trial_start_and_conversion() {
        let trial = trial_started(instant(TRIAL_END));
        assert_eq!(trial.status, Status::Active);
        assert_eq!(trial.period_type, PeriodType::Trial);
        assert!(trial.renews);
        assert_eq!(trial.access_until, Some(instant(TRIAL_END)));
        assert!(gives_access(&trial, instant(START)));

        let mut renewed = rc_event(
            LifecycleKind::Renewed {
                trial_conversion: true,
            },
            instant(TRIAL_END),
        );
        renewed.period = Some(period(instant(TRIAL_END), instant(PAID_END)));
        let paid = step(&trial, &renewed);
        assert_eq!(paid.status, Status::Active);
        assert_eq!(paid.period_type, PeriodType::Normal);
        assert_eq!(paid.access_until, Some(instant(PAID_END)));
        assert!(gives_access(&paid, instant(TRIAL_END)));
    }

    #[test]
    fn cancel_during_trial_keeps_access_to_the_period_end() {
        let trial = trial_started(instant(TRIAL_END));
        let cancel = rc_event(
            LifecycleKind::CancellationScheduled {
                reason: CancelReason::Unsubscribe,
            },
            instant("2026-05-10T00:00:00Z"),
        );
        let cancelled = step(&trial, &cancel);
        assert_eq!(cancelled.status, Status::Active);
        assert!(!cancelled.renews);
        assert_eq!(cancelled.access_until, Some(instant(TRIAL_END)));
        assert!(gives_access(&cancelled, instant("2026-05-14T23:59:59Z")));
        assert!(!gives_access(&cancelled, instant(TRIAL_END)));

        let expired = rc_event(
            LifecycleKind::Expired {
                reason: ExpirationReason::Unsubscribe,
            },
            instant(TRIAL_END),
        );
        let ended = step(&cancelled, &expired);
        assert_eq!(ended.status, Status::Expired);
        assert!(!ended.renews);
        assert!(!gives_access(&ended, instant(TRIAL_END)));
    }

    #[test]
    fn billing_issues_follow_the_grace_and_the_policy() {
        let active = representative(Status::Active, instant(START));
        let issue_at = instant("2026-05-05T00:00:00Z");
        let grace_at = instant("2026-05-10T00:00:00Z");

        // A provider that reports a grace period: access lasts until it ends.
        let issue = rc_event(
            LifecycleKind::BillingIssue {
                grace_until: Some(grace_at),
            },
            issue_at,
        );
        let in_grace = step(&active, &issue);
        assert_eq!(in_grace.status, Status::InGracePeriod);
        assert_eq!(in_grace.access_until, Some(grace_at));
        assert!(gives_access(&in_grace, instant("2026-05-09T23:59:59Z")));
        assert!(!gives_access(&in_grace, grace_at));

        // RevenueCat with no grace period: billing retry, no access, the
        // period's own end kept as `access_until`.
        let issue = rc_event(LifecycleKind::BillingIssue { grace_until: None }, issue_at);
        let retry = step(&active, &issue);
        assert_eq!(retry.status, Status::InBillingRetry);
        assert_eq!(retry.access_until, active.access_until);
        assert!(!gives_access(&retry, issue_at));

        // Stripe's past-due defaults to grace; the policy knob makes it a
        // billing retry instead.
        let mut stripe_issue =
            rc_event(LifecycleKind::BillingIssue { grace_until: None }, issue_at);
        stripe_issue.provider = Provider::Stripe;
        assert_eq!(step(&active, &stripe_issue).status, Status::InGracePeriod);

        let retry_policy = LifecyclePolicy {
            stripe_past_due: PastDuePolicy::InBillingRetry,
            ..LifecyclePolicy::default()
        };
        let next = applied(transition(Some(&active), &stripe_issue, &retry_policy));
        assert_eq!(next.status, Status::InBillingRetry);
        assert!(!gives_access(&next, issue_at));
    }

    #[test]
    fn a_refund_applies_before_or_after_a_renewal() {
        let renewed_at = instant("2026-05-02T00:00:00Z");
        let mut renewed = rc_event(
            LifecycleKind::Renewed {
                trial_conversion: false,
            },
            renewed_at,
        );
        renewed.period = Some(period(renewed_at, instant("2026-06-02T00:00:00Z")));
        let active = applied(transition(None, &renewed, &LifecyclePolicy::default()));
        assert!(gives_access(&active, renewed_at));

        // Older than the renewal that arrived first, but a refund only ever
        // takes access away, so it still applies — and `last_event_at` must
        // not rewind to it.
        let revoked = step(&active, &whole_refund(instant(START)));
        assert_eq!(revoked.status, Status::Revoked);
        assert!(revoked.revoked);
        assert!(!revoked.renews);
        assert!(!gives_access(&revoked, renewed_at));
        assert_eq!(revoked.last_event_at, renewed_at);

        // Newer than the renewal, it revokes just the same.
        let later = step(&active, &whole_refund(instant("2026-05-03T00:00:00Z")));
        assert_eq!(later.status, Status::Revoked);
        assert_eq!(later.last_event_at, instant("2026-05-03T00:00:00Z"));
    }

    #[test]
    fn a_stale_renewal_after_an_expiration_is_ignored() {
        let expired = SubscriptionState {
            status: Status::Expired,
            renews: false,
            ..representative(Status::Active, instant("2026-05-02T00:00:00Z"))
        };
        let older = rc_event(
            LifecycleKind::Renewed {
                trial_conversion: false,
            },
            instant(START),
        );
        assert_eq!(
            transition(Some(&expired), &older, &LifecyclePolicy::default()),
            Transition::IgnoreStale
        );
    }

    #[test]
    fn disputes_revoke_on_loss_and_restore_on_a_win() {
        let active = representative(Status::Active, instant(START));

        let opened = rc_event(
            LifecycleKind::DisputeOpened,
            instant("2026-05-05T00:00:00Z"),
        );
        let flagged = step(&active, &opened);
        assert_eq!(flagged.status, Status::Active);
        assert!(gives_access(&flagged, instant("2026-05-05T00:00:00Z")));

        let lost = rc_event(
            LifecycleKind::DisputeClosed {
                outcome: DisputeOutcome::Lost,
            },
            instant("2026-05-06T00:00:00Z"),
        );
        let revoked = step(&flagged, &lost);
        assert_eq!(revoked.status, Status::Revoked);
        assert!(!gives_access(&revoked, instant("2026-05-06T00:00:00Z")));

        let won = rc_event(
            LifecycleKind::DisputeClosed {
                outcome: DisputeOutcome::Won,
            },
            instant("2026-05-07T00:00:00Z"),
        );
        let restored_state = step(&revoked, &won);
        assert_eq!(restored_state.status, Status::Active);
        assert!(!restored_state.revoked);
        assert!(gives_access(
            &restored_state,
            instant("2026-05-07T00:00:00Z")
        ));
    }

    #[test]
    fn product_change_and_activation_touch_pending_product() {
        let active = representative(Status::Active, instant(START));
        let at = instant("2026-05-02T00:00:00Z");
        let change = |to_product: &str, effective| {
            rc_event(
                LifecycleKind::ProductChanged {
                    to_product: to_product.to_owned(),
                    effective,
                },
                at,
            )
        };

        let scheduled = step(&active, &change("pro_annual", ChangeTiming::NextRenewal));
        assert_eq!(scheduled.pending_product.as_deref(), Some("pro_annual"));

        // An immediate change takes effect now, so nothing is left pending.
        let switched = step(&scheduled, &change("pro_m", ChangeTiming::Immediate));
        assert_eq!(switched.pending_product, None);

        // Nor does the next payment, which lands on the new product.
        let mut renewed = rc_event(
            LifecycleKind::Renewed {
                trial_conversion: false,
            },
            at,
        );
        renewed.period = Some(period(at, instant(PAID_END)));
        assert_eq!(step(&scheduled, &renewed).pending_product, None);
    }

    #[test]
    fn the_policy_knobs_move_the_outcome() {
        let active = representative(Status::Active, instant(START));
        let at = instant("2026-05-05T00:00:00Z");
        let opened = rc_event(LifecycleKind::DisputeOpened, at);
        let lost = rc_event(
            LifecycleKind::DisputeClosed {
                outcome: DisputeOutcome::Lost,
            },
            at,
        );
        let partial = rc_event(
            LifecycleKind::Refunded {
                partial: true,
                origin: RefundOrigin::Merchant,
            },
            at,
        );
        let issue = rc_event(LifecycleKind::BillingIssue { grace_until: None }, at);

        let open_revokes = LifecyclePolicy {
            dispute: DisputePolicy::RevokeOnOpen,
            ..LifecyclePolicy::default()
        };
        assert_eq!(
            applied(transition(Some(&active), &opened, &open_revokes)).status,
            Status::Revoked
        );

        let ignore = LifecyclePolicy {
            dispute: DisputePolicy::Ignore,
            ..LifecyclePolicy::default()
        };
        assert_eq!(
            applied(transition(Some(&active), &lost, &ignore)).status,
            Status::Active
        );

        // A partial refund never revokes, and a whole one does not when the
        // policy says so.
        assert_eq!(step(&active, &partial).status, Status::Active);
        let keeps = LifecyclePolicy {
            refund_revokes: false,
            ..LifecyclePolicy::default()
        };
        assert_eq!(
            applied(transition(Some(&active), &whole_refund(at), &keeps)).status,
            Status::Active
        );

        // A billing retry that still grants access.
        let grants = LifecyclePolicy {
            billing_retry_grants_access: true,
            ..LifecyclePolicy::default()
        };
        let granted = applied(transition(Some(&active), &issue, &grants));
        assert_eq!(granted.status, Status::InGracePeriod);
        assert!(gives_access(&granted, at));
    }

    #[test]
    fn a_revoked_state_never_grants_access() {
        let past = instant("2026-01-01T00:00:00Z");
        let now = instant("2026-06-01T00:00:00Z");
        let future = instant("2027-01-01T00:00:00Z");
        for status in all_statuses() {
            for access_until in [None, Some(past), Some(future)] {
                for instant_at in [past, now, future] {
                    let state = SubscriptionState {
                        revoked: true,
                        access_until,
                        ..representative(status, now)
                    };
                    assert!(
                        !gives_access(&state, instant_at),
                        "{status:?} with access until {access_until:?} at {instant_at:?}"
                    );
                }
            }
        }
    }
}
