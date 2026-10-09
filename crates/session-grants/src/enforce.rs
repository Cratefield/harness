//! The server-side gate. Before the server takes *any* action under a
//! grant, this decides whether the grant allows it: status first (the
//! off-chain kill switches), then window, then chain, then the per-call
//! policies, then the spend caps and the rate limit. Nothing in here
//! talks to a chain — it is the mirror the server checks against, so an
//! out-of-limit action is refused before a port call is ever built.

use time::OffsetDateTime;

use cratefield_core::Clock;

use crate::grant::{GrantScope, GrantStatus, IntendedAction, NativeLimit, TokenLimit, Usage};
use crate::store::GrantStore;
use crate::types::Pubkey;

/// The outcome of one authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "an ignored decision acts by default"]
pub enum Decision {
    /// The grant allows the action; the caller has recorded its usage.
    Allow,
    /// The grant refuses the action, for the stated reason.
    Deny(DenyReason),
}

impl Decision {
    /// Whether the action may proceed.
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// Why the server refuses to act.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DenyReason {
    /// No grant under that id.
    #[error("no grant {0:?}")]
    UnknownGrant(String),
    /// Denied off chain. Checked before everything else: the deny takes
    /// effect immediately, whether or not the on-chain permission has
    /// been revoked yet.
    #[error("the grant is denied off chain; the owner revoked the server's authority")]
    Denied,
    /// Paused off chain, resumable by the owner.
    #[error("the grant is paused")]
    Paused,
    /// The owner-signed on-chain revoke confirmed.
    #[error("the grant is revoked on chain")]
    Revoked,
    /// Outside the validity window.
    #[error("the grant is not valid until {at}")]
    NotYetValid {
        /// The instant the grant becomes valid.
        at: OffsetDateTime,
    },
    /// The window has closed. The on-chain permission may still exist —
    /// the owner signs the revoke to free it — but the server stops here.
    #[error("the grant expired at {at}")]
    Expired {
        /// The instant the grant expired.
        at: OffsetDateTime,
    },
    /// The action targets a different chain than the grant lives on.
    #[error("the grant lives on another chain than the action targets")]
    ChainMismatch,
    /// No call policy matches the target and selector, or an argument
    /// condition failed.
    #[error("no call policy allows {target} {selector}")]
    CallNotAllowed {
        /// The contract the action wanted to call.
        target: String,
        /// The selector the action wanted to call.
        selector: String,
    },
    /// The transfer's destination is not in the spending limit's
    /// allowlist (Squads).
    #[error("the destination {0:?} is not in the spending limit")]
    DestinationNotAllowed(String),
    /// The call carries more native value than its policy allows.
    #[error("the call carries {requested} wei, over the {cap} wei per-call cap")]
    CallValueOverCap {
        /// The requested amount.
        requested: u128,
        /// The per-call cap.
        cap: u128,
    },
    /// The action would push the native spend over a recurring limit.
    #[error("the native spend would pass its recurring limit: {requested} of {cap}")]
    NativeOverCap {
        /// The amount this action (or the window total with it) reaches.
        requested: u128,
        /// The recurring cap.
        cap: u128,
    },
    /// The action would push the token spend over a recurring limit.
    #[error("the token spend would pass its recurring limit: {requested} of {cap}")]
    TokenOverCap {
        /// The amount this action (or the window total with it) reaches.
        requested: u128,
        /// The recurring cap.
        cap: u128,
    },
    /// More actions this period than the rate limit allows.
    #[error("the rate limit allows {max_calls} calls per {period_secs} s")]
    RateLimited {
        /// The limit's call count.
        max_calls: u32,
        /// The limit's period.
        period_secs: u64,
    },
}

/// Why the enforcer itself failed — a refusal is a [`Decision`], this is
/// an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EnforceError {
    /// The store under the enforcer failed.
    #[error("the grant store failed: {0}")]
    Store(#[from] crate::store::StoreError),
    /// The grant's spec no longer validates — it was stored before this
    /// crate enforced its invariants.
    #[error("the stored grant spec is invalid: {0}")]
    Spec(#[from] crate::grant::SpecError),
}

/// The enforcer over a store and a clock. It holds neither state nor
/// caches — every check reads the store, so a deny written by another
/// isolate is honored on the next action.
pub struct Enforcer<'a> {
    store: &'a dyn GrantStore,
    clock: &'a dyn Clock,
}

impl<'a> Enforcer<'a> {
    /// An enforcer reading `store`, answering "may I act now?" against
    /// `clock`.
    #[must_use]
    pub fn new(store: &'a dyn GrantStore, clock: &'a dyn Clock) -> Self {
        Self { store, clock }
    }

    /// Checks an action against the grant, without recording usage.
    ///
    /// # Errors
    /// [`EnforceError`] when the store or the stored spec fails — a
    /// refusal is a [`Decision::Deny`], not an error.
    pub async fn check(&self, id: &str, action: &IntendedAction) -> Result<Decision, EnforceError> {
        let Some(record) = self.store.get(id).await? else {
            return Ok(Decision::Deny(DenyReason::UnknownGrant(id.to_owned())));
        };
        // A spec stored before validation was enforced must not be
        // honored; and a spec that fails now gets the same refusals a
        // fresh one would.
        record.spec.validate()?;
        let now = self.clock.now();

        // The off-chain layer first, and ahead of the window: a deny or a
        // pause stops the server immediately, independently of what is
        // still installed on chain.
        match record.status {
            GrantStatus::Denied => return Ok(Decision::Deny(DenyReason::Denied)),
            GrantStatus::Paused => return Ok(Decision::Deny(DenyReason::Paused)),
            GrantStatus::Revoked => return Ok(Decision::Deny(DenyReason::Revoked)),
            GrantStatus::Active => {}
        }

        if !record.spec.window.contains(now) {
            return Ok(Decision::Deny(if now < record.spec.window.valid_after {
                DenyReason::NotYetValid {
                    at: record.spec.window.valid_after,
                }
            } else {
                DenyReason::Expired {
                    at: record.spec.window.valid_until,
                }
            }));
        }

        match (&record.spec.scope, action) {
            (GrantScope::EvmKernel(grant), IntendedAction::EvmCall { .. }) => {
                if let Some(deny) = self.check_evm(id, grant, action, now).await? {
                    return Ok(Decision::Deny(deny));
                }
            }
            (GrantScope::SolanaSwig(grant), IntendedAction::SolanaTransfer { .. }) => {
                if let Some(deny) = self.check_swig(id, grant, action, now).await? {
                    return Ok(Decision::Deny(deny));
                }
            }
            (GrantScope::SolanaSquads(grant), IntendedAction::SolanaTransfer { .. }) => {
                if let Some(deny) = self.check_squads(id, grant, action, now).await? {
                    return Ok(Decision::Deny(deny));
                }
            }
            // The scope and the action name different chains: an EVM
            // action under a Solana grant or the reverse is a server bug,
            // refused rather than routed.
            _ => return Ok(Decision::Deny(DenyReason::ChainMismatch)),
        }

        if let Some(rate) = record.spec.rate_limit {
            let usage = self
                .store
                .usage_since(id, window_start(now, rate.period_secs))
                .await?;
            if usage.calls >= u64::from(rate.max_calls) {
                return Ok(Decision::Deny(DenyReason::RateLimited {
                    max_calls: rate.max_calls,
                    period_secs: rate.period_secs,
                }));
            }
        }

        Ok(Decision::Allow)
    }

    /// Checks an EVM action against the call policies and the caps;
    /// `Some` is the reason to refuse.
    async fn check_evm(
        &self,
        id: &str,
        grant: &crate::grant::EvmGrant,
        action: &IntendedAction,
        now: OffsetDateTime,
    ) -> Result<Option<DenyReason>, EnforceError> {
        let IntendedAction::EvmCall {
            chain_id,
            target,
            selector,
            args,
            value,
            token,
        } = action
        else {
            return Ok(None);
        };
        if *chain_id != grant.chain_id {
            return Ok(Some(DenyReason::ChainMismatch));
        }
        let policy = grant.calls.iter().find(|policy| {
            policy.target == *target
                && policy.selector == *selector
                && policy.args.iter().all(|cond| cond.matches(args))
        });
        let Some(policy) = policy else {
            return Ok(Some(DenyReason::CallNotAllowed {
                target: target.to_string(),
                selector: selector.to_string(),
            }));
        };
        if let Some(cap) = policy.value_cap
            && *value > cap
        {
            return Ok(Some(DenyReason::CallValueOverCap {
                requested: *value,
                cap,
            }));
        }
        if let Some((token, amount)) = token
            && let Some(limit) = &grant.token_limit
            && let Some(deny) = self
                .check_token(id, limit, token.as_str(), None, *amount, now)
                .await?
        {
            return Ok(Some(deny));
        }
        if let Some(limit) = &grant.value_limit
            && let Some(deny) = self.check_native(id, limit, None, *value, now).await?
        {
            return Ok(Some(deny));
        }
        Ok(None)
    }

    /// Checks a Swig action against the program scopes and the limits;
    /// `Some` is the reason to refuse.
    async fn check_swig(
        &self,
        id: &str,
        grant: &crate::grant::SwigGrant,
        action: &IntendedAction,
        now: OffsetDateTime,
    ) -> Result<Option<DenyReason>, EnforceError> {
        let IntendedAction::SolanaTransfer {
            cluster,
            program,
            lamports,
            destination,
            token,
        } = action
        else {
            return Ok(None);
        };
        if *cluster != grant.cluster {
            return Ok(Some(DenyReason::ChainMismatch));
        }
        if !grant.programs.iter().any(|scope| &scope.program == program) {
            return Ok(Some(DenyReason::CallNotAllowed {
                target: program.to_string(),
                selector: "solana instruction".to_owned(),
            }));
        }
        if let Some((mint, amount)) = token
            && let Some(limit) = grant
                .token_limits
                .iter()
                .find(|limit| limit.token == mint.as_str())
            && let Some(deny) = self
                .check_token(id, limit, mint.as_str(), Some(destination), *amount, now)
                .await?
        {
            return Ok(Some(deny));
        }
        if let Some(limit) = &grant.sol_limit
            && let Some(deny) = self
                .check_native(id, limit, Some(destination), *lamports, now)
                .await?
        {
            return Ok(Some(deny));
        }
        Ok(None)
    }

    /// Checks a Squads action against the vault's spending limits;
    /// `Some` is the reason to refuse.
    async fn check_squads(
        &self,
        id: &str,
        grant: &crate::grant::SquadsGrant,
        action: &IntendedAction,
        now: OffsetDateTime,
    ) -> Result<Option<DenyReason>, EnforceError> {
        let IntendedAction::SolanaTransfer {
            cluster,
            lamports,
            destination,
            token,
            ..
        } = action
        else {
            return Ok(None);
        };
        if *cluster != grant.cluster {
            return Ok(Some(DenyReason::ChainMismatch));
        }
        // The spending limit that covers this movement: the native one,
        // or the mint's.
        let (limit, amount, used) = match token {
            None => match grant.limits.iter().find(|limit| limit.mint.is_none()) {
                None => {
                    return Ok(Some(DenyReason::CallNotAllowed {
                        target: "vault".to_owned(),
                        selector: "native transfer".to_owned(),
                    }));
                }
                Some(limit) => {
                    let spent = self
                        .store
                        .usage_since(id, window_start(now, limit.period.period_secs()))
                        .await?;
                    (limit, *lamports, spent.native_total())
                }
            },
            Some((mint, amount)) => {
                match grant.limits.iter().find(|limit| {
                    limit.mint.as_ref().map(crate::types::Pubkey::as_str) == Some(mint.as_str())
                }) {
                    None => {
                        return Ok(Some(DenyReason::CallNotAllowed {
                            target: "vault".to_owned(),
                            selector: format!("transfer of {mint}"),
                        }));
                    }
                    Some(limit) => {
                        let spent = self
                            .store
                            .usage_since(id, window_start(now, limit.period.period_secs()))
                            .await?;
                        (limit, *amount, spent.token_total(mint.as_str()))
                    }
                }
            }
        };
        if !limit.destinations.is_empty()
            && !limit
                .destinations
                .iter()
                .any(|allowed| allowed == destination)
        {
            return Ok(Some(DenyReason::DestinationNotAllowed(
                destination.to_string(),
            )));
        }
        if used + amount > limit.amount {
            return Ok(Some(match token {
                // The leg that passed its cap names its own unit.
                None => DenyReason::NativeOverCap {
                    requested: used + amount,
                    cap: limit.amount,
                },
                Some(_) => DenyReason::TokenOverCap {
                    requested: used + amount,
                    cap: limit.amount,
                },
            }));
        }
        Ok(None)
    }

    /// Checks the native recurring and per-destination limits. `None` as
    /// the destination is the EVM path, which has no per-destination
    /// notion.
    async fn check_native(
        &self,
        id: &str,
        limit: &NativeLimit,
        destination: Option<&Pubkey>,
        amount: u128,
        now: OffsetDateTime,
    ) -> Result<Option<DenyReason>, EnforceError> {
        let spent = self
            .store
            .usage_since(id, window_start(now, limit.recurring.period_secs))
            .await?;
        if spent.native_total() + amount > limit.recurring.amount {
            return Ok(Some(DenyReason::NativeOverCap {
                requested: spent.native_total() + amount,
                cap: limit.recurring.amount,
            }));
        }
        if let (Some(destination), Some(per)) = (destination, &limit.per_destination) {
            let per_spent = self
                .store
                .usage_since(id, window_start(now, per.period_secs))
                .await?;
            let per_used = per_spent.native_to(destination.as_str());
            if per_used + amount > per.amount {
                return Ok(Some(DenyReason::NativeOverCap {
                    requested: per_used + amount,
                    cap: per.amount,
                }));
            }
        }
        Ok(None)
    }

    /// Checks the token recurring and per-destination limits.
    async fn check_token(
        &self,
        id: &str,
        limit: &TokenLimit,
        token: &str,
        destination: Option<&Pubkey>,
        amount: u128,
        now: OffsetDateTime,
    ) -> Result<Option<DenyReason>, EnforceError> {
        let spent = self
            .store
            .usage_since(id, window_start(now, limit.recurring.period_secs))
            .await?;
        if spent.token_total(token) + amount > limit.recurring.amount {
            return Ok(Some(DenyReason::TokenOverCap {
                requested: spent.token_total(token) + amount,
                cap: limit.recurring.amount,
            }));
        }
        if let (Some(destination), Some(per)) = (destination, &limit.per_destination) {
            let per_spent = self
                .store
                .usage_since(id, window_start(now, per.period_secs))
                .await?;
            let per_used = per_spent.token_to(token, destination.as_str());
            if per_used + amount > per.amount {
                return Ok(Some(DenyReason::TokenOverCap {
                    requested: per_used + amount,
                    cap: per.amount,
                }));
            }
        }
        Ok(None)
    }

    /// Checks the action and, on [`Decision::Allow`], records the usage
    /// it generates — the check plus the ledger write every server
    /// action goes through.
    ///
    /// # Errors
    /// [`EnforceError`] when the store or the stored spec fails.
    pub async fn authorize(
        &self,
        id: &str,
        action: &IntendedAction,
    ) -> Result<Decision, EnforceError> {
        let decision = self.check(id, action).await?;
        if decision.is_allow() {
            self.store
                .record_usage(id, &Usage::of(action), self.clock.now())
                .await?;
        }
        Ok(decision)
    }
}

/// The start of the fixed window `period_secs` long that `at` falls in,
/// anchored to the Unix epoch.
#[must_use]
pub fn window_start(at: OffsetDateTime, period_secs: u64) -> OffsetDateTime {
    let Some(window_secs) = i64::try_from(period_secs).ok().filter(|secs| *secs > 0) else {
        return at;
    };
    let epoch_secs = (at - OffsetDateTime::UNIX_EPOCH).whole_seconds();
    OffsetDateTime::UNIX_EPOCH
        + time::Duration::seconds(epoch_secs - epoch_secs.rem_euclid(window_secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_anchor_to_the_epoch() {
        let at = OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(3_600 * 5 + 61);
        assert_eq!(
            window_start(at, 3_600),
            OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(3_600 * 5)
        );
        assert_eq!(window_start(at, 0), at);
        assert_eq!(window_start(at, u64::MAX), at);
    }
}
