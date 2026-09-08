//! Scheduled work (issues #9, #10, #11, #12).
//!
//! `Module::scheduled` is handed the cron expression, so one module can serve
//! two cadences. A venture wires both:
//!
//! | Cron | Work |
//! |---|---|
//! | `*/5 * * * *` | publish due posts, confirm publish-requested posts, poll assets |
//! | `0 3 * * *` | refresh tokens, warn about expiry, sync the page directory |
//!
//! Token upkeep runs on **both**, cheaply: it reads one row and only calls
//! LinkedIn when a refresh is actually due. That way a venture that wires only
//! the frequent trigger still keeps its connection alive.

use cratefield_core::{AnyError, ModuleContext};

use crate::handlers::{self, Settings};
use crate::{images, pages, posts, store, tokens};

/// The publisher cadence a venture should configure. `scheduled_at` is
/// honoured to within this interval.
pub const CRON_PUBLISHER_HINT: &str = "*/5 * * * *";

/// The daily cadence: token refresh, expiry warnings, directory sync.
pub const CRON_DAILY_HINT: &str = "0 3 * * *";

/// Whether this trigger is the daily one. A cron whose hour field is not `*`
/// runs at most once a day; anything else is treated as the publisher.
fn is_daily(cron: &str) -> bool {
    cron.split_whitespace()
        .nth(1)
        .is_some_and(|hour| hour != "*" && !hour.contains('/'))
}

pub(crate) async fn run(ctx: &ModuleContext, base: &Settings, cron: &str) -> Result<(), AnyError> {
    let settings = handlers::settings_of(ctx, base);
    let Some(scope) = handlers::cron_scope(ctx, cron) else {
        tracing::warn!("the linkedin module has no Defer port; skipping scheduled work");
        return Ok(());
    };

    // Cheap on every trigger, and the only thing standing between a
    // single-cron deployment and an expired token.
    tokens::maintain(ctx, &settings, &scope).await;

    if is_daily(cron) {
        daily(ctx, &settings, &scope).await;
    } else {
        publisher(ctx, &settings, &scope).await;
    }
    Ok(())
}

async fn publisher(ctx: &ModuleContext, settings: &Settings, scope: &cratefield_core::Scope) {
    // Media first: a post whose image settled during this very pass should
    // go out now rather than wait a whole cycle for the next one.
    let assets = images::poll_in_flight(ctx, settings, scope).await;
    let published = posts::publish_due(ctx, settings, scope).await;
    let confirmed = posts::confirm_pending(ctx, settings, scope).await;
    if published + confirmed + assets > 0 {
        tracing::info!(
            published,
            confirmed,
            assets,
            "linkedin publisher pass finished"
        );
    }
}

async fn daily(ctx: &ModuleContext, settings: &Settings, scope: &cratefield_core::Scope) {
    if let Ok(db) = handlers::db(ctx)
        && let Ok(clock) = handlers::clock(ctx)
    {
        let now = store::now_iso(clock);
        match store::purge_expired_states(db, &now).await {
            Ok(purged) if purged > 0 => tracing::info!(purged, "purged expired connect states"),
            Ok(_) => {}
            Err(error) => tracing::warn!(error = %error, "could not purge connect states"),
        }
    }

    match pages::sync(ctx, settings, scope).await {
        Ok(outcome) => tracing::info!(
            pages = outcome.pages,
            showcases = outcome.showcases,
            revoked = outcome.revoked,
            "linkedin page directory synced"
        ),
        Err(trouble) => {
            tracing::warn!(trouble = ?trouble, "scheduled linkedin page sync did not run");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hour_field_tells_the_two_cadences_apart() {
        assert!(is_daily(CRON_DAILY_HINT));
        assert!(is_daily("30 4 * * *"));
        assert!(!is_daily(CRON_PUBLISHER_HINT));
        assert!(!is_daily("0 * * * *"));
        assert!(!is_daily("*/10 */2 * * *"));
        assert!(!is_daily(""));
    }
}
