//! The durable challenge budget (issue #442).
//!
//! `login/options` is reachable by anyone, writes a challenge row on every
//! call, and answers differently for an address that has a passkey and one
//! that does not — which is inherent to the non-discoverable ceremony. The
//! optional `RateLimiter` was the only thing bounding that, so a
//! composition without one ran an unlimited enumeration oracle. The cap is
//! therefore a row in a table this module owns, the way the sign-in-link
//! send cooldown is (issue #133's shape): the database enforces it,
//! race-free without a transaction, and the optional limiter composes on
//! top of it as the configurable second layer rather than being the only
//! defence.
//!
//! One window is three statements, each decided by its affected-row count —
//! the guarded-update-then-insert primitive [`SendCooldown`] uses, with a
//! counter where the cooldown keeps a timestamp:
//!
//! 1. `UPDATE ... SET issued = issued + 1 WHERE subject = ? AND
//!    window_started_at >= ?cutoff AND issued < ?cap` — a caller counts
//!    itself into a window that is still open and under its cap.
//! 2. `UPDATE ... SET window_started_at = ?now, issued = 1 WHERE subject = ?
//!    AND window_started_at < ?cutoff` — exactly one caller opens the next
//!    window once the old one has passed.
//! 3. `INSERT ... ON CONFLICT DO NOTHING` — the first caller ever for a
//!    subject.
//!
//! Three zero answers means the budget is spent. The caller is refused
//! without a challenge row being written, which is what makes the cap bound
//! the write amplifier and not only the oracle.
//!
//! [`SendCooldown`]: cratefield_core::SendCooldown

use cratefield_core::{Database, DbError, ModuleContext, Statement};
use sea_query::{Alias, Expr, OnConflict, Query};

fn iden(name: &str) -> Alias {
    Alias::new(name)
}

/// The budget table, created by this module's migration. Must match the
/// `CREATE TABLE` in `migrations/sqlite/0001_challenge_budget.sql`.
pub(crate) const CHALLENGE_BUDGET_TABLE: &str = "auth_passkeys_challenge_budget";

/// How long a budget window is. A minute is longer than any legitimate
/// retry loop — a browser asks for options when the page loads, again when
/// the person picks an account, and again after a failed ceremony — and far
/// shorter than the wait an enumerator feels: at the caps below, sweeping
/// addresses from one client address crawls at thirty a minute instead of
/// running unbounded.
pub(crate) const CHALLENGE_BUDGET_WINDOW_SECS: i64 = 60;

/// Challenges one client address may ask for per window, per named account
/// address. Five covers a person and their two devices retrying within the
/// minute; sweeping needs thousands.
pub(crate) const CHALLENGE_BUDGET_PER_EMAIL: u32 = 5;

/// Challenges one client address may ask for per window, summed over every
/// address it names. Thirty absorbs an office or a VPN egress signing in at
/// once; it also bounds what a single address can learn per minute without
/// depending on the optional limiter.
pub(crate) const CHALLENGE_BUDGET_PER_IP: u32 = 30;

/// How long past its window a spent row is kept before the scheduled
/// handler deletes it. The window is what the cap needs; the extra day is
/// only so a refused client that retries sees its own refusal rather than a
/// fresh window, and so a sweep of probed addresses is not remembered much
/// longer than it took.
pub(crate) const CHALLENGE_BUDGET_RETENTION_SECS: i64 = 86_400;

/// The budget subjects one `login/options` call counts against, with each
/// subject's cap: always the client address — `ip:unknown` when no address
/// is visible, the same fallback `rate_limit_keys` uses — and the named
/// account address when the browser supplied one. Naming an address an
/// attacker invented is exactly the enumeration probe, so the budget does
/// not wait to find out whether the account exists.
pub(crate) fn subjects(ip: Option<&str>, email: Option<&str>) -> Vec<(String, u32)> {
    let mut subjects = vec![(
        format!("ip:{}", ip.unwrap_or("unknown")),
        CHALLENGE_BUDGET_PER_IP,
    )];
    if let Some(email) = email {
        subjects.push((format!("email:{email}"), CHALLENGE_BUDGET_PER_EMAIL));
    }
    subjects
}

/// Counts one challenge against `subject`. `true` when the caller may have
/// its challenge, `false` when every window still open for the subject is
/// at its cap.
///
/// # Errors
///
/// [`DbError`] when a statement fails.
pub(crate) async fn acquire(
    db: &dyn Database,
    subject: &str,
    now: &str,
    cutoff: &str,
    cap: u32,
) -> Result<bool, DbError> {
    // An open window with room left: one caller wins the increment. Two
    // concurrent callers at the last slot cannot both pass — the affected-row
    // count is recomputed against the committed row (the same race the
    // single-use challenge's conditional update settles).
    let mut count_one = Query::update();
    count_one
        .table(iden(CHALLENGE_BUDGET_TABLE))
        .value(iden("issued"), Expr::col(iden("issued")).add(1))
        .and_where(Expr::col(iden("subject")).eq(subject))
        .and_where(Expr::col(iden("window_started_at")).gte(cutoff))
        .and_where(Expr::col(iden("issued")).lt(i64::from(cap)));
    if db.execute(&Statement::render(&count_one)).await? == 1 {
        return Ok(true);
    }

    // The window has passed: one caller opens the next one, the rest count
    // into it through the statement above.
    let mut next_window = Query::update();
    next_window
        .table(iden(CHALLENGE_BUDGET_TABLE))
        .value(iden("window_started_at"), now)
        .value(iden("issued"), 1i64)
        .and_where(Expr::col(iden("subject")).eq(subject))
        .and_where(Expr::col(iden("window_started_at")).lt(cutoff));
    if db.execute(&Statement::render(&next_window)).await? == 1 {
        return Ok(true);
    }

    // The subject was never seen. Won by exactly one caller; the losers
    // conflict, report zero rows, and are refused — the same shape
    // `SendCooldown`'s update-then-insert takes.
    let mut first = Query::insert();
    first
        .into_table(iden(CHALLENGE_BUDGET_TABLE))
        .columns(["subject", "window_started_at", "issued"])
        .values_panic([
            subject.to_owned().into(),
            now.to_owned().into(),
            1i64.into(),
        ])
        .on_conflict(OnConflict::column(iden("subject")).do_nothing().to_owned());
    Ok(db.execute(&Statement::render(&first)).await? == 1)
}

/// Deletes rows whose window closed before `before`. Returns the number
/// removed; the module's scheduled handler calls this.
///
/// # Errors
///
/// [`DbError`] when the delete fails.
pub(crate) async fn prune(db: &dyn Database, before: &str) -> Result<u64, DbError> {
    let mut delete = Query::delete();
    delete
        .from_table(iden(CHALLENGE_BUDGET_TABLE))
        .and_where(Expr::col(iden("window_started_at")).lt(before));
    db.execute(&Statement::render(&delete)).await
}

/// The module's scheduled work: delete budget rows whose window closed more
/// than [`CHALLENGE_BUDGET_RETENTION_SECS`] ago, so the ledger holds the
/// recent past and nothing else.
pub(crate) async fn scheduled_prune(
    ctx: &ModuleContext,
    cron: &str,
) -> Result<(), cratefield_core::AnyError> {
    let (Some(db), Some(clock)) = (ctx.ports.db.clone(), ctx.ports.clock.clone()) else {
        return Ok(());
    };
    let before = crate::iso(
        clock
            .now()
            .saturating_sub(time::Duration::seconds(CHALLENGE_BUDGET_RETENTION_SECS)),
    );
    let removed = prune(&*db, &before)
        .await
        .map_err(|err| Box::new(err) as cratefield_core::AnyError)?;
    if removed > 0 {
        tracing::info!(cron, removed, "pruned spent challenge budget rows");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_call_counts_against_the_client_address_and_any_named_account() {
        let subjects = subjects(Some("203.0.113.7"), Some("nick@example.com"));
        assert_eq!(
            subjects,
            vec![
                ("ip:203.0.113.7".to_owned(), CHALLENGE_BUDGET_PER_IP),
                (
                    "email:nick@example.com".to_owned(),
                    CHALLENGE_BUDGET_PER_EMAIL
                ),
            ]
        );
    }

    #[test]
    fn a_call_without_a_visible_address_still_has_a_budget() {
        let subjects = subjects(None, None);
        assert_eq!(
            subjects,
            vec![("ip:unknown".to_owned(), CHALLENGE_BUDGET_PER_IP)]
        );
    }
}
