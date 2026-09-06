//! In-process cron (issue #19): the native counterpart of a Worker's
//! `[triggers] crons`. Each expression in `CRONS` gets one tokio task
//! that sleeps to the next occurrence (UTC) and fans out to every
//! module's `scheduled(ctx, cron)` — exactly what
//! `factory0_runtime_cloudflare::serve_scheduled` does per trigger.
//!
//! Expressions are strictly **five-field** (minute hour day month
//! weekday), the form wrangler accepts; a six-field expression with
//! leading seconds is rejected rather than silently reinterpreted.
//! "Now" always comes through the clock (`tokio`/`time`), never
//! `chrono::Utc::now`: croner's chrono dependency arrives without its
//! `clock` feature, so that call could not compile here even by
//! accident (PR #50's lesson, applied structurally).

use std::sync::Arc;
use std::time::Duration;

use factory0_core::{Clock, Harness, Ports};
use tokio::task::JoinHandle;

/// A `CRONS` entry that could not be parsed.
#[derive(Debug, thiserror::Error)]
#[error("invalid cron expression {expr:?}: {reason}")]
pub struct CronError {
    expr: String,
    reason: String,
}

fn parse(expr: &str) -> Result<croner::Cron, CronError> {
    croner::parser::CronParser::builder()
        .seconds(croner::parser::Seconds::Disallowed)
        .build()
        .parse(expr)
        .map_err(|err| CronError {
            expr: expr.to_owned(),
            reason: err.to_string(),
        })
}

/// `time` → the datetime library croner computes with (chrono without
/// its `clock` feature — types only, never `now`).
fn to_cron_time(t: time::OffsetDateTime) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::from_timestamp(t.unix_timestamp(), t.nanosecond().rem_euclid(1_000_000_000))
}

/// One task per expression: sleep to the next occurrence, fan out,
/// repeat. Ticks are missed, not queued, while the fan-out runs — the
/// same posture a Worker has when a scheduled handler overruns its
/// schedule.
async fn run_expression(harness: Arc<Harness>, ports: Ports, expr: String, cron: croner::Cron) {
    loop {
        let now = to_cron_time(crate::ports::TokioClock.now());
        let Some(now) = now else {
            tracing::error!(cron = %expr, "clock out of range; cron task stopping");
            return;
        };
        let next = match cron.find_next_occurrence(&now, false) {
            Ok(next) => next,
            Err(err) => {
                tracing::error!(cron = %expr, error = %err, "cannot compute next tick; stopping");
                return;
            }
        };
        let until_next = (next - now)
            .to_std()
            .unwrap_or_else(|_| Duration::from_millis(1));
        tokio::time::sleep(until_next).await;
        fan_out(&harness, &ports, &expr).await;
    }
}

/// Fans one trigger out to every module's `scheduled(ctx, cron)` with a
/// per-tick context. Handler errors are logged and never fail the tick
/// (or the process) — the semantics of `serve_scheduled` on Workers.
/// Public so a venture that owns its scheduler (or its tests) can drive
/// the same fan-out itself.
pub async fn fan_out(harness: &Harness, ports: &Ports, cron: &str) {
    for module in harness.modules() {
        let module_ctx = harness.module_context(module.as_ref(), ports);
        if let Err(err) = module.scheduled(&module_ctx, cron).await {
            tracing::error!(
                module = module.name(),
                cron = %cron,
                error = %err,
                "scheduled module work failed",
            );
        }
    }
}

/// Validates every expression, then spawns one task per expression.
/// Validation happens before any task starts so an invalid `CRONS`
/// entry fails the process at startup (wrangler's deploy-time check),
/// never as a silently dead schedule.
///
/// # Errors
///
/// [`CronError`] naming the first expression that does not parse as a
/// five-field cron.
pub fn spawn_cron_scheduler(
    harness: &Arc<Harness>,
    ports: &Ports,
    expressions: &[String],
) -> Result<Vec<JoinHandle<()>>, CronError> {
    let parsed: Vec<(String, croner::Cron)> = expressions
        .iter()
        .map(|expr| parse(expr).map(|cron| (expr.clone(), cron)))
        .collect::<Result<_, _>>()?;
    Ok(parsed
        .into_iter()
        .map(|(expr, cron)| {
            tokio::spawn(run_expression(
                Arc::clone(harness),
                crate::runtime::clone_ports(ports),
                expr,
                cron,
            ))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_field_expressions_parse() {
        for expr in ["*/5 * * * *", "0 3 * * *", "30 4 1,15 8 *"] {
            parse(expr).unwrap_or_else(|err| panic!("{expr} should parse: {err}"));
        }
    }

    #[test]
    fn six_field_expressions_are_rejected_not_reinterpreted() {
        let err = parse("0 */5 * * * *").expect_err("leading seconds must be rejected");
        assert!(err.to_string().contains("0 */5 * * * *"));
    }

    #[test]
    fn plain_garbage_is_rejected() {
        assert!(parse("not a cron").is_err());
        assert!(parse("").is_err());
    }
}
