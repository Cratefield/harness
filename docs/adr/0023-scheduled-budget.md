# ADR 0023: A scheduled invocation runs on a cooperative budget

Status: accepted, 2026-09-27. Issue #537. Records how one cron tick's
limits are shared out to the modules it fans out to, and how a module
processes "the N most due items" without spending the whole invocation.

## Context

A scheduled event fans out to every module's `Module::scheduled`, serially,
in one invocation. On Workers that invocation has hard limits — most
sharply, the Free plan's 50 subrequests per invocation — and nothing in
the fan-out accounted for them. A module that polls a thousand
merchants' accounts per tick spends the invocation before the modules
after it have run one statement; their work is silently skipped, not
failed, and the tick answers success.

Two things were missing: a way for a module to know what it may spend
(this tick, of the invocation's total), and a primitive for the shape of
work that causes the problem — "check everything due, do as much as fits,
leave the rest for next tick".

## Decision

**The budget lives on `ModuleContext`, not on a new `scheduled`
parameter.** `ModuleContext` gains `scheduled: Arc<ScheduledBudget>` —
what this module may spend in this invocation. Adding a parameter to
`Module::scheduled` would break all twelve implementors at once for a
value most modules ignore; the field is unbounded outside `scheduled`,
so request handlers and tests that never set it see no limit that does
not apply to them. `ModuleContext` is a plain public struct, so the
addition is a compile break for struct-literal sites only — in this
repository the production one in `Harness::module_context` plus a
handful of test-support fixtures — and semver-minor for everyone who
builds contexts that way.

**The budget is cooperative, and the split rolls unspent share forward.**
The runtime never cancels a module: cancellation would make a timeout a
correctness hazard (half-finished work, lost leases) for a saving the
module can make itself. A module checks `try_spend(n)` around each unit
and stops when it answers `false`. The runtime divides the invocation's
`ScheduledLimits` (wall time, subrequest-shaped steps) across the modules
in order — the next module gets what is left over the modules still to
run — and after each module `settle` returns the unspent subrequests to
the pool. A module that spends nothing does not strand its share; a
module that overspends its own share has taken it from the modules behind
it, which the runtime names in a warning, and is why the free default
(`CLOUDFLARE_SCHEDULED_LIMITS`: 25 s wall, 40 subrequests — a
conservative fit under the Free plan's 50, not a plan constant) leaves
headroom. A paid-plan venture passes larger limits through
`serve_scheduled_with_limits`.

**"N due items per tick" is a drain over the outbox lease.** `Outbox`
gains `drain_within`, which claims up to the smaller of the caller's
limit and what the remaining subrequests can carry, and stops mid-batch
— releasing every claimed-but-unprocessed row by rescheduling it due
now, unleased — when the budget runs out. The outbox lease already
solves the two hard parts (exactly-one drainer per row; at-least-once
across a crash), so the budgeted drain adds only the stopping rule.

**`reschedule` is the per-item cursor.** A recurring poller is one
outbox row per thing to poll; its handler answers `Processed::NextAt`
with the row's next poll time, and `reschedule` moves the row there
**without counting an attempt** — a poll that ran is not a failed
delivery, so a slow-but-honest poller never trips bounded retry, while
`Processed::RetryAt` still counts when the work genuinely fails.

## Rejected

- **A `deadline`/`max_items` parameter on `Module::scheduled`.** Breaks
  every implementor, and hard-codes one limit shape into the trait
  signature instead of a value the runtime can vary.
- **Cancelling a module at its deadline.** `Defer` and leases make
  abandonment at-least-once already; aborting mid-handler adds a second,
  unknowable truncation point (post-lease, pre-commit) that no test can
  pin.
- **Even fixed shares, no roll-forward.** With N modules and a tight
  limit, the modules that need nothing would starve the one that polls.
- **Cloudflare Queues fan-out (see below).** Right shape, wrong issue.

## Consequences

A module that polls unboundedly ignores all of this and still overruns —
the budget is advice the runtime logs, not a wall. The system's
correctness does not depend on modules cooperating: uncooperative
modules degrade the modules after them exactly as before this ADR, but
the degradation is now visible per module in Workers Logs. A drain that
fails mid-batch keeps its leases (at-least-once, as ever); released rows
are due immediately, not after the lease lapses. The native runtime's
cron fan-out hands out unbounded budgets — same contract, no allowance
to spend against.

## Not done here: Cloudflare Queues fan-out

The durable answer to "more work than one invocation holds" is a Queue
producer port plus a `#[event(queue)]` consumer entry point in the
generated worker: each module enqueues its own per-item work and the
invocation returns, with Workers spreading the batches across
invocations under the platform's own limits. That is a port, a runtime
entry point, a manifest section and a pricing story — a follow-up issue,
not a rider on this one. `drain_within` is the interim: bounded,
durable, and slow on purpose.

## References

- [docs/MODULE-AUTHORING.md](../MODULE-AUTHORING.md): "Scheduled work
  (cron)" — what a module author does with the budget.
- ADR 0016: a dead letter is a module-owned table, not a terminal state
  on core's `Outbox` — same boundary: core owns the lease, the module
  owns the policy.
- `crates/core/src/scheduled.rs`, `crates/core/src/outbox.rs`,
  `crates/runtime-cloudflare/src/lib.rs` (`serve_scheduled_with_limits`),
  `crates/runtime-native/src/cron.rs` (`fan_out`).
