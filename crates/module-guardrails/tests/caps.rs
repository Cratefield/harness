//! Caps and slippage: the micro-USD windows, their boundaries, the ledger
//! that feeds them, and the ways a spend is refused for money reasons —
//! no caps, no price, no slippage bound, an unusable period.

mod support;

use cratefield_module_guardrails::{
    Action, CapExceeded, Caps, Chain, DenyReason, Policy, SYSTEM_PROGRAM, SolanaInstruction,
    SpendEntry, SpendLedger, SubjectPolicy, SwapQuote, TokenKey,
};
use time::{Duration, OffsetDateTime};

use support::*;

/// Caps over `token_key()`, with the windows a test does not care about
/// left effectively unbounded.
fn caps(per_action: u128, per_day: u128, per_period: u128, period: Duration) -> Caps {
    Caps::uniform(&token_key(), per_action, per_day, per_period, period, 200)
}

/// The policy the cap tests run: one contract, one destination, one
/// spender, and `caps` on the subject.
fn money_policy(caps: Caps) -> Policy {
    Policy::new()
        .chain(Chain::Evm { chain_id: 1 })
        .contract(ROUTER, &[SEL_APPROVE])
        .destination(RECIPIENT)
        .spender(SPENDER)
        .subject(SUBJECT, SubjectPolicy::new().caps(caps))
}

/// A rig whose simulator always reports a spend of `units` of `TOKEN` by
/// the acting address, with `TOKEN` priced at 1 micro-USD per unit, so
/// units are micro-USD.
fn spend_rig(caps: Caps, units: i128) -> Rig {
    let sim = ScriptedSimulator::new().respond(spend_report(TOKEN, -units));
    let prices = FixedPrices::new().price(token_key(), 1);
    rig_with(money_policy(caps), sim, prices)
}

/// Seeds the ledger with `micro_usd` already spent at `at`.
fn seed(rig: &Rig, micro_usd: u128, at: OffsetDateTime) {
    pollster::block_on(rig.ledger.record(
        SUBJECT,
        &[SpendEntry {
            key: token_key(),
            micro_usd,
        }],
        at,
    ))
    .expect("seed ledger");
}

#[test]
fn a_spend_within_every_cap_is_allowed_and_recorded() {
    let rig = spend_rig(
        caps(10_000_000, 12_000_000, 12_000_000, Duration::hours(24)),
        6_000_000,
    );
    allow(&rig.engine, approve(0));
    let recorded = rig.ledger.recorded();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].subject, SUBJECT);
    assert_eq!(recorded[0].entry.key, token_key());
    assert_eq!(recorded[0].entry.micro_usd, 6_000_000);
    assert_eq!(recorded[0].at, NOW);
}

#[test]
fn a_spend_over_the_per_action_cap_is_denied() {
    let rig = spend_rig(
        caps(5_999_999, 12_000_000, 12_000_000, Duration::hours(24)),
        6_000_000,
    );
    let denied = deny(&rig.engine, approve(0));
    assert_eq!(
        denied.reasons,
        vec![DenyReason::CapExceeded(CapExceeded::PerAction)]
    );
    // A deny records nothing.
    assert!(rig.ledger.recorded().is_empty());
}

#[test]
fn the_per_action_cap_boundary_is_inclusive() {
    // Exactly the cap is allowed; the deny side is one micro-USD over, in
    // `a_spend_over_the_per_action_cap_is_denied`.
    let rig = spend_rig(
        caps(6_000_000, 6_000_000, 6_000_000, Duration::hours(24)),
        6_000_000,
    );
    allow(&rig.engine, approve(0));
}

#[test]
fn the_day_cap_accumulates_across_allows() {
    let rig = spend_rig(
        caps(6_000_000, 12_000_000, u128::MAX, Duration::hours(24)),
        6_000_000,
    );
    // 6 m + 6 m == the 12 m day cap exactly: still allowed.
    allow(&rig.engine, approve(0));
    allow(&rig.engine, approve(0));
    // A third 6 m tips the day over — and only the day.
    let denied = deny(&rig.engine, approve(0));
    assert_eq!(
        denied.reasons,
        vec![DenyReason::CapExceeded(CapExceeded::PerDay)]
    );
    // Exactly the two allowed spends were recorded.
    assert_eq!(rig.ledger.recorded().len(), 2);
}

#[test]
fn yesterday_spend_is_outside_the_day_window() {
    let rig = spend_rig(
        caps(6_000_000, 12_000_000, u128::MAX, Duration::hours(24)),
        6_000_000,
    );
    // 12 m spent 25 h ago: the UTC-day window (from midnight) does not see
    // it, so today's first 6 m goes through.
    seed(&rig, 12_000_000, NOW - Duration::hours(25));
    allow(&rig.engine, approve(0));
}

#[test]
fn today_spend_counts_from_midnight_not_from_now() {
    let rig = spend_rig(
        caps(6_000_000, 12_000_000, u128::MAX, Duration::hours(24)),
        6_000_000,
    );
    // 6 m spent 3 h ago — still today, still inside any 24 h period.
    seed(&rig, 6_000_000, NOW - Duration::hours(3));
    // 6 m + 6 m == the day cap: allowed. A third would not be.
    allow(&rig.engine, approve(0));
    let denied = deny(&rig.engine, approve(0));
    assert_eq!(
        denied.reasons,
        vec![DenyReason::CapExceeded(CapExceeded::PerDay)]
    );
}

#[test]
fn the_period_window_sees_only_its_span() {
    // A 1 h period of 12 m: 6 m spent 2 h ago is outside it (though inside
    // the day), so two more 6 m spends fit the period but the third does
    // not — and only the period refuses it.
    let rig = spend_rig(
        caps(6_000_000, u128::MAX, 12_000_000, Duration::hours(1)),
        6_000_000,
    );
    seed(&rig, 6_000_000, NOW - Duration::hours(2));
    allow(&rig.engine, approve(0));
    allow(&rig.engine, approve(0));
    let denied = deny(&rig.engine, approve(0));
    assert_eq!(
        denied.reasons,
        vec![DenyReason::CapExceeded(CapExceeded::PerPeriod)]
    );
}

#[test]
fn a_token_with_no_cap_entry_has_a_cap_of_zero() {
    // The simulation spends a token no caps table names: default deny
    // reaches the caps, whatever `TOKEN` is trusted with.
    // Built at runtime so no long hex literal sits in this file; 40 hex
    // digits is a 20-byte address. The reference coerces to `&str` at the
    // call sites below.
    let other = &format!("0x{}", "9".repeat(40));
    let sim = ScriptedSimulator::new().respond(spend_report(other, -1));
    let prices = FixedPrices::new().price(
        TokenKey {
            chain: Chain::Evm { chain_id: 1 },
            token: other.to_owned(),
        },
        1,
    );
    let rig = rig_with(
        money_policy(caps(
            10_000_000,
            12_000_000,
            12_000_000,
            Duration::hours(24),
        )),
        sim,
        prices,
    );
    let denied = deny(&rig.engine, approve(0));
    // A cap of zero refuses in all three windows at once.
    assert_eq!(
        denied.reasons,
        vec![
            DenyReason::CapExceeded(CapExceeded::PerAction),
            DenyReason::CapExceeded(CapExceeded::PerDay),
            DenyReason::CapExceeded(CapExceeded::PerPeriod),
        ]
    );
}

#[test]
fn a_token_with_no_price_is_denied() {
    // The rig's price table is empty: the outflow cannot be valued.
    let sim = ScriptedSimulator::new().respond(spend_report(TOKEN, -1));
    let rig = rig_with(
        money_policy(caps(
            10_000_000,
            12_000_000,
            12_000_000,
            Duration::hours(24),
        )),
        sim,
        FixedPrices::new(),
    );
    let denied = deny(&rig.engine, approve(0));
    assert_eq!(denied.reasons, vec![DenyReason::NoPrice(token_key())]);
}

#[test]
fn a_subject_with_no_caps_is_denied() {
    let policy = Policy::new()
        .chain(Chain::Evm { chain_id: 1 })
        .contract(ROUTER, &[SEL_APPROVE])
        .spender(SPENDER);
    // No subject entry at all: no caps, no go.
    let rig = rig_with_policy(policy);
    let denied = deny(&rig.engine, approve(0));
    assert_eq!(denied.reasons, vec![DenyReason::NoCaps]);
}

#[test]
fn a_spend_on_solana_is_capped_by_its_own_token_key() {
    // The caps are per (chain, token): a mainnet-EVM price entry says
    // nothing about a Solana cluster's native coin, which then has a cap
    // of zero.
    let cluster = Chain::Solana {
        cluster: "mainnet-beta".to_owned(),
    };
    let sim = ScriptedSimulator::new().respond(spend_report("native", -1));
    let prices = FixedPrices::new().price(TokenKey::native(cluster.clone()), 1);
    let policy = Policy::new()
        .chain(cluster.clone())
        .program(SYSTEM_PROGRAM)
        .destination(RECIPIENT)
        .subject(
            SUBJECT,
            SubjectPolicy::new().caps(Caps::uniform(
                &token_key(), // the EVM token, not the Solana native coin
                10_000_000,
                12_000_000,
                12_000_000,
                Duration::hours(24),
                200,
            )),
        );
    let rig = rig_with(policy, sim, prices);
    let denied = deny(
        &rig.engine,
        request(Action::SolanaTx {
            cluster: "mainnet-beta".to_owned(),
            instructions: vec![SolanaInstruction {
                program_id: SYSTEM_PROGRAM.to_owned(),
                accounts: vec![FROM.to_owned(), RECIPIENT.to_owned()],
                // System `Transfer`: discriminant 2, then the lamports.
                data: vec![2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
            }],
        }),
    );
    // The Solana native coin has a cap of zero: refused in every window.
    assert_eq!(
        denied.reasons,
        vec![
            DenyReason::CapExceeded(CapExceeded::PerAction),
            DenyReason::CapExceeded(CapExceeded::PerDay),
            DenyReason::CapExceeded(CapExceeded::PerPeriod),
        ]
    );
}

#[test]
fn slippage_within_the_bound_is_allowed() {
    let rig = spend_rig(
        caps(10_000_000, 12_000_000, 12_000_000, Duration::hours(24)),
        6_000_000,
    );
    let mut req = approve(0);
    // (1_000_000 - 980_000) / 1_000_000 = 200 bps: exactly the bound.
    req.swap = Some(SwapQuote {
        quoted_out: 1_000_000,
        min_out: 980_000,
    });
    allow(&rig.engine, req);
}

#[test]
fn slippage_over_the_bound_is_denied() {
    let rig = spend_rig(
        caps(10_000_000, 12_000_000, 12_000_000, Duration::hours(24)),
        6_000_000,
    );
    let mut req = approve(0);
    // 300 bps of slippage against a 200 bps bound.
    req.swap = Some(SwapQuote {
        quoted_out: 1_000_000,
        min_out: 970_000,
    });
    let denied = deny(&rig.engine, req);
    assert_eq!(denied.reasons, vec![DenyReason::SlippageExceeded]);
}

#[test]
fn a_swap_shaped_action_without_a_quote_is_denied() {
    // The simulation shows the actor paying one token and receiving
    // another: a swap. With no SwapQuote there is no bound to compare, so
    // the action is refused rather than waved through unpriced.
    let sim = ScriptedSimulator::new().respond(report(
        vec![
            balance_change(FROM, TOKEN, -6_000_000),
            balance_change(FROM, STRANGER, 5_000_000),
        ],
        Vec::new(),
        Vec::new(),
    ));
    let rig = rig_with(
        money_policy(caps(
            10_000_000,
            12_000_000,
            12_000_000,
            Duration::hours(24),
        )),
        sim,
        FixedPrices::new().price(token_key(), 1),
    );
    let denied = deny(&rig.engine, approve(0));
    assert_eq!(denied.reasons, vec![DenyReason::SlippageUnbounded]);
    // A deny records nothing.
    assert!(rig.ledger.recorded().is_empty());
}

#[test]
fn a_swap_with_no_sensible_quote_is_denied() {
    let rig = spend_rig(
        caps(10_000_000, 12_000_000, 12_000_000, Duration::hours(24)),
        6_000_000,
    );
    // A zero quote divides nothing: refused, not allowed.
    let mut req = approve(0);
    req.swap = Some(SwapQuote {
        quoted_out: 0,
        min_out: 0,
    });
    assert_eq!(
        deny(&rig.engine, req).reasons,
        vec![DenyReason::SlippageExceeded]
    );
    // A min above the quoted number is not negative slippage, it is a lie.
    let mut req = approve(0);
    req.swap = Some(SwapQuote {
        quoted_out: 1_000,
        min_out: 1_001,
    });
    assert_eq!(
        deny(&rig.engine, req).reasons,
        vec![DenyReason::SlippageExceeded]
    );
}

#[test]
fn an_overflowing_ledger_total_is_a_cap_deny() {
    // u128::MAX already spent plus one more micro-USD overflows: the sum
    // must refuse the spend, not panic in debug or wrap in release.
    let rig = spend_rig(
        caps(u128::MAX, 6_000_000, 6_000_000, Duration::hours(24)),
        1,
    );
    seed(&rig, u128::MAX, NOW);
    let denied = deny(&rig.engine, approve(0));
    assert_eq!(
        denied.reasons,
        vec![
            DenyReason::CapExceeded(CapExceeded::PerDay),
            DenyReason::CapExceeded(CapExceeded::PerPeriod),
        ]
    );
}

#[test]
fn an_invalid_period_denies_instead_of_disabling_the_window() {
    // A zero period would make the rolling window a no-op...
    let rig = spend_rig(caps(10_000_000, 12_000_000, 12_000_000, Duration::ZERO), 1);
    assert_eq!(
        deny(&rig.engine, approve(0)).reasons,
        vec![DenyReason::InvalidCaps]
    );
    // ...and a period too long for a timestamp has no computable floor.
    let rig = spend_rig(caps(10_000_000, 12_000_000, 12_000_000, Duration::MAX), 1);
    assert_eq!(
        deny(&rig.engine, approve(0)).reasons,
        vec![DenyReason::InvalidCaps]
    );
}

#[test]
fn outflows_are_what_the_simulation_saw_not_what_was_claimed() {
    // Only the report's negative delta for the actor is capped: a report
    // with no balance changes prices at zero and records nothing, whatever
    // the request's `value` field claims.
    let sim = ScriptedSimulator::new().clean();
    let rig = rig_with(
        money_policy(caps(1, 1, 1, Duration::hours(24))),
        sim,
        FixedPrices::new(),
    );
    allow(&rig.engine, native_transfer(1));
    assert!(rig.ledger.recorded().is_empty());
}
