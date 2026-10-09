//! A property test over randomized requests (issue #763): for a few
//! thousand deterministic cases, the engine's answer is exactly the answer
//! the documented gate order gives — allow if and only if the request is
//! allowlisted, the simulation is clean, the caps are configured and within
//! reach, and no kill switch or hard deny fires — and every check leaves
//! exactly one audit entry.
//!
//! `proptest` is not in the workspace's dependency tree, so the cases come
//! from a hand-rolled xorshift PRNG: small, deterministic, and replayable
//! from the seed in the first assertion.

mod support;

use cratefield_module_guardrails::{
    Caps, Chain, DenyReason, KillSwitch, NotAllowlisted, Policy, SEL_APPROVE, SEL_TRANSFER,
    SYSTEM_PROGRAM, Scope, ScriptedSimulator, SimulationReport, SubjectPolicy, TokenKey, Verdict,
    u256_from_u128,
};
use time::Duration;

use support::*;

/// xorshift64*: one multiply-xorshift step, seeded nonzero. Deterministic
/// across platforms and runs; the same seed replays the same cases.
struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A value below `n` (which must be nonzero).
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    /// A value below `n`, as an index (which must be nonzero).
    fn index(&mut self, n: u64) -> usize {
        usize::try_from(self.next() % n).expect("below n")
    }
}

/// Which shape a generated case takes.
enum Kind {
    Evm {
        chain_id: u64,
        contract: &'static str,
        selector: u32,
        recipient: &'static str,
        unlimited: bool,
    },
    Sol {
        program: &'static str,
        assign: bool,
    },
}

/// One drawn case, with the request built to match.
struct Case {
    kill: Option<Scope>,
    kind: Kind,
    sim: &'static str,
    outflow: u128,
    caps_present: bool,
    req: Request,
}

fn draw(rng: &mut Xorshift) -> Case {
    let kill = match rng.below(4) {
        0 => Some(Scope::Global),
        1 => Some(Scope::Venture(VENTURE.to_owned())),
        2 => Some(Scope::Subject(SUBJECT.to_owned())),
        _ => None,
    };
    let on_solana = rng.below(4) == 3;
    let sim = ["clean", "reverted", "failed"][rng.index(3)];
    let outflow = [0_u128, 1_000_000, 20_000_000][rng.index(3)];
    let caps_present = rng.below(4) != 3;
    let (kind, action) = if on_solana {
        let allowlisted = rng.below(2) == 0;
        let assign = rng.below(4) == 0;
        let program = if allowlisted {
            SYSTEM_PROGRAM
        } else {
            // A fake program id, built from fragments so no long
            // base58-shaped literal sits in this file.
            concat!(
                "Prog", "1111", "1111", "1111", "1111", "1111", "1111", "1111", "1111", "1111", "1"
            )
        };
        // System `Assign` (the hard-deny arm) or a plain `Transfer`.
        let data = if assign {
            vec![1, 0, 0, 0]
        } else {
            vec![2, 0, 0, 0, 1, 0, 0, 0]
        };
        (
            Kind::Sol { program, assign },
            solana_tx(program, data).action,
        )
    } else {
        let chain_id = [1_u64, 137][rng.index(2)];
        let contract = [ROUTER, STRANGER][rng.index(2)];
        let recipient = [RECIPIENT, STRANGER][rng.index(2)];
        let selector = [SEL_APPROVE, SEL_TRANSFER, 0xDEAD_BEEF_u32][rng.index(3)];
        // Four shapes of amount: a random small value, one high bit set
        // anywhere, exactly 2^128 (the line itself), a bounded random.
        let amount = match rng.below(4) {
            0 => u256_from_u128(u128::from(rng.below(1_u64 << 32))),
            1 => {
                let mut w = [0_u8; 32];
                w[rng.index(32)] = 1;
                w
            }
            2 => {
                let mut w = [0_u8; 32];
                w[15] = 1;
                w
            }
            _ => u256_from_u128(u128::from(rng.next())),
        };
        // The word after the selector: the spender for an approve (always
        // allowlisted), the recipient for a transfer — which is the
        // destination gate's input.
        let word = if selector == SEL_TRANSFER {
            recipient
        } else {
            SPENDER
        };
        let kind = Kind::Evm {
            chain_id,
            contract,
            selector,
            recipient,
            unlimited: amount_unlimited(&amount),
        };
        let action = with_calldata(
            evm_tx(chain_id, Some(contract), 0, Vec::new()),
            calldata(selector, &[addr_word(word), amount]),
        )
        .action;
        (kind, action)
    };
    Case {
        kill,
        kind,
        sim,
        outflow,
        caps_present,
        req: request(action),
    }
}

/// What the engine should answer, computed by the documented gate order —
/// written from the spec, not by calling the engine.
fn expected(case: &Case) -> Result<(), &'static str> {
    let Case {
        kill,
        kind,
        sim,
        outflow,
        caps_present,
        ..
    } = case;
    if kill.is_some() {
        return Err("kill switch");
    }
    match kind {
        Kind::Evm {
            chain_id,
            contract,
            selector,
            recipient,
            unlimited,
        } => {
            // A big `transfer` is money, not power — the caps' business.
            if *unlimited && *selector == SEL_APPROVE {
                return Err("hard deny");
            }
            if *chain_id != 1 {
                return Err("chain");
            }
            if *contract != ROUTER {
                return Err("contract");
            }
            if *selector != SEL_APPROVE && *selector != SEL_TRANSFER {
                return Err("selector");
            }
            if *selector == SEL_TRANSFER && *recipient != RECIPIENT {
                return Err("destination");
            }
        }
        Kind::Sol { program, assign } => {
            // The static pass only refuses what it can see: the owner
            // reassignment denies are keyed to the real System program, so
            // assign-shaped calldata on a stranger program proves nothing
            // and falls through to the program allowlist.
            if *assign && *program == SYSTEM_PROGRAM {
                return Err("hard deny");
            }
            if *program != SYSTEM_PROGRAM {
                return Err("program");
            }
        }
    }
    match *sim {
        "reverted" => return Err("reverted"),
        "failed" => return Err("failed"),
        _ => {}
    }
    if !*caps_present {
        return Err("no caps");
    }
    // With caps on, the EVM token is capped at 10 m per action; the Solana
    // native coin has no entry, so its cap is zero.
    let limit = match kind {
        Kind::Evm { .. } => 10_000_000,
        Kind::Sol { .. } => 0,
    };
    if *outflow > limit {
        return Err("cap");
    }
    Ok(())
}

/// Whether the word crosses the unlimited line — the rule the crate
/// documents, spelled out here so the property does not lean on the code
/// it checks.
fn amount_unlimited(amount: &[u8; 32]) -> bool {
    amount[..16].iter().any(|&b| b != 0)
}

/// The policy the cases run: both chains, one contract with `approve` and
/// `transfer`, one program, one destination, one spender — and caps on the
/// subject exactly when the case says so.
fn prop_policy(caps_present: bool) -> Policy {
    let policy = Policy::new()
        .chain(Chain::Evm { chain_id: 1 })
        .chain(Chain::Solana {
            cluster: "mainnet-beta".to_owned(),
        })
        .contract(ROUTER, &[SEL_APPROVE, SEL_TRANSFER])
        .program(SYSTEM_PROGRAM)
        .destination(RECIPIENT)
        .spender(SPENDER);
    if caps_present {
        policy.subject(
            SUBJECT,
            SubjectPolicy::new().caps(Caps::uniform(
                &token_key(),
                10_000_000,
                50_000_000,
                50_000_000,
                Duration::hours(24),
                200,
            )),
        )
    } else {
        policy
    }
}

#[test]
fn check_matches_the_documented_gate_order_over_random_requests() {
    let mut rng = Xorshift(0x5EED_7633);
    // Both outflowing tokens are priced at 1 micro-USD per unit, so outflow
    // units are micro-USD.
    let prices = FixedPrices::new().price(token_key(), 1).price(
        TokenKey::native(Chain::Solana {
            cluster: "mainnet-beta".to_owned(),
        }),
        1,
    );

    for case_no in 0..2_000_u32 {
        let case = draw(&mut rng);
        let rig = rig_with(
            prop_policy(case.caps_present),
            match case.sim {
                "clean" => ScriptedSimulator::new().respond(spent_report(&case)),
                "reverted" => ScriptedSimulator::new().respond(SimulationReport::reverted()),
                _ => ScriptedSimulator::new(), // unscripted: errors
            },
            prices.clone(),
        );
        if let Some(scope) = &case.kill {
            pollster::block_on(rig.kill.engage(scope.clone(), "test")).expect("engage");
        }

        let want = expected(&case);
        let result = pollster::block_on(rig.engine.check(case.req.clone()));

        // The audit trail: exactly one entry per check, allow or deny.
        assert_eq!(rig.audit.len(), 1, "case {case_no}: one entry per check");
        match want {
            Ok(()) => {
                let approval =
                    result.unwrap_or_else(|d| panic!("case {case_no}: expected allow, got {d}"));
                assert_eq!(approval.request().subject, SUBJECT);
                assert_eq!(rig.audit.entries()[0].verdict, Verdict::Allow);
            }
            Err(gate) => {
                let denied =
                    result.expect_err(&format!("case {case_no}: expected a deny at gate {gate}"));
                assert!(!denied.reasons.is_empty());
                assert_eq!(
                    rig.audit.entries()[0].verdict,
                    Verdict::Deny(denied.reasons.clone())
                );
                // The first reason names the first gate that refused: the
                // short-circuit is part of the contract.
                assert_first_reason(gate, &denied.reasons[0], case_no);
            }
        }
    }
}

/// The clean-simulation report a case's simulator answers with: the actor
/// pays `outflow` units of the case's chain token, and nothing else happens.
fn spent_report(case: &Case) -> SimulationReport {
    let token = match case.kind {
        Kind::Evm { .. } => TOKEN,
        Kind::Sol { .. } => "native",
    };
    spend_report(token, -i128::try_from(case.outflow).expect("fits"))
}

/// The first reason must name the gate the spec refuses at.
fn assert_first_reason(gate: &str, first: &DenyReason, case: u32) {
    let ok = matches!(
        (gate, first),
        ("kill switch", DenyReason::KillSwitch(_))
            | ("hard deny", DenyReason::HardDeny(_))
            | ("chain", DenyReason::NotAllowlisted(NotAllowlisted::Chain))
            | (
                "contract",
                DenyReason::NotAllowlisted(NotAllowlisted::Contract(_))
            )
            | (
                "selector",
                DenyReason::NotAllowlisted(NotAllowlisted::Selector(_))
            )
            | (
                "destination",
                DenyReason::NotAllowlisted(NotAllowlisted::Destination(_))
            )
            | (
                "program",
                DenyReason::NotAllowlisted(NotAllowlisted::Program(_))
            )
            | ("reverted", DenyReason::SimulationReverted)
            | ("failed", DenyReason::SimulationFailed)
            | ("no caps", DenyReason::NoCaps)
            | ("cap", DenyReason::CapExceeded(_))
    );
    assert!(ok, "case {case}: gate {gate} refused with {first}");
}

#[test]
fn the_seed_and_the_case_count_cover_the_matrix() {
    // The generator must actually reach every gate, or the property is
    // quietly vacuous. Replay the same stream through the same draws and
    // record which gate each case would refuse at.
    let mut rng = Xorshift(0x5EED_7633);
    let mut gates = std::collections::BTreeSet::new();
    for _ in 0..2_000_u32 {
        let case = draw(&mut rng);
        if let Err(gate) = expected(&case) {
            gates.insert(gate);
        }
    }
    for gate in [
        "kill switch",
        "hard deny",
        "chain",
        "contract",
        "selector",
        "destination",
        "program",
        "reverted",
        "failed",
        "no caps",
        "cap",
    ] {
        assert!(gates.contains(gate), "gate never reached: {gate}");
    }
    assert_eq!(gates.len(), 11);
}
