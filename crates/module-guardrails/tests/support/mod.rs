//! Fixtures and helpers for the guardrails suite: a full engine over the
//! in-memory fakes, a pinned clock, and the request builders every test
//! starts from. Deterministic and offline — the clock is one fixed instant,
//! the ids come from the fakes, and no test depends on the wall clock.

// A test-support module, included with `mod support;` into each test binary
// in this crate. `pub` is how a helper reads here, and the lint is right
// that nothing outside can reach it — the module is private to every binary
// that includes it. Saying so once beats `pub(crate)` on every helper.
#![allow(unreachable_pub)]
#![allow(dead_code)]

pub use cratefield_module_guardrails::{
    Action, Approval, ApprovalChange, BalanceChange, CallFrame, Caps, Chain, Denied, FixedPrices,
    Guardrails, GuardrailsBuilder, MemoryAllowances, MemoryAudit, MemoryKillSwitch, MemoryLedger,
    Policy, Request, SEL_APPROVE, SEL_PERMIT_2612, SEL_TRANSFER, ScriptedSimulator,
    SimulationReport, SolanaInstruction, SubjectPolicy, TokenKey, U256, u256_from_u128,
};
use time::{OffsetDateTime, Time};

pub use cratefield_testing::FixedClock;

/// The fixed instant every test runs at: 2023-11-14 22:13:20 UTC, a Tuesday
/// mid-afternoon, so neither the day window nor the period window is near a
/// boundary.
pub const NOW: OffsetDateTime = {
    let dt = OffsetDateTime::from_unix_timestamp(1_700_000_000);
    match dt {
        Ok(t) => t,
        Err(_) => panic!("a valid constant timestamp"),
    }
};

/// Builds a placeholder EVM address by repeating one 4-hex-digit chunk
/// ten times, so the suite keeps its obvious `1111…`, `aaaa…` fixtures
/// without any long hex literal sitting in this file.
macro_rules! hex_addr {
    ($chunk:literal) => {
        concat!(
            "0x", $chunk, $chunk, $chunk, $chunk, $chunk, $chunk, $chunk, $chunk, $chunk, $chunk
        )
    };
}

/// The acting address — the wallet the job controls.
pub const FROM: &str = hex_addr!("1111");
/// The one contract the policy names, a router.
pub const ROUTER: &str = hex_addr!("aaaa");
/// The one destination the policy names.
pub const RECIPIENT: &str = hex_addr!("bbbb");
/// The one approval spender the policy names.
pub const SPENDER: &str = hex_addr!("cccc");
/// A token the simulation moves.
pub const TOKEN: &str = hex_addr!("dddd");
/// A contract the policy does not name.
pub const STRANGER: &str = hex_addr!("eeee");

/// The per-token key the caps tables are keyed by: `TOKEN` on mainnet.
pub fn token_key() -> TokenKey {
    TokenKey {
        chain: Chain::Evm { chain_id: 1 },
        token: TOKEN.to_owned(),
    }
}

/// The subject whose policy the suite exercises.
pub const SUBJECT: &str = "job-7";
/// The venture above it.
pub const VENTURE: &str = "treasury";

/// A policy that allows one chain, one contract with `approve`, `transfer`
/// and EIP-2612 `permit`, one destination, one spender — and caps `SUBJECT`
/// at 10 m / 50 m / 50 m micro-USD per action / day / 24 h period, with
/// 200 bps of slippage room.
pub fn policy() -> Policy {
    Policy::new()
        .chain(Chain::Evm { chain_id: 1 })
        .contract(ROUTER, &[SEL_APPROVE, SEL_TRANSFER, SEL_PERMIT_2612])
        .destination(RECIPIENT)
        .spender(SPENDER)
        .subject(
            SUBJECT,
            SubjectPolicy::new().caps(Caps::uniform(
                &token_key(),
                10_000_000,
                50_000_000,
                50_000_000,
                time::Duration::hours(24),
                200,
            )),
        )
}

/// A `Request` framework with the suite's venture, subject and `from`.
pub fn request(action: Action) -> Request {
    Request {
        venture: VENTURE.to_owned(),
        subject: SUBJECT.to_owned(),
        from: FROM.to_owned(),
        action,
        swap: None,
    }
}

/// An `EvmTx` with empty calldata — a native transfer of `value` to `to`.
pub fn evm_tx(chain_id: u64, to: Option<&str>, value: u128, data: Vec<u8>) -> Request {
    request(Action::EvmTx {
        chain_id,
        to: to.map(str::to_owned),
        value: u256_from_u128(value),
        data,
        authorizations: Vec::new(),
    })
}

/// `approve(spender, amount)` on the router, the canonical allowed action.
pub fn approve(amount: u128) -> Request {
    with_calldata(
        evm_tx(1, Some(ROUTER), 0, Vec::new()),
        calldata(SEL_APPROVE, &[addr_word(SPENDER), u256_from_u128(amount)]),
    )
}

/// `selector ++ words`: calldata as the EVM ABI lays it out — the 4-byte
/// selector, then one 32-byte word per entry.
pub fn calldata(selector: u32, words: &[U256]) -> Vec<u8> {
    let mut d = selector.to_be_bytes().to_vec();
    for w in words {
        d.extend_from_slice(w);
    }
    d
}

/// Replaces an `EvmTx` request's calldata.
pub fn with_calldata(mut req: Request, data: Vec<u8>) -> Request {
    if let Action::EvmTx { data: slot, .. } = &mut req.action {
        *slot = data;
    }
    req
}

/// Replaces an `EvmTx` request's target.
pub fn with_to(mut req: Request, to: &str) -> Request {
    if let Action::EvmTx { to: slot, .. } = &mut req.action {
        *slot = Some(to.to_owned());
    }
    req
}

/// Replaces an `EvmTx` request's chain id.
pub fn with_chain(mut req: Request, chain_id: u64) -> Request {
    if let Action::EvmTx { chain_id: slot, .. } = &mut req.action {
        *slot = chain_id;
    }
    req
}

/// A native transfer of `value` wei to the recipient.
pub fn native_transfer(value: u128) -> Request {
    evm_tx(1, Some(RECIPIENT), value, Vec::new())
}

/// An `ERC-20 transfer(to, amount)` to `to` on the router.
pub fn token_transfer(to: &str, amount: u128) -> Request {
    with_calldata(
        evm_tx(1, Some(ROUTER), 0, Vec::new()),
        calldata(SEL_TRANSFER, &[addr_word(to), u256_from_u128(amount)]),
    )
}

/// One Solana transaction: a single instruction on `program`, with the
/// actor and the recipient as its accounts.
pub fn solana_tx(program: &str, data: Vec<u8>) -> Request {
    request(Action::SolanaTx {
        cluster: "mainnet-beta".to_owned(),
        instructions: vec![SolanaInstruction {
            program_id: program.to_owned(),
            accounts: vec![FROM.to_owned(), RECIPIENT.to_owned()],
            data,
        }],
    })
}

/// A success report with one balance change for the acting address: `delta`
/// units of `token` (negative is an outflow).
pub fn spend_report(token: &str, delta: i128) -> SimulationReport {
    report(
        vec![balance_change(FROM, token, delta)],
        Vec::new(),
        Vec::new(),
    )
}

/// A successful report with exactly the changes, approvals and calls given.
pub fn report(
    balance_changes: Vec<BalanceChange>,
    approvals: Vec<ApprovalChange>,
    calls: Vec<CallFrame>,
) -> SimulationReport {
    SimulationReport {
        success: true,
        balance_changes,
        approvals,
        calls,
    }
}

/// `owner`'s balance of `token` moves by `delta` (negative is an outflow).
pub fn balance_change(owner: &str, token: &str, delta: i128) -> BalanceChange {
    BalanceChange {
        owner: owner.to_owned(),
        token: token.to_owned(),
        delta,
    }
}

/// `owner` approves `spender` to move `token`, up to `amount`.
pub fn approval_change(owner: &str, token: &str, spender: &str, amount: U256) -> ApprovalChange {
    ApprovalChange {
        token: token.to_owned(),
        owner: owner.to_owned(),
        spender: spender.to_owned(),
        amount,
    }
}

/// The 20 address bytes of a `0x`-hex string.
pub fn hex_str_bytes(addr: &str) -> [u8; 20] {
    let mut out = [0_u8; 20];
    let hexed = addr.strip_prefix("0x").unwrap_or(addr);
    let bytes = hex::decode(hexed).expect("fixture addresses are hex");
    out.copy_from_slice(&bytes);
    out
}

/// A word over the unlimited line: every byte set, so the high half is
/// nonzero. The shape of `type(uint256).max`, the "infinite" approval.
pub fn unlimited_word() -> U256 {
    [0xff_u8; 32]
}

/// A full `U256` word from 20 address bytes.
pub fn addr_word(addr: &str) -> U256 {
    let mut word = [0_u8; 32];
    word[12..].copy_from_slice(&hex_str_bytes(addr));
    word
}

/// One engine over the given fakes, clock pinned to [`NOW`]. The allowance
/// source is not wired — hygiene tests wire their own.
pub struct Rig {
    pub kill: MemoryKillSwitch,
    pub sim: ScriptedSimulator,
    pub prices: FixedPrices,
    pub ledger: MemoryLedger,
    pub audit: MemoryAudit,
    pub engine: Guardrails,
}

/// A rig with the suite's policy, a clean simulator, `TOKEN` priced at
/// 1 micro-USD per smallest unit, and nothing spent yet.
pub fn rig() -> Rig {
    rig_with_policy(policy())
}

/// A rig over a caller-supplied policy.
pub fn rig_with_policy(policy: Policy) -> Rig {
    rig_with(policy, ScriptedSimulator::new().clean(), FixedPrices::new())
}

/// A rig over a caller-supplied policy, simulator and price table.
pub fn rig_with(policy: Policy, sim: ScriptedSimulator, prices: FixedPrices) -> Rig {
    build_rig(
        Guardrails::builder()
            .policy(policy)
            .simulator(sim.clone())
            .prices(prices.clone()),
        sim,
        prices,
    )
}

/// A rig like [`rig_with`], with an allowance source wired for the hygiene
/// scan and the suite's price table.
pub fn rig_with_allowances(
    policy: Policy,
    sim: ScriptedSimulator,
    allowances: MemoryAllowances,
) -> Rig {
    let prices = FixedPrices::new();
    build_rig(
        Guardrails::builder()
            .policy(policy)
            .simulator(sim.clone())
            .prices(prices.clone())
            .allowances(allowances),
        sim,
        prices,
    )
}

/// Finishes a builder with the shared kill switch, ledger, audit and clock.
fn build_rig(builder: GuardrailsBuilder, sim: ScriptedSimulator, prices: FixedPrices) -> Rig {
    let kill = MemoryKillSwitch::new();
    let ledger = MemoryLedger::new();
    let audit = MemoryAudit::new();
    let engine = builder
        .kill_switch(kill.clone())
        .ledger(ledger.clone())
        .audit(audit.clone())
        .clock(FixedClock(NOW))
        .build()
        .expect("every port wired");
    Rig {
        kill,
        sim,
        prices,
        ledger,
        audit,
        engine,
    }
}

/// A pre-wired builder over the suite's policy and standard fakes, for tests
/// that must swap one port for a failing one before building.
pub fn builder_with(policy: Policy) -> GuardrailsBuilder {
    Guardrails::builder()
        .policy(policy)
        .kill_switch(MemoryKillSwitch::new())
        .simulator(ScriptedSimulator::new().clean())
        .prices(FixedPrices::new())
        .ledger(MemoryLedger::new())
        .audit(MemoryAudit::new())
        .clock(FixedClock(NOW))
}

/// Runs `check` and unwraps the approval.
pub fn allow(engine: &Guardrails, req: Request) -> Approval {
    pollster::block_on(engine.check(req)).expect("expected an allow")
}

/// Runs `check` and unwraps the denial.
pub fn deny(engine: &Guardrails, req: Request) -> Denied {
    pollster::block_on(engine.check(req)).expect_err("expected a deny")
}

/// Runs the hygiene scan for the suite's venture, subject and wallet on
/// EVM mainnet.
pub fn scan(rig: &Rig) -> Vec<cratefield_module_guardrails::HygieneFinding> {
    pollster::block_on(rig.engine.scan_allowances(
        VENTURE,
        SUBJECT,
        &Chain::Evm { chain_id: 1 },
        FROM,
    ))
}

/// The UTC midnight before `at`, the day window's floor.
pub fn midnight(at: OffsetDateTime) -> OffsetDateTime {
    at.replace_time(Time::MIDNIGHT)
}
