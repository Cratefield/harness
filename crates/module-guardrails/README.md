# cratefield-module-guardrails

The policy engine every automated value-moving action must pass. A job that
would move a venture's or a user's funds — send a transaction, sign a
permit, approve a spender, swap — describes itself as a [`Request`] and gets
one of two answers: an opaque [`Approval`] that only the engine can mint, or
a typed [`Denied`] with every reason. Default deny everywhere, and fail
closed on any port error: a simulator that cannot be reached, an oracle with
no quote, a ledger that cannot be read, an audit sink that cannot record —
each is a refusal, never a shrug.

```rust
use cratefield_module_guardrails::*;

// Placeholder addresses, built at runtime so no long hex literal sits in
// this file; 40 hex digits is a 20-byte address.
let from = format!("0x{}", "1".repeat(40));
let spender = format!("0x{}", "2".repeat(40));

let engine = Guardrails::builder()
    .policy(Policy::new()
        .chain(Chain::Evm { chain_id: 1 })
        .contract(&from, &[SEL_APPROVE])
        .spender(&spender)
        .subject("job-7", SubjectPolicy::new()
            .caps(Caps::uniform(
                &TokenKey::native(Chain::Evm { chain_id: 1 }),
                5_000_000,                     // $5 per action, in micro-USD
                20_000_000,                    // $20 per UTC day
                20_000_000,                    // $20 per rolling period
                time::Duration::hours(24),
                200,                           // 2% max slippage
            ))
            .auto_revoke(true)))
    .kill_switch(MemoryKillSwitch::new())
    .simulator(ScriptedSimulator::new().clean())
    .prices(FixedPrices::new())
    .ledger(MemoryLedger::new())
    .audit(MemoryAudit::new())
    .allowances(MemoryAllowances::new())
    .build()
    .expect("every port wired");
```

## The decision order

`Guardrails::check` runs one gate after another and stops at the first that
refuses — a request refused statically never reaches the simulator:

1. **Kill switch** — engaged at the global, venture or subject scope is a
   deny before anything else is consulted, and is checked *again* at the
   moment of signing, so a job holding an approval is still stopped;
2. **Hard denies** — `setApprovalForAll`, unlimited approvals (`approve`,
   `increaseAllowance`, Permit2 `approve`, SPL `Approve` at `u64::MAX`),
   permits (EIP-2612, DAI-style, Permit2) to a spender the policy does not
   name, with an unlimited/unboundable amount, or with calldata too
   truncated to read, EIP-7702 authorizations
   with `chain_id == 0`, Solana owner reassignment (System `Assign` /
   `AssignWithSeed`, SPL `SetAuthority`) and `AdvanceNonceAccount` — from
   the request alone, whatever the allowlist says;
3. **Allowlists** — the chain; the contract *with its explicit selector
   set* (or the Solana program); every destination the action moves funds
   to (native transfers, decoded ERC-20 `transfer`/`transferFrom`
   recipients, System `Transfer` and SPL `Transfer`/`TransferChecked`
   destinations); approval spenders; EIP-7702 delegates;
4. **Simulation** — required, via the `Simulator` port (`eth_simulateV1` /
   `simulateTransaction` in an adapter). Denied on: a revert, an unlimited
   approval, an approval to a non-allowlisted spender (an approval of
   exactly zero is a revoke, and exempt), a credit to a non-allowlisted
   destination, a delegatecall into a non-allowlisted contract;
5. **Caps and slippage** — per action, per UTC day and per rolling period,
   in micro-USD per token, priced through the `Prices` port from the
   simulation's outflows. A subject with no caps, a token with no cap entry
   (zero), no price, a swap over `max_slippage_bps`, or a swap-shaped
   action (the actor both pays and receives) with no quote at all is
   denied; a non-positive or out-of-range period denies the subject rather
   than silently disabling the rolling window;
6. **Ledger** — the priced outflows are recorded, only on the way to an
   allow;
7. **Audit** — one entry per decision, allow or deny, on `check`, on every
   sign and on every hygiene finding; a sink error is a deny.

An "unlimited" amount is one at or above 2^128 — `MAX_UINT256`, Permit2's
`MAX_UINT160` and every practical infinite approval are all far above the
line, and no honest bounded amount comes near it.

## The ports, and their fakes

| Port | Answers | Fake |
|---|---|---|
| `KillSwitch` | `engaged` / `engage` / `release` over `Scope::{Global, Venture, Subject}` | `MemoryKillSwitch` |
| `Simulator` | the `SimulationReport`: success, balance changes, approvals, call trace | `ScriptedSimulator` |
| `Prices` | micro-USD for (chain, token, raw amount); `None` is no quote | `FixedPrices` |
| `SpendLedger` | `spent(subject, token, since)` / `record(...)` | `MemoryLedger` |
| `AuditSink` | `record(&AuditEntry)` | `MemoryAudit`, `FailingAudit` |
| `AllowanceSource` | a wallet's open allowances | `MemoryAllowances` |
| `WalletSigner` | the actual signing (e.g. a Turnkey adapter) | `RecordingSigner` |

Around them: [`Guardrails::check`] mints [`Approval`]s; [`GuardedSigner::sign`]
consumes one and re-checks all three kill-switch scopes first (in-flight
jobs die at signing time); [`Guardrails::job_allowed`] lets the actor skip
scheduling for a killed subject; [`turnkey_deny_policy`] renders a scope as
a Turnkey `EFFECT_DENY` policy body so the remote signer refuses even if
this process is bypassed (`None` for ids outside `[A-Za-z0-9._:-]+`, which
could rewrite the condition);
[`Guardrails::scan_allowances`] finds old
allowances today's policy would not issue and builds `approve(spender, 0)`
revokes — sent through `check` itself when the subject sets `auto_revoke`,
and reported unremediable when a malformed spender can name no revoke.

`GuardrailsModule` mounts the engine as a harness module: no tables, a
status route, and a `scheduled` hook that runs the hygiene scan over
configured watched wallets.

## Limits

- **No RPC or provider adapter ships here.** The `Simulator`,
  `AllowanceSource` and `WalletSigner` ports need an adapter per provider;
  this crate is the policy, not the plumbing.
- **The ledger is not transactional.** `spent` + `record` is a
  check-then-act pair; callers must serialize per subject (one actor per
  subject, jobs one at a time), which is the harness's own contract.
  Concurrent checks for one subject can exceed a cap by the overlap.
- **The hygiene scan is EVM-only** — an `approve(spender, 0)` revoke has no
  Solana twin here.
- **Permit2 batch permits are always denied** as unboundable: their amounts
  live in a dynamic array no static check can bound.
- Every port error denies, and an audit-sink error after the ledger recorded
  leaves the spend recorded — over-counting is the conservative direction.
