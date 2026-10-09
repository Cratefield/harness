# cratefield-session-grants

On-chain session grants for the Cratefield harness: **scoped, capped,
expiring, revocable automation keys** (issue #762) for ERC-4337/ERC-7579
Kernel accounts, EIP-7702 EOAs, Swig roles and Squads v4 vaults.

The owner's credential — a passkey or a sealed key — signs a grant once.
After that the server can act only inside the on-chain limits the grant
names: which contracts or programs, which functions, how much value or
token, how often, until when. The crate holds the ports, the domain model,
the off-chain enforcer and the conformance suites; real Pimlico/ZeroDev/
Swig adapters plug in behind the ports without changing any of it.

## The pieces

- **Grant spec** ([`GrantSpec`]): what the owner signs once — credential,
  validity window, rate limit, and one scope: an ERC-7579 permission on a
  Kernel account, a Swig role with a session authority, or Squads v4
  spending limits on a treasury vault.
- **Summary** ([`summarize`]): a pure function from the spec to the
  display model the UI renders *before* the user signs — every contract
  or program, its caps, the expiry. [`GrantSummary::render`] is the
  text shape of the same model.
- **Enforcer** ([`Enforcer`]): the gate every server action goes through.
  Status first (the off-chain deny/pause kill switches), then window,
  then chain, then call policies, then spend caps and rate limit, then —
  only on allow — the usage ledger write.
- **Ports**: [`Bundler`] + paymaster (the Pimlico/ZeroDev call shapes,
  [`BundlerClient`] over any [`JsonRpcTransport`]), [`KernelPermissions`]
  (grant through the permission validator, keep the serialized permission
  account, revoke via `uninstallPlugin`), [`SwigSessions`] (role + session
  expiry, revoke by removing the role), [`SquadsLimits`], [`GrantStore`].
- **Test kit** (feature `testing`): a fake for every port, the clocks the
  tests move by hand, and one conformance suite per port that a real
  adapter runs against too.

## Two-layer revocation

A deny (or pause) is an off-chain write to the grant store. It stops the
server on its next action — before, and independently of, anything on
chain. The on-chain revoke — `uninstallPlugin` for Kernel, role removal
for Swig, limit deactivation for Squads — is signed by the *user*, and
the crate keeps every grant's on-chain binding ([`OnChainBinding`], with
the serialized permission account) so the revoke can name what it frees.
An expired grant behaves the same way: the server stops, the owner still
signs the on-chain revoke when they want the state gone.

## The one absolute refusal

An EIP-7702 authorization with `chain_id = 0` is valid on *every* chain.
A session grant is an automation key with per-chain limits, so a
chain-agnostic one is refused everywhere: [`Eip7702Authorization::new`],
its `Deserialize` impl, and [`GrantSpec::validate`] all reject it.

## Usage

```rust,ignore
use cratefield_session_grants::*;

// Compose and show the grant before the owner signs.
let spec = evm_spec("grant-1", window_start_at);
let summary = summarize(&spec);
ui.confirm(summary.render());

// The owner signs; the grant goes on chain and the serialized permission
// account comes back with the permission id.
let binding = kernel.grant(&spec, &passkey_signature()).await?;

// The record keeps the binding and the status.
let mut record = GrantRecord::pending(spec.clone(), now);
record.attach(binding)?;
store.save(record).await?;

// Every server action goes through the enforcer.
let enforcer = Enforcer::new(&store, &clock);
match enforcer.authorize(&spec.id, &action).await? {
    Decision::Allow => { /* build the UserOperation and send it */ }
    Decision::Deny(reason) => { /* refuse, tell the caller why */ }
}

// Off-chain deny: immediate, no signature needed.
// On-chain revoke: the owner signs the uninstallPlugin operation.
```

## Platform

Pure logic and ports: no I/O stack of its own. The bundler client speaks
JSON-RPC 2.0 over the injected [`JsonRpcTransport`], so it runs on
Workers and natively unchanged, and builds for `wasm32-unknown-unknown`.
