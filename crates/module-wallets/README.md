# cratefield-module-wallets

Link a person's **own** crypto wallet to a Cratefield account they have
already signed in to — EVM or Solana — by proving they control the address
with a signature, not a password.

The wallet is never the login. Passkeys, OIDC and the rest of the auth stack
own "who is signed in"; this module only answers "and which address does
this person also control". That is why every route here requires a signed-in
caller: a signature over a message proves ownership of an address, never of
a session.

**This module cannot move funds.** It reads an address and proves ownership
of it. No approval, allowance or spending flow of any kind appears anywhere
in the crate, and no transaction of any kind is ever requested. Connecting a
wallet that can *spend* is a different and much larger module; it is not
this one.

## The flow

1. The signed-in caller posts `{"chain": "evm"}` (or `"solana"`) to
   `/v1/wallets/nonce` and gets back a single-use nonce plus everything the
   message will contain — domain, URI, statement, chain id, expiry.
2. The wallet builds a SIWE (`… wants you to sign in with your Ethereum
   account:`) or SIWS (`… Solana account:`) message around that nonce and
   signs it: `personal_sign` for EVM, the exact message bytes for Solana.
3. The caller posts the message and the signature to
   `/v1/wallets/verify`. The module checks the domain, the chain, the
   nonce's ownership and expiry, the message's own `Expiration Time` and
   `Not Before`, consumes the nonce, verifies the signature, and links the
   address to the caller's account.

The nonce is the replay defence and it is consumed atomically, so a message
that was signed once cannot be presented twice even if two requests arrive
together. The domain in the message is the phishing defence: a message
minted for another site is refused rather than verified.

## Composition

```rust
use cratefield_core::{RandomBytes, RandomError};
use cratefield_module_wallets::{Wallets, SOLANA_CHAIN_ID};

struct OsEntropy;
impl RandomBytes for OsEntropy {
    fn fill(&self, dest: &mut [u8]) -> Result<(), RandomError> {
        // In a venture this is the platform CSPRNG (e.g. `getrandom`).
        for byte in dest.iter_mut() {
            *byte = 0x2a;
        }
        Ok(())
    }
}

let module = Wallets::builder()
    .domain("example.com")                  // required — the phishing defence
    .statement("Link this wallet to your account.")  // the line a person reads
    .chain_id("1")                          // the EVM chain messages name
    .nonce_ttl(time::Duration::seconds(600))
    .random(OsEntropy)
    .build();
```

`uri` defaults to `https://<domain>`. `self_check` refuses a composition
with no domain (every message would be refused) or no entropy source (no
nonce could be minted).

## Contract wallets (EIP-1271)

An EOA signature recovers a secp256k1 public key and the address falls out
of it. A smart-contract wallet has no key, so anything that does not
recover the address in the message is handed to a
`ContractSignatureVerifier` — the `isValidSignature(bytes32, bytes)` call
EIP-1271 defines. The same path carries EIP-6492 counterfactual
signatures, which is the answer to "the wallet does not exist on this chain
yet".

`.contract_verifier(..)` sets it. Left unset the module serves EOAs only,
which is a smaller module rather than a broken one: a contract address then
fails with `wallets/signature-invalid` instead of the server hanging on a
chain call. `StaticContractVerifier` is a no-network adapter that approves
one `(address, message)` pair, for tests and fakes.

## The endpoints

| Route | Who calls it | What it answers |
|---|---|---|
| `POST /v1/wallets/nonce` | the signed-in caller | the nonce and the message fields |
| `POST /v1/wallets/verify` | the signed-in caller | the linked wallet, or a refusal |
| `GET /v1/wallets` | the signed-in caller | that caller's linked wallets, and only theirs |
| `DELETE /v1/wallets/{id}` | the signed-in caller | unlinks one of that caller's wallets |

All four require a signed-in caller and answer `401` without one. Refusals
are RFC 9457 problems with stable slugs: `wallets/domain-mismatch`,
`wallets/nonce-invalid`, `wallets/message-expired`,
`wallets/signature-invalid`, `wallets/chain-mismatch`,
`wallets/address-already-linked`, `wallets/not-found`.

An EVM address is normalised to its EIP-55 checksummed form and a Solana
address to its canonical base58 form, so the same wallet reached two ways
is stored once. A wallet already linked to a *different* account is refused
with `409`; re-verifying a wallet this account already holds is
idempotent.

## Storage

Two tables, `wallet_nonces` and `wallet_links`, in the venture's own
database. A nonce is a `PRIMARY KEY` row with `consumed_at` set by one
guarded conditional `UPDATE`, which is what makes replay impossible. A
link is unique on `(chain, address)` — one wallet, one account. No
signature and no signature hash is ever stored, so a row in either table
cannot be replayed as a proof of anything. The migration is
`crates/module-wallets/migrations/sqlite/0001_init.sql`; a scheduled job
purges nonces past their expiry, spent or not.

## Ports

| Port | How |
|---|---|
| `Database` | required — nonces and links live here |
| `Auth` | required — every route answers only to a signed-in caller |
| `Clock` | optional — what makes nonce and message expiry deterministic |
| `IdGen` | optional — names each link; without one the handler derives it |

## What is deliberately not here

The browser side of a wallet connection — EIP-6963 discovery, the
`WalletConnect` v2 session, Coinbase Smart Wallet, the Wallet Standard
registry and the picker component — is a separate piece of work. So is any
flow that would let a linked wallet authorise a spend: that is a
transaction-signing module and this one is not it.