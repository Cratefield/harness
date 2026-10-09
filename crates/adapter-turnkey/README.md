<p align="center">
  <a href="https://crates.io/crates/cratefield-adapter-turnkey"><img src="https://img.shields.io/crates/v/cratefield-adapter-turnkey.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-adapter-turnkey on crates.io"></a>
  <a href="https://docs.rs/cratefield-adapter-turnkey"><img src="https://img.shields.io/docsrs/cratefield-adapter-turnkey?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-adapter-turnkey documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-adapter-turnkey

The [Turnkey](https://turnkey.com) provider for the [`KeySigner`
port](https://docs.rs/cratefield-signer) (issue #761): every end user gets
a Turnkey **sub-organization** whose root user is the user's own passkey,
the venture's backend acts only as a policy-restricted **delegated access**
user, and signing goes **by key reference** — sub-organization id plus
wallet account address. No export activity is ever wrapped: there is no
method here that can return key material.

```rust,ignore
use std::sync::Arc;
use cratefield_adapter_turnkey::{AllowRule, SubOrgSetup, TurnkeySigner};

let signer = TurnkeySigner::new(
    http, clock,
    "parent-org-uuid",                       // our Turnkey organization
    secrets, actor, "turnkey/api-key/acme",  // where the P-256 API key is sealed
);

// One-time setup per end user (issue #761): create the sub-organization
// with the user's passkey as root user and our backend as a delegated
// access user, scope allow policies to that user, then hand the root
// quorum to the user alone — after this the backend cannot change policy.
let sub_org = signer
    .create_sub_organization(&SubOrgSetup {
        venture: "acme",
        name: "acme:user-42",
        rules: &[AllowRule::evm(1, "0x…", Some("0xa9059cbb"), Some(1_000_000))?],
        // … plus the passkey attestation the browser hands back
        ..SubOrgSetup::default()
    })
    .await?;

// Signing, through the signer port:
let key_ref = signer.key_ref("acme", &sub_org.id, Scheme::Secp256k1, &sub_org.evm_address)?;
let signature = signer.sign(&key_ref, &payload).await?;
```

## The setup flow, in order

`create_sub_organization` performs four steps, in this order:

1. **`ACTIVITY_TYPE_CREATE_SUB_ORGANIZATION_V7`** on the parent
   organization: two root users — the end user (WebAuthn authenticator =
   the passkey attestation the client produced) and our delegated access
   user (an API key, the P-256 pair sealed in the Secrets port) — a root
   quorum threshold of 1, and a wallet with an EVM (`m/44'/60'/0'/0/0`)
   and a Solana (`m/44'/501'/0'/0'`) account.
2. **`POST /public/v1/query/list_users`** on the sub-organization: the
   users are read back and identified — the delegated access user by the
   API key public key it carries (the one this crate stamps with), the
   end user as the other of exactly two. The answer's `rootUserIds`
   order is never trusted; an ambiguous listing fails loudly before any
   policy is created or the quorum is touched.
3. **`ACTIVITY_TYPE_CREATE_POLICY_V3`** on the sub-organization, one
   `EFFECT_ALLOW` policy per rule, each with consensus scoped to the DA
   user (`approvers.any(user, user.id == '<DA_USER_ID>')`) and a
   condition built by [`policy`](crate::policy): `eth.tx.to`,
   `eth.tx.chain_id`, `eth.tx.value <= cap`, the four-byte selector as
   `eth.tx.data[0..10] == '0xa9059cbb'`, and for Solana
   `solana.tx.instructions.all(i, i.program_key == '…')`.
4. **`ACTIVITY_TYPE_UPDATE_ROOT_QUORUM`** with threshold 1 and the end
   user as the only member. From here the backend **cannot** change
   policies, users or the quorum: it was in the quorum only for the
   setup call, which is also why a failed setup must be retried, not
   abandoned — a sub-organization that stopped between steps 3 and 4
   leaves the DA user root until the quorum update lands.

## Kill switches are DENY policies

`set_kill_switch` inserts a `EFFECT_DENY` policy whose consensus is the
DA user and whose condition is `true` — while it exists, nothing the
backend signs is approved, no matter what the allow policies say.
`clear_kill_switch` deletes it by the policy id the create returned.
Both are plain `create_policy`/`delete_policy` calls, stamped by the DA
key, and they keep working after the quorum hand-over only because a
DENY/allow policy decision is all the backend ever needed.

## Signing

The port's `KeyRef` is `turnkey/{venture}/{sub-organization}/{scheme}/{address}`
— self-describing, the way `SecretsSigner`'s store names are. Over it:

- `Payload::EvmTransaction` goes out as
  **`ACTIVITY_TYPE_SIGN_TRANSACTION_V2`** with the RLP-encoded unsigned
  EIP-1559 transaction (`TRANSACTION_TYPE_ETHEREUM`). This is deliberate:
  Turnkey's policy engine parses full transactions — `eth.tx.*`
  conditions only evaluate on this activity — while raw-payload signing
  bypasses them. The signed transaction that comes back is RLP-decoded
  into the port's `(r, s, v)`.
- `Payload::UserOperation` and `Payload::Eip712` go out as
  **`ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2`** over the digest the signer
  port computes (`userOpHash`, the EIP-712 digest), hex-encoded with
  `HASH_FUNCTION_NO_OP` — the payload is already a hash, and Turnkey
  signs it without hashing again.
- `Payload::SolanaMessage` goes out the same way with
  `HASH_FUNCTION_NOT_APPLICABLE` (ed25519 hashes internally; RFC 8032
  allows nothing else) and comes back as the 64-byte `r ‖ s`.

Activity statuses map onto the port: `ACTIVITY_STATUS_COMPLETED`
returns; `ACTIVITY_STATUS_REJECTED` and `ACTIVITY_STATUS_CONSENSUS_NEEDED`
become `SignerError::Denied` — a policy refused, or the DA user's
consensus was not enough of one; `ACTIVITY_STATUS_FAILED` and everything
else become `SignerError::Provider`. A completed answer still has to
earn the name before it is returned: every secp256k1 answer must recover
to the key reference's identity address over the digest this crate
computed, and every ed25519 answer must verify against the identity
pubkey over the exact message — an answer minted by another key, or over
other bytes, is a provider error, never a signature.

`create_key` deliberately returns `SignerError::Unsupported`: Turnkey
keys are born with their owner's passkey at sub-organization creation,
and the port's `create_key(subject, scheme, label)` cannot carry a
passkey attestation. Use [`TurnkeySigner::create_sub_organization`] then
[`TurnkeySigner::key_ref`]. For the same reason the signer crate's
`key_signer_conformance` suite does not run against this provider: its
determinism check (RFC 6979 / ed25519) excludes a provider whose
signatures are minted by distributed signing infrastructure, and its
`create_key`-first shape cannot express this setup. The adapter's tests
cover the parts that transfer — sign/verify against the published
identity, scheme mismatches, malformed payloads and refusals.

## The stamp

Every request is stamped with the venture's Turnkey **API key**: the
`X-Stamp` header is base64url of `{"publicKey": …, "signature": …,
"scheme": "SIGNATURE_SCHEME_TK_API_P256"}`, where the public key is the
compressed P-256 point in hex and the signature is the DER ECDSA
signature over the **exact** request body (SHA-256 digest). The private
scalar lives in the Secrets port (a 32-byte P-256 scalar, wherever the
venture names it), is unsealed only inside the stamping call into a
zeroising buffer, and never crosses a public API of this crate. The
stamp is produced with RustCrypto `p256` — deterministic RFC 6979
nonces, so stamping needs no RNG and runs on wasm32.

## Costs

Turnkey bills roughly **$0.05–$0.10 per signature** on its standard
plans — an order of magnitude above the marginal cost of
`SecretsSigner`. Reach for this adapter when the key must be rooted in
the user's own passkey and portable across the user's devices, not when
a server-held session key would do.

## Testing

Tests run against a scripted fake HTTP transport (no network): the setup
flow's request order and bodies, stamp verification against the sealed
key, policy-builder escaping, EVM/Solana/UserOperation/EIP-712 signing
with signature verification, and the status-to-error mapping.
