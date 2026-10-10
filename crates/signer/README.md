# cratefield-signer

Signs a payload by key reference: a venture asks for an EVM transaction,
an ERC-4337 UserOperation, EIP-712 data or a Solana message to be signed,
names the key, and never touches raw key material. Keys are created here
and referenced everywhere else; no API exports a private key.

Every sign call runs the same gauntlet, in order: the payload's intent is
decoded, the guardrails are asked, the decision and the outcome are written
to an append-only audit chain, and only on **allow** does the underlying
provider see the payload. A deny, a decode failure, a tripped kill switch
or a failed audit record means the provider is never called.

```rust
use cratefield_signer::{
    EvmTransaction, FakeSigner, GuardedSigner, MemorySignAudit, Payload, Scheme,
    SignerError, StaticGuardrails, Subject,
};

let guardrails = StaticGuardrails::new().allow_evm(
    1,
    "0x000000000000000000000000000000000000aaaa",
    [0xa9, 0x05, 0x9c, 0xbb],
)?;
let signer = GuardedSigner::new(FakeSigner::new(), guardrails, MemorySignAudit::new());
let subject = Subject::new("acme", None)?;
let key = pollster::block_on(async {
    signer
        .create_key(&subject, Scheme::Secp256k1, "session-1")
        .await
})?;

let tx = EvmTransaction {
    chain_id: 1,
    nonce: 0,
    max_priority_fee_per_gas: 1_000_000_000,
    max_fee_per_gas: 2_000_000_000,
    gas_limit: 21_000,
    to: Some("0x000000000000000000000000000000000000aaaa".into()),
    value: 1_000_000_000_000_000_000,
    data: vec![0xa9, 0x05, 0x9c, 0xbb], // the allowed selector
};
let signature = pollster::block_on(async {
    signer
        .sign(&subject, &key.key_ref(), &Payload::EvmTransaction(tx))
        .await
})?;
assert!(matches!(signature, cratefield_signer::Signature::Secp256k1 { .. }));
# Ok::<(), SignerError>(())
```

The default composition is `SecretsSigner`: a secp256k1 or ed25519 key held
in the Secrets port, decrypted inside `sign` and never before, wrapped in a
`GuardedSigner`. It mints **session keys only** — there is no import API, by
design; owner keys belong in a hardware wallet or a KMS, not in a tenant
database. Wrap the audit trail in `MemorySignAudit` (or your own
`SignAudit`) and the chain's `verify` will name the first tampered entry.

The signing hashes are computed here, not trusted from the caller: RLP +
keccak256 for an EIP-1559 transaction, `userOpHash` for a v0.7 packed
UserOperation, `0x1901 || domain separator || struct hash` for EIP-712.
Known-answer tests pin all of them to published vectors.

Pure Rust, no network, nothing key-specific leaves the process; builds for
`wasm32-unknown-unknown`. `fakes` and `conformance` ship in the crate so a
provider can be built against the same suite the reference implementations
pass.
