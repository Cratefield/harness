# Changelog

All notable changes to `cratefield-signer` are documented here.

## [Unreleased]

- Key-reference signing port (`KeySigner`), payloads (`EvmTransaction`,
  `UserOperation`, `Eip712`, `SolanaMessage`) with locally computed signing
  hashes, `StaticGuardrails`, the `MemorySignAudit` hash chain, the
  `GuardedSigner` composition, the `SecretsSigner` session-key provider, and
  the `fakes` / `conformance` kit (issue #761).
