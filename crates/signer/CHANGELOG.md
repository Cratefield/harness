# Changelog

All notable changes to `cratefield-signer` are documented here.

## [Unreleased]

## [0.1.1](https://github.com/Cratefield/harness/compare/cratefield-signer-v0.1.0...cratefield-signer-v0.1.1) - 2026-10-19

### Other

- updated the following local packages: cratefield-secrets

- Key-reference signing port (`KeySigner`), payloads (`EvmTransaction`,
  `UserOperation`, `Eip712`, `SolanaMessage`) with locally computed signing
  hashes, `StaticGuardrails`, the `MemorySignAudit` hash chain, the
  `GuardedSigner` composition, the `SecretsSigner` session-key provider, and
  the `fakes` / `conformance` kit (issue #761).
