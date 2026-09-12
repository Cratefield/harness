<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/readme-banner.png" alt="Cratefield Harness. The open-source core. Modules are crates, compiled into one stateless Worker with its own database." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-secrets"><img src="https://img.shields.io/crates/v/cratefield-secrets.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-secrets on crates.io"></a>
  <a href="https://docs.rs/cratefield-secrets"><img src="https://img.shields.io/docsrs/cratefield-secrets?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-secrets documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-secrets

The secrets store (issue #39, `docs/SECRETS-DESIGN.md`, ADR 0102).
Envelope encryption over the `Database` port in two tiers: global secrets
in the control database, tenant secrets in that tenant's own database.

Each store holds its own wrapped data key, which the KMS unwraps and never
stores, so a database dump is ciphertext plus a blob nobody outside the KMS
can open. Every ciphertext is bound by the AEAD's additional data to its
store, name, version and key id, so a row that is copied, renamed, rolled
back or repointed fails to decrypt rather than quietly succeeding.

`SecretBytes` zeroises on drop, prints as `[redacted]`, and implements
neither `Display`, `Serialize` nor `Clone`.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
