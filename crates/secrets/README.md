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
