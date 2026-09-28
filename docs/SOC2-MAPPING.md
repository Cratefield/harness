# SOC 2 control mapping

Issue #43 (epic #24). One row per Trust Services Criteria point this
repository claims, the mechanism that satisfies it, and the evidence
artifact at a real path in this tree. Scope is the schema and secrets
epics only (#23–#44); HR, vendor management and physical controls are out
of scope and not claimed.

**The rule:** every evidence link must resolve. A control with no
evidence in this repository is marked a gap, not papered over with a
description.

**Status of the document itself:** not yet reviewed by whoever runs the
SOC 2 programme. Human review, with gaps turned into issues, is a
separate step and is outstanding (issue #43's acceptance criterion).

| Control | Mechanism | Evidence | Owner | Review date | Gaps |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CC6.1** Logical access — tenant isolation and least privilege | One database per tenant (secrets, migration history and audit log live in the tenant's own database); two-tier secrets with the global store unreachable from module code — by API and by credentials; `Secrets::global()` takes a `HarnessOnly` token only the harness can construct | `docs/adr/0008-native-runtime-is-multi-tenant-database-per-tenant.md`; `docs/TENANT-ONBOARDING.md` §1 (the role scoped to one database, step 2); `docs/SECRETS-DESIGN.md` §1–§2; `crates/secrets/src/store.rs` (`HarnessOnly`, `Secrets::global`, `Secrets::tenant`) | Harness owner (@Nick-CHI) | 2027-03-01 | The multi-tenant native runtime that instantiates this shape is #32 and unbuilt (see the "native runtime" section of `docs/SECURITY.md`); the isolation claim today is architectural, enforced by tests, not by deployed tenants |
| **CC6.6** Encryption at rest | Envelope encryption: XChaCha20-Poly1305 AEAD, 24-random-byte nonces, per-store 256-bit DEKs wrapped by a non-exportable KEK; every ciphertext sealed with injective AAD binding store, name, version and key id, so a moved, renamed or repointed row fails to decrypt; `SecretBytes` zeroises on drop and is not `Serialize`/`Clone` | `docs/SECRETS-DESIGN.md` §2–§5 and §7 (threat model); `docs/adr/0102-crypto-crate.md`; `crates/secrets/src/lib.rs` (`aad`, `SecretBytes`); `spikes/crypto/tests/roundtrip.rs` (attack-mode proofs); `crates/kms/src/lib.rs` (`Dek`, `KmsError` unavailability/denied/tampered split) | Harness owner (@Nick-CHI) | 2027-03-01 | Managed KMS providers are not written; the Worker-secret KEK provider exists in the crate (ADR 0103, `crates/kms/src/worker_secret.rs`) but nothing wires a KMS into a runtime yet (`docs/SECRETS-DESIGN.md` §5, "The port") — production today still uses wrangler bindings, to which this control does not yet apply |
| **CC6.7** Key management — rotation | Two documented operations, both implemented and tested: DEK rotation (`rotate_dek`, single-transaction new-key install, safe to interrupt, idempotent) and re-wrap under a new master key (`rewrap`); the old key row is never deleted, so a pre-rotation restore still unwraps; `LocalFileKms` refuses to construct in production; every provider passes a conformance suite | `docs/KEY-ROTATION.md` (runbook, cadence table, rollback position); `docs/TENANT-ONBOARDING.md` §2 (the crypto-shred in offboarding); `crates/secrets/src/rotate.rs` (`RotationReport`, `RewrapReport`); `crates/kms/src/local.rs` (production refusal); `crates/kms/src/lib.rs` (`conformance`) | Harness owner (@Nick-CHI) | 2027-03-01 | **Rehearsal record is empty** — `docs/KEY-ROTATION.md` "Rehearsal record" has no entries; the quarterly staging rehearsal is not a scheduled task. The `harness secrets` / `harness audit` CLI commands are unwired (operations exist; command wiring awaits #32) |
| **CC7.2** Monitoring — secret access | Append-only, tamper-evident audit chain per store: a trigger refuses `UPDATE`/`DELETE` for every role including the migration role; each row's SHA-256 covers the previous row's hash, so `verify` names the first broken link; `verify` returns an `Anchor` (store, seq, last hash) for publication, closing the truncation blind spot; the store **refuses the access** when the sink cannot record it | `crates/secrets/src/audit.rs` (`ChainAudit`, `verify`, `Anchor`); `crates/secrets/src/lib.rs` (`AuditEvent`, every method records on success and failure); `docs/SECRETS-DESIGN.md` §5 "The audit chain" (mechanism table, volume analysis) | Harness owner (@Nick-CHI) | 2027-03-01 | No alerting pipeline in this repository: the KMS error-rate and cold-process-decrypt alarms in `docs/SECRETS-DESIGN.md` §6 are specified, not implemented; audit-log ingestion and unwrap-storm alerting are open question #4 of the same document |
| **CC8.1** Change management | Forward-only migrations with a never-edit rule enforced twice: the CI `migration-guard` job ("migrations are never edited") and a checksum comparison at boot; plus the standing PR gates — rustfmt, clippy `-D warnings`, `cargo deny` (advisories are deny), wasm dependency-boundary checks, and the drift checks for the error taxonomy and compatibility matrix | `.github/workflows/ci.yml` (`migration-guard`, `fmt`, `clippy`, `test`, `deny`, `doc-commands` jobs); `docs/adr/0004-sea-query-and-portable-sql-migrations.md`; `docs/RECONCILIATION.md` (boot-time checksum and failure behaviour); `CODEOWNERS` (single owner reviews every path) | Harness owner (@Nick-CHI) | 2027-03-01 | Single-owner review (@Nick-CHI in `CODEOWNERS`) is a bus-factor risk an auditor may flag; broadening review is an organisational decision outside this repository |
| **A1.2** Recovery (availability) | Written rollback and recovery runbooks for forward-only migrations: A (failed part-way — transactional vs non-transactional), B (applied and wrong — forward fix or scratch restore), C (rewind one tenant via D1 Time Travel / Postgres PITR; migration history travels inside the database), D (code rollback with an expand/contract discipline); backup requirements specified: PITR ≥ 30 days, nightly export retained 90 days, export before any backfill migration | `docs/ROLLBACK.md` §1–§6 (runbooks and the requirements table); `docs/TENANT-ONBOARDING.md` §1 (PITR at provisioning, step 1); `docs/RECONCILIATION.md`; `docs/DATA-MOVE.md` (`fz data export` / `fz data import`) | Harness owner (@Nick-CHI) | 2027-03-01 | **Restore drill has never been run** — `docs/ROLLBACK.md` §7 states this plainly; the quarterly timed drill required by §6 is unexecuted. Backup implementation is filed as issue #203, not built. Runbook C has never been executed against a real database (document's own status banner) |

## How to read the gaps

Four gaps are material and each already has a home:

1. **Rehearsals not run** (CC6.7, A1.2) — the controls' mechanisms exist
   and are tested; the operational proof (timed rehearsal, restore
   drill) does not. `docs/KEY-ROTATION.md` and `docs/ROLLBACK.md` §7 are
   the records to fill.
2. **No alerting pipeline** (CC7.2) — the audit chain and anchors are
   produced and verifiable, but nothing consumes them automatically.
3. **Multi-tenant runtime unbuilt** (CC6.1, and indirectly the rest) —
   the controls are designed and enforced in the crates, but #32 must
   land before the rows describe a deployed system rather than a
   tested one.
4. **Human review of this table** — the issue's acceptance criterion;
   the reviewer either accepts each row or opens an issue for its gap.

## Review record

| Date | Reviewer | Outcome |
| :--- | :--- | :--- |
| — | — | Awaiting first review (issue #43) |
