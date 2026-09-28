# ADR 0103: A versioned Worker-secret KEK is the accepted production KMS

Status: accepted, 2026-09-28

## Context

The KMS port (#40) has one provider: `LocalFileKms` (ADR 0102's cipher
behind a key file), which refuses to construct in production — its
master key sits on a local disk, which is the property a KMS exists to
remove. That is correct for what it is and useless where the harness
actually runs: a Worker has no filesystem to hold the file. The managed
vendor providers (AWS KMS, GCP KMS) are still unwritten, deliberately:
each needs credentials and a nightly job against the real service, and
an unexercised vendor integration in this position is worse than an
absent one (`docs/SECRETS-DESIGN.md` §5).

Production still needs to wrap data keys.

## Decision

**`WorkerSecretKms` (`crates/kms/src/worker_secret.rs`, #535) is an
accepted production KMS for the Cloudflare path.** The KEK is not one
secret but a small numbered set: `HARNESS_KEK_CURRENT` holds the decimal
version new wraps use, and `HARNESS_KEK_V1`, `HARNESS_KEK_V2`, … hold
the key material (standard base64 of 32 bytes). Everything is read once
at construction, and the current version is bounded (≤ 1024) so a typo
fails at startup rather than firing thousands of missing lookups. Wrap
always uses the current version with a fresh nonce; unwrap dispatches on
the version header in the blob — `version: u32 big-endian || nonce(24)
|| XChaCha20-Poly1305`, with the version inside the AAD so the header is
authenticated like the rest. Rotation is `wrangler secret put
HARNESS_KEK_V<n+1>`, point `HARNESS_KEK_CURRENT` at it, redeploy,
re-wrap, then delete the old secret (`docs/KEY-ROTATION.md`).

It does not refuse production because the KEK lives in the platform's
secret store: encrypted at rest, never on a host disk, never in D1 next
to the wrapped DEKs, readable by nothing that cannot read Worker
secrets. The provider takes a lookup closure rather than a `worker`
binding, so `cratefield-kms` stays wasm-safe with no Worker dependency;
the runtime adapts `env.secret(name)` to it.

## Consequences

- Not an HSM KMS, and not claimed as one: the Worker isolate can read
  the KEK material, and a wrap carries no per-call IAM or audit at the
  key. The compromise of a running isolate exposes the KEK. The Kms
  seam stays, so an HSM-backed provider, if one arrives, is a re-wrap
  rather than a redesign.
- Old versions matter only while blobs still reference them: after a
  re-wrap the old secret is deleted, and a blob wrapped under it fails
  as `KmsError::Tampered`, naming the missing secret — restore the
  secret or re-wrap.
- **Not decided here:** adopting the tenant secrets store on the Worker
  path — a `Secrets` port over this provider — would supersede the
  "Worker path unchanged" scope of ADR 0008 and `docs/SECRETS-DESIGN.md`
  §9. That is a follow-up of #535; until it lands, the Worker deploy
  gains no new bindings from this ADR.
