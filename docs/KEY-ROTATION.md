# Rotating keys

Runbook for issue #42. Two different operations, often confused:

| | What changes | What it costs | When |
| :--- | :--- | :--- | :--- |
| **Data key rotation** | A new DEK becomes active and **every live secret is re-encrypted** under it | One decrypt and one encrypt per live secret version, plus one KMS wrap | Yearly, and after any incident that could have exposed a data key |
| **Re-wrap** | The DEKs are unchanged; their **wrapping** moves to the master key's current material | One KMS unwrap and one wrap per data key. No secret is touched | After the KMS rotates its master key material, or when moving master keys |

Both leave reads working throughout, because a secret row names the key
that sealed it and the old key row stays until nothing references it.

## Before

```sh
# What is there now: one active key, and what is sealed under each.
harness secrets keys --tenant <id>
# What a rotation would do, without doing it.
harness secrets rotate-dek --tenant <id> --plan
# The audit chain is intact before you start.
harness audit verify --tenant <id>
```

Record the count of secret versions per `key_id` and the chain's anchor.
Both are what you compare against afterwards.

## Rotating a data key

```sh
harness secrets rotate-dek --tenant <id>          # one tenant
harness secrets rotate-dek --global               # the control database
```

What it does, in order: installs the new key and marks the old one
`retiring` **in one transaction**, so there is never a moment with two
active keys or none; re-encrypts each live secret version, one at a time;
marks the old key `retired` once nothing references it.

**Interrupting it is safe.** A store whose secrets are split across two
keys is a valid state — every row names its own key — and running the
command again finishes the job.

**A soft-deleted secret keeps the old key `retiring` rather than
`retired`,** deliberately: its ciphertexts are still in the table, and a
key nothing can read is not the same as a key nobody needs. Retire it by
hand once you are sure those rows are gone for good.

## Re-wrapping after a master key rotation

AWS KMS rotates key material in place and old material keeps decrypting,
so nothing breaks at the moment of rotation and there is no rush. Re-wrap
so that no wrapped key still depends on the old material:

```sh
harness secrets rewrap --tenant <id> --plan
harness secrets rewrap --tenant <id>
```

For a provider without in-place rotation, point the harness at the new
master key reference and run the same command: it unwraps under whatever
wrapped each key and wraps again under the current one, recording the new
provider and reference on the row.

## After

```sh
harness secrets keys --tenant <id>      # one active key; the old one retired
harness audit verify --tenant <id>      # a clean chain, and a new anchor
```

Then read one secret through the application. A rotation that passes
every check and breaks the app is the failure mode worth catching.

## Rollback

There is none, and there does not need to be. The old key stays
`retiring` or `retired` in the table rather than being deleted, so a
restore of a database from before the rotation still has a key that
unwraps. Nothing is destroyed until an offboarding shred, which is a
separate, deliberate act (#36).

## Cadence

| What | How often | Owner |
| :--- | :--- | :--- |
| Data key rotation | Yearly, and on incident | Owner |
| Master key | Per the KMS policy, then re-wrap | Owner |
| Rehearsal on staging | Quarterly, with timings recorded below | Owner |

## Rehearsal record

| Date | Environment | Tenants | Secrets | Duration | Read failures | Notes |
| :--- | :--- | ---: | ---: | ---: | ---: | :--- |
| — | — | — | — | — | — | Not yet rehearsed. The first entry is the one that matters: it is what tells you whether the yearly rotation is a five-minute job or a maintenance window. |

## What is not built yet

- The `harness secrets` and `harness audit` commands above. The
  operations themselves are implemented and tested
  (`SecretStore::rotate_dek`, `SecretStore::rewrap`,
  `factory0_secrets::verify`); wiring commands that address a tenant by
  id needs the tenant registry and the control database (#32).
- The quarterly rehearsal as a scheduled task with an owner.
