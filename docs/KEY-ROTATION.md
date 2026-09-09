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
| Signing key (`HARNESS_SECRET`) | Yearly, and immediately on incident — see "Signing keys" | Owner |
| Rehearsal on staging | Quarterly, with timings recorded below | Owner |

## Rehearsal record

| Date | Environment | Tenants | Secrets | Duration | Read failures | Notes |
| :--- | :--- | ---: | ---: | ---: | ---: | :--- |
| — | — | — | — | — | — | Not yet rehearsed. The first entry is the one that matters: it is what tells you whether the yearly rotation is a five-minute job or a maintenance window. |

## Signing keys (the token ring)

`HARNESS_SECRET` is a different kind of key from the DEKs above. It signs
confirm, status and unsubscribe links (ADR 0006, as amended by ADR 0014),
and no table row names the key that minted a link — only the token's own
`kid` does. The ring is bounded (issue #137): one signing key plus three
demoted or revoked entries, so a token survives at most three rotations
after it was minted, then its key is retired and the link dies. That is
the documented price of being able to revoke a compromised key without a
token table.

### Planned rotation (nothing leaked)

```sh
wrangler secret put HARNESS_SECRET_PREVIOUS  # the old HARNESS_SECRET value
wrangler secret put HARNESS_SECRET           # a fresh one, >= 32 bytes
```

The next cold start builds the new ring: the old value verifies what it
signed but can no longer sign anything. Clear `HARNESS_SECRET_PREVIOUS`
only once no link you care about can still be alive: confirm tokens expire
after seven days and status tokens after ninety (mint-time ceilings,
ADR 0014), but a *signed* unsubscribe link lives as long as its key stays
in the ring. The opaque unsubscribe tokens `module-email-signup` mails
(issue #137) are unaffected by any key event: they live in the
subscriber's row and the next mail retires them.

### After a leak (revocation, not deletion)

Revoke by key id and deploy. Revocation is a state on the ring, not a
deletion race, so the secret does not have to vanish from the environment
in the same release:

```sh
wrangler secret put HARNESS_SECRET_REVOKED   # ids, comma-separated: "prev" or a name
```

- A leaked `HARNESS_SECRET` value: rotate it and do **not** carry the
  leaked value into `HARNESS_SECRET_PREVIOUS` — then no ring entry holds
  it and its links stop verifying immediately.
  `HARNESS_SECRET_REVOKED` cannot name `cur`: `cur` is rebuilt from the
  current secret at every boot, and dropping a leaked value from the ring
  is exactly the rotation above.
- A leaked `HARNESS_SECRET_PREVIOUS` value: list `prev`. Its signatures
  are refused now, its id is burned, and that secret can never re-enter
  the ring under another name.
- A leaked named key from tooling-built rings: list its name (max 32
  characters).

Every revocation also kills the links that key signed, so revoke keys
that only ever minted bounded-lifetime purposes. If you need to sever one
subscriber's never-dying link, that is what the opaque unsubscribe token
replaced the signed link for.

### Cross-venture binding

Tokens are stamped with `HARNESS_VENTURE` and `ENV` (issue #137): a token
minted in one venture or environment never verifies in another, so a
leaked staging secret cannot sign production links. Links already mailed
without the stamp keep verifying — switching binding on does not break
the wild — but the unbound population only shrinks.

## What is not built yet

- The `harness secrets` and `harness audit` commands above. The
  operations themselves are implemented and tested
  (`SecretStore::rotate_dek`, `SecretStore::rewrap`,
  `cratefield_secrets::verify`); wiring commands that address a tenant by
  id needs the tenant registry and the control database (#32).
- The quarterly rehearsal as a scheduled task with an owner.
