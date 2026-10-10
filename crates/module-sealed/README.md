# cratefield-module-sealed

The server half of Cratefield's sealed-blob store (issue #757). A client —
the `@cratefield/sealed` TypeScript package — encrypts data in the browser
under a content key that is wrapped once per unlock (a passkey PRF output or
an Argon2id recovery code) and posts the result here. This module stores it,
serves it back byte-identical, and never learns what it holds.

```rust,no_run
use cratefield_kms::{Dek, Kms, KmsError};
use cratefield_module_sealed::{NoopNotifier, Sealed};

struct MyKms;

#[async_trait::async_trait]
impl Kms for MyKms {
    fn provider(&self) -> &'static str {
        "example"
    }

    fn key_ref(&self) -> &str {
        "example-key"
    }

    // A real provider wraps the data key under its master key, and
    // `unwrap` reverses exactly that; this stub stores nothing anywhere.
    async fn wrap(&self, dek: &Dek) -> Result<Vec<u8>, KmsError> {
        Ok(dek.expose().to_vec())
    }

    async fn unwrap(&self, wrapped: &[u8]) -> Result<Dek, KmsError> {
        Dek::from_bytes(wrapped.to_vec())
    }
}

let module =
    Sealed::new(std::sync::Arc::new(MyKms), std::sync::Arc::new(NoopNotifier));
```

Mounted at `/v1/sealed`. The `Db`, `Auth` and `Blob` ports are declared
required, `RateLimiter` and `Clock` used-when-present, and a
[`cratefield_kms::Kms`] comes with the constructor — the KMS is not a
`Port` because the harness has no binding for one yet; a venture wires the
provider it chose when it composes the module.

## What the server holds

The client posts `{blob_id, version, purpose, alg, ciphertext, wraps,
created_by_credential}`. The server treats `ciphertext` and `wraps` as
opaque bytes — it validates their wire shape and nothing else. On the way in
it seals the client's ciphertext body under a fresh per-blob data key
(AES-256-GCM, additional authenticated data binding
`subject|blob_id|version`) and stores the DEK wrapped by the KMS. Three
tables:

- `sealed_blobs` — one row per `(subject, blob_id)`: the outer-wrapped body
  (inline below `INLINE_BODY_MAX_BYTES`, in the blob store above it), the
  client's wraps as JSON, and the metadata the wire record carries.
- `sealed_deks` — the wrapped per-blob data key, in a table of its own so
  erasure is a visible, countable row deletion.
- `sealed_audit` — the append-only, hash-chained access log. Every read is
  appended; `crate::audit::verify` walks the chain and names the first
  broken link. An append that loses a sequence race retries on the new head;
  under sustained contention it fails loudly — refusing the request — rather
  than let a mutation commit unrecorded.

**The outer wrap is defence in depth, not a decryption service.** The server
unwraps a DEK only to serve a record back to its subject; it has no code
path — no endpoint, no function — that decrypts the client layer, and the
content key itself never exists outside the user's device. There is no
server-side recovery path: lose every unlock and the data is gone, by
design.

## Erasure is crypto-shredding

`DELETE /v1/sealed/blobs/{id}` deletes the DEK row first, then the body row
and the blob-store object, in one atomic batch followed by the object
removal. From the moment the DEK row is gone, every remaining copy of the
body — in a database backup, a replica that has not caught up, an object the
object-store delete missed — is inert ciphertext. The same shred happens
through `cratefield-module-privacy`, whose erasure deletes both declared
tables from the personal-data catalog. What an export returns is the
metadata, the wrap set, and the body as the server holds it — in the outer
wrap, so not bytes the user can open; a venture honouring a portability
request serves the wire record through the API instead, which hands back
exactly the client ciphertext.

The `sealed_audit` rows are declared `Retain`: the chain is append-only and
tamper-evident precisely so that no one — including an operator — can
remove one person's rows without breaking the proof that nobody altered
anyone else's. A retained row holds the subject id, the blob id, the action
and the time. It never holds content, because the server never has any.

## Routes

All routes are subject-scoped: the caller must present a credential the
deployment's `Auth` port accepts, and every query is bounded by the
authenticated subject's id, never by a value in the request.

- `POST /blobs` — create; `201` with the stored record.
- `GET /blobs` — list the subject's blob metadata (no bodies).
- `GET /blobs/{blob_id}` — read; rate-limited per subject and appended to
  the audit chain, and fires the "blob unlocked" notification.
- `PUT /blobs/{blob_id}/wraps` — replace the wrap set; the payload is
  untouched, and at least two wraps remain required. Guarded by `If-Match`
  (below).
- `PUT /blobs/{blob_id}` — content-key rotation: a new payload and wrap set
  under a fresh DEK, `version` bumped. Guarded by `If-Match` (below).
- `DELETE /blobs/{blob_id}` — erase; the crypto-shred above.

`created_by_credential` comes from the request body: the signed-in subject
(`Auth`) exposes an id, a session and a verified address, but not the
WebAuthn credential behind the session, and the client — which ran the
ceremony — records which credential owns the PRF wrap. The server validates
that it is present and stores it opaquely.

## Concurrent writes: `ETag` and `If-Match`

Every record response — read, create, wrap edit, rotation, and the list —
carries an `ETag` naming the server-side revision the response was built
from (the `revision` column; `version` cannot serve, because the client's
payload AAD binds it, so a wrap edit must leave it alone). The two mutating
routes are compare-and-swap writes: they must echo that `ETag` back as
`If-Match`.

- A wrap edit or rotation **without** `If-Match` is refused with `428`
  (`sealed-precondition-required`) rather than applied blind.
- One whose `If-Match` no longer matches — somebody wrote first — is
  refused with `412` (`sealed-precondition-failed`), and writes nothing:
  of two rotations racing from the same revision exactly one lands, and
  the loser's new body never mixes with the winner's key material.
  `If-Match: *` is not accepted — "any state will do" is the one thing a
  compare-and-swap write may not assert.

The guard lives in the storage layer itself: the `UPDATE` carries the
revision in its `WHERE` clause and writes a fresh value there, and the
read-back after the batch attributes the row's state to one request. A lost
race therefore cannot commit half of itself, at any layer. The wire body is
unchanged — the TypeScript client keeps sending `{version, wraps}` and only
adds the header. A body too big for the row parks in the blob store under an
object key unique to that one write, so a rotation frees the previous body
only after the commit names the new one, and a refused create never unparks
a body that belongs to a live record.

## Notification

[`crate::notify::UnlockNotifier`] is the "blob unlocked" hook fired on every
download. The default is a no-op; [`crate::notify::MailNotifier`] sends a
short notice through the harness `Mailer` port to the subject's verified
address when the deployment's verifier provides one (no address, no notice —
the server does not guess one); a recording fake backs the tests, and
[`crate::notify::conformance`] holds any implementation to the contract. A
notification failure is logged and never fails the download.

## Documented limits

- **Offline automation is impossible by design.** Opening a record needs a
  user unlock — a passkey touch or a recovery code — so nothing server-side,
  scheduled or otherwise, can read a blob. A venture that needs server-side
  automation over this data should not use this module for it.
- **A compromised server can serve malicious JavaScript.** The client runs
  in the browser, so an attacker who controls what the origin serves can
  steal unlocks as they happen — no storage design helps. Mitigate by
  serving the app from a separate static origin, pinning scripts with SRI,
  a strict CSP, and reviewing signed releases.
- **Custody reads on the key.** Some regulators treat access to a user's
  *encrypted* key material as custody of the asset it protects (SEC staff
  statement of 2026-04-13). A venture whose sealed blobs protect regulated
  assets should prefer designs where no one but the user ever holds the key
  — passkey-owned smart accounts — over any layout in which this module's
  tables are load-bearing.
- **No server-side recovery path**, as above. This is a promise, not a gap:
  there is no escrowed key, no override, and no endpoint that returns
  plaintext.
