# @cratefield/sealed

Browser-side envelope crypto for the **Cratefield sealed-blob store**: AES-256-GCM
payloads whose content key is wrapped once per unlock — a passkey PRF output or
an Argon2id-stretched recovery code. The server stores ciphertext and wraps; it
never sees a plaintext, a content key, or any unlock secret. It is the
TypeScript counterpart of the Rust `module-sealed` crate, which validates the
same wire format without ever being able to open a blob.

It depends only on Web-standard APIs (WebCrypto, TextEncoder/TextDecoder,
atob/btoa) plus `hash-wasm` for Argon2id, which the WebCrypto platforms refuse
to implement.

## Usage

```ts
import { generateRecoveryCode, newBlobId, newPrfSalt, open, seal } from '@cratefield/sealed';

// `prfOutput` is the 32-byte result of evaluating the WebAuthn `prf`
// extension for the credential — `navigator.credentials.get` with
// `extensions: {prf: {eval: {first: prfSalt}}}`. @cratefield/auth exposes a
// helper for that evaluation; this package takes the bytes from there.
const prfSalt = newPrfSalt(); // stored publicly in the wrap; replay on unlock
const prfOutput = await evaluatePrf(credentialId, prfSalt); // 32 bytes
const recoveryCode = generateRecoveryCode(); // show once, then the user keeps it offline

const created = await seal({
  subject: 'user_123',
  blobId: newBlobId(), // client-generated: it is bound into the AAD
  purpose: 'vault.notes',
  plaintext: new TextEncoder().encode('attack at dawn'),
  unlocks: [
    { kind: 'prf', credentialId, prfOutput, prfSalt },
    { kind: 'recovery', code: recoveryCode },
  ],
  createdByCredential: credentialId,
});
await fetch('/blobs', { method: 'POST', body: JSON.stringify(created) });
```

Opening needs the record from `GET /blobs/{id}` plus one unlock:

```ts
const record = await (await fetch(`/blobs/${blobId}`)).json();
const plaintext = await open(record, { kind: 'prf', credentialId, prfOutput });
// or, when the passkey is lost:
const plaintext = await open(record, { kind: 'recovery', code: typedRecoveryCode });
```

Wrap edits never touch the payload — they return the body for
`PUT /blobs/{id}/wraps`:

```ts
import { addWrap, removeWrap, rotateWraps } from '@cratefield/sealed';

await addWrap(record, unlock, { kind: 'recovery', id: 'recovery-paper', code: printedCode });
removeWrap(record, 'recovery-paper'); // no unlock needed; never below two wraps
await rotateWraps(record, unlock, newUnlocks); // retire unlock *identifiers*
```

The server stamps every read with an `ETag` and requires it back as `If-Match`
on wrap edits and on rotation: send the `ETag` of the record you based the edit
on, and a `PUT` fails with `412` on a mismatch or `428` if the header is
missing. That way a stale wrap edit from another device is refused instead of
silently winning.

Only `rotateContentKey` re-encrypts — use it when the content key itself may
have leaked. It returns the full `PUT /blobs/{id}` body with `version` bumped
so the server can reject lost updates.

A record is refused at `open` unless it carries **at least two wraps**, and a
recovery wrap asking for Argon2id below the floor (64 MiB, 3 passes, 1 lane)
fails the whole record — a below-floor wrap is one a thief could brute-force
offline, so it is treated as tampering, not as a hint.

## Wire format

All JSON keys are snake_case, all binary fields are unpadded base64url, and the
shapes in `src/types.ts` are the contract with the server crate:

- `ciphertext` — `nonce ‖ ciphertext ‖ tag`: AES-256-GCM with a fresh 12-byte
  nonce and 16-byte tag. The additional authenticated data is
  `subject|blob_id|version|purpose`, UTF-8 — so a record moved between
  subjects, renamed or re-versioned without re-encryption fails to decrypt.
- One wrap per unlock. `prf`: KEK = HKDF-SHA256 over the 32-byte PRF output,
  with the wrap's `salt` (the same bytes evaluated by the authenticator) as the
  HKDF salt and `cratefield/sealed/v1/prf|subject|blob_id` as `info`.
  `recovery`: KEK = Argon2id over the normalised code (dashes and spaces
  stripped, Crockford look-alikes folded) with a per-wrap 16-byte salt.
- The content key is AES-256 and travels only as `wrapped_key` — AES-KW output,
  40 bytes, one per wrap.

## Threat model

**What this protects:** a fully compromised server — database dump, backups, a
curious operator — reads only ciphertext and wrapped keys. Neither unlock
material nor content key ever reaches it; `blob_id` is client-generated so the
server cannot choose AAD input; AES-GCM verification catches any record the
server moves, edits or re-purposes.

**What it cannot protect:** the browser that renders the app. The client that
decrypts is whatever JavaScript the server serves, so a compromised server can
simply serve code that exfiltrates unlocks as they are used. Sealing bounds
what an attacker learns from storage alone; it does not make the server
trustworthy. The usual mitigations apply, and ventures using sealed blobs
should adopt them: serve the app from a separate static origin so the API
compromise is not automatically a code compromise, pin scripts with
subresource integrity, run a strict CSP, and verify signed releases.

**Documented limits** (issue #757):

- **Offline automation is impossible by design.** Every unlock needs the user
  — a PRF evaluation inside the authenticator, or a typed recovery code.
  Server-side jobs can store and serve sealed blobs but can never read them.
- **A compromised server can serve malicious JS** — see above; mitigate with a
  separate static origin, SRI, strict CSP and signed releases.
- **Regulatory custody risk.** Some regulators read access to a user's
  *encrypted* key as custody of the asset. (SEC staff statement,
  2026-04-13.) Ventures that store other people's value should prefer keyless
  designs — such as passkey-owned smart accounts, where no server ever holds a
  wrapped key — over sealed blobs where they can.
- **There is no server-side recovery path.** Losing every unlock loses the
  data; that is the trade the package exists to make, and nothing can relax it
  after the fact.

## License

MIT
