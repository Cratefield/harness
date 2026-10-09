# Passkey PRF — a user-held key for sealed data

The WebAuthn `prf` extension lets a passkey's ceremony output 32 deterministic
bytes derived from the credential's own secret plus a salt. The bytes never
leave the client: the server stores only the salt and a capability flag, and
the client stretches the output into a non-extractable WebCrypto key with
`@cratefield/auth`'s PRF helpers. That is a key the **user holds** and the
**server never sees** — suitable for sealing notes, Sealbin content, wallet
keys and API keys so that neither a database leak nor the auth instance
itself can decrypt them.

The TypeScript side lives in `packages/auth-ts` (`getPrfKey`, `derivePrfKey`,
`redactPrfResults`, `hasPrfCapablePasskey`); the server side (salts,
capability recording, redaction enforcement) is the auth-passkeys module —
`GET /v1/auth-passkeys/passkeys/prf` is its listing route; see its README for
the rest.

## The rule first: always enrol two unlock methods

**Before sealing anything, the user must have at least two independent unlock
methods — e.g. two PRF-capable passkeys enrolled on different providers, or a
PRF passkey plus a recovery key.** The PRF output is a function of the
authenticator's secret, which no server holds a copy of: if the only
authenticator is lost — a phone dropped in the sea, a password manager
account locked out — the sealed data is unrecoverable, and **the server
cannot help**. The salts are stored precisely so any *other* capable
authenticator can derive the same key; one capable credential is one point of
failure. Gates that enable sealed storage should require
`hasPrfCapablePasskey` and nudge toward enrolling a second method.

## The flow

1. **Registration.** The server includes `extensions.prf = {}` in the
   creation options and records a capability per credential — `supported`
   when the authenticator's signed `hmac-secret: true` or the client's
   redacted `enabled: true` says it can evaluate, `unknown` otherwise;
   it never records `unsupported` at creation — plus a per-credential
   random 32-byte `prfSalt` (base64url, no padding). The salt is not secret —
   it only has to be unique per credential so the PRF outputs of different
   credentials diverge. The register verify response names both, as `prf`
   and `prfSalt` — omitted when the row could not be written. The
   credential is already stored by then, so the ceremony still succeeds and
   the pair turns up once the row is created lazily at the next login.
2. **Listing.** `GET /v1/auth-passkeys/passkeys/prf` (a session is
   required) returns the caller's own passkeys as
   `{ passkeys: [{ credentialId, prf, prfSalt }] }`. This is what a client
   passes to `getPrfKey`.
3. **Derivation.** The client runs a fresh ceremony with the listed
   credentials and derives a purpose-bound key:

   ```ts
   import { getPrfKey } from '@cratefield/auth';

   // One browser unlock (userVerification: "required"), one key.
   const key = await getPrfKey(
     passkeys.map((passkey) => passkey.credentialId), // b64url ids
     passkeys.map((passkey) => passkey.prfSalt),      // matching salts, same order
     { info: 'cratefield:sealed-notes:v1' },
   );
   // `key` is a non-extractable AES-GCM-256 key; seal/decrypt locally.
   ```

   `getPrfKey` sends `eval.first` when one credential is allowed and
   `evalByCredential` (keyed by base64url credential id) when several are;
   discovers which credential the user actually unlocked; **checks the raw
   output is present and 32 bytes long**; and throws `PrfUnavailableError`
   otherwise. A browser's or extension's own support claim is never trusted:
   `prf.enabled` and `PublicKeyCredential.getClientCapabilities()` have both
   been observed true on providers that cannot actually evaluate (below), so
   only real `results` count.

   The raw PRF bytes go straight into HKDF-SHA256 (fixed empty salt, `info`
   = UTF-8 of the purpose string, non-extractable output key) and are not
   kept: `derivePrfKey(prfOutput, info)` is the pure, testable half if you
   already hold an output.
4. **Reporting back.** The server **never accepts PRF output** — a ceremony
   result posted with `clientExtensionResults.prf.results` is rejected with
   `400`, `auth/passkey-prf-output-rejected`, before the challenge is spent
   or anything is stored. Post the redacted form instead:

   ```ts
   import { redactPrfResults } from '@cratefield/auth';

   // { prf: { enabled: true|false } }, other extensions preserved.
   await post('/ceremony/complete', redactPrfResults(credential.getClientExtensionResults()));
   ```

   `enabled` is `true` exactly when the ceremony produced a `first` result —
   a fact the client observed, not a claim it repeats.

## Capability states

`prf` per credential, as the server records it:

| State | Meaning | Becomes |
| --- | --- | --- |
| `unknown` | Registered before PRF was requested, or the provider has not said | `supported`/`unsupported` after the first evaluated ceremony that posts a redacted result |
| `supported` | The authenticator's signed `hmac-secret: true` at registration, or an evaluation that produced a real 32-byte result (`enabled: true` posted) | Sticky; a later `enabled: false` does not demote it |
| `unsupported` | The authenticator returned nothing (`enabled: false` posted) | `supported` if a later evaluation succeeds |

A venture enabling sealed storage should require at least one `supported`
passkey — `hasPrfCapablePasskey(passkeys)` — and treat `unknown` as *not*
capable until an evaluation proves otherwise. `unknown` exists because some
providers (Samsung Pass, for one) only report the extension on the `get`
*after* the one that first evaluated it.

## HKDF `info`: one purpose, one string

The key domain is `info` alone (the salt is fixed and empty: the PRF output
is already uniform and secret, so a salt would add nothing, and pinning it
keeps derivations portable across providers). Every independent use of the
key gets its own versioned string — `cratefield:sealed-notes:v1`,
`cratefield:wallet:v1`, `cratefield:api-keys:v1` — and the same string always
yields the same key for the same credential, on every device and provider.
Changing a string rotates every key derived under it; reusing one string for
two purposes lets both purposes decrypt each other. The same PRF output can
feed many purposes; the outputs are independent keys.

## Support matrix (2026)

| Provider | PRF via `getPrfKey` |
| --- | --- |
| Apple Passwords (iOS ≥ 18.4, macOS ≥ 15; Safari and anything using the platform provider) | Works |
| Google Password Manager (Android, Chrome) | Works |
| Windows Hello | Works from the Feb 2026 Windows update, with Chrome/Edge ≥ 147 |
| 1Password, Proton Pass, Keeper | Works |
| Bitwarden | Partial |
| Microsoft Password Manager in Edge | **Broken for evaluation**: registration may report `enabled`, but `get` fails to produce results |
| Hardware security keys | Only those implementing CTAP2 `hmac-secret` |
| Samsung Pass | Often reports PRF only on the `get` after the first evaluation (hence `unknown` above) |

This is exactly why capability is measured, not claimed: a browser can say
`enabled` (Edge) or stay silent on the first try (Samsung) and still work —
or claim `enabled` and never work (Microsoft Password Manager).

## Discoverable/autofill logins get no PRF evaluation

A discoverable-credential or autofill login sends no `allowCredentials`, and
without an allow list there is nothing to evaluate salts against — the
ceremony carries no `prf.eval`. That login is still a perfectly good sign-in;
it just cannot produce the key. After signing in that way, call `getPrfKey`
with the credentials from `GET /v1/auth-passkeys/passkeys/prf`: it runs its own
unlock (a second, quick user verification) and returns the key.
