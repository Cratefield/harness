# ADR 0014: Bounded key ring, mint-time token policy, revocable links

Status: accepted, 2026-09-09. Amends ADR 0006, which it does not retract.

## Context

ADR 0006's signer has exactly two named slots — `cur` and `prev` — and two
kinds of lifetime: confirm tokens expire, unsubscribe tokens never do. That
shape has three problems, all of issue #137.

1. **A key cannot be revoked, only deleted.** With two slots, forgetting a
   compromised secret and retiring it are the same act, so revoking a key
   kills every link ever signed with it — including the unsubscribe links
   that by contract must never die. Revocation has to be a state, and it
   has to survive the secret still being configured while an operator
   decides.
2. **The caller owns expiry.** A missing `exp` means "forever", which is a
   policy nobody wrote down: the waitlist mints indefinite status links,
   and forever-URLs live in logs, forwards and bookmarks permanently.
3. **Tokens are global.** Any token verifies in every venture and every
   environment; one leaked test secret mints links that production
   accepts.

## Decision

- `HmacSigner` verifies against a `KeyRing` of at most **four** keys, each
  in one of three states: `Signing` (exactly one; mints every new token),
  `VerifyingOnly` (demoted, still accepts what it signed), `Revoked` (its
  signatures are refused even while its secret stays configured, and its
  id is burned — it can never re-enter, under its own or anyone's name).
- The wire format is unchanged: `base64url(json).base64url(hmac)`, the MAC
  over the encoded payload, so a token keeps exactly one valid encoding.
  The JSON gains an optional `iss`; `kid` accepts `cur`, `prev`, or a
  name up to 32 characters. Verification MACs every live key in
  constant time with no early exit — the superset of the old named-key
  plus fallback, which is what lets pre-ring tokens survive. `Kid::Prev`
  no longer signs: verification-only means verification-only.
- A `TokenPolicy` bounds every lifetime **at mint**: `confirm` seven days,
  `status` ninety, anything else thirty, and `unsubscribe` deliberately
  none. A requested `exp` past the ceiling is clamped down; a missing
  `exp` gets the ceiling, never "forever by omission". Verification never
  re-clamps, so links already in the wild keep working.
- Runtimes bind their signer: `iss` is venture plus environment, stamped
  into every new token. A token that carries an `iss` verifies only under
  the same one; a legacy token without it still verifies, so already-mailed
  links survive turning binding on — but a bound signer never mints one.
  The binding lives in the payload, not in an `aud` claim or a second key.
- The non-expiring unsubscribe link gains a revocable shape:
  `module-email-signup` stores an **opaque per-subscription token** (two
  ULIDs, ~160 bits, no signature) on the subscriber row, mails that, and
  the next mail retires the old one. Deleting or re-confirming a subscriber
  revokes their link without touching any key. The pre-#137 signed form is
  still accepted — links in the wild must not die — and a dot in the token
  is the format discriminator.

## Consequences

The tension this ADR exists to settle — longevity versus revocation — is a
menu, not a compromise:

| Want | Get it by | Cost |
|---|---|---|
| a link that never dies | the signed `unsubscribe` purpose | it is revocable only by destroying the key, which revokes every such link for every subscriber |
| a link that dies on demand | the opaque token in the row | one column; the link outlives no key event at all, and the next mail replaces it |
| a key's tokens dead today | `revoke(kid)` | everything that key ever signed dies too, so only bounded-lifetime purposes (confirm, status) are safe to sign with a key you may revoke |
| long link history | a bigger ring | the ring is bounded at four: a token outlives three rotations, then its key is retired and the link dies |

- A retired verification-only key leaves a bytes-empty tombstone (the id is
  burned, the secret is gone) while the ring has room for one; under
  capacity pressure the oldest burned name decays — bounded memory beats
  remembering every name forever, the same rule `revoke` applies to a full
  ring.
- `HARNESS_SECRET_PREVIOUS` becomes the positional `prev`
  verification-only entry and now meets the same 32-byte minimum as
  `HARNESS_SECRET`; the old signer length-checked only the current secret.
- Waitlist status links, minted with no expiry before this ADR, are clamped
  to ninety days by the policy from the first mint after it; no module
  change was needed.
- The ring is built once per isolate and frozen inside the signer (ADR
  0007: not ambient request state). Rotating keys in a running Worker still
  means updating the secrets and letting the next cold start build a new
  ring — the runbook is `docs/KEY-ROTATION.md`.
