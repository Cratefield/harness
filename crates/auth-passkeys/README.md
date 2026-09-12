# auth-passkeys

Passkey registration and login for the Factory Zero auth service
(issues #13, #14). Mounted at `/v1/auth-passkeys`.

## Routes

| Route | Session | What it does |
|---|---|---|
| `POST /register/options` | required | A challenge plus the RP, the user handle, the algorithms we accept and the credentials to exclude |
| `POST /register/verify` | required | Checks the ceremony and stores the credential |
| `POST /login/options` | no | A challenge; with an email, the account's credential ids, otherwise an empty list for discoverable credentials |
| `POST /login/verify` | no | Checks the assertion, advances the counter, issues a session |
| `GET /credentials` | required | The account's passkeys |
| `DELETE /credentials/{id}` | required | Removes one, unless it is the account's only way in |

## Configuration

| Key | Required | Default |
|---|---|---|
| `AUTH_PASSKEYS_RP_ID` | yes | the registrable domain passkeys are bound to |
| `AUTH_PASSKEYS_ORIGINS` | no | `https://<rp id>`; comma-separated |
| `AUTH_PASSKEYS_RP_NAME` | no | the RP id |
| `AUTH_PASSKEYS_CHALLENGE_TTL_SECS` | no | `300`, bounded to 60..900 |
| `AUTH_PASSKEYS_USER_VERIFICATION` | no | `preferred` |

Every origin must be the RP id or a subdomain of it. That is WebAuthn's own
rule, checked at configuration time because an origin outside it could never
produce a valid ceremony: allowing one would only ever be a way to get it
wrong.

## What this module does not own

Nothing in the database. `auth-core` owns `users`, `credentials`,
`sessions` and `single_use_tokens`, and publishes the typed store API this
module writes through, so the schema has one definition and one migration
history. The `passkey_suspect_at` column this module needs was added there,
in migration `0004`.

## Verification

`webauthn-rs` cannot build for `wasm32-unknown-unknown` — OpenSSL is a hard
dependency of `webauthn-rs-core` — so relying-party verification is
implemented directly on the wire types (ADR 0200). ES256, RS256 and EdDSA
are all accepted; anything else is refused at registration rather than
stored and failed at every later login. Registration requests
`attestation: none` and accepts other formats without verifying them, which
is the ordinary consumer relying-party position; the statement itself is
logged and not retained, since nothing here would ever read it back.

## Two rules that run through the module

**A challenge is spent exactly once**, by a conditional update whose
affected-row count decides the winner. Not a read followed by a write, and
not KV, whose eventual consistency would let a replay through.

**Every failed login answers identically.** Unknown credential, spent
challenge, wrong origin and a bad signature return the same problem, because
an attacker who can tell them apart learns which half of the ceremony to
work on. The tests assert the responses are identical apart from the request
id.

**The signature is checked before the counter.** That order is the spec's
(7.2 steps 21 then 22) and it matters here more than most places: a counter
regression is the one failure this module acts on permanently, and every
part of an assertion except the signature is attacker-chosen. Checking the
counter first would let one unauthenticated request with a garbage signature
mark a stranger's passkey as a clone.

## What this module does not resist

`POST /login/options` with an email returns that account's credential ids,
which is inherent to the non-discoverable flow: the browser needs them to
choose an authenticator. An account with no passkeys and an address with no
account are indistinguishable, but an account *with* a passkey is not. Both
public endpoints are rate limited by client address for that reason, and by
address only: keying on the email too would let anyone lock a named account
out of its own logins.

Registration requires a live session but not a *recent* one, so a hijacked
session can add a passkey. Requiring a fresh authentication before adding a
credential is the usual hardening and is filed separately.

## Known gap

The tests mint ceremonies with a software authenticator, which covers all
three algorithms and every negative case, but no test here has met real
hardware. Issue #13's last acceptance box is a manual run in a browser
against `wrangler dev` with a platform authenticator, and it stays open.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
